#include "idf_modem_imei.h"

#include <array>
#include <atomic>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <deque>
#include <string>
#include <vector>

using esp_err_t = int;
using TickType_t = uint32_t;
using BaseType_t = int;
constexpr int ESP_OK = 0, ESP_FAIL = -1, ESP_ERR_TIMEOUT = 1, ESP_ERR_INVALID_STATE = 2;
constexpr int ESP_ERR_INVALID_SIZE = 3, ESP_ERR_INVALID_ARG = 4, IDF_MODEM_ERR_BUSY = 5;
constexpr int pdTRUE = 1, portTICK_PERIOD_MS = 1, MODEM_UART = 1;
constexpr TickType_t portMAX_DELAY = UINT32_MAX;
#define pdMS_TO_TICKS(ms) static_cast<TickType_t>(ms)
constexpr size_t OWNER_COMMAND_SLOTS = 4, OWNER_AT_RESPONSE_LIMIT = 8192;
constexpr uint32_t OWNER_SLOT_RECLAIM_MUTEX_TIMEOUT_MS = 100;
constexpr uint32_t HTTPS_UART_DRAIN_MAX_MS = 250, HTTPS_CLEANUP_WAIT_MARGIN_MS = 1000;
constexpr size_t IDF_MODEM_HTTPS_POST_MAX_URL = 2048, IDF_MODEM_HTTPS_POST_MAX_BODY = 8192;
constexpr size_t IDF_MODEM_HTTPS_POST_MAX_CONTENT_TYPE = 256, IDF_MODEM_HTTPS_POST_MAX_HEADER_NAME = 256;
constexpr size_t IDF_MODEM_HTTPS_POST_MAX_HEADER_VALUE = 256, IDF_MODEM_HTTPS_ROOT_DER_MAX = 4096;
enum class IdfHttpsFailureStage { none, modem };
enum class IdfModemUsbQueryBusyReason { gate_closed, mutex_timeout, slots_full, queue_full };
struct IdfModemHttpsPostRequest {
    std::string url, body, contentType, headerName, headerValue, apn;
    std::vector<uint8_t> rootCertificateDer;
    std::array<uint8_t, 32> rootCertificateSha256{};
};
struct IdfModemHttpsPostResult { bool ok = false; IdfHttpsFailureStage failureStage = IdfHttpsFailureStage::none; };
struct FakeSemaphore { bool completion = false; unsigned tokens = 0; };
using SemaphoreHandle_t = FakeSemaphore*;
using QueueHandle_t = std::deque<int>*;
#include "imei_types.inc"

static int64_t now_us = 1000000;
static bool session_blocked = false;
static bool refuse_queue = false, reset_on_dispatch = false;
static bool enqueue_sms_ack = false;
static uint32_t queue_delay_ms = 0;
static FakeSemaphore session_sem, command_sem, status_sem, completions[OWNER_COMMAND_SLOTS];
static SemaphoreHandle_t s_session_mutex = &session_sem, s_command_mutex = &command_sem;
static SemaphoreHandle_t s_status_mutex = &status_sem;
static std::deque<int> normal_queue, priority_queue;
static QueueHandle_t s_command_queue = &normal_queue, s_priority_command_queue = &priority_queue;
static OwnerCommandSlot s_command_slots[OWNER_COMMAND_SLOTS];
static bool s_started = true;
static std::atomic<bool> s_runtime_queue_ready{true};
static std::atomic<int> s_reset_request{0};
static int current_task = 1, s_owner_task = 2;
static IdfModemStatus s_status;
static std::string s_uart_line_carry, urcs;
static bool s_uart_wait_cmt_pdu = false;
static int64_t s_uart_wait_cmt_until_us = 0;
static std::vector<std::string> writes;
struct UartChunk { std::string bytes; uint32_t delay_ms = 0; };
static std::deque<std::vector<UartChunk>> replies;
static std::deque<UartChunk> receive_chunks;

static int64_t esp_timer_get_time() { return now_us; }
static TickType_t xTaskGetTickCount() { return static_cast<TickType_t>(now_us / 1000); }
static void vTaskDelay(TickType_t ticks) { now_us += static_cast<int64_t>(ticks) * 1000; }
static int xTaskGetCurrentTaskHandle() { return current_task; }
static void assert_owner_task() { assert(current_task == s_owner_task); }
static bool owner_process_one_command(bool priority);
static void pump_owner()
{
    const int caller = current_task;
    current_task = s_owner_task;
    if (reset_on_dispatch) s_reset_request = 1;
    owner_process_one_command(false);
    current_task = caller;
}
static BaseType_t xSemaphoreTake(SemaphoreHandle_t sem, TickType_t wait)
{
    if (!sem->completion) return pdTRUE;
    if (!sem->tokens && wait) {
        const auto delay = std::min(wait, queue_delay_ms);
        now_us += static_cast<int64_t>(delay) * 1000;
        queue_delay_ms -= delay;
        if (delay < wait && !normal_queue.empty()) pump_owner();
        else if (delay == 0) now_us += static_cast<int64_t>(wait) * 1000;
    }
    if (!sem->tokens) return 0;
    --sem->tokens;
    return pdTRUE;
}
static BaseType_t xSemaphoreTakeRecursive(SemaphoreHandle_t, TickType_t wait)
{
    if (!session_blocked) return pdTRUE;
    now_us += static_cast<int64_t>(wait) * 1000;
    return 0;
}
static void xSemaphoreGive(SemaphoreHandle_t sem) { if (sem->completion) ++sem->tokens; }
static void xSemaphoreGiveRecursive(SemaphoreHandle_t) {}
static BaseType_t xQueueSend(QueueHandle_t queue, const int* slot, TickType_t)
{
    if (refuse_queue) return 0;
    queue->push_back(*slot);
    return pdTRUE;
}
static BaseType_t xQueueReceive(QueueHandle_t queue, int* slot, TickType_t)
{
    if (queue->empty()) return 0;
    *slot = queue->front();
    queue->pop_front();
    return pdTRUE;
}
static void wake_owner_task() {}
static void set_query_busy_reason(uint8_t* out, uint8_t value) { if (out) *out = value; }
static int owner_uart_write(const void* data, size_t length)
{
    assert_owner_task();
    writes.emplace_back(static_cast<const char*>(data), length);
    if (writes.back() == "AT+CNMA=0\r\n") {
        receive_chunks.push_back({"OK\r\n"});
        return static_cast<int>(length);
    }
    if (enqueue_sms_ack) {
        enqueue_sms_ack = false;
        auto& slot = s_command_slots[1];
        slot.request.command = "AT+CNMA=0";
        slot.request.timeout_ms = 1500;
        slot.state = OwnerCommandState::queued;
        priority_queue.push_back(1);
    }
    if (!replies.empty()) {
        for (const auto& chunk : replies.front()) receive_chunks.push_back(chunk);
        replies.pop_front();
    }
    return static_cast<int>(length);
}
static int owner_uart_read(uint8_t* out, size_t capacity, TickType_t wait)
{
    assert_owner_task();
    if (receive_chunks.empty()) { now_us += static_cast<int64_t>(wait) * 1000; return 0; }
    auto& chunk = receive_chunks.front();
    const auto delay = std::min(wait, chunk.delay_ms);
    now_us += static_cast<int64_t>(delay) * 1000;
    chunk.delay_ms -= delay;
    if (chunk.delay_ms) return 0;
    const auto size = std::min(capacity, chunk.bytes.size());
    std::memcpy(out, chunk.bytes.data(), size);
    chunk.bytes.erase(0, size);
    if (chunk.bytes.empty()) receive_chunks.pop_front();
    return static_cast<int>(size);
}
static esp_err_t uart_get_buffered_data_len(int, size_t* length)
{
    *length = receive_chunks.empty() || receive_chunks.front().delay_ms ? 0 : receive_chunks.front().bytes.size();
    return ESP_OK;
}
static void append_urc_text(const std::string& value) { urcs += value; }
static std::string idf_util_trim_copy(const std::string& input)
{
    const size_t first = input.find_first_not_of(" \r\n\t");
    return first == std::string::npos ? std::string() : input.substr(first, input.find_last_not_of(" \r\n\t") - first + 1);
}
namespace idf_modem_https_wire {
struct MipOpenLatch { bool nonfatal() const { return true; } bool feed(std::string_view) { return true; } };
}
struct TickDeadline;
static esp_err_t owner_send_at(const std::string&, uint32_t, std::string&, bool = false,
                               const char* = nullptr, size_t = OWNER_AT_RESPONSE_LIMIT,
                               bool* = nullptr, uint8_t* = nullptr);
static esp_err_t submit_owner_command(const OwnerCommand&, std::string*, bool, uint8_t* = nullptr,
                                      IdfModemHttpsPostResult* = nullptr, bool* = nullptr, uint8_t* = nullptr);
static esp_err_t owner_send_at_until(const std::string&, const char*, uint32_t, std::string&) { assert(false); return ESP_FAIL; }
static esp_err_t owner_send_pdu(const std::string&, const char*, uint32_t, std::string&) { assert(false); return ESP_FAIL; }
static esp_err_t owner_https_post(const IdfModemHttpsPostRequest&, IdfModemHttpsPostResult&, TickDeadline&) { assert(false); return ESP_FAIL; }
#include "imei_runtime.inc"
#include "imei_sampling.inc"

static void reset_fixture()
{
    now_us = 1000000;
    session_blocked = false;
    refuse_queue = false; reset_on_dispatch = false;
    enqueue_sms_ack = false;
    queue_delay_ms = 0;
    normal_queue.clear(); priority_queue.clear();
    s_started = true; s_runtime_queue_ready = true; s_reset_request = 0;
    current_task = 1;
    s_status = {};
    s_status.imei = "860000000000009";
    s_uart_line_carry.clear(); s_uart_wait_cmt_pdu = false; s_uart_wait_cmt_until_us = 0;
    urcs.clear(); writes.clear(); replies.clear(); receive_chunks.clear();
    for (size_t i = 0; i < OWNER_COMMAND_SLOTS; ++i) {
        completions[i] = {true, 0};
        s_command_slots[i].completed = &completions[i];
        reset_owner_slot(s_command_slots[i]);
    }
}

static void test_session_deadline()
{
    reset_fixture();
    session_blocked = true;
    std::string output = "sentinel";
    const auto start = now_us;
    assert(idf_modem_get_imei(output, 1500) == ESP_ERR_TIMEOUT);
    assert(output.empty());
    assert(writes.empty());
    assert(now_us - start <= 1500000);
}

static void test_owner_queue_deadline()
{
    reset_fixture();
    queue_delay_ms = 800;
    replies = {{{"860000000000001\r\nOK\r\n", 600}}};
    std::string output = "sentinel";
    const auto start = now_us;
    assert(idf_modem_get_imei(output, 1000) == ESP_ERR_TIMEOUT);
    assert(output.empty());
    assert(now_us - start <= 1000000);
    assert(writes.size() == 1);

    reset_fixture();
    queue_delay_ms = 2000;
    assert(idf_modem_get_imei(output, 1000) == ESP_ERR_TIMEOUT);
    assert(output.empty());
    now_us += 2000000;
    while (!normal_queue.empty()) pump_owner();
    assert(writes.empty());
    for (const auto& slot : s_command_slots) assert(slot.state == OwnerCommandState::free);
}

static void test_fallbacks_and_output_contract()
{
    reset_fixture();
    replies = {
        {{"AT+CGSN=1\r\nERROR\r\n"}},
        {{"AT+GSN=1\r\n+GSN: 860000000000001\r\nOK\r\n"}},
    };
    std::string output = "sentinel";
    assert(idf_modem_get_imei(output, 3000) == ESP_OK);
    assert(output == "860000000000001");
    assert((writes == std::vector<std::string>{"AT+CGSN=1\r\n", "AT+GSN=1\r\n"}));
    assert(s_status.imei == "860000000000009");
    assert(!s_status.identityFresh && !s_status.signalFresh);

    reset_fixture();
    replies = {
        {{"ERROR\r\n"}}, {{"ERROR\r\n"}}, {{"ERROR\r\n"}},
        {{"+GSN: 860000000000001\r\nOK\r\n"}},
    };
    assert(idf_modem_get_imei(output, 3000) == ESP_OK);
    assert(output == "860000000000001");
    assert((writes == std::vector<std::string>{"AT+CGSN=1\r\n", "AT+GSN=1\r\n", "AT+CGSN\r\n", "AT+GSN\r\n"}));

    reset_fixture();
    const std::string malformed = "+UNKNOWN: 860000000000001\r\nOK\r\n";
    replies = {{{malformed}}, {{malformed}}, {{malformed}}, {{malformed}}};
    output = "sentinel";
    assert(idf_modem_get_imei(output, 3000) != ESP_OK);
    assert(output.empty());
    assert(s_status.imei == "860000000000009");

    reset_fixture();
    refuse_queue = true;
    output = "sentinel";
    assert(idf_modem_get_imei(output, 3000) == IDF_MODEM_ERR_BUSY);
    assert(output.empty() && writes.empty());
    assert(normal_queue.empty());

    reset_fixture();
    reset_on_dispatch = true;
    assert(idf_modem_get_imei(output, 3000) == ESP_ERR_INVALID_STATE);
    assert(output.empty() && writes.empty());

    reset_fixture();
    assert(idf_modem_get_imei(output, 0) == ESP_ERR_TIMEOUT);
    assert(output.empty() && writes.empty());
}

static void test_uart_interleaving_and_framing()
{
    reset_fixture();
    replies = {{{"860000000000001\r\nOK\r\n+CEREG: 1\r\n"}}};
    std::string output;
    assert(idf_modem_get_imei(output, 3000) == ESP_OK);
    assert(output == "860000000000001");
    assert(urcs == "+CEREG: 1\r\n");
    assert(writes.size() == 1);

    reset_fixture();
    current_task = s_owner_task;
    constexpr char header[] = "+CMT: ,23\r\n0011";
    preserve_uart_urcs(reinterpret_cast<const uint8_t*>(header), sizeof(header) - 1);
    current_task = 1;
    replies = {{{"000D916819845612F60000FFAA00\r\n", 10},
                {"+CGSN: 860000000000001\r\nOK\r\n", 10}}};
    assert(idf_modem_get_imei(output, 3000) == ESP_OK);
    assert(output == "860000000000001");
    assert(urcs == "+CMT: ,23\r\n0011000D916819845612F60000FFAA00\r\n");
    assert(!s_uart_wait_cmt_pdu);

    reset_fixture();
    replies = {{{"860000000000001\r\nOK"}, {"AY\r\n"}}};
    assert(idf_modem_get_imei(output, 500) != ESP_OK);
    assert(output.empty());

    reset_fixture();
    replies = {{{"+CGSN: 860000000000001\r\nO"}, {"K\r\n", 10}}};
    assert(idf_modem_get_imei(output, 500) == ESP_OK);
    assert(output == "860000000000001");

    reset_fixture();
    current_task = s_owner_task;
    replies = {{{"860000000000001\r\nOK\r\n"}}};
    assert(idf_modem_get_imei(output, 500) == ESP_OK);
    assert(output == "860000000000001" && normal_queue.empty());
    assert(!s_status.identityFresh && !s_status.signalFresh);

    reset_fixture();
    replies = {{{"+CSQ: 20,99\r\nOK"}}};
    std::string response;
    assert(send_ok("AT+CSQ", 1000, &response));
    assert(response == "+CSQ: 20,99\r\nOK");
}

static void test_frames()
{
    const std::vector<std::pair<std::string, bool>> frames = {
        {"860000000000001\r\nOK\r\n", true},
        {"+CGSN: 860000000000001\r\nOK", true},
        {"+GSN: 860000000000001\r\nOK", true},
        {"AT+CGSN\r\n860000000000001\r\nOK", true},
        {"AT+CGSN\r\nAT+CGSN\r\n860000000000001\r\nOK", false},
        {"860000000000001\r\n+CGSN: 860000000000001\r\nOK", false},
        {"AT+GSN\r\n860000000000001\r\nOK", false},
        {"+UNKNOWN: 860000000000001\r\nOK", false},
        {"text 860000000000001\r\nOK", false},
        {"ERROR\r\n", false},
        {"+CMS ERROR: 500\r\n", false},
        {"+CME ERROR: 10\r\n", false},
        {"860000000000001\r\n", false},
        {"860000000000001\r\nOK\r\n+UNKNOWN: 1\r\n", false},
        {"+CGSN: 86000000000000\r\nOK", false},
        {"+CGSN: 8600000000000011\r\nOK", false},
        {"+CGSN: 86000000000000111\r\nOK", false},
        {"+CGSN: 86000000000000x\r\nOK", false},
        {std::string("860000000000001\0\r\nOK", 20), false},
        {"+CMT: ,23\r\nOK", false},
    };
    for (const auto& [frame, expected] : frames) {
        std::string output = "sentinel";
        assert(idf_modem_parse_imei_frame(frame, "AT+CGSN", output) == expected);
        assert(output == (expected ? "860000000000001" : ""));
    }
    assert(is_imei_text("860000000000001"));
    assert(!is_imei_text("86000000000000"));
    assert(!is_imei_text("8600000000000011"));
    assert(!is_imei_text("86000000000000111"));
    reset_fixture();
    for (const char* value : {"86000000000000", "8600000000000011", "86000000000000111"}) {
        IdfModemStatus patch;
        patch.imei = value;
        update_status(patch);
        assert(s_status.imei == "860000000000009");
    }
    IdfModemStatus patch;
    patch.imei = "860000000000001";
    update_status(patch, true);
    assert(s_status.imei == "860000000000001" && s_status.identityFresh);
}

static void test_sampling_acknowledges_sms_between_fallbacks()
{
    reset_fixture();
    current_task = s_owner_task;
    enqueue_sms_ack = true;
    replies = {{{"ERROR\r\n"}}, {{"+GSN: 860000000000001\r\nOK\r\n"}}};
    std::string output;
    sample_imei_slice(output);
    assert(output == "860000000000001");
    assert((writes == std::vector<std::string>{"AT+CGSN=1\r\n", "AT+CNMA=0\r\n", "AT+GSN=1\r\n"}));
}

int main()
{
    test_sampling_acknowledges_sms_between_fallbacks();
    test_session_deadline();
    test_owner_queue_deadline();
    test_fallbacks_and_output_contract();
    test_uart_interleaving_and_framing();
    test_frames();
    return 0;
}
