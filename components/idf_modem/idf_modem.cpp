#include "idf_modem.h"

#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

#include <algorithm>
#include <atomic>

#include "driver/gpio.h"
#include "driver/uart.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "idf_log.h"
#include "idf_modem_imei.h"
#include "idf_modem_https_wire.h"
#if SMS_USB_RECOVERY
#include "idf_modem_cpol_summary.h"
#endif
#include "idf_modem_query_filter.h"
#include "idf_modem_registration.h"
#include "idf_util.h"
#include "nvs.h"

static const char* TAG = "idf_modem";

static constexpr uart_port_t MODEM_UART = UART_NUM_1;
static constexpr gpio_num_t MODEM_TXD = GPIO_NUM_3;
static constexpr gpio_num_t MODEM_RXD = GPIO_NUM_4;
static constexpr gpio_num_t MODEM_EN = GPIO_NUM_5;
static constexpr int MODEM_BAUD = 115200;
static constexpr int UART_RX_BUF = 4096;
static constexpr int MODEM_POWERDOWN_MS = 1200;
static constexpr int MODEM_POWERUP_MIN_MS = 1500;
static constexpr int MODEM_POWERUP_MAX_MS = 6000;
static constexpr uint32_t MODEM_DATA_MODE_RETRY_GAP_MS = 10000UL;
static constexpr uint8_t MODEM_DATA_MODE_RETRY_MAX = 3;
static constexpr uint32_t HTTPS_CLEANUP_TIMEOUT_MS = 10000UL;
static constexpr uint32_t HTTPS_UART_DRAIN_MAX_MS = 250UL;
static constexpr uint32_t HTTPS_CLEANUP_CLOSE_COMMANDS_MAX = 1UL;
static constexpr uint32_t HTTPS_CLEANUP_CLOSE_STATE_COMMANDS_MAX = 1UL;
static constexpr uint32_t HTTPS_CLEANUP_CONFIGS_MAX = 3UL;  // ssl, autofree, encoding
static constexpr uint32_t HTTPS_CLEANUP_CONFIG_COMMANDS_MAX = 2UL;  // setter and query
static constexpr uint32_t HTTPS_CLEANUP_PDP_COMMANDS_MAX = 1UL;
static constexpr uint32_t HTTPS_CLEANUP_PDP_PROFILE_RESTORE_COMMANDS_MAX = 2UL;
static constexpr uint32_t OWNER_SLOT_RECLAIM_MUTEX_TIMEOUT_MS = 100UL;
static constexpr uint32_t HTTPS_CLEANUP_COMMANDS_MAX =
    HTTPS_CLEANUP_CLOSE_COMMANDS_MAX +
    HTTPS_CLEANUP_CLOSE_STATE_COMMANDS_MAX +
    HTTPS_CLEANUP_CONFIGS_MAX * HTTPS_CLEANUP_CONFIG_COMMANDS_MAX +
    HTTPS_CLEANUP_PDP_COMMANDS_MAX +
    HTTPS_CLEANUP_PDP_PROFILE_RESTORE_COMMANDS_MAX;
static constexpr uint32_t HTTPS_CLEANUP_WAIT_MARGIN_MS =
    HTTPS_CLEANUP_COMMANDS_MAX * (HTTPS_CLEANUP_TIMEOUT_MS + HTTPS_UART_DRAIN_MAX_MS) + 1000UL;
static constexpr uint32_t IDENTITY_RETRY_INTERVAL_MS = 600000UL;
static constexpr uint32_t MODEM_RETRY_DELAYS_MS[] = {
    30000UL, 60000UL, 120000UL, 300000UL, IDENTITY_RETRY_INTERVAL_MS,
};
static constexpr size_t MODEM_RETRY_DELAY_COUNT =
    sizeof(MODEM_RETRY_DELAYS_MS) / sizeof(MODEM_RETRY_DELAYS_MS[0]);
static constexpr uint32_t SIGNAL_INTERVAL_WEB_MS = 10000UL;
static constexpr uint32_t SIGNAL_DETAIL_INTERVAL_WEB_MS = 30000UL;
static constexpr uint32_t SIM_CHECK_INTERVAL_MS = 15000UL;  // SIM hot-swap poll interval
static constexpr int64_t WEB_POLL_ACTIVE_WINDOW_US = 15LL * 1000LL * 1000LL;
static constexpr size_t URC_BUFFER_MAX = 8192;
static constexpr size_t OWNER_COMMAND_SLOTS = 4;
static constexpr size_t OWNER_AT_RESPONSE_LIMIT = 8192;
static constexpr size_t OWNER_MIP_RESPONSE_LIMIT = 16384;

enum class OwnerCommandKind : uint8_t { at, until, pdu, https_post };
enum class OwnerCommandState : uint8_t { free, queued, running, done, abandoned };

struct OwnerCommand {
    OwnerCommandKind kind = OwnerCommandKind::at;
    std::string command;
    std::string token;
    std::string pdu;
    IdfModemHttpsPostRequest https_post_request;
    uint32_t timeout_ms = 0;
    int64_t deadline_us = 0;
    TickType_t deadline_start = 0;
    TickType_t deadline_span = 0;
    bool filter_urcs = false;
    std::string response_prefix;
    size_t response_limit = OWNER_AT_RESPONSE_LIMIT;
    bool capture_other_line = false;
};

struct OwnerCommandSlot {
    OwnerCommandState state = OwnerCommandState::free;
    std::atomic<bool> caller_abandoned{false};
    OwnerCommand request;
    std::string response;
    bool other_line_present = false;
    uint8_t msslcipher_telemetry = 0;
    IdfModemHttpsPostResult https_post_result;
    esp_err_t result = ESP_FAIL;
    SemaphoreHandle_t completed = nullptr;
};

static void reset_owner_slot(OwnerCommandSlot& slot);

static bool https_status_valid(int status)
{
    return status >= 100 && status <= 599;
}

static bool https_certificate_material_invalid(const IdfModemHttpsPostRequest& request)
{
    return request.rootCertificateDer.empty() ||
           request.rootCertificateDer.size() > IDF_MODEM_HTTPS_ROOT_DER_MAX ||
           std::all_of(request.rootCertificateSha256.begin(), request.rootCertificateSha256.end(),
                       [](uint8_t byte) { return byte == 0; });
}

static IdfHttpsFailureStage https_request_failure_stage(
    const IdfModemHttpsPostRequest& request)
{
    if (https_certificate_material_invalid(request)) return IdfHttpsFailureStage::ca;
    IdfModemHttpsTarget target;
    std::string error;
    const size_t max_url = request.method == IdfModemHttpsMethod::Get
                               ? IDF_MODEM_HTTPS_GET_MAX_URL
                               : IDF_MODEM_HTTPS_POST_MAX_URL;
    if (!idf_modem_https_parse_url(request.url, target, error, max_url)) {
        return IdfHttpsFailureStage::target;
    }
    return IdfHttpsFailureStage::request;
}

// session_mutex keeps exclusive eSIM multi-command sessions. Command slots never store caller pointers.
static SemaphoreHandle_t s_session_mutex = nullptr;
static SemaphoreHandle_t s_command_mutex = nullptr;
static SemaphoreHandle_t s_status_mutex = nullptr;
static SemaphoreHandle_t s_urc_mutex = nullptr;
static QueueHandle_t s_command_queue = nullptr;
static QueueHandle_t s_priority_command_queue = nullptr;
static OwnerCommandSlot s_command_slots[OWNER_COMMAND_SLOTS];
static TaskHandle_t s_owner_task = nullptr;
// UART events wake the modem task when a URC arrives instead of polling every 500 ms.
static QueueHandle_t s_uart_evt_queue = nullptr;
// Wake the SMS task for a buffered URC or queued Web SMS.
static SemaphoreHandle_t s_event_sem = nullptr;
static IdfModemStatus s_status;
static std::string s_urc_buffer;
// AT responses and asynchronous URCs share the UART. Extract SMS and call URCs
// by line so a split +CMT header and PDU do not enter the next AT response.
static std::string s_uart_line_carry;
static bool s_uart_wait_cmt_pdu = false;

#if SMS_USB_RECOVERY
static void set_query_busy_reason(uint8_t* output, uint8_t reason)
{
    if (output) *output = reason;
}
#else
static void set_query_busy_reason(uint8_t*, uint8_t) {}
#endif
static int64_t s_uart_wait_cmt_until_us = 0;
static bool s_started = false;
// Before normal queue scheduling, accept only direct SMS acknowledgments.
static std::atomic<bool> s_runtime_queue_ready{false};
static std::atomic<int> s_reset_request{0};  // 1=AT soft reset, 2=EN hard reset; modem task executes
static std::atomic<bool> s_data_mode_retry_pending{false};
static std::atomic<uint8_t> s_data_mode_retry_count{0};
static std::atomic<TickType_t> s_next_data_mode_retry{0};
static std::atomic<int> s_logged_sms_storage_code{-1};  // -1=unknown, 0=MT, 1=ME, 2=SM
static bool s_identity_static_attempted = false;
static bool s_identity_network_attempted = false;
static std::atomic<int64_t> s_last_web_poll_us{-WEB_POLL_ACTIVE_WINDOW_US};
static std::atomic<uint32_t> s_status_sample_requests{0};
static std::atomic<uint32_t> s_esim_operation_depth{0};
static std::atomic<int> s_sim_unlock_request{0};  // 1=recheck or automatic PIN, 2=confirmed PUK attempt
static std::string s_last_pin_attempt_key;
static std::atomic<uint8_t> s_health_reset_retry_count{0};
static std::atomic<TickType_t> s_next_health_reset_tick{0};
static std::atomic<bool> s_health_reset_claimed{false};

void idf_modem_signal_event(void);

struct TickDeadline;

static esp_err_t owner_send_at(const std::string& cmd, uint32_t timeout_ms, std::string& response,
                               bool filter_urcs = false, const char* response_prefix = nullptr,
                               size_t response_limit = OWNER_AT_RESPONSE_LIMIT,
                               bool* other_line_present = nullptr,
                               uint8_t* msslcipher_telemetry = nullptr);
static esp_err_t owner_send_at_until(const std::string& cmd, const char* token,
                                     uint32_t timeout_ms, std::string& response);
static esp_err_t owner_send_pdu(const std::string& cmgs_cmd, const char* pdu,
                                uint32_t timeout_ms, std::string& response);
static esp_err_t owner_https_post(const IdfModemHttpsPostRequest& request,
                                  IdfModemHttpsPostResult& result, TickDeadline& deadline);
static esp_err_t submit_owner_command(const OwnerCommand& request, std::string* response,
                                      bool priority,
                                      uint8_t* query_busy_reason = nullptr,
                                      IdfModemHttpsPostResult* https_result = nullptr,
                                      bool* other_line_present = nullptr,
                                      uint8_t* msslcipher_telemetry = nullptr);
static bool owner_process_one_command(bool priority);
static void owner_drain_priority_commands();
static void wake_owner_task();

static void assert_owner_task()
{
    configASSERT(s_owner_task != nullptr);
    configASSERT(xTaskGetCurrentTaskHandle() == s_owner_task);
}

static int owner_uart_read(uint8_t* data, size_t size, TickType_t wait)
{
    assert_owner_task();
    return uart_read_bytes(MODEM_UART, data, size, wait);
}

static int owner_uart_write(const void* data, size_t size)
{
    assert_owner_task();
    return uart_write_bytes(MODEM_UART, data, size);
}

static void owner_uart_flush()
{
    assert_owner_task();
    uart_flush_input(MODEM_UART);
}

static void cleanup_start_resources()
{
    if (s_session_mutex) {
        vSemaphoreDelete(s_session_mutex);
        s_session_mutex = nullptr;
    }
    if (s_command_mutex) {
        vSemaphoreDelete(s_command_mutex);
        s_command_mutex = nullptr;
    }
    if (s_status_mutex) {
        vSemaphoreDelete(s_status_mutex);
        s_status_mutex = nullptr;
    }
    if (s_urc_mutex) {
        vSemaphoreDelete(s_urc_mutex);
        s_urc_mutex = nullptr;
    }
    if (s_event_sem) {
        vSemaphoreDelete(s_event_sem);
        s_event_sem = nullptr;
    }
    if (s_command_queue) {
        vQueueDelete(s_command_queue);
        s_command_queue = nullptr;
    }
    if (s_priority_command_queue) {
        vQueueDelete(s_priority_command_queue);
        s_priority_command_queue = nullptr;
    }
    for (auto& slot : s_command_slots) {
        if (slot.completed) vSemaphoreDelete(slot.completed);
        slot.completed = nullptr;
        reset_owner_slot(slot);
    }
    s_owner_task = nullptr;
    s_runtime_queue_ready.store(false, std::memory_order_release);
    s_urc_buffer.clear();
    s_uart_line_carry.clear();
    s_uart_wait_cmt_pdu = false;
    s_uart_wait_cmt_until_us = 0;
}

static bool parse_long_token(const std::string& value, long& out)
{
    std::string text = idf_util_trim_copy(value);
    if (text.empty()) return false;
    errno = 0;
    char* end = nullptr;
    long parsed = strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || errno == ERANGE) return false;
    while (*end && isspace(static_cast<unsigned char>(*end))) ++end;
    if (*end != '\0') return false;
    out = parsed;
    return true;
}

static bool parse_comma_longs(const std::string& text, long* values, int max_values, int& count)
{
    count = 0;
    size_t start = 0;
    while (start < text.size() && count < max_values) {
        size_t comma = text.find(',', start);
        std::string part = text.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        part = idf_util_trim_copy(part);
        long value = 0;
        if (part.empty() || !parse_long_token(part, value)) return false;
        values[count++] = value;
        if (comma == std::string::npos) break;
        start = comma + 1;
    }
    return count > 0;
}

// Use an unsigned elapsed-time difference across the 49.7-day tick wrap.
static TickType_t timeout_ticks_ceil(uint32_t milliseconds)
{
    if (milliseconds == 0) return 0;
    const uint32_t tick_ms = portTICK_PERIOD_MS;
    return static_cast<TickType_t>((milliseconds + tick_ms - 1U) / tick_ms);
}

struct TickDeadline {
    TickType_t start;
    TickType_t span;
    int64_t deadline_us = 0;
    explicit TickDeadline(uint32_t ms) : start(xTaskGetTickCount()), span(timeout_ticks_ceil(ms)) {}
    TickDeadline(TickType_t start_tick, TickType_t span_ticks)
        : start(start_tick), span(span_ticks) {}
    TickType_t remaining_ticks() const
    {
        const TickType_t elapsed = static_cast<TickType_t>(xTaskGetTickCount() - start);
        if (elapsed >= span) return 0;
        TickType_t remaining = span - elapsed;
        if (deadline_us != 0) {
            const int64_t remaining_us = deadline_us - esp_timer_get_time();
            if (remaining_us <= 0) return 0;
            remaining = std::min<TickType_t>(remaining,
                remaining_us / (1000LL * portTICK_PERIOD_MS));
        }
        return remaining;
    }
    bool expired() const { return remaining_ticks() == 0; }
    void restart(uint32_t ms) { start = xTaskGetTickCount(); span = timeout_ticks_ceil(ms); }
};

static bool owner_uart_write_all(const void* data, size_t size, TickDeadline& deadline)
{
    assert_owner_task();
    const auto* bytes = static_cast<const uint8_t*>(data);
    size_t written = 0;
    while (written < size) {
        if (deadline.expired()) return false;
        const int count = owner_uart_write(bytes + written, size - written);
        if (count <= 0 || static_cast<size_t>(count) > size - written) return false;
        written += static_cast<size_t>(count);
    }
    return true;
}

// Final AT result: 1=OK, -1=ERROR/+CMS ERROR/+CME ERROR, 0=incomplete.
// Accept a final result without trailing CRLF because a UART block can end at "OK".
static int at_final_result(const std::string& resp)
{
    size_t pos = 0;
    while (pos < resp.size()) {
        size_t end = resp.find_first_of("\r\n", pos);
        if (end == std::string::npos) end = resp.size();
        std::string line = idf_util_trim_copy(resp.substr(pos, end - pos));
        if (line == "OK") return 1;
        if (line == "ERROR" || line.rfind("+CMS ERROR", 0) == 0 ||
            line.rfind("+CME ERROR", 0) == 0) return -1;
        pos = end;
        while (pos < resp.size() && (resp[pos] == '\r' || resp[pos] == '\n')) ++pos;
    }
    return 0;
}

static bool has_cmgs_result(const std::string& resp)
{
    size_t pos = resp.find("+CMGS:");
    if (pos == std::string::npos) return false;
    pos += strlen("+CMGS:");
    while (pos < resp.size() && isspace(static_cast<unsigned char>(resp[pos]))) ++pos;
    if (pos >= resp.size() || !isdigit(static_cast<unsigned char>(resp[pos]))) return false;
    while (pos < resp.size() && isdigit(static_cast<unsigned char>(resp[pos]))) ++pos;
    return true;
}

// Return the complete line that contains the token, not the first non-empty line.
static std::string line_containing(const std::string& resp, size_t pos)
{
    size_t start = resp.rfind('\n', pos);
    start = (start == std::string::npos) ? 0 : start + 1;
    size_t end = resp.find('\n', pos);
    if (end == std::string::npos) end = resp.size();
    std::string line = resp.substr(start, end - start);
    size_t s = 0;
    while (s < line.size() && isspace(static_cast<unsigned char>(line[s]))) ++s;
    size_t e = line.size();
    while (e > s && isspace(static_cast<unsigned char>(line[e - 1]))) --e;
    return line.substr(s, e - s);
}

static bool line_is_payload(const std::string& line, const char* cmd)
{
    if (line.empty() || line == "OK" || line == "ERROR") return false;
    if (cmd && line == cmd) return false;
    return true;
}

static std::string first_payload_line(const std::string& resp, const char* cmd = nullptr)
{
    size_t pos = 0;
    while (pos < resp.size()) {
        size_t end = resp.find('\n', pos);
        if (end == std::string::npos) end = resp.size();
        std::string line = idf_util_trim_copy(resp.substr(pos, end - pos));
        if (line_is_payload(line, cmd)) return line;
        pos = end + 1;
    }
    return {};
}

static std::string first_digits_line(const std::string& resp, size_t min_len, size_t max_len)
{
    size_t pos = 0;
    while (pos < resp.size()) {
        size_t end = resp.find('\n', pos);
        if (end == std::string::npos) end = resp.size();
        std::string line = idf_util_trim_copy(resp.substr(pos, end - pos));
        bool digits = !line.empty();
        for (char ch : line) digits = digits && isdigit(static_cast<unsigned char>(ch));
        if (digits && line.size() >= min_len && line.size() <= max_len) return line;
        pos = end + 1;
    }
    return {};
}

static std::string first_digit_run(const std::string& resp, size_t min_len, size_t max_len)
{
    size_t start = std::string::npos;
    for (size_t i = 0; i <= resp.size(); ++i) {
        bool digit = i < resp.size() && isdigit(static_cast<unsigned char>(resp[i]));
        if (digit && start == std::string::npos) {
            start = i;
        } else if (!digit && start != std::string::npos) {
            size_t len = i - start;
            if (len >= min_len && len <= max_len) return resp.substr(start, len);
            start = std::string::npos;
        }
    }
    return {};
}

static bool is_iccid_text(const std::string& value)
{
    if (value.size() < 15 || value.size() > 22) return false;
    bool seen_digit = false;
    bool padding = false;
    uint8_t padding_count = 0;
    for (char ch : value) {
        if (isdigit(static_cast<unsigned char>(ch))) {
            if (padding) return false;
            seen_digit = true;
        } else if (ch == 'F' || ch == 'f') {
            if (!seen_digit) return false;
            padding = true;
            if (++padding_count > 1) return false;
        } else {
            return false;
        }
    }
    return seen_digit;
}

static bool is_imei_text(const std::string& value)
{
    return idf_modem_imei_digits(value);
}

static bool is_imsi_text(const std::string& value)
{
    if (value.size() < 14 || value.size() > 16) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return isdigit(static_cast<unsigned char>(ch));
    });
}

static std::string first_quoted(const std::string& line, size_t start = 0)
{
    size_t q1 = line.find('"', start);
    if (q1 == std::string::npos) return {};
    size_t q2 = line.find('"', q1 + 1);
    if (q2 == std::string::npos) return {};
    return line.substr(q1 + 1, q2 - q1 - 1);
}

static void set_phase(const char* phase)
{
    if (xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        s_status.phase = phase;
        if (strcmp(phase, "powering") == 0 || strcmp(phase, "failed") == 0) {
            s_status.atReady = false;
            s_status.modemReady = false;
        } else if (strcmp(phase, "at_ready") == 0 || strcmp(phase, "registering") == 0 ||
                   strcmp(phase, "sim_locked") == 0) {
            s_status.atReady = true;
            s_status.modemReady = false;
        } else if (strcmp(phase, "ready") == 0) {
            s_status.atReady = true;
            s_status.modemReady = true;
        }
        xSemaphoreGive(s_status_mutex);
    }
}

static void update_status(const IdfModemStatus& patch, bool identity = false, bool signal = false)
{
    if (xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
    s_status.started = patch.started || s_status.started;
    bool phase_patch = !patch.phase.empty() && patch.phase != "off";
    if (phase_patch) {
        s_status.phase = patch.phase;
        if (patch.phase == "powering" || patch.phase == "failed") {
            s_status.atReady = false;
            s_status.modemReady = false;
        } else if (patch.phase == "at_ready" || patch.phase == "registering" || patch.phase == "sim_locked") {
            s_status.atReady = true;
            s_status.modemReady = false;
        } else if (patch.phase == "ready") {
            s_status.atReady = true;
            s_status.modemReady = true;
        }
    }
    if (patch.atReady) s_status.atReady = true;
    bool carries_registration = patch.ceregStat >= 0 || patch.modemReady ||
                                patch.phase == "ready" || patch.phase == "registering" ||
                                patch.phase == "sim_locked" || patch.phase == "failed";
    if (carries_registration) s_status.modemReady = patch.modemReady;
    if (patch.ceregStat >= 0) s_status.ceregStat = patch.ceregStat;
    if (patch.csq >= 0) s_status.csq = patch.csq;
    if (patch.csq >= 0 || patch.ber != 99) s_status.ber = patch.ber;
    if (patch.rsrp != 999) s_status.rsrp = patch.rsrp;
    if (patch.rsrq != 999) s_status.rsrq = patch.rsrq;
    if (patch.sinr != 999) s_status.sinr = patch.sinr;
    if (!patch.mfr.empty()) s_status.mfr = patch.mfr;
    if (!patch.model.empty()) s_status.model = patch.model;
    if (!patch.fwver.empty()) s_status.fwver = patch.fwver;
    if (!patch.imei.empty() && is_imei_text(patch.imei)) s_status.imei = patch.imei;
    if (!patch.iccid.empty() && is_iccid_text(patch.iccid)) s_status.iccid = patch.iccid;
    if (!patch.imsi.empty() && is_imsi_text(patch.imsi)) s_status.imsi = patch.imsi;
    if (!patch.operatorName.empty()) s_status.operatorName = patch.operatorName;
    if (!patch.apnSim.empty()) s_status.apnSim = patch.apnSim;
    if (!patch.cellIp.empty()) s_status.cellIp = patch.cellIp;
    if (!patch.phone.empty()) s_status.phone = patch.phone;
    if (patch.simState != "unknown") {
        s_status.simState = patch.simState;
        s_status.simCredentialMatched = patch.simCredentialMatched;
        s_status.simUnlockMessage = patch.simUnlockMessage;
    }
    if (identity) s_status.identityFresh = true;
    if (signal) s_status.signalFresh = true;
    xSemaphoreGive(s_status_mutex);
}

static bool startup_info_complete(void)
{
    bool complete = false;
    if (xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        complete = s_status.signalFresh &&
                   s_status.identityFresh &&
                   !s_status.mfr.empty() &&
                   !s_status.model.empty() &&
                   !s_status.fwver.empty() &&
                   is_imei_text(s_status.imei) &&
                   is_iccid_text(s_status.iccid) &&
                   is_imsi_text(s_status.imsi) &&
                   !s_status.operatorName.empty() &&
                   s_identity_network_attempted;
        xSemaphoreGive(s_status_mutex);
    }
    return complete;
}

// SIM or network responses can omit ICCID or operator data. Mark one sampling
// pass ready, then let startup_info_complete() request missing fields later.
static bool startup_sampling_done(void)
{
    IdfModemStatus status = idf_modem_get_status();
    return status.signalFresh && status.identityFresh;
}

static void reset_identity_sampling_state(void)
{
    s_identity_static_attempted = false;
    s_identity_network_attempted = false;
}

static void invalidate_registration_state(const char* phase, bool at_ready)
{
    s_data_mode_retry_pending.store(false, std::memory_order_release);
    s_data_mode_retry_count.store(0, std::memory_order_relaxed);
    s_next_data_mode_retry.store(0, std::memory_order_relaxed);
    reset_identity_sampling_state();
    if (xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
    idf_modem_invalidate_registration_stat(s_status.ceregStat);
    s_status.phase = phase;
    s_status.atReady = at_ready;
    s_status.modemReady = false;
    s_status.signalFresh = false;
    s_status.identityFresh = false;
    s_status.cellIp.clear();
    xSemaphoreGive(s_status_mutex);
}

static void set_status_cell_ip(const std::string& ip)
{
    if (xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(500)) != pdTRUE) return;
    s_status.cellIp = ip;
    xSemaphoreGive(s_status_mutex);
}

static std::string read_nvs_string(nvs_handle_t nvs, const char* key, size_t max_len)
{
    size_t len = 0;
    esp_err_t err = nvs_get_str(nvs, key, nullptr, &len);
    if (err != ESP_OK || len == 0 || len > max_len + 1) return {};
    std::string value(len, '\0');
    err = nvs_get_str(nvs, key, value.data(), &len);
    if (err != ESP_OK) return {};
    if (!value.empty() && value.back() == '\0') value.pop_back();
    return value;
}

static void save_identity_cache(const std::string& imei, const std::string& iccid)
{
    bool valid_imei = is_imei_text(imei);
    bool valid_iccid = is_iccid_text(iccid);
    if (!valid_imei && !valid_iccid) return;
    nvs_handle_t nvs = 0;
    if (nvs_open("sms_config", NVS_READWRITE, &nvs) != ESP_OK) return;
    std::string old_imei = read_nvs_string(nvs, "modemImei", 32);
    std::string old_iccid = read_nvs_string(nvs, "modemIccid", 32);
    esp_err_t err = ESP_OK;
    bool changed = false;
    if (valid_imei && imei != old_imei) {
        err = nvs_set_str(nvs, "modemImei", imei.c_str());
        changed = err == ESP_OK;
    }
    if (err == ESP_OK && valid_iccid && iccid != old_iccid) {
        err = nvs_set_str(nvs, "modemIccid", iccid.c_str());
        changed = changed || err == ESP_OK;
    }
    if (err == ESP_OK && changed) err = nvs_commit(nvs);
    nvs_close(nvs);
    if (err == ESP_OK && changed) idf_log_line("modem identity written to cache");
}

static std::string mask_identity(const std::string& value)
{
    if (value.empty()) return "-";
    if (value.size() <= 8) return "****";
    return value.substr(0, 4) + "****" + value.substr(value.size() - 4);
}

static void append_urc_text(const std::string& text)
{
    if (text.empty() || !s_urc_mutex) return;
    if (xSemaphoreTake(s_urc_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return;
    if (text.size() >= URC_BUFFER_MAX) {
        // Keep a complete-line tail when URCs in a long AT response exceed the buffer.
        size_t start = text.size() - URC_BUFFER_MAX;
        size_t nl = text.find('\n', start);
        if (nl != std::string::npos && nl + 1 < text.size()) start = nl + 1;
        s_urc_buffer.assign(text.data() + start, text.size() - start);
    } else {
        size_t need = s_urc_buffer.size() + text.size();
        if (need > URC_BUFFER_MAX) {
            size_t drop = need - URC_BUFFER_MAX;
            s_urc_buffer.erase(0, std::min(drop, s_urc_buffer.size()));
            size_t nl = s_urc_buffer.find('\n');
            if (nl != std::string::npos && nl + 1 < s_urc_buffer.size()) s_urc_buffer.erase(0, nl + 1);
        }
        s_urc_buffer += text;
    }
    xSemaphoreGive(s_urc_mutex);
    idf_modem_signal_event();  // Wake the SMS task immediately.
}

static void append_capped(std::string& out, const uint8_t* data, size_t len, size_t cap);

static bool looks_like_pdu_line(const std::string& line)
{
    if (line.size() < 32 || (line.size() & 1) != 0) return false;
    return std::all_of(line.begin(), line.end(), [](unsigned char ch) { return isxdigit(ch); });
}

static void preserve_uart_urc_line(const std::string& raw)
{
    std::string line = idf_util_trim_copy(raw);
    if (line.empty()) return;
    if (s_uart_wait_cmt_pdu && esp_timer_get_time() > s_uart_wait_cmt_until_us) {
        s_uart_wait_cmt_pdu = false;
    }

    bool cmt = line.rfind("+CMT:", 0) == 0;
    bool standalone = idf_modem_is_standalone_urc_line(line);
    if (cmt || standalone || (s_uart_wait_cmt_pdu && looks_like_pdu_line(line))) {
        append_urc_text(line + "\r\n");
    }
    if (cmt) {
        s_uart_wait_cmt_pdu = true;
        s_uart_wait_cmt_until_us = esp_timer_get_time() + 3LL * 1000LL * 1000LL;
    } else if (s_uart_wait_cmt_pdu && looks_like_pdu_line(line)) {
        s_uart_wait_cmt_pdu = false;
    }
}

static void preserve_uart_urcs(const uint8_t* data, size_t len)
{
    for (size_t i = 0; i < len; ++i) {
        char ch = static_cast<char>(data[i]);
        if (ch == '\r' || ch == '\n') {
            if (!s_uart_line_carry.empty()) preserve_uart_urc_line(s_uart_line_carry);
            s_uart_line_carry.clear();
        } else if (s_uart_line_carry.size() < 768) {
            s_uart_line_carry += ch;
        } else {
            s_uart_line_carry.clear();
            s_uart_wait_cmt_pdu = false;
        }
    }
}

static bool capture_pending_uart_locked(
    TickDeadline& deadline,
    idf_modem_https_wire::MipOpenLatch* open_latch = nullptr)
{
    assert_owner_task();
    if (open_latch && !open_latch->nonfatal()) return false;
    // Return immediately when RX is empty. This runs before every AT command.
    size_t buffered = 0;
    if (uart_get_buffered_data_len(MODEM_UART, &buffered) == ESP_OK && buffered == 0) return true;

    uint8_t buf[128];
    // Bound one pre-command drain without resetting the caller's operation deadline.
    const TickType_t drain_limit =
        std::min(deadline.remaining_ticks(), timeout_ticks_ceil(HTTPS_UART_DRAIN_MAX_MS));
    const TickType_t drain_start = xTaskGetTickCount();
    const TickType_t quiet_limit = timeout_ticks_ceil(40);
    TickType_t quiet_start = drain_start;
    while (!deadline.expired()) {
        const TickType_t elapsed = static_cast<TickType_t>(xTaskGetTickCount() - drain_start);
        if (elapsed >= drain_limit) break;
        const TickType_t quiet_elapsed =
            static_cast<TickType_t>(xTaskGetTickCount() - quiet_start);
        if (quiet_elapsed >= quiet_limit) break;
        TickType_t wait = std::min(pdMS_TO_TICKS(20), drain_limit - elapsed);
        wait = std::min(wait, quiet_limit - quiet_elapsed);
        if (wait == 0) break;
        const int got = owner_uart_read(buf, sizeof(buf), wait);
        if (got > 0) {
            preserve_uart_urcs(buf, static_cast<size_t>(got));
            if (open_latch &&
                !open_latch->feed(std::string_view(
                    reinterpret_cast<const char*>(buf), static_cast<size_t>(got)))) {
                return false;
            }
            quiet_start = xTaskGetTickCount();
        }
    }
    return true;
}

static bool poll_unsolicited_uart(uint32_t max_ms)
{
    assert_owner_task();
    TickDeadline deadline(max_ms);
    capture_pending_uart_locked(deadline);
    return true;
}

static void handle_uart_event_error(const uart_event_t& evt)
{
    if (evt.type == UART_FIFO_OVF || evt.type == UART_BUFFER_FULL) {
        idf_log_line(evt.type == UART_FIFO_OVF
                         ? "modem UART hardware FIFO overflow; received data can be incomplete"
                         : "modem UART receive buffer full; received data can be incomplete");
    } else if (evt.type == UART_PARITY_ERR) {
        idf_log_line("modem UART parity error; received data can be corrupt");
    } else if (evt.type == UART_FRAME_ERR) {
        idf_log_line("modem UART frame error; received data can be corrupt");
    }
}

static bool at_channel_idle_now(void)
{
    if (idf_modem_esim_operation_active()) return false;
    if (!s_session_mutex || !s_command_mutex) return false;
    if (xSemaphoreTakeRecursive(s_session_mutex, 0) != pdTRUE) return false;
    bool idle = false;
    if (xSemaphoreTake(s_command_mutex, 0) == pdTRUE) {
        idle = std::all_of(std::begin(s_command_slots), std::end(s_command_slots), [](const auto& slot) {
            return slot.state == OwnerCommandState::free;
        });
        xSemaphoreGive(s_command_mutex);
    }
    xSemaphoreGiveRecursive(s_session_mutex);
    return idle;
}

static void append_capped(std::string& out, const uint8_t* data, size_t len, size_t cap)
{
    if (!data || len == 0 || cap == 0) return;
    if (len >= cap) {
        out.assign(reinterpret_cast<const char*>(data + len - cap), cap);
        return;
    }
    size_t need = out.size() + len;
    if (need > cap) out.erase(0, need - cap);
    out.append(reinterpret_cast<const char*>(data), len);
}

static esp_err_t owner_send_at_deadline(const std::string& cmd, TickDeadline& deadline,
                                        std::string& response, bool filter_urcs,
                                        const char* response_prefix,
                                        bool* modem_error = nullptr,
                                        size_t response_limit = OWNER_AT_RESPONSE_LIMIT,
                                        bool* other_line_present = nullptr,
                                        uint8_t* msslcipher_telemetry = nullptr)
{
    assert_owner_task();
    if (modem_error) *modem_error = false;
    if (other_line_present) *other_line_present = false;
    if (msslcipher_telemetry) *msslcipher_telemetry = 0;
    if (deadline.expired()) return ESP_ERR_TIMEOUT;

    capture_pending_uart_locked(deadline);
    std::string wire = cmd;
    wire += "\r\n";
    if (!owner_uart_write_all(wire.data(), wire.size(), deadline)) {
        return ESP_FAIL;
    }

    response.clear();
    response.reserve(512);
    const bool imei_query = idf_modem_is_imei_command(cmd);
    const bool imei_waiting_for_pdu = s_uart_wait_cmt_pdu &&
                                    esp_timer_get_time() <= s_uart_wait_cmt_until_us;
    if (imei_query) response = s_uart_line_carry;
    // Limit responses to 8 KB because AT+CMGL can exceed 10 KB with full storage.
    // Detect a truncated OK or ERROR in the overlap window. Later polling recovers omitted SMS.
    constexpr size_t MAX_RESPONSE = 8192;
    uint8_t buf[128];
    std::string scan;  // Overlap window for truncated or split final result codes
    IdfModemQueryResponseFilter query_filter(
        cmd, response_prefix ? response_prefix : "", s_uart_line_carry, s_uart_wait_cmt_pdu,
        std::min(response_limit, OWNER_AT_RESPONSE_LIMIT));
    esp_err_t ret = ESP_ERR_TIMEOUT;
    while (!deadline.expired()) {
        int got = owner_uart_read(buf, sizeof(buf),
                                  std::min(pdMS_TO_TICKS(80), deadline.remaining_ticks()));
        if (got > 0) {
            if (filter_urcs) {
                query_filter.feed(reinterpret_cast<const char*>(buf), static_cast<size_t>(got));
                if (!query_filter.urcs().empty()) {
                    append_urc_text(query_filter.urcs());
                    query_filter.clear_urcs();
                }
                response = query_filter.response();
                s_uart_line_carry = query_filter.carry();
                s_uart_wait_cmt_pdu = query_filter.waiting_for_pdu();
                if (other_line_present) {
                    *other_line_present = query_filter.other_line_present();
                }
                if (msslcipher_telemetry) {
                    *msslcipher_telemetry = query_filter.msslcipher_telemetry();
                }
                scan = response;
                if (!query_filter.carry().empty()) {
                    scan += "\r\n";
                    scan += query_filter.carry();
                }
            } else {
                preserve_uart_urcs(buf, static_cast<size_t>(got));
                size_t room = MAX_RESPONSE > response.size() ? MAX_RESPONSE - response.size() : 0;
                if (room > 0) response.append(reinterpret_cast<const char*>(buf), std::min<size_t>(room, got));
                scan.append(reinterpret_cast<const char*>(buf), got);
            }
            int final_code;
            if (imei_query) {
                bool complete = false;
                std::string imei;
                const bool valid = idf_modem_parse_imei_frame(
                    response, cmd, imei, &complete, imei_waiting_for_pdu);
                final_code = complete ? (valid ? 1 : -1) : 0;
                if (complete) response = valid ? imei + "\r\nOK\r\n" : std::string();
            } else {
                final_code = at_final_result(scan);
            }
            if (final_code != 0) {
                if (filter_urcs) {
                    query_filter.flush_pending();
                    if (!query_filter.urcs().empty()) {
                        append_urc_text(query_filter.urcs());
                        query_filter.clear_urcs();
                    }
                    response = query_filter.response();
                    s_uart_line_carry = query_filter.carry();
                    s_uart_wait_cmt_pdu = query_filter.waiting_for_pdu();
                    if (other_line_present) {
                        *other_line_present = query_filter.other_line_present();
                    }
                    if (msslcipher_telemetry) {
                        *msslcipher_telemetry = query_filter.msslcipher_telemetry();
                    }
                }
                ret = final_code > 0 ? ESP_OK : ESP_FAIL;
                if (final_code < 0 && modem_error) *modem_error = true;
                break;
            }
            if (scan.size() > 32) scan.erase(0, scan.size() - 32);
        }
    }
    if (other_line_present) *other_line_present = query_filter.other_line_present();
    if (msslcipher_telemetry) *msslcipher_telemetry = query_filter.msslcipher_telemetry();
    return ret;
}

static esp_err_t owner_send_at(const std::string& cmd, uint32_t timeout_ms, std::string& response,
                               bool filter_urcs, const char* response_prefix,
                               size_t response_limit, bool* other_line_present,
                               uint8_t* msslcipher_telemetry)
{
    TickDeadline deadline(timeout_ms);
    return owner_send_at_deadline(cmd, deadline, response, filter_urcs, response_prefix, nullptr,
                                  response_limit, other_line_present, msslcipher_telemetry);
}

static esp_err_t owner_send_at_until(const std::string& cmd, const char* token,
                                     uint32_t timeout_ms, std::string& response)
{
    assert_owner_task();
    if (!token || !*token) return ESP_ERR_INVALID_ARG;

    TickDeadline deadline(timeout_ms);
    if (deadline.expired()) return ESP_ERR_TIMEOUT;
    capture_pending_uart_locked(deadline);
    std::string wire = cmd;
    wire += "\r\n";
    owner_uart_write(wire.data(), wire.size());

    response.clear();
    response.reserve(512);
    constexpr size_t MAX_RESPONSE = 4096;
    uint8_t buf[128];
    std::string scan;
    esp_err_t ret = ESP_ERR_TIMEOUT;
    while (!deadline.expired()) {
        int got = owner_uart_read(buf, sizeof(buf), pdMS_TO_TICKS(100));
        if (got > 0) {
            preserve_uart_urcs(buf, static_cast<size_t>(got));
            append_capped(response, buf, static_cast<size_t>(got), MAX_RESPONSE);
            scan.append(reinterpret_cast<const char*>(buf), got);
            if (response.find(token) != std::string::npos || scan.find(token) != std::string::npos) {
                ret = ESP_OK;
                break;
            }
            if (at_final_result(scan) < 0) {
                ret = ESP_FAIL;
                break;
            }
            if (scan.size() > 64) scan.erase(0, scan.size() - 64);
        }
    }
    return ret;
}

static esp_err_t owner_send_pdu(const std::string& cmgs_cmd, const char* pdu,
                                uint32_t timeout_ms, std::string& response)
{
    assert_owner_task();
    if (!pdu) return ESP_ERR_INVALID_ARG;

    TickDeadline prompt_deadline(5000);
    if (prompt_deadline.expired()) return ESP_ERR_TIMEOUT;
    capture_pending_uart_locked(prompt_deadline);
    std::string wire = cmgs_cmd;
    wire += "\r\n";
    owner_uart_write(wire.data(), wire.size());

    response.clear();
    response.reserve(512);
    constexpr size_t MAX_RESPONSE = 4096;
    uint8_t buf[128];
    bool got_prompt = false;
    esp_err_t ret = ESP_ERR_TIMEOUT;
    std::string scan;
    while (!prompt_deadline.expired()) {
        int got = owner_uart_read(buf, sizeof(buf), pdMS_TO_TICKS(80));
        if (got > 0) {
            preserve_uart_urcs(buf, static_cast<size_t>(got));
            append_capped(response, buf, static_cast<size_t>(got), MAX_RESPONSE);
            scan.append(reinterpret_cast<const char*>(buf), got);
            if (response.find('>') != std::string::npos || scan.find('>') != std::string::npos) {
                got_prompt = true;
                break;
            }
            if (at_final_result(scan) < 0) {
                ret = ESP_FAIL;  // A prompt-stage error such as +CMS ERROR is a failure, not a timeout.
                break;
            }
            if (scan.size() > 64) scan.erase(0, scan.size() - 64);
        }
    }

    if (got_prompt) {
        size_t pdu_len = strlen(pdu);
        owner_uart_write(pdu, pdu_len);
        // encodePDU already terminates the PDU with Ctrl+Z. Do not send another 0x1A.
        if (pdu_len == 0 || static_cast<uint8_t>(pdu[pdu_len - 1]) != 0x1A) {
            const uint8_t end = 0x1A;
            owner_uart_write(&end, 1);
        }
        TickDeadline deadline(timeout_ms);
        scan.clear();
        while (!deadline.expired()) {
            int got = owner_uart_read(buf, sizeof(buf), pdMS_TO_TICKS(120));
            if (got > 0) {
                preserve_uart_urcs(buf, static_cast<size_t>(got));
                append_capped(response, buf, static_cast<size_t>(got), MAX_RESPONSE);
                scan.append(reinterpret_cast<const char*>(buf), got);
                // +CMGS:<mr> means the network accepted SMS-SUBMIT. Do not require
                // complete CRLF after the trailing OK.
                if (has_cmgs_result(response) || has_cmgs_result(scan)) {
                    ret = ESP_OK;
                    break;
                }
                int final_code = at_final_result(scan);
                if (final_code != 0) {
                    ret = final_code > 0 ? ESP_OK : ESP_FAIL;
                    break;
                }
                if (scan.size() > 64) scan.erase(0, scan.size() - 64);
            }
        }
    }

    return ret;
}

esp_err_t idf_modem_send_at(const std::string& cmd, uint32_t timeout_ms, std::string& response)
{
    OwnerCommand request;
    request.kind = OwnerCommandKind::at;
    request.command = cmd;
    request.timeout_ms = timeout_ms;
    request.filter_urcs = cmd == "AT+CEREG?";
    if (request.filter_urcs) request.response_prefix = "+CEREG:";
    bool priority = cmd.rfind("AT+CNMA", 0) == 0;
    if (xTaskGetCurrentTaskHandle() == s_owner_task) {
        esp_err_t result = owner_send_at(
            cmd, timeout_ms, response, request.filter_urcs,
            request.response_prefix.empty() ? nullptr : request.response_prefix.c_str());
        // Acknowledge direct SMS at safe AT boundaries during startup and sampling.
        // CNMA does not recurse into drain, which avoids nested acknowledgment calls.
        if (!priority) owner_drain_priority_commands();
        return result;
    }
    return submit_owner_command(request, &response, priority);
}

esp_err_t idf_modem_get_imei(std::string& out, uint32_t timeout_ms)
{
    out.clear();
    static constexpr const char* commands[] = {
        "AT+CGSN=1", "AT+GSN=1", "AT+CGSN", "AT+GSN",
    };
    const int64_t deadline_us =
        esp_timer_get_time() + static_cast<int64_t>(timeout_ms) * 1000LL;
    esp_err_t last_err = ESP_ERR_TIMEOUT;
    for (const char* command : commands) {
        const int64_t remaining_us = deadline_us - esp_timer_get_time();
        if (remaining_us <= 0) break;
        const uint32_t attempt_ms = static_cast<uint32_t>(
            std::min<int64_t>(1000, remaining_us / 1000));
        if (attempt_ms == 0) break;

        OwnerCommand request;
        request.command = command;
        request.timeout_ms = attempt_ms;
        request.deadline_us = std::min<int64_t>(deadline_us,
            esp_timer_get_time() + static_cast<int64_t>(attempt_ms) * 1000LL);
        std::string response;
        esp_err_t err;
        if (xTaskGetCurrentTaskHandle() == s_owner_task) {
            TickDeadline deadline(attempt_ms);
            deadline.deadline_us = request.deadline_us;
            err = owner_send_at_deadline(command, deadline, response, false, nullptr);
        } else {
            err = submit_owner_command(request, &response, false);
        }
        if (esp_timer_get_time() >= deadline_us) {
            last_err = ESP_ERR_TIMEOUT;
            break;
        }
        if (err == ESP_OK) {
            std::string parsed;
            if (idf_modem_parse_imei_frame(response, command, parsed)) {
                out = std::move(parsed);
                return ESP_OK;
            }
            last_err = ESP_FAIL;
        } else {
            last_err = err;
            if (err == IDF_MODEM_ERR_BUSY || err == ESP_ERR_INVALID_STATE) break;
        }
    }
    out.clear();
    return last_err;
}

#if SMS_USB_RECOVERY
static const char* usb_query_command(uint8_t query_id)
{
    switch (query_id) {
        case IDF_MODEM_USB_QUERY_ATI: return "ATI";
        case IDF_MODEM_USB_QUERY_CPIN: return "AT+CPIN?";
        case IDF_MODEM_USB_QUERY_CEREG: return "AT+CEREG?";
        case IDF_MODEM_USB_QUERY_COPS: return "AT+COPS?";
        case IDF_MODEM_USB_QUERY_CGATT: return "AT+CGATT?";
        case IDF_MODEM_USB_QUERY_CGACT: return "AT+CGACT?";
        case IDF_MODEM_USB_QUERY_CGPADDR: return "AT+CGPADDR";
        case IDF_MODEM_USB_QUERY_ICCID: return "AT+ICCID";
        case IDF_MODEM_USB_QUERY_CSQ: return "AT+CSQ";
        case IDF_MODEM_USB_QUERY_CESQ: return "AT+CESQ";
        case IDF_MODEM_USB_QUERY_CFUN: return "AT+CFUN?";
        case IDF_MODEM_USB_QUERY_CREG: return "AT+CREG?";
        case IDF_MODEM_USB_QUERY_CGREG: return "AT+CGREG?";
        case IDF_MODEM_USB_QUERY_CEER: return "AT+CEER";
        case IDF_MODEM_USB_QUERY_CIMI: return "AT+CIMI";
        case IDF_MODEM_USB_QUERY_CPOL: return "AT+CPOL?";
        case IDF_MODEM_USB_QUERY_CGDCONT: return "AT+CGDCONT?";
        case IDF_MODEM_USB_QUERY_MSSLCIPHER: return "AT+MSSLCIPHER=?";
        default: return nullptr;
    }
}

static const char* usb_query_response_prefix(uint8_t query_id)
{
    switch (query_id) {
        case IDF_MODEM_USB_QUERY_CPIN: return "+CPIN:";
        case IDF_MODEM_USB_QUERY_CEREG: return "+CEREG:";
        case IDF_MODEM_USB_QUERY_COPS: return "+COPS:";
        case IDF_MODEM_USB_QUERY_CGATT: return "+CGATT:";
        case IDF_MODEM_USB_QUERY_CGACT: return "+CGACT:";
        case IDF_MODEM_USB_QUERY_CGPADDR: return "+CGPADDR:";
        case IDF_MODEM_USB_QUERY_ICCID: return "+ICCID:";
        case IDF_MODEM_USB_QUERY_CSQ: return "+CSQ:";
        case IDF_MODEM_USB_QUERY_CESQ: return "+CESQ:";
        case IDF_MODEM_USB_QUERY_CFUN: return "+CFUN:";
        case IDF_MODEM_USB_QUERY_CREG: return "+CREG:";
        case IDF_MODEM_USB_QUERY_CGREG: return "+CGREG:";
        case IDF_MODEM_USB_QUERY_CEER: return "+CEER:";
        case IDF_MODEM_USB_QUERY_CPOL: return "+CPOL:";
        case IDF_MODEM_USB_QUERY_CGDCONT: return "+CGDCONT:";
        case IDF_MODEM_USB_QUERY_MSSLCIPHER: return "+MSSLCIPHER:";
        case IDF_MODEM_USB_QUERY_ATI: return "";
        case IDF_MODEM_USB_QUERY_CIMI: return "";
        default: return nullptr;
    }
}

esp_err_t idf_modem_usb_query(uint8_t query_id, std::string& response, uint8_t* busy_reason,
                              bool* other_line_present, uint8_t* msslcipher_telemetry)
{
    response.clear();
    if (other_line_present) *other_line_present = false;
    if (msslcipher_telemetry) *msslcipher_telemetry = 0;
    const char* command = usb_query_command(query_id);
    if (!command) return ESP_ERR_INVALID_ARG;
    const bool queue_ready = s_runtime_queue_ready.load(std::memory_order_acquire);
    IdfModemStatus status = idf_modem_get_status();
    switch (idf_modem_usb_query_admission(
        queue_ready, status.atReady, s_reset_request.load(std::memory_order_acquire) != 0)) {
        case IdfModemUsbQueryAdmission::busy:
            set_query_busy_reason(
                busy_reason, static_cast<uint8_t>(IdfModemUsbQueryBusyReason::gate_closed));
            return IDF_MODEM_ERR_BUSY;
        case IdfModemUsbQueryAdmission::not_ready:
            return ESP_ERR_INVALID_STATE;
        case IdfModemUsbQueryAdmission::submit:
            break;
    }
    OwnerCommand request;
    const uint32_t timeout_ms = query_id == IDF_MODEM_USB_QUERY_CPOL
                                    ? IDF_MODEM_USB_QUERY_CPOL_TIMEOUT_MS
                                    : IDF_MODEM_USB_QUERY_TIMEOUT_MS;
    const size_t response_limit = query_id == IDF_MODEM_USB_QUERY_MSSLCIPHER
                                      ? IDF_MODEM_USB_QUERY_MSSLCIPHER_MAX_RESPONSE
                                      : OWNER_AT_RESPONSE_LIMIT;
    const size_t output_limit = query_id == IDF_MODEM_USB_QUERY_MSSLCIPHER
                                    ? IDF_MODEM_USB_QUERY_MSSLCIPHER_MAX_RESPONSE
                                    : IDF_MODEM_USB_QUERY_MAX_RESPONSE;
    request.kind = OwnerCommandKind::at;
    request.command = command;
    request.timeout_ms = timeout_ms;
    request.filter_urcs = true;
    request.response_prefix = usb_query_response_prefix(query_id);
    request.response_limit = response_limit;
    request.capture_other_line = query_id == IDF_MODEM_USB_QUERY_MSSLCIPHER;
    esp_err_t err;
    if (xTaskGetCurrentTaskHandle() == s_owner_task) {
        err = owner_send_at(command, timeout_ms, response, true,
                            request.response_prefix.c_str(), request.response_limit,
                            other_line_present, msslcipher_telemetry);
    } else {
        err = submit_owner_command(request, &response, false, busy_reason, nullptr,
                                   other_line_present, msslcipher_telemetry);
    }
    if (err == ESP_OK && query_id == IDF_MODEM_USB_QUERY_CPOL) {
        response = idf_modem_cpol_compact_summary(response);
        return ESP_OK;
    }
    if (err == ESP_OK && response.size() > output_limit) {
        idf_logf("USB modem query response too large: id=0x%02X length=%u limit=%u",
                 static_cast<unsigned>(query_id),
                 static_cast<unsigned>(response.size()),
                 static_cast<unsigned>(output_limit));
        response.clear();
        return ESP_ERR_INVALID_SIZE;
    }
    return err;
}
#endif

esp_err_t idf_modem_send_at_until(const std::string& cmd, const char* token,
                                  uint32_t timeout_ms, std::string& response)
{
    if (!token || !*token) return ESP_ERR_INVALID_ARG;
    OwnerCommand request;
    request.kind = OwnerCommandKind::until;
    request.command = cmd;
    request.token = token;
    request.timeout_ms = timeout_ms;
    if (xTaskGetCurrentTaskHandle() == s_owner_task) {
        return owner_send_at_until(cmd, token, timeout_ms, response);
    }
    return submit_owner_command(request, &response, false);
}

esp_err_t idf_modem_send_pdu(const std::string& cmgs_cmd, const char* pdu,
                             uint32_t timeout_ms, std::string& response)
{
    if (!pdu) return ESP_ERR_INVALID_ARG;
    OwnerCommand request;
    request.kind = OwnerCommandKind::pdu;
    request.command = cmgs_cmd;
    request.pdu = pdu;
    request.timeout_ms = timeout_ms;
    if (xTaskGetCurrentTaskHandle() == s_owner_task) {
        return owner_send_pdu(cmgs_cmd, pdu, timeout_ms, response);
    }
    return submit_owner_command(request, &response, false);
}

static void reset_owner_slot(OwnerCommandSlot& slot)
{
    slot.caller_abandoned.store(false, std::memory_order_release);
    slot.request = OwnerCommand();
    slot.response.clear();
    slot.other_line_present = false;
    slot.msslcipher_telemetry = 0;
    slot.https_post_result = IdfModemHttpsPostResult();
    slot.result = ESP_FAIL;
    slot.state = OwnerCommandState::free;
}

static bool owner_request_bounded(const OwnerCommand& request)
{
    if (request.command.size() > 4096 || request.pdu.size() > 4096 ||
        request.token.size() > 256 || request.response_limit > OWNER_AT_RESPONSE_LIMIT) {
        return false;
    }
    if (request.kind != OwnerCommandKind::https_post) return true;
    const bool post = request.https_post_request.method == IdfModemHttpsMethod::Post;
    const bool get = request.https_post_request.method == IdfModemHttpsMethod::Get;
    const bool body_bounded = post
                                  ? !request.https_post_request.body.empty() &&
                                        request.https_post_request.body.size() <= IDF_MODEM_HTTPS_POST_MAX_BODY
                                  : get && request.https_post_request.body.empty();
    const bool content_type_bounded = post
                                          ? !request.https_post_request.contentType.empty() &&
                                                request.https_post_request.contentType.size() <=
                                                    IDF_MODEM_HTTPS_POST_MAX_CONTENT_TYPE
                                          : get && request.https_post_request.contentType.empty();
    return (post || get) &&
           request.https_post_request.url.size() <=
               (get ? IDF_MODEM_HTTPS_GET_MAX_URL : IDF_MODEM_HTTPS_POST_MAX_URL) &&
           body_bounded && content_type_bounded &&
           request.https_post_request.headerName.size() <= IDF_MODEM_HTTPS_POST_MAX_HEADER_NAME &&
           request.https_post_request.headerValue.size() <= IDF_MODEM_HTTPS_POST_MAX_HEADER_VALUE &&
           !request.https_post_request.rootCertificateDer.empty() &&
           request.https_post_request.rootCertificateDer.size() <= IDF_MODEM_HTTPS_ROOT_DER_MAX &&
           request.https_post_request.rootCertificateSha256.size() == 32 &&
           !std::all_of(request.https_post_request.rootCertificateSha256.begin(),
                        request.https_post_request.rootCertificateSha256.end(),
                        [](uint8_t byte) { return byte == 0; }) &&
           request.https_post_request.apn.size() <= 96;
}

static void wake_owner_task()
{
    // The owner waits on UART events while idle. A payload-free DATA event wakes it early.
    if (!s_uart_evt_queue) return;
    uart_event_t wake = {};
    wake.type = UART_DATA;
    xQueueSend(s_uart_evt_queue, &wake, 0);
}

static esp_err_t submit_owner_command(const OwnerCommand& request, std::string* response,
                                      bool priority,
                                      uint8_t* query_busy_reason,
                                      IdfModemHttpsPostResult* https_result,
                                      bool* other_line_present,
                                      uint8_t* msslcipher_telemetry)
{
    const auto mark_https_modem_failure = [&]() {
        if (https_result && request.kind == OwnerCommandKind::https_post) {
            https_result->ok = false;
            https_result->failureStage = IdfHttpsFailureStage::modem;
        }
    };
    if (!s_started || !s_command_mutex || !s_command_queue || !s_priority_command_queue) {
        mark_https_modem_failure();
        return ESP_ERR_INVALID_STATE;
    }
    if (!priority && !s_runtime_queue_ready.load(std::memory_order_acquire)) {
        set_query_busy_reason(query_busy_reason,
                              static_cast<uint8_t>(IdfModemUsbQueryBusyReason::gate_closed));
        mark_https_modem_failure();
        return IDF_MODEM_ERR_BUSY;
    }
    if (!owner_request_bounded(request)) {
        mark_https_modem_failure();
        return ESP_ERR_INVALID_SIZE;
    }

    bool session_held = false;
    uint32_t wait_margin_ms = request.kind == OwnerCommandKind::pdu ? 7000UL : 1000UL;
    if (request.kind == OwnerCommandKind::https_post) {
        wait_margin_ms = HTTPS_CLEANUP_WAIT_MARGIN_MS;
    }
    uint32_t wait_ms = request.timeout_ms + wait_margin_ms;
    if (request.deadline_us != 0) wait_ms = request.timeout_ms;
    TickDeadline deadline(wait_ms);
    deadline.deadline_us = request.deadline_us;
    TickDeadline operation_deadline(deadline.start, timeout_ticks_ceil(request.timeout_ms));
    if (!priority) {
        if (!s_session_mutex ||
            xSemaphoreTakeRecursive(s_session_mutex, deadline.remaining_ticks()) != pdTRUE) {
            mark_https_modem_failure();
            return ESP_ERR_TIMEOUT;
        }
        session_held = true;
    }

    TickType_t remaining = deadline.remaining_ticks();
    TickType_t command_wait = std::min(remaining, timeout_ticks_ceil(100));
    if (remaining == 0 || xSemaphoreTake(s_command_mutex, command_wait) != pdTRUE) {
        if (session_held) xSemaphoreGiveRecursive(s_session_mutex);
        if (deadline.expired()) {
            mark_https_modem_failure();
            return ESP_ERR_TIMEOUT;
        }
        set_query_busy_reason(query_busy_reason,
                              static_cast<uint8_t>(IdfModemUsbQueryBusyReason::mutex_timeout));
        mark_https_modem_failure();
        return IDF_MODEM_ERR_BUSY;
    }
    int slot_index = -1;
    for (size_t i = 0; i < OWNER_COMMAND_SLOTS; ++i) {
        if (s_command_slots[i].state == OwnerCommandState::free) {
            slot_index = static_cast<int>(i);
            break;
        }
    }
    if (slot_index < 0) {
        xSemaphoreGive(s_command_mutex);
        if (session_held) xSemaphoreGiveRecursive(s_session_mutex);
        set_query_busy_reason(query_busy_reason,
                              static_cast<uint8_t>(IdfModemUsbQueryBusyReason::slots_full));
        mark_https_modem_failure();
        return IDF_MODEM_ERR_BUSY;
    }

    if (deadline.expired()) {
        xSemaphoreGive(s_command_mutex);
        if (session_held) xSemaphoreGiveRecursive(s_session_mutex);
        mark_https_modem_failure();
        return ESP_ERR_TIMEOUT;
    }

    OwnerCommandSlot& slot = s_command_slots[slot_index];
    slot.caller_abandoned.store(false, std::memory_order_release);
    while (xSemaphoreTake(slot.completed, 0) == pdTRUE) {}
    slot.request = request;
    if (request.kind == OwnerCommandKind::https_post) {
        slot.request.deadline_start = operation_deadline.start;
        slot.request.deadline_span = operation_deadline.span;
    }
    slot.response.clear();
    slot.other_line_present = false;
    slot.msslcipher_telemetry = 0;
    slot.https_post_result = IdfModemHttpsPostResult();
    slot.result = ESP_FAIL;
    slot.state = OwnerCommandState::queued;
    QueueHandle_t queue = priority ? s_priority_command_queue : s_command_queue;
    if (xQueueSend(queue, &slot_index, 0) != pdTRUE) {
        reset_owner_slot(slot);
        xSemaphoreGive(s_command_mutex);
        if (session_held) xSemaphoreGiveRecursive(s_session_mutex);
        set_query_busy_reason(query_busy_reason,
                              static_cast<uint8_t>(IdfModemUsbQueryBusyReason::queue_full));
        mark_https_modem_failure();
        return IDF_MODEM_ERR_BUSY;
    }
    xSemaphoreGive(s_command_mutex);
    wake_owner_task();

    // Reserve one command-mutex window so an expiry can still mark the slot abandoned.
    TickType_t completion_wait = deadline.remaining_ticks();
    const TickType_t cleanup_wait = timeout_ticks_ceil(OWNER_SLOT_RECLAIM_MUTEX_TIMEOUT_MS);
    if (completion_wait > cleanup_wait) completion_wait -= cleanup_wait;
    else completion_wait = 0;
    BaseType_t completed = xSemaphoreTake(slot.completed, completion_wait);
    esp_err_t result = ESP_ERR_TIMEOUT;
    const bool caller_timed_out = completed != pdTRUE;
    if (caller_timed_out) {
        // Publish abandonment before the bounded mutex window. If the owner is
        // between execute() and its final lock, it will reclaim the slot there.
        slot.caller_abandoned.store(true, std::memory_order_release);
    }
    const TickType_t reclaim_wait =
        std::min(deadline.remaining_ticks(), cleanup_wait);
    if (xSemaphoreTake(s_command_mutex, reclaim_wait) == pdTRUE) {
        if (completed == pdTRUE && slot.state == OwnerCommandState::done) {
            result = slot.result;
            if (response) *response = slot.response;
            if (other_line_present) *other_line_present = slot.other_line_present;
            if (msslcipher_telemetry) *msslcipher_telemetry = slot.msslcipher_telemetry;
            if (https_result) *https_result = slot.https_post_result;
            reset_owner_slot(slot);
        } else if (slot.state == OwnerCommandState::done) {
            // Prefer completion if its signal arrives with the caller timeout.
            result = slot.result;
            if (response) *response = slot.response;
            if (other_line_present) *other_line_present = slot.other_line_present;
            if (msslcipher_telemetry) *msslcipher_telemetry = slot.msslcipher_telemetry;
            if (https_result) *https_result = slot.https_post_result;
            reset_owner_slot(slot);
            xSemaphoreTake(slot.completed, 0);
        } else if (slot.state == OwnerCommandState::queued ||
                   slot.state == OwnerCommandState::running) {
            slot.state = OwnerCommandState::abandoned;
        } else if (slot.state == OwnerCommandState::free) {
            slot.caller_abandoned.store(false, std::memory_order_release);
        }
        xSemaphoreGive(s_command_mutex);
    } else {
        // The owner retries reclamation on its next wake and after command
        // completion. Never leave a slot owned by a caller that could not
        // complete the final critical-section handoff.
        slot.caller_abandoned.store(true, std::memory_order_release);
        wake_owner_task();
    }
    if (session_held) xSemaphoreGiveRecursive(s_session_mutex);
    if (https_result && request.kind == OwnerCommandKind::https_post &&
        result != ESP_OK && https_result->failureStage == IdfHttpsFailureStage::none) {
        mark_https_modem_failure();
    }
    return result;
}

static bool send_ok(const char* cmd, uint32_t timeout_ms = 1000, std::string* out = nullptr)
{
    std::string resp;
    esp_err_t err = idf_modem_send_at(cmd, timeout_ms, resp);
    if (out) *out = resp;
    return err == ESP_OK;
}

static void clear_health_reset_backoff(void)
{
    s_health_reset_retry_count.store(0, std::memory_order_relaxed);
    s_next_health_reset_tick.store(0, std::memory_order_relaxed);
}

static bool request_health_reset_with_backoff(void)
{
    bool expected = false;
    if (!s_health_reset_claimed.compare_exchange_strong(
            expected, true, std::memory_order_acquire, std::memory_order_relaxed)) {
        return false;
    }

    bool requested = false;
    do {
        if (s_reset_request.load(std::memory_order_acquire) != 0) break;
        const TickType_t now = xTaskGetTickCount();
        const TickType_t next = s_next_health_reset_tick.load(std::memory_order_relaxed);
        if (static_cast<int32_t>(now - next) < 0) break;
        const uint8_t retry_count = s_health_reset_retry_count.load(std::memory_order_relaxed);
        if (!idf_modem_health_reset_retry_allowed(retry_count)) break;
        if (idf_modem_request_reset(true) != ESP_OK) break;
        s_health_reset_retry_count.store(retry_count + 1, std::memory_order_relaxed);
        s_next_health_reset_tick.store(
            now + pdMS_TO_TICKS(idf_modem_health_reset_backoff_ms(retry_count)),
            std::memory_order_relaxed);
        requested = true;
    } while (false);

    s_health_reset_claimed.store(false, std::memory_order_release);
    return requested;
}

static std::string parse_iccid_response(const std::string& raw)
{
    std::string line = first_payload_line(raw);
    size_t p = line.find(':');
    std::string value = idf_util_trim_copy(p == std::string::npos ? line : line.substr(p + 1));
    value.erase(std::remove(value.begin(), value.end(), '"'), value.end());
    std::replace(value.begin(), value.end(), 'f', 'F');
    if (!value.empty() && value.back() == 'F') value.pop_back();
    if (is_iccid_text(value)) return value;
    // Some firmware adds slot or status fields around ICCID. Fall back to consecutive digits.
    return first_digit_run(raw, 15, 22);
}

static std::string parse_iccid_crsm_response(const std::string& line)
{
    if (line.rfind("+CRSM:", 0) != 0) return {};
    const size_t first = line.find(',', 6);
    const size_t second = first == std::string::npos ? first : line.find(',', first + 1);
    if (second == std::string::npos) return {};
    const std::string sw1 = idf_util_trim_copy(line.substr(6, first - 6));
    const std::string sw2 = idf_util_trim_copy(line.substr(first + 1, second - first - 1));
    const std::string encoded = idf_util_trim_copy(line.substr(second + 1));
    if ((sw1 != "144" && sw1 != "145") || sw2 != "0" ||
        encoded.size() != 22 || encoded.front() != '"' || encoded.back() != '"') return {};
    std::string iccid;
    for (size_t i = 1; i < 21; i += 2) {
        iccid += static_cast<char>(toupper(static_cast<unsigned char>(encoded[i + 1])));
        iccid += static_cast<char>(toupper(static_cast<unsigned char>(encoded[i])));
    }
    if (iccid.back() == 'F') iccid.pop_back();
    if (!std::all_of(iccid.begin(), iccid.end(), [](char ch) {
            return ch >= '0' && ch <= '9';
        })) return {};
    return iccid;
}

static bool single_at_frame_payload(const std::string& raw, const char* command, std::string& payload)
{
    payload.clear();
    bool echo_seen = false, terminal_seen = false, waiting_for_pdu = false;
    size_t position = 0;
    while (position < raw.size()) {
        size_t end = raw.find_first_of("\r\n", position);
        if (end == std::string::npos) end = raw.size();
        const std::string line = idf_util_trim_copy(raw.substr(position, end - position));
        position = end + 1;
        if (line.empty()) continue;
        if (waiting_for_pdu && idf_modem_imei_pdu_line(line)) {
            waiting_for_pdu = false;
            continue;
        }
        if (idf_modem_imei_known_urc(line)) {
            if (line.rfind("+CMT:", 0) == 0) waiting_for_pdu = true;
            continue;
        }
        if (terminal_seen) return false;
        if (line == command) {
            if (echo_seen || !payload.empty()) return false;
            echo_seen = true;
        } else if (line == "OK") {
            if (payload.empty()) return false;
            terminal_seen = true;
        } else {
            if (!payload.empty() || line.rfind("AT", 0) == 0 || line == "ERROR" ||
                line.rfind("+CME ERROR", 0) == 0 || line.rfind("+CMS ERROR", 0) == 0) return false;
            payload = line;
        }
    }
    return terminal_seen && !payload.empty();
}

static std::string query_current_iccid(uint32_t retry_delay_ms = 0)
{
    const char* commands[] = {"AT+MCCID", "AT+ICCID", "AT+CCID"};
    std::string resp;
    for (const char* cmd : commands) {
        std::string iccid, payload;
        if (send_ok(cmd, 1500, &resp) && single_at_frame_payload(resp, cmd, payload)) {
            iccid = parse_iccid_response(payload);
        }
        if (retry_delay_ms) vTaskDelay(pdMS_TO_TICKS(retry_delay_ms));
        if (!iccid.empty()) return iccid;
    }
    const char* crsm = "AT+CRSM=176,12258,0,0,10";
    std::string payload;
    if (send_ok(crsm, 2000, &resp) && single_at_frame_payload(resp, crsm, payload)) {
        return parse_iccid_crsm_response(payload);
    }
    return {};
}

static bool parse_modem_clock(const std::string& response, time_t& epoch)
{
    std::string payload;
    if (!single_at_frame_payload(response, "AT+CCLK?", payload) ||
        payload.rfind("+CCLK:", 0) != 0) return false;
    const std::string value = idf_util_trim_copy(payload.substr(6));
    if (value.size() != 22 || value[0] != '"' || value[21] != '"' ||
        value[3] != '/' || value[6] != '/' || value[9] != ',' ||
        value[12] != ':' || value[15] != ':' ||
        (value[18] != '+' && value[18] != '-')) return false;
    for (size_t i : {1U, 2U, 4U, 5U, 7U, 8U, 10U, 11U, 13U, 14U, 16U, 17U, 19U, 20U}) {
        if (value[i] < '0' || value[i] > '9') return false;
    }
    const auto two_digits = [&](size_t pos) {
        return (value[pos] - '0') * 10 + value[pos + 1] - '0';
    };
    int year = two_digits(1);
    year += year >= 70 ? 1900 : 2000;
    const int month = two_digits(4), day = two_digits(7);
    const int hour = two_digits(10), minute = two_digits(13), second = two_digits(16);
    int zone = two_digits(19);
    if (month < 1 || month > 12 || day < 1 || hour > 23 || minute > 59 ||
        second > 59 || zone > 96) return false;
    const auto leap = [](int y) { return y % 4 == 0 && (y % 100 != 0 || y % 400 == 0); };
    int month_days[] = {31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31};
    if (leap(year)) month_days[1] = 29;
    if (day > month_days[month - 1]) return false;
    int64_t days = day - 1;
    for (int y = 1970; y < year; ++y) days += leap(y) ? 366 : 365;
    for (int m = 1; m < month; ++m) days += month_days[m - 1];
    if (value[18] == '-') zone = -zone;
    epoch = static_cast<time_t>(days * 86400 + hour * 3600 + minute * 60 + second - zone * 900);
    return true;
}

static void bootstrap_clock_once()
{
    constexpr time_t minimum_epoch = 1700000000;
    static int64_t next_attempt_us = 0;
    const int64_t now = esp_timer_get_time();
    if (time(nullptr) >= minimum_epoch || now < next_attempt_us ||
        idf_modem_get_status().ceregStat != 1 || !at_channel_idle_now() ||
        (s_uart_wait_cmt_pdu && now <= s_uart_wait_cmt_until_us)) return;
    next_attempt_us = now + 60LL * 1000LL * 1000LL;
    std::string response;
    time_t epoch = 0;
    if (!send_ok("AT+CCLK?", 1000, &response) || !parse_modem_clock(response, epoch) ||
        epoch < minimum_epoch) return;
    timeval value{};
    value.tv_sec = epoch;
    if (time(nullptr) < minimum_epoch) settimeofday(&value, nullptr);
}

static std::string query_sim_state(void)
{
    std::string resp;
    if (!send_ok("AT+CPIN?", 1500, &resp)) {
        std::string compact = resp;
        compact.erase(std::remove_if(compact.begin(), compact.end(), [](unsigned char ch) {
            return isspace(ch);
        }), compact.end());
        if (compact.find("+CMEERROR:10") != std::string::npos) return "absent";
        return "unknown";
    }
    std::string compact = resp;
    compact.erase(std::remove_if(compact.begin(), compact.end(), [](unsigned char ch) {
        return isspace(ch);
    }), compact.end());
    if (compact.find("+CPIN:READY") != std::string::npos) return "ready";
    if (compact.find("+CPIN:SIMPIN2") != std::string::npos ||
        compact.find("+CPIN:SIMPUK2") != std::string::npos) return "other";
    if (compact.find("+CPIN:SIMPUK") != std::string::npos) return "puk";
    if (compact.find("+CPIN:SIMPIN") != std::string::npos) return "pin";
    return "other";
}

static void set_sim_status(const std::string& state, bool matched, const std::string& message,
                           const std::string& iccid = {})
{
    IdfModemStatus patch;
    patch.simState = state;
    patch.simCredentialMatched = matched;
    patch.simUnlockMessage = message;
    patch.iccid = iccid;
    if (state == "pin" || state == "puk" || state == "other") patch.phase = "sim_locked";
    update_status(patch, !iccid.empty());
}

static constexpr bool sim_unlock_allowed(bool has_secret, uint8_t failed, uint8_t limit,
                                         bool puk, bool user_confirmed)
{
    return has_secret && failed < limit && (!puk || user_confirmed);
}
static_assert(sim_unlock_allowed(true, 0, 1, false, false), "first automatic PIN attempt must be allowed");
static_assert(!sim_unlock_allowed(true, 1, 1, false, false), "PIN must stop at the attempt limit");
static_assert(!sim_unlock_allowed(true, 0, 1, true, false), "PUK must not run automatically");

static bool try_unlock_sim(bool allow_puk)
{
    send_ok("ATE0", 1000);
    send_ok("AT+CMEE=1", 1200);
    std::string state = query_sim_state();
    if (state == "ready") {
        set_sim_status("ready", false, "SIM is ready");
        return true;
    }
    if (state != "pin" && state != "puk") {
        set_sim_status(state, false, state == "absent" ? "SIM not detected" : "Cannot handle this SIM state automatically");
        return false;
    }
    if (allow_puk && state != "puk") {
        set_sim_status(state, false, "SIM requires a PIN. PUK was not attempted");
        return false;
    }

    std::string iccid = query_current_iccid();
    if (iccid.empty()) {
        set_sim_status(state, false, "Cannot read ICCID while SIM is locked. No credential was attempted");
        return false;
    }
    IdfSimUnlockView view = idf_config_get_sim_unlock_view(iccid);
    if (!view.found) {
        set_sim_status(state, false, "No credential matches this ICCID", iccid);
        return false;
    }
    const IdfSimCredential& item = view.credential;
    bool puk = state == "puk";
    const std::string& secret = puk ? item.puk : item.pin;
    uint8_t failed = puk ? item.pukFailedAttempts : item.pinFailedAttempts;
    uint8_t limit = puk ? item.pukMaxAttempts : item.pinMaxAttempts;
    bool has_secret = !secret.empty() && (!puk || !item.pin.empty());
    if (!sim_unlock_allowed(has_secret, failed, limit, puk, allow_puk) && !has_secret) {
        set_sim_status(state, true, puk ? "Save the PUK and a new PIN" : "No PIN is saved", iccid);
        return false;
    }
    if (!sim_unlock_allowed(has_secret, failed, limit, puk, allow_puk) && failed >= limit) {
        set_sim_status(state, true, std::string(puk ? "PUK" : "PIN") + " reached the local attempt limit", iccid);
        return false;
    }
    if (!sim_unlock_allowed(has_secret, failed, limit, puk, allow_puk)) {
        set_sim_status(state, true, "Confirm the PUK attempt manually in the Web UI", iccid);
        return false;
    }
    std::string attempt_key = iccid;
    if (!puk && s_last_pin_attempt_key == attempt_key) {
        set_sim_status(state, true, "This PIN was already attempted. Update the credential", iccid);
        return false;
    }
    if (!puk) s_last_pin_attempt_key = attempt_key;

    std::string cmd = puk ? "AT+CPIN=\"" + item.puk + "\",\"" + item.pin + "\""
                          : "AT+CPIN=\"" + item.pin + "\"";
    std::string resp;
    esp_err_t submit_err = idf_modem_send_at(cmd, 5000, resp);
    bool ready = false;
    for (int i = 0; i < 10 && !ready; ++i) {
        vTaskDelay(pdMS_TO_TICKS(500));
        ready = query_sim_state() == "ready";
    }
    if (ready) {
        idf_config_record_sim_unlock_result(iccid, puk, true);
        if (puk) idf_config_record_sim_unlock_result(iccid, false, true);
        s_last_pin_attempt_key.clear();
        set_sim_status("ready", true, puk ? "PUK unlock succeeded" : "Automatic PIN unlock succeeded", iccid);
        idf_log_line(puk ? "manual SIM PUK unlock succeeded" : "automatic SIM PIN unlock succeeded");
        return true;
    }
    if (submit_err == ESP_FAIL) idf_config_record_sim_unlock_result(iccid, puk, false);
    set_sim_status(state, true, std::string(puk ? "PUK" : "PIN") +
                   (submit_err == ESP_FAIL ? " was rejected by the modem. Attempts stopped" : " submission timed out. Attempt count unchanged"), iccid);
    idf_log_line(puk ? "SIM PUK unlock failed. Attempts stopped" : "SIM PIN unlock failed. Attempts stopped");
    return false;
}

static constexpr uint32_t modem_retry_delay_ms(uint8_t level)
{
    return MODEM_RETRY_DELAYS_MS[std::min<size_t>(level, MODEM_RETRY_DELAY_COUNT - 1)];
}

static bool parse_csq(const std::string& resp, int& csq, int& ber)
{
    size_t p = resp.find("+CSQ:");
    if (p == std::string::npos) return false;
    std::string line = line_containing(resp, p);
    const char* token = strstr(line.c_str(), "+CSQ:");
    if (!token) return false;
    long values[2] = {};
    int count = 0;
    if (!parse_comma_longs(token + strlen("+CSQ:"), values, 2, count) || count < 2) return false;
    if (!((values[0] >= 0 && values[0] <= 31) || values[0] == 99)) return false;
    if (!((values[1] >= 0 && values[1] <= 7) || values[1] == 99)) return false;
    csq = static_cast<int>(values[0]);
    ber = static_cast<int>(values[1]);
    return true;
}

static bool parse_cereg(const std::string& resp, int& stat)
{
    return idf_modem_parse_cereg_status(resp, stat);
}

// Parse the line that contains the token. A CEREG=2 URC can share the response,
// so the first non-empty line can belong to a different command.
static std::string parse_cops(const std::string& resp)
{
    size_t p = resp.find("+COPS:");
    if (p == std::string::npos) return {};
    std::string line = line_containing(resp, p);
    // Automatic mode can return only "+COPS: 0" until the name format is selected.
    // Return empty so the caller retries with COPS=3,0 instead of caching the mode.
    return first_quoted(line);
}

static std::string parse_apn(const std::string& resp)
{
    size_t pos = 0;
    while (true) {
        size_t p = resp.find("+CGDCONT:", pos);
        if (p == std::string::npos) return {};
        std::string line = line_containing(resp, p);
        size_t q1 = line.find('"');
        if (q1 != std::string::npos) {
            size_t q2 = line.find('"', q1 + 1);
            if (q2 != std::string::npos) {
                std::string apn = first_quoted(line, q2 + 1);
                if (!apn.empty()) return apn;
            }
        }
        pos = p + strlen("+CGDCONT:");
    }
}

// Some modems decode international TOA 0x91 as BCD and prefix CNUM with "+19".
// Strip "19" only before a known country code so valid NANP numbers remain unchanged.
static std::string normalize_msisdn(std::string phone)
{
    size_t start = 0;
    while (start < phone.size() && isspace(static_cast<unsigned char>(phone[start]))) ++start;
    size_t end = phone.size();
    while (end > start && isspace(static_cast<unsigned char>(phone[end - 1]))) --end;
    if (start >= end) return {};
    phone = phone.substr(start, end - start);

    bool had_plus = !phone.empty() && phone[0] == '+';
    std::string digits;
    digits.reserve(phone.size());
    for (size_t i = had_plus ? 1 : 0; i < phone.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(phone[i]);
        if (isdigit(ch)) digits += static_cast<char>(ch);
        else if (!isspace(ch) && ch != '-' && ch != '(' && ch != ')') {
            return phone;
        }
    }
    if (digits.size() < 8) return phone;
    if (had_plus && digits.size() == 11 && digits[0] == '1') {
        return std::string("+") + digits;
    }

    static const char* kCountryCodes[] = {
        "44", "86", "33", "49", "81", "61", "91", "39", "34", "82", "65",
        "852", "886", "853", "855", "856", "60", "62", "63", "66", "84",
        "90", "971", "966", "974", "973", "968", "965", "962", "961",
        "20", "27", "234", "254", "255", "256", "233", "212",
        "7", "380", "48", "40", "36", "30", "31", "32",
        "41", "43", "45", "46", "47", "351", "352", "353", "354", "358",
        "420", "421", "370", "371", "372", "373", "374", "375", "376",
        "52", "55", "54", "56", "57", "51", "58",
        "1",
    };
    if (digits.rfind("19", 0) == 0) {
        std::string rest = digits.substr(2);
        for (const char* cc : kCountryCodes) {
            size_t n = strlen(cc);
            if (rest.size() < n + 6) continue;
            if (rest.compare(0, n, cc) != 0) continue;
            if (strcmp(cc, "1") == 0) continue;
            return std::string("+") + rest;
        }
    }
    if (had_plus) return std::string("+") + digits;
    return phone;
}

static std::string parse_cnum_phone(const std::string& resp)
{
    size_t p = resp.find("+CNUM:");
    if (p == std::string::npos) return {};
    std::string line = line_containing(resp, p);
    std::string alpha = first_quoted(line);
    size_t after_alpha = line.find('"');
    if (after_alpha == std::string::npos) return {};
    after_alpha = line.find('"', after_alpha + 1);
    if (after_alpha == std::string::npos) return {};
    std::string phone = first_quoted(line, after_alpha + 1);
    if (phone.empty()) phone = alpha;
    return normalize_msisdn(phone);
}

static bool apn_valid_for_at(const std::string& apn)
{
    return apn.size() <= 96 && apn.find('"') == std::string::npos &&
           apn.find('\r') == std::string::npos && apn.find('\n') == std::string::npos;
}

static bool sample_cell_ip_once(void)
{
    std::string resp;
    std::string ip;
    if (send_ok("AT+CGPADDR=1", 3000, &resp) && idf_modem_parse_cgpaddr_ipv4(resp, ip)) {
        set_status_cell_ip(ip);
        idf_log_line("cellular IP acquired");
        return true;
    }
    set_status_cell_ip("");
    return false;
}

static bool parse_muestats_cell(const std::string& resp, IdfModemStatus& patch)
{
    size_t line_pos = resp.find("\"scell\"");
    if (line_pos == std::string::npos) return false;
    size_t line_end = resp.find('\n', line_pos);
    if (line_end == std::string::npos) line_end = resp.size();
    std::string line = resp.substr(line_pos, line_end - line_pos);

    std::string parts[12];
    int count = 0;
    size_t pos = 0;
    while (pos <= line.size() && count < 12) {
        size_t comma = line.find(',', pos);
        if (comma == std::string::npos) comma = line.size();
        parts[count++] = idf_util_trim_copy(line.substr(pos, comma - pos));
        if (comma == line.size()) break;
        pos = comma + 1;
    }
    if (count <= 10) return false;

    bool got = false;
    if (!parts[7].empty()) {
        long value = 0;
        if (parse_long_token(parts[7], value) && value > -32768) {
            patch.rsrp = static_cast<int>(value / 10);
            got = true;
        }
    }
    if (!parts[8].empty()) {
        long value = 0;
        if (parse_long_token(parts[8], value) && value > -32768) {
            patch.rsrq = static_cast<int>(value / 10);
            got = true;
        }
    }
    if (!parts[10].empty()) {
        long value = 0;
        if (parse_long_token(parts[10], value) && value > -32768) {
            patch.sinr = static_cast<int>(value / 10);
            got = true;
        }
    }
    return got;
}

static bool parse_cesq_signal(const std::string& resp, IdfModemStatus& patch)
{
    size_t p = resp.find("+CESQ:");
    if (p == std::string::npos) return false;
    long values[6] = {};
    int count = 0;
    size_t value_start = p + strlen("+CESQ:");
    size_t line_end = resp.find_first_of("\r\n", value_start);
    std::string line = resp.substr(
        value_start, line_end == std::string::npos ? std::string::npos : line_end - value_start);
    if (!parse_comma_longs(line, values, 6, count) || count < 6) return false;
    bool got = false;
    if (values[4] >= 0 && values[4] <= 34) {
        patch.rsrq = static_cast<int>(values[4] / 2 - 20);
        got = true;
    }
    if (values[5] >= 0 && values[5] <= 97) {
        patch.rsrp = static_cast<int>(values[5] - 141);
        got = true;
    }
    return got;
}

static void sample_signal_detail_once(void)
{
    IdfModemStatus current = idf_modem_get_status();
    if (!current.modemReady) return;
    std::string resp;
    IdfModemStatus patch;
    bool got = false;
    if (send_ok("AT+MUESTATS=\"cell\"", 2000, &resp)) {
        got = parse_muestats_cell(resp, patch);
    }
    if (!got && send_ok("AT+CESQ", 2000, &resp)) {
        got = parse_cesq_signal(resp, patch);
    }
    if (!got) return;
    int next_rsrp = patch.rsrp != 999 ? patch.rsrp : current.rsrp;
    int next_rsrq = patch.rsrq != 999 ? patch.rsrq : current.rsrq;
    int next_sinr = patch.sinr != 999 ? patch.sinr : current.sinr;
    if (next_rsrp == 999 && next_rsrq == 999 && next_sinr == 999) return;

    update_status(patch, false, true);
}

static bool model_skips_cgact(void)
{
    IdfModemStatus status = idf_modem_get_status();
    if (status.model == "ML307Y") return true;
    std::string resp;
    if (!send_ok("AT+CGMM", 1000, &resp)) return false;
    std::string model = first_payload_line(resp, "AT+CGMM");
    if (!model.empty()) {
        IdfModemStatus patch;
        patch.model = model;
        update_status(patch);
    }
    return model == "ML307Y";
}

static bool apply_configured_data_mode_once(const IdfSimSettingsView& cfg, uint32_t active_timeout_ms,
                                            uint32_t inactive_timeout_ms)
{
    const int cereg_stat = idf_modem_get_status().ceregStat;
    if (!idf_modem_data_activation_allowed(cereg_stat)) {
        // Home registration is the only state where this product may touch PDP data.
        // RLOS/unknown/roaming states remain read-only and continue probing CEREG.
        return true;
    }
    std::string resp;
    std::string apn = idf_util_trim_copy(cfg.apn);
    bool want_data = cfg.dataEnabled;
    if (want_data) {
        if (!apn.empty() && apn_valid_for_at(apn)) {
            std::string cmd = "AT+CGDCONT=1,\"IP\",\"";
            cmd += apn;
            cmd += "\"";
            send_ok(cmd.c_str(), 3000, &resp);
        } else if (!apn.empty()) {
            idf_log_line("APN contains invalid characters. CGDCONT not sent at startup");
        }
        bool ok = send_ok("AT+CGACT=1,1", active_timeout_ms, &resp);
        if (ok) sample_cell_ip_once();
        return ok;
    }

    bool ok = send_ok("AT+CGACT=0,1", inactive_timeout_ms, &resp);
    if (ok) set_status_cell_ip("");
    return ok;
}

// Disable data after registration if roaming is not allowed. This switch controls
// only PDP data. SMS availability also depends on the SIM, modem, and carrier.
// Do not infer SMS availability from one CEREG or CREG state.
static void enforce_roaming_data_policy(const IdfSimSettingsView& cfg, int stat)
{
    if (!cfg.dataEnabled || cfg.roamingEnabled) return;  // No policy change required.
    if (stat != 5) return;                                // Home network.
    if (idf_modem_get_status().cellIp.empty()) return;    // PDP data is already inactive.
    std::string resp;
    if (send_ok("AT+CGACT=0,1", 3000, &resp)) {
        set_status_cell_ip("");
        idf_log_line("data roaming disabled. Cellular data stopped while roaming");
    }
}

static void schedule_data_mode_retry(void)
{
    s_data_mode_retry_pending.store(true, std::memory_order_release);
    s_data_mode_retry_count.store(0, std::memory_order_relaxed);
    s_next_data_mode_retry.store(xTaskGetTickCount() + pdMS_TO_TICKS(MODEM_DATA_MODE_RETRY_GAP_MS),
                                 std::memory_order_relaxed);
}

static void apply_startup_data_mode(int cereg_stat)
{
    if (!idf_modem_data_activation_allowed(cereg_stat)) return;
    if (model_skips_cgact()) {
        idf_log_line("this model skips startup CGACT setup");
        return;
    }
    IdfSimSettingsView cfg = idf_config_get_sim_settings_view();
    bool ok = apply_configured_data_mode_once(cfg, 6000, 2500);
    if (ok) {
        idf_log_line(cfg.dataEnabled ? "cellular data enabled (AT+CGACT=1,1)"
                                     : "data connection disabled (AT+CGACT=0,1)");
    } else {
        idf_log_line(cfg.dataEnabled ? "startup data activation failed. Retrying in background"
                                     : "startup data disable not confirmed. Retrying in background");
        schedule_data_mode_retry();
    }
}

static bool plmn_valid(const std::string& plmn)
{
    if (plmn.empty()) return true;
    if (plmn.size() < 5 || plmn.size() > 6) return false;
    return std::all_of(plmn.begin(), plmn.end(), [](char ch) {
        return isdigit(static_cast<unsigned char>(ch));
    });
}

static void apply_operator_if_configured(const IdfSimSettingsView& cfg, int cereg_stat)
{
    if (cereg_stat != 1) return;
    if (cfg.operatorPlmn.empty()) return;
    if (!plmn_valid(cfg.operatorPlmn)) {
        idf_log_line("operator PLMN is invalid. COPS not sent at startup");
        return;
    }
    std::string cmd = "AT+COPS=1,2,\"";
    cmd += cfg.operatorPlmn;
    cmd += "\"";
    std::string resp;
    esp_err_t err = idf_modem_send_at(cmd, 30000, resp);
    idf_logf("operator: lock PLMN %s %s", cfg.operatorPlmn.c_str(),
             err == ESP_OK ? "succeeded" : "failed (possibly unreachable)");
}

static bool process_data_mode_retry(void)
{
    if (!s_data_mode_retry_pending.load(std::memory_order_acquire)) return false;
    if (s_reset_request.load(std::memory_order_acquire) != 0 ||
        idf_modem_get_status().ceregStat < 0) {
        s_data_mode_retry_pending.store(false, std::memory_order_release);
        return false;
    }
    if (static_cast<int32_t>(xTaskGetTickCount() -
                             s_next_data_mode_retry.load(std::memory_order_relaxed)) < 0) return false;  // Wrap-safe.
    if (!at_channel_idle_now()) return false;

    s_data_mode_retry_count.fetch_add(1, std::memory_order_relaxed);
    IdfSimSettingsView cfg = idf_config_get_sim_settings_view();
    bool ok = apply_configured_data_mode_once(cfg, 8000, 3000);
    if (ok) {
        s_data_mode_retry_pending.store(false, std::memory_order_release);
        idf_log_line(cfg.dataEnabled ? "background retry enabled cellular data" : "background retry disabled cellular data");
    } else if (s_data_mode_retry_count.load(std::memory_order_relaxed) >= MODEM_DATA_MODE_RETRY_MAX) {
        s_data_mode_retry_pending.store(false, std::memory_order_release);
        idf_log_line("background CGACT retry failed. Current modem state retained");
    } else {
        s_next_data_mode_retry.store(xTaskGetTickCount() + pdMS_TO_TICKS(MODEM_DATA_MODE_RETRY_GAP_MS),
                                     std::memory_order_relaxed);
        idf_log_line("background CGACT retry did not succeed. Retrying later");
    }
    return true;
}

esp_err_t idf_modem_cellular_http_get(const std::string& url,
                                      const IdfCellularHttpConfig& config,
                                      IdfCellularHttpResult& result)
{
    (void)url;
    (void)config;
    result = IdfCellularHttpResult();
    result.message = "Cellular HTTP is not supported";
    return ESP_ERR_NOT_SUPPORTED;
}

struct OwnerHttpsCallbackContext {
    TickDeadline& deadline;
    idf_modem_https_wire::MipOpenLatch open_latch;
};

static esp_err_t owner_send_mip_deadline(const std::string& command, TickDeadline& deadline,
                                         std::string& response, bool* modem_error = nullptr,
                                         bool await_mip_open = false,
                                         idf_modem_https_wire::MipOpenLatch* open_latch = nullptr)
{
    assert_owner_task();
    if (modem_error) *modem_error = false;
    if (deadline.expired()) return ESP_ERR_TIMEOUT;

    if (!capture_pending_uart_locked(deadline, open_latch)) return ESP_FAIL;
    std::string wire = command;
    wire += "\r\n";
    if (!owner_uart_write_all(wire.data(), wire.size(), deadline)) {
        return deadline.expired() ? ESP_ERR_TIMEOUT : ESP_FAIL;
    }
    if (await_mip_open) {
        if (!open_latch) return ESP_FAIL;
        open_latch->begin();
    }

    response.clear();
    response.reserve(1024);
    std::string scan;
    std::string line_carry;
    bool terminal_seen = false;
    bool open_seen = false;
    bool sms_pdu_pending = false;
    auto known_mip_urc = [](std::string_view line) {
        static constexpr std::string_view prefixes[] = {
            "+CMTI:", "+CEREG:", "+CREG:", "+CGREG:", "+CLIP:",
            "+CSQ:", "+CESQ:", "+MUESTATS:",
        };
        return line == "RING" || std::any_of(
                                  std::begin(prefixes), std::end(prefixes),
                                  [line](std::string_view prefix) {
                                      return line.rfind(prefix, 0) == 0;
                                  });
    };
    auto consume_open_line = [&](std::string_view raw_line) -> int {
        const std::string line = idf_util_trim_copy(std::string(raw_line));
        if (line.empty()) return 0;
        if (line == command) return 0;
        if (line == "OK") {
            if (terminal_seen) return -1;
            terminal_seen = true;
            return 0;
        }
        if (line == "ERROR" || line.rfind("+CMS ERROR", 0) == 0 ||
            line.rfind("+CME ERROR", 0) == 0) {
            return -1;
        }
        if (line.rfind("+MIPURC:", 0) == 0) {
            uint32_t received = 0;
            uint32_t total = 0;
            uint8_t state = 0;
            bool disconnected = false;
            if (!idf_modem_https_wire::parse_mip_urc(line, received, total, state,
                                                      disconnected) || disconnected) {
                return -1;
            }
            return 0;
        }
        if (line.rfind("+MIPOPEN:", 0) == 0) {
            if (open_seen) return -1;
            // Parse only the sanitized, complete async line. The full response is
            // retained separately so known SMS/registration URCs are preserved.
            std::string sanitized_response = "\r\n";
            sanitized_response += command;
            sanitized_response += "\r\n";
            sanitized_response += line;
            sanitized_response += "\r\nOK\r\n";
            bool present = false;
            if (!idf_modem_https_wire::parse_mip_open(sanitized_response, command, 0, present) ||
                !present) {
                return -1;
            }
            open_seen = true;
            return 0;
        }
        if (line.rfind("+CMT:", 0) == 0) {
            sms_pdu_pending = true;
            return 0;
        }
        if (sms_pdu_pending && looks_like_pdu_line(line)) {
            sms_pdu_pending = false;
            return 0;
        }
        if (known_mip_urc(line)) return 0;
        sms_pdu_pending = false;
        // A complete line not covered by the observed command/URC grammar is
        // a protocol error; do not silently pass it to the session parser.
        return -1;
    };
    uint8_t buf[128];
    while (!deadline.expired()) {
        const TickType_t wait = std::min(pdMS_TO_TICKS(80), deadline.remaining_ticks());
        if (wait == 0) break;
        const int got = owner_uart_read(buf, sizeof(buf), wait);
        if (got <= 0) continue;
        preserve_uart_urcs(buf, static_cast<size_t>(got));
        if (open_latch && !open_latch->connected() &&
            !open_latch->feed(std::string_view(
                reinterpret_cast<const char*>(buf), static_cast<size_t>(got)))) {
            return ESP_FAIL;
        }
        if (static_cast<size_t>(got) > OWNER_MIP_RESPONSE_LIMIT - response.size()) {
            return ESP_ERR_INVALID_SIZE;
        }
        response.append(reinterpret_cast<const char*>(buf), static_cast<size_t>(got));
        scan.append(reinterpret_cast<const char*>(buf), static_cast<size_t>(got));
        if (await_mip_open) {
            line_carry.append(reinterpret_cast<const char*>(buf), static_cast<size_t>(got));
            size_t line_end = std::string::npos;
            while ((line_end = line_carry.find_first_of("\r\n")) != std::string::npos) {
                const std::string line = line_carry.substr(0, line_end);
                size_t consumed = line_end + 1;
                while (consumed < line_carry.size() &&
                       (line_carry[consumed] == '\r' || line_carry[consumed] == '\n')) {
                    ++consumed;
                }
                line_carry.erase(0, consumed);
                if (consume_open_line(line) < 0) {
                    if (terminal_seen && modem_error) *modem_error = true;
                    return ESP_FAIL;
                }
            }
            if (terminal_seen && line_carry.empty()) return ESP_OK;
            continue;
        }
        // For non-OPEN MIP commands, retain the hardware-evidenced result-before-OK behavior.
        const int final_code = at_final_result(scan);
        if (final_code != 0) {
            if (final_code < 0 && modem_error) *modem_error = true;
            return final_code > 0 ? ESP_OK : ESP_FAIL;
        }
        if (scan.size() > 64) scan.erase(0, scan.size() - 64);
    }
    return ESP_ERR_TIMEOUT;
}

static IdfModemHttpsCommandResult owner_https_send_command(
    void* opaque, std::string_view command, std::string& response,
    bool cleanup)
{
    auto& context = *static_cast<OwnerHttpsCallbackContext*>(opaque);
    const std::string command_text(command);
    bool modem_error = false;
    TickDeadline cleanup_deadline(HTTPS_CLEANUP_TIMEOUT_MS);
    TickDeadline& active_deadline = cleanup ? cleanup_deadline : context.deadline;
    const bool await_mip_open = command_text.rfind("AT+MIPOPEN=", 0) == 0;
    if (cleanup) context.open_latch.reset();
    const esp_err_t err = owner_send_mip_deadline(command_text, active_deadline, response,
                                                  &modem_error, await_mip_open,
                                                  &context.open_latch);
    if (err == ESP_OK) return IdfModemHttpsCommandResult::ok;
    if (!context.open_latch.nonfatal()) return IdfModemHttpsCommandResult::open_failed;
    if (err == ESP_ERR_TIMEOUT) return IdfModemHttpsCommandResult::timeout;
    return modem_error ? IdfModemHttpsCommandResult::modem_error
                        : IdfModemHttpsCommandResult::failed;
}

static IdfModemHttpsCommandResult owner_https_confirm_open(void* opaque)
{
    auto& context = *static_cast<OwnerHttpsCallbackContext*>(opaque);
    if (context.deadline.expired()) return IdfModemHttpsCommandResult::timeout;
    if (!capture_pending_uart_locked(context.deadline, &context.open_latch)) {
        if (!context.open_latch.nonfatal()) return IdfModemHttpsCommandResult::open_failed;
        return context.deadline.expired() ? IdfModemHttpsCommandResult::timeout
                                          : IdfModemHttpsCommandResult::failed;
    }
    if (context.deadline.expired()) return IdfModemHttpsCommandResult::timeout;
    if (!context.open_latch.finish()) return IdfModemHttpsCommandResult::open_failed;
    return IdfModemHttpsCommandResult::ok;
}

static esp_err_t owner_https_post(const IdfModemHttpsPostRequest& request,
                                  IdfModemHttpsPostResult& result, TickDeadline& deadline)
{
    assert_owner_task();
    result = IdfModemHttpsPostResult();
    const IdfModemStatus status = idf_modem_get_status();
    if (!status.atReady) {
        result.message = "Modem AT is not ready";
        result.failureStage = IdfHttpsFailureStage::modem;
        return ESP_ERR_INVALID_STATE;
    }
    if (!idf_modem_https_model_allowed(status.model)) {
        result.message = "Cellular HTTPS requires an ML307A modem";
        result.failureStage = IdfHttpsFailureStage::modem;
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (!idf_modem_data_activation_allowed(status.ceregStat)) {
        result.message = "Cellular HTTPS requires home registration";
        result.failureStage = IdfHttpsFailureStage::registration;
        return ESP_ERR_INVALID_STATE;
    }
    OwnerHttpsCallbackContext context{deadline, {}};
    const IdfModemHttpsCallbacks callbacks{
        &context, &owner_https_send_command, &owner_https_confirm_open};
    const IdfModemHttpsRunResult run_result =
        idf_modem_https_run_post(request, callbacks, result);
    context.open_latch.reset();
    if (run_result == IdfModemHttpsRunResult::ok && !https_status_valid(result.httpStatus)) {
        result.ok = false;
        result.failureStage = IdfHttpsFailureStage::response;
        result.failureReason = IdfModemHttpsDiagnosticReason::response_invalid;
        result.message = "HTTPS response status is invalid";
        return ESP_FAIL;
    }
    switch (run_result) {
        case IdfModemHttpsRunResult::ok:
            return ESP_OK;
        case IdfModemHttpsRunResult::invalid_request:
            return ESP_ERR_INVALID_ARG;
        case IdfModemHttpsRunResult::timed_out:
            return ESP_ERR_TIMEOUT;
        case IdfModemHttpsRunResult::command_failed:
        case IdfModemHttpsRunResult::response_failed:
        case IdfModemHttpsRunResult::cleanup_failed:
            return ESP_FAIL;
    }
    return ESP_FAIL;
}

esp_err_t idf_modem_https_post(const IdfModemHttpsPostRequest& request,
                               IdfModemHttpsPostResult& result)
{
    result = IdfModemHttpsPostResult();
    std::string error;
    if (!idf_modem_https_validate_request(request, error)) {
        result.message = error;
        result.failureStage = https_request_failure_stage(request);
        return ESP_ERR_INVALID_ARG;
    }

    OwnerCommand owner_request;
    owner_request.kind = OwnerCommandKind::https_post;
    owner_request.https_post_request = request;
    owner_request.timeout_ms = request.timeoutMs;
    if (xTaskGetCurrentTaskHandle() == s_owner_task) {
        TickDeadline deadline(request.timeoutMs);
        return owner_https_post(request, result, deadline);
    }
    const esp_err_t err = submit_owner_command(owner_request, nullptr, false, nullptr, &result);
    if (err == IDF_MODEM_ERR_BUSY) result.message = "Modem command queue is full";
    else if (err == ESP_ERR_TIMEOUT && result.message.empty()) {
        result.message = request.method == IdfModemHttpsMethod::Get
                             ? "Modem HTTPS GET timed out"
                             : "Modem HTTPS POST timed out";
    }
    else if (err == ESP_ERR_INVALID_STATE && result.message.empty()) result.message = "Modem is not started";
    if (err != ESP_OK && result.failureStage == IdfHttpsFailureStage::none) {
        result.failureStage = IdfHttpsFailureStage::modem;
    }
    return err;
}

static esp_err_t execute_owner_command(OwnerCommandSlot& slot)
{
    assert_owner_task();
    switch (slot.request.kind) {
        case OwnerCommandKind::at:
            if (slot.request.deadline_us != 0) {
                TickDeadline deadline(slot.request.timeout_ms);
                deadline.deadline_us = slot.request.deadline_us;
                return owner_send_at_deadline(slot.request.command, deadline, slot.response,
                                              false, nullptr);
            }
            return owner_send_at(slot.request.command, slot.request.timeout_ms, slot.response,
                                 slot.request.filter_urcs,
                                 slot.request.response_prefix.empty()
                                     ? nullptr
                                     : slot.request.response_prefix.c_str(),
                                 slot.request.response_limit,
                                 slot.request.capture_other_line ? &slot.other_line_present : nullptr,
                                 slot.request.capture_other_line ? &slot.msslcipher_telemetry : nullptr);
        case OwnerCommandKind::until:
            return owner_send_at_until(slot.request.command, slot.request.token.c_str(),
                                       slot.request.timeout_ms, slot.response);
        case OwnerCommandKind::pdu:
            return owner_send_pdu(slot.request.command, slot.request.pdu.c_str(),
                                  slot.request.timeout_ms, slot.response);
        case OwnerCommandKind::https_post: {
            TickDeadline deadline(slot.request.deadline_start, slot.request.deadline_span);
            return owner_https_post(slot.request.https_post_request, slot.https_post_result,
                                    deadline);
        }
    }
    return ESP_ERR_INVALID_ARG;
}

static void owner_reclaim_expired_done_slots()
{
    assert_owner_task();
    if (!s_command_mutex || xSemaphoreTake(s_command_mutex, 0) != pdTRUE) return;
    for (size_t index = 0; index < OWNER_COMMAND_SLOTS; ++index) {
        OwnerCommandSlot& slot = s_command_slots[index];
        if (!slot.caller_abandoned.load(std::memory_order_acquire) ||
            (slot.state != OwnerCommandState::done &&
             slot.state != OwnerCommandState::free)) {
            continue;
        }
        if (slot.state == OwnerCommandState::done) {
            while (slot.completed && xSemaphoreTake(slot.completed, 0) == pdTRUE) {}
            reset_owner_slot(slot);
        } else {
            slot.caller_abandoned.store(false, std::memory_order_release);
        }
    }
    xSemaphoreGive(s_command_mutex);
}

static bool owner_process_one_command(bool priority)
{
    assert_owner_task();
    owner_reclaim_expired_done_slots();
    int slot_index = -1;
    QueueHandle_t queue = priority ? s_priority_command_queue : s_command_queue;
    if (!queue || xQueueReceive(queue, &slot_index, 0) != pdTRUE) return false;
    if (slot_index < 0 || slot_index >= static_cast<int>(OWNER_COMMAND_SLOTS)) return true;

    if (xSemaphoreTake(s_command_mutex, portMAX_DELAY) != pdTRUE) return true;
    OwnerCommandSlot& slot = s_command_slots[slot_index];
    if (slot.state == OwnerCommandState::abandoned ||
        slot.caller_abandoned.load(std::memory_order_acquire)) {
        reset_owner_slot(slot);
        xSemaphoreGive(s_command_mutex);
        return true;
    }
    if (slot.state != OwnerCommandState::queued) {
        xSemaphoreGive(s_command_mutex);
        return true;
    }

    const bool reset_requested = s_reset_request.load(std::memory_order_acquire) != 0;
    const bool runtime_queue_ready = s_runtime_queue_ready.load(std::memory_order_acquire);
    if (!idf_modem_owner_command_allowed(priority, reset_requested, runtime_queue_ready)) {
        slot.response.clear();
        slot.result = ESP_ERR_INVALID_STATE;
        slot.state = OwnerCommandState::done;
        xSemaphoreGive(s_command_mutex);
        xSemaphoreGive(slot.completed);
        return true;
    }
    slot.state = OwnerCommandState::running;
    xSemaphoreGive(s_command_mutex);

    esp_err_t result = execute_owner_command(slot);
    if (xSemaphoreTake(s_command_mutex, portMAX_DELAY) != pdTRUE) return true;
    bool signal_completion = false;
    if (slot.state == OwnerCommandState::abandoned ||
        slot.caller_abandoned.load(std::memory_order_acquire)) {
        reset_owner_slot(slot);
    } else {
        slot.result = result;
        slot.state = OwnerCommandState::done;
        signal_completion = true;
    }
    xSemaphoreGive(s_command_mutex);
    if (signal_completion) xSemaphoreGive(slot.completed);
    return true;
}

static void owner_drain_priority_commands()
{
    assert_owner_task();
    while (owner_process_one_command(true)) {}
}

static void sample_signal_once(void)
{
    std::string resp;
    if (!send_ok("AT+CSQ", 1000, &resp)) return;
    int csq = -1;
    int ber = 99;
    if (!parse_csq(resp, csq, ber)) return;
    IdfModemStatus patch;
    patch.csq = csq;
    patch.ber = ber;
    update_status(patch, false, true);
}

static bool sample_identity_once(bool log_summary = false, bool include_network_fields = true)
{
    if (!idf_modem_identity_sampling_allowed(idf_modem_get_status().ceregStat)) return false;
    IdfModemStatus before = idf_modem_get_status();
    bool need_static = !s_identity_static_attempted ||
                       before.mfr.empty() ||
                       before.model.empty() ||
                       before.fwver.empty();
    std::string resp;
    IdfModemStatus patch;

    // Retry stable firmware and manufacturer fields until startup sampling is complete.
    if (need_static && before.mfr.empty()) {
        if (send_ok("AT+CGMI", 1000, &resp)) patch.mfr = first_payload_line(resp, "AT+CGMI");
        vTaskDelay(pdMS_TO_TICKS(150));
    }
    if (need_static && before.model.empty()) {
        if (send_ok("AT+CGMM", 1000, &resp)) patch.model = first_payload_line(resp, "AT+CGMM");
        vTaskDelay(pdMS_TO_TICKS(150));
    }
    if (need_static && before.fwver.empty()) {
        if (send_ok("AT+CGMR", 1000, &resp)) patch.fwver = first_payload_line(resp, "AT+CGMR");
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    if (!is_imei_text(before.imei)) {
        const char* imei_cmds[] = {"AT+CGSN=1", "AT+GSN=1", "AT+CGSN", "AT+GSN"};
        for (const char* cmd : imei_cmds) {
            if (!patch.imei.empty()) break;
            if (send_ok(cmd, 1000, &resp)) {
                idf_modem_parse_imei_frame(resp, cmd, patch.imei);
            }
            vTaskDelay(pdMS_TO_TICKS(80));
        }
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    if (before.iccid.size() < 15) {
        patch.iccid = query_current_iccid(80);
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    if (before.imsi.empty()) {
        if (send_ok("AT+CIMI", 1000, &resp)) {
            patch.imsi = first_digits_line(resp, 14, 16);
            if (patch.imsi.empty()) patch.imsi = first_digit_run(resp, 14, 16);
        }
        vTaskDelay(pdMS_TO_TICKS(150));
    }

    // Get operator and APN after registration. A missing SIM phone number does not block startup.
    bool need_network = include_network_fields &&
                        (!s_identity_network_attempted || before.operatorName.empty());
    if (need_network) {
        if (before.operatorName.empty()) {
            // 漫遊只查詢現有格式，不修改模組選網設定。
            if (before.ceregStat == 1) send_ok("AT+COPS=3,0", 1500, &resp);
            if (send_ok("AT+COPS?", 1500, &resp)) patch.operatorName = parse_cops(resp);
            vTaskDelay(pdMS_TO_TICKS(150));
        }
        if (before.apnSim.empty()) {
            if (send_ok("AT+CGDCONT?", 1500, &resp)) patch.apnSim = parse_apn(resp);
            vTaskDelay(pdMS_TO_TICKS(150));
        }
        if (before.phone.empty()) {
            if (send_ok("AT+CNUM", 1500, &resp)) patch.phone = parse_cnum_phone(resp);
        }
    }

    bool static_changed = (!patch.mfr.empty() && patch.mfr != before.mfr) ||
                          (!patch.model.empty() && patch.model != before.model) ||
                          (!patch.fwver.empty() && patch.fwver != before.fwver) ||
                          (!patch.imei.empty() && patch.imei != before.imei) ||
                          (!patch.iccid.empty() && patch.iccid != before.iccid) ||
                          (!patch.imsi.empty() && patch.imsi != before.imsi);
    bool network_changed = (!patch.operatorName.empty() && patch.operatorName != before.operatorName) ||
                           (!patch.apnSim.empty() && patch.apnSim != before.apnSim) ||
                           (!patch.phone.empty() && patch.phone != before.phone);
    bool material_static_change = (!patch.imei.empty() && !before.imei.empty() && patch.imei != before.imei) ||
                                  (!patch.iccid.empty() && !before.iccid.empty() && patch.iccid != before.iccid) ||
                                  (!patch.imsi.empty() && !before.imsi.empty() && patch.imsi != before.imsi);
    bool changed = static_changed || network_changed;
    update_status(patch, true, false);
    IdfModemStatus after = idf_modem_get_status();
    s_identity_static_attempted = !after.mfr.empty() && !after.model.empty() && !after.fwver.empty();
    if (include_network_fields) {
        s_identity_network_attempted = !after.operatorName.empty();
    }
    if (material_static_change) {
        ESP_LOGI(TAG, "identity changed imei=%s iccid=%s imsi=%s",
                 mask_identity(after.imei).c_str(), mask_identity(after.iccid).c_str(),
                 mask_identity(after.imsi).c_str());
        idf_logf("modem identity changed IMEI=%s ICCID=%s IMSI=%s",
                 mask_identity(after.imei).c_str(), mask_identity(after.iccid).c_str(),
                 mask_identity(after.imsi).c_str());
    }
    save_identity_cache(patch.imei, patch.iccid);
    return changed;
}

static void modem_en_gpio_init(void)
{
    gpio_config_t io = {};
    io.pin_bit_mask = 1ULL << MODEM_EN;
    io.mode = GPIO_MODE_OUTPUT;
    io.pull_up_en = GPIO_PULLUP_DISABLE;
    io.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&io);
}

// Raise EN without a power cycle for warm-start detection. Write the output
// register before setting its direction to avoid a low pulse on a running modem.
static void modem_power_hold_on(void)
{
    gpio_set_level(MODEM_EN, 1);
    modem_en_gpio_init();
    gpio_set_level(MODEM_EN, 1);
}

static void modem_power_cycle(void)
{
    modem_en_gpio_init();

    set_phase("powering");
    gpio_set_level(MODEM_EN, 0);
    vTaskDelay(pdMS_TO_TICKS(MODEM_POWERDOWN_MS));
    gpio_set_level(MODEM_EN, 1);
    vTaskDelay(pdMS_TO_TICKS(MODEM_POWERUP_MIN_MS));
}

static bool wait_at_ready(void)
{
    TickDeadline deadline(MODEM_POWERUP_MAX_MS);
    while (!deadline.expired()) {
        if (send_ok("AT", 700)) return true;
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    return false;
}

static bool modem_hot_start_allowed(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_PANIC:
        case ESP_RST_INT_WDT:
        case ESP_RST_TASK_WDT:
        case ESP_RST_WDT:
        case ESP_RST_CPU_LOCKUP:
            return true;
        default:
            return false;
    }
}

static bool modem_quick_start_allowed(esp_reset_reason_t reason)
{
    switch (reason) {
        case ESP_RST_POWERON:
        case ESP_RST_SW:
        case ESP_RST_EXT:
            return true;
        default:
            return false;
    }
}

// Parse <mem1> capacity from an AT+CPMS set response. A quoted storage name
// belongs to a query response and intentionally does not match.
static bool parse_cpms_total(const std::string& resp, long& total)
{
    size_t p = resp.find("+CPMS:");
    if (p == std::string::npos) return false;
    std::string line = line_containing(resp, p);
    const char* token = strstr(line.c_str(), "+CPMS:");
    if (!token) return false;
    long values[6] = {};
    int count = 0;
    if (!parse_comma_longs(token + strlen("+CPMS:"), values, 6, count) || count < 2) return false;
    total = values[1];
    return true;
}

static int sms_storage_code(const char* name)
{
    if (strcmp(name, "MT") == 0) return 0;
    if (strcmp(name, "ME") == 0) return 1;
    if (strcmp(name, "SM") == 0) return 2;
    return -1;
}

static void log_sms_storage_if_changed(const char* name)
{
    int current = sms_storage_code(name);
    int previous = s_logged_sms_storage_code.exchange(current, std::memory_order_relaxed);
    if (previous == current) return;
    // Suppress the initial normal MT selection. Log fallback or later changes.
    if (previous != -1 || current != 0) idf_logf("SMS storage uses %s", name);
}

// Select SMS storage in MT, ME, SM order. Treat reported zero capacity as
// unavailable (issue #3). Accept an OK response when firmware omits capacity.
static bool select_sms_storage(void)
{
    static const struct { const char* cmd; const char* name; } kCandidates[] = {
        {"AT+CPMS=\"MT\",\"MT\",\"MT\"", "MT"},
        {"AT+CPMS=\"ME\",\"ME\",\"ME\"", "ME"},
        {"AT+CPMS=\"SM\",\"SM\",\"SM\"", "SM"},
    };
    for (const auto& c : kCandidates) {
        std::string resp;
        if (!send_ok(c.cmd, 1500, &resp)) continue;
        long total = -1;
        if (parse_cpms_total(resp, total) && total <= 0) {
            idf_logf("SMS storage %s has zero capacity. Trying the next candidate", c.name);
            continue;
        }
        log_sms_storage_if_changed(c.name);
        return true;
    }
    idf_log_line("WARNING: No SMS storage is available (MT, ME, or SM). SMS reception can fail");
    return false;
}

// CPMS can run before a slow SIM is ready and reject every storage candidate.
// Retry after registration. Only modem_task accesses this flag.
static bool s_sms_storage_pending = false;

static void retry_sms_storage_if_pending(void)
{
    if (!s_sms_storage_pending) return;
    idf_log_line("SIM ready. Retrying SMS storage selection");
    s_sms_storage_pending = !select_sms_storage();
}

void idf_modem_reassert_sms_storage(void)
{
    // Reassert CPMS after an unobserved modem reset restores default storage.
    // select_sms_storage uses the locked AT channel and is safe across tasks.
    select_sms_storage();
}

static bool configure_sms_and_registration(void)
{
    send_ok("ATE0", 1000);
    send_ok("AT+CMEE=1", 1200);  // Request specific +CMS/+CME numeric errors.
    // Use Phase 2+ acknowledgment for direct +CMT. The SMS task sends AT+CNMA=0
    // after each PDU, as required for reliable ML307R multipart delivery.
    bool phase2_ok = send_ok("AT+CSMS=1", 1200);
    bool pdu_mode_ok = send_ok("AT+CMGF=0", 1200);
    // Keep +CMTI and CMGL/CMGR on the same storage for startup and special-class backfill.
    bool storage_ok = select_sms_storage();
    s_sms_storage_pending = !storage_ok;
    // Deliver normal SMS directly with +CMT to avoid storage that keeps only the
    // final segment. Keep +CMTI and CMGL for startup and special-class backfill.
    bool cnmi_ok = send_ok("AT+CNMI=2,2,0,0,0", 1200);
    send_ok("AT+CEREG=2", 1200);
    // Enable caller ID through RING and +CLIP. Ignore ERROR on hardware without voice support.
    send_ok("AT+CLIP=1", 1200);
    // Apply the saved NET LED setting (ML307R: AT+MLED=0,<0/1>) on each initialization.
    send_ok(idf_config_net_led_enabled() ? "AT+MLED=0,1" : "AT+MLED=0,0", 1200);
    bool sms_ready = phase2_ok && pdu_mode_ok && storage_ok && cnmi_ok;
    if (!sms_ready) idf_log_line("SMS setup incomplete. A later health check will retry");
    return sms_ready;
}

static bool response_has_compact(std::string response, const char* expected)
{
    response.erase(std::remove_if(response.begin(), response.end(), [](unsigned char ch) {
        return isspace(ch);
    }), response.end());
    return response.find(expected) != std::string::npos;
}

static void query_sms_receive_config(bool& phase2, bool& pdu, bool& cnmi)
{
    std::string resp;
    phase2 = send_ok("AT+CSMS?", 1200, &resp) && response_has_compact(resp, "+CSMS:1,");
    pdu = send_ok("AT+CMGF?", 1200, &resp) && response_has_compact(resp, "+CMGF:0");
    cnmi = send_ok("AT+CNMI?", 1200, &resp) &&
           response_has_compact(resp, "+CNMI:2,2,0,0,0");
}

bool idf_modem_sms_health_check(std::string& summary)
{
    summary.clear();
    IdfModemStatus initial_status = idf_modem_get_status();
    const bool sim_present = initial_status.simState != "absent" &&
                             initial_status.simState != "unknown";
    if (!initial_status.atReady) {
        if (idf_modem_health_reset_required(false, sim_present, initial_status.simState == "ready",
                                            false, -1, false, false) &&
            request_health_reset_with_backoff()) {
            summary = "Modem AT is not ready. Hard reset requested";
        } else {
            summary = "Modem AT is not ready. Reset deferred";
        }
        idf_logf("daily SMS health check failed: %s", summary.c_str());
        return false;
    }

    std::string resp;
    int stat = -1;
    bool cereg_query_ok = send_ok("AT+CEREG?", 1200, &resp) && parse_cereg(resp, stat);
    bool registered = cereg_query_ok && (stat == 1 || stat == 5);
    bool phase2 = false;
    bool pdu = false;
    bool cnmi = false;
    query_sms_receive_config(phase2, pdu, cnmi);
    bool storage = select_sms_storage();
    bool sim_ready = idf_modem_get_status().simState == "ready";
    bool initially_ok = registered && phase2 && pdu && cnmi && storage;

    if (!phase2 || !pdu || !cnmi || !storage) {
        configure_sms_and_registration();
        stat = -1;
        cereg_query_ok = send_ok("AT+CEREG?", 1200, &resp) && parse_cereg(resp, stat);
        registered = cereg_query_ok && (stat == 1 || stat == 5);
        query_sms_receive_config(phase2, pdu, cnmi);
        storage = select_sms_storage();
    }

    bool final_ok = idf_modem_sms_health_complete(registered, phase2, pdu, cnmi, storage);
    if (final_ok) clear_health_reset_backoff();
    char state[192];
    const char* registration = registered ? "ok" :
                               (cereg_query_ok && stat == 11 ? "restricted-rlos" : "unavailable");
    snprintf(state, sizeof(state),
             "registration=%s, Phase2+=%s, PDU=%s, CNMI=%s, storage=%s (carrier delivery not tested)",
             registration, phase2 ? "ok" : "error", pdu ? "ok" : "error",
             cnmi ? "ok" : "error", storage ? "ok" : "error");

    if (initially_ok) {
        summary = std::string("OK: ") + state;
        idf_logf("daily SMS health check passed: %s", summary.c_str());
        return true;
    }
    if (final_ok) {
        summary = std::string("Error found and repaired: ") + state;
    } else if (!idf_modem_health_reset_required(
                   true, sim_present, sim_ready, cereg_query_ok, cereg_query_ok ? stat : -1,
                   phase2 && pdu && cnmi, storage)) {
        summary = std::string("Registration unavailable; modem reset not requested: ") + state;
    } else if (request_health_reset_with_backoff()) {
        summary = std::string("Error remains. Hard modem reset requested: ") + state;
    } else {
        summary = std::string("Error remains. Hard modem reset deferred: ") + state;
    }
    idf_logf("daily SMS health check failed: %s", summary.c_str());
    return false;
}

static int query_sim_present(void)
{
    std::string state = query_sim_state();
    return idf_modem_sim_presence(state);
}

// After a reset handshake fails, run full initialization when any later probe
// finds AT ready. This restores echo, URCs, registration, and data policy.
static bool s_reinit_pending = false;

static bool handle_reset_request_if_any(void)
{
    // Delay a requested reset until the APDU session closes to avoid truncating eSIM work.
    if (s_esim_operation_depth.load(std::memory_order_relaxed) != 0) return false;
    int request = s_reset_request.exchange(0, std::memory_order_relaxed);
    if (request == 0) return false;

    s_runtime_queue_ready.store(false, std::memory_order_release);

    IdfModemStatus patch;
    patch.phase = "powering";
    patch.atReady = false;
    patch.modemReady = false;
    update_status(patch);
    invalidate_registration_state("powering", false);
    if (request == 2) {
        idf_log_line("performing hard modem reset");
        modem_power_cycle();
    } else {
        idf_log_line("performing soft modem reset");
        send_ok("AT+CFUN=1,1", 15000);
        vTaskDelay(pdMS_TO_TICKS(5000));
    }

    if (!wait_at_ready()) {
        set_phase("failed");
        idf_log_line("AT handshake failed after modem reset. Initialization will run after recovery");
        s_reinit_pending = true;
        return true;
    }
    patch = {};
    patch.started = true;
    patch.atReady = true;
    patch.modemReady = false;
    patch.phase = "at_ready";
    update_status(patch);
    if (try_unlock_sim(false)) {
        invalidate_registration_state("registering", true);
        configure_sms_and_registration();
        set_phase("registering");
        // Data setup waits for the first valid CEREG result below.
    }
    // AT transport is usable even when the SIM is locked or not registered.
    s_runtime_queue_ready.store(true, std::memory_order_release);
    s_reinit_pending = false;
    return true;
}

// Complete initialization after AT recovery when s_reinit_pending is set.
static void run_pending_reinit_if_recovered(void)
{
    if (!s_reinit_pending) return;
    invalidate_registration_state("powering", false);
    if (!at_channel_idle_now()) return;
    if (!send_ok("AT", 700)) return;
    idf_log_line("modem AT recovered. Restoring SMS, registration, and data setup");
    IdfModemStatus patch;
    patch.started = true;
    patch.atReady = true;
    patch.modemReady = false;
    patch.phase = "at_ready";
    update_status(patch);
    if (try_unlock_sim(false)) {
        invalidate_registration_state("registering", true);
        configure_sms_and_registration();
        set_phase("registering");
        // Data setup waits for a valid CEREG result after reset recovery.
    }
    s_runtime_queue_ready.store(true, std::memory_order_release);
    s_reinit_pending = false;
}

static void modem_task(void*)
{
    s_owner_task = xTaskGetCurrentTaskHandle();
    owner_uart_flush();
    invalidate_registration_state("powering", false);
    IdfModemStatus patch;
    patch.started = true;
    patch.phase = "powering";
    update_status(patch);
    reset_identity_sampling_state();

    bool at_ready = false;
    esp_reset_reason_t reset_reason = esp_reset_reason();
    // Use the warm-start fast path only after an unexpected crash or watchdog reset.
    // USB and serial resets use a cold start to avoid a partially initialized modem.
    if (modem_hot_start_allowed(reset_reason)) {
        modem_power_hold_on();
        if (wait_at_ready()) {
            at_ready = true;
            idf_log_line("modem already running. Skipping power cycle for warm start");
        } else {
            idf_log_line("warm-start probe failed after unexpected reset. Using cold start");
        }
    } else if (modem_quick_start_allowed(reset_reason)) {
        modem_power_hold_on();
        if (wait_at_ready()) {
            at_ready = true;
            idf_logf("reset reason %d. Modem fast power-on complete", static_cast<int>(reset_reason));
        } else {
            idf_logf("reset reason %d. Modem fast power-on timed out. Using cold start", static_cast<int>(reset_reason));
        }
    } else {
        idf_logf("reset reason %d. Performing modem cold start", static_cast<int>(reset_reason));
    }

    if (!at_ready) {
        // Never abandon the startup handshake. Exiting this task disables reset,
        // URC polling, and health recovery until a full device power cycle.
        modem_power_cycle();
        int round = 0;
        uint32_t retry_gap_ms = 5000;
        while (!wait_at_ready()) {
            set_phase("failed");
            ++round;
            ESP_LOGE(TAG, "AT handshake timed out (round %d)", round);
            idf_logf("modem AT handshake timed out (round %d). Retrying power-on later", round);
            s_reset_request.store(0, std::memory_order_relaxed);  // This power-on satisfies the reset request.
            vTaskDelay(pdMS_TO_TICKS(retry_gap_ms));
            if (retry_gap_ms < 60000) retry_gap_ms *= 2;  // Back off from 5 to 60 seconds.
            modem_power_cycle();
        }
    }

    patch = {};
    patch.started = true;
    patch.atReady = true;
    patch.phase = "at_ready";
    update_status(patch);
    ESP_LOGI(TAG, "AT ready");
    idf_log_line("modem AT ready");

    bool sim_ready = try_unlock_sim(false);
    if (sim_ready) {
        invalidate_registration_state("registering", true);
        configure_sms_and_registration();
        set_phase("registering");
        // Data setup waits for a valid CEREG result after AT recovery.
    }

    // The sole owner can now dispatch bounded AT requests. Registration is a
    // separate modem state; CPIN/CEREG diagnostics must work while it is pending.
    s_runtime_queue_ready.store(true, std::memory_order_release);

    int check_count = 0;
    int stat = -1;
    while (sim_ready && check_count++ < 30) {
        while (owner_process_one_command(true)) {}
        if (owner_process_one_command(false)) continue;
        std::string resp;
        if (send_ok("AT+CEREG?", 1200, &resp) && parse_cereg(resp, stat)) {
            IdfModemStatus reg_patch;
            reg_patch.ceregStat = stat;
            reg_patch.phase = (stat == 1 || stat == 5) ? "sampling" : "registering";
            reg_patch.modemReady = (stat == 1 || stat == 5);
            update_status(reg_patch);
            if (reg_patch.modemReady) break;
        }
        vTaskDelay(pdMS_TO_TICKS(1500));
    }
    bool registered = (stat == 1 || stat == 5);
    bool post_register_done = false;
    if (sim_ready && !registered) {
        set_phase("registering");
    } else if (registered) {
        bootstrap_clock_once();
        retry_sms_storage_if_pending();
        apply_startup_data_mode(stat);
        IdfSimSettingsView cfg = idf_config_get_sim_settings_view();
        apply_operator_if_configured(cfg, stat);
        enforce_roaming_data_policy(cfg, stat);
        // Sample overview data after registration. Web and WiFi are already available.
        sample_signal_once();
        sample_signal_detail_once();
        sample_identity_once(false, true);
        post_register_done = startup_sampling_done();
        set_phase(post_register_done ? "ready" : "sampling");
    }

    TickType_t last_signal = 0;
    TickType_t last_identity = xTaskGetTickCount();
    uint8_t identity_retry_level = 0;
    TickType_t last_sim_unlock_check = xTaskGetTickCount();
    uint8_t sim_unlock_retry_level = 0;
    TickType_t last_detail = 0;
    TickType_t last_health = 0;
    int health_fail_count = 0;
    int dereg_count = 0;
    bool rlos_only_seen = false;
    TickType_t last_sim_check = 0;
    int64_t sim_check_not_before_us = 0;  // Allow SIM and CPIN startup time after modem reset.
    int sim_present = -1;  // -1=unknown baseline, 0=absent, 1=present
    int sim_confirmed_present = -1;
    bool sms_reconfigure_pending = false;  // Reassert SMS after SIM or network recovery.
    while (true) {
        // Process direct SMS acknowledgments before caller commands. Run at most
        // one caller command per pass so the owner returns to URC and health work.
        while (owner_process_one_command(true)) {}
        if (owner_process_one_command(false)) continue;
        bool reset_handled = handle_reset_request_if_any();
        run_pending_reinit_if_recovered();
        const bool sim_recovered = !sim_ready && idf_modem_get_status().simState == "ready";
        if (sim_recovered) sim_ready = true;
        TickType_t now = xTaskGetTickCount();
        if (reset_handled || sim_recovered) {
            sim_ready = idf_modem_get_status().simState == "ready";
            // Clear local registration state after an in-service reset so recovery
            // uses the fast probe interval instead of the 60-second registered interval.
            registered = false;
            post_register_done = false;
            health_fail_count = 0;
            dereg_count = 0;
            rlos_only_seen = false;
            last_health = 0;
            last_identity = now;
            identity_retry_level = 0;
            last_sim_unlock_check = now;
            sim_unlock_retry_level = 0;
            last_sim_check = now;  // Allow one full SIM initialization interval.
            sim_check_not_before_us = esp_timer_get_time() + 30LL * 1000LL * 1000LL;
            sim_present = -1;
            sms_reconfigure_pending = true;
        }
        int unlock_request = s_sim_unlock_request.exchange(0, std::memory_order_relaxed);
        bool sim_unlock_checked = false;
        if (unlock_request != 0) {
            if (!at_channel_idle_now()) {
                s_sim_unlock_request.store(unlock_request, std::memory_order_relaxed);
            } else {
                if (unlock_request == 1) s_last_pin_attempt_key.clear();
                sim_ready = try_unlock_sim(unlock_request == 2);
                sim_unlock_checked = true;
                last_sim_unlock_check = xTaskGetTickCount();
                sim_unlock_retry_level = 0;
            }
        }
        const bool sim_unlock_retry_due = !sim_ready &&
            now - last_sim_unlock_check >= pdMS_TO_TICKS(modem_retry_delay_ms(sim_unlock_retry_level));
        if (!sim_unlock_checked && sim_unlock_retry_due && at_channel_idle_now()) {
            sim_ready = try_unlock_sim(false);
            sim_unlock_checked = true;
            last_sim_unlock_check = xTaskGetTickCount();
            if (sim_ready) {
                sim_unlock_retry_level = 0;
            } else if (sim_unlock_retry_level + 1U < MODEM_RETRY_DELAY_COUNT) {
                ++sim_unlock_retry_level;
            }
        }
        if (sim_unlock_checked && sim_ready) {
            invalidate_registration_state("registering", true);
            if (at_channel_idle_now()) configure_sms_and_registration();
            set_phase("registering");
            registered = false;
            post_register_done = false;
            last_identity = xTaskGetTickCount();
            identity_retry_level = 0;
            sms_reconfigure_pending = true;
            last_health = 0;
        }
        if (!sim_ready) s_status_sample_requests.store(0, std::memory_order_relaxed);
        if (process_data_mode_retry()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }
        bootstrap_clock_once();
        // A manual refresh bypasses the interval. Retain the request while AT is busy.
        bool force_sample = s_status_sample_requests.load(std::memory_order_relaxed) > 0;
        bool web_active = force_sample ||
                          (esp_timer_get_time() -
                           s_last_web_poll_us.load(std::memory_order_relaxed)) < WEB_POLL_ACTIVE_WINDOW_US;
        bool startup_sampling = registered && !post_register_done;
        const bool identity_retry_due = !startup_info_complete() &&
            idf_modem_identity_sampling_allowed(idf_modem_get_status().ceregStat) &&
            now - last_identity >= pdMS_TO_TICKS(modem_retry_delay_ms(identity_retry_level));
        if (sim_ready && (web_active || startup_sampling || identity_retry_due) && at_channel_idle_now()) {
            if (force_sample) {
                s_status_sample_requests.store(0, std::memory_order_relaxed);
            }
            if (startup_sampling || force_sample || last_signal == 0 ||
                now - last_signal > pdMS_TO_TICKS(SIGNAL_INTERVAL_WEB_MS)) {
                sample_signal_once();
                last_signal = now;
            }
            if (startup_sampling || force_sample || last_detail == 0 ||
                now - last_detail > pdMS_TO_TICKS(SIGNAL_DETAIL_INTERVAL_WEB_MS)) {
                sample_signal_detail_once();
                last_detail = now;
            }
            if (startup_sampling || force_sample || identity_retry_due) {
                const bool identity_changed = sample_identity_once(false, true);
                last_identity = xTaskGetTickCount();
                if (startup_sampling || force_sample || identity_changed || startup_info_complete()) {
                    identity_retry_level = 0;
                } else if (identity_retry_level + 1U < MODEM_RETRY_DELAY_COUNT) {
                    ++identity_retry_level;
                }
            }
            if (startup_sampling && startup_sampling_done()) {
                set_phase("ready");
                post_register_done = true;
            }
        }
        const int64_t sim_check_now_us = esp_timer_get_time();
        const bool sim_check_due =
            sim_check_now_us >= sim_check_not_before_us &&
            (last_sim_check == 0 || now - last_sim_check >= pdMS_TO_TICKS(SIM_CHECK_INTERVAL_MS)) &&
            at_channel_idle_now();
        // Probe every 60 seconds when healthy and every 5 seconds while unregistered
        // unless the SIM is confirmed absent.
        uint32_t health_interval_ms = 60000UL;
        if (!registered && sim_present != 0) health_interval_ms = 5000UL;
        else if (sms_reconfigure_pending && sim_present != 0) health_interval_ms = 15000UL;
        if (!sim_check_due && sim_ready &&
            (reset_handled || now - last_health > pdMS_TO_TICKS(health_interval_ms)) &&
            at_channel_idle_now()) {
            last_health = now;
            std::string resp;
            int probed_stat = -1;
            if (send_ok("AT+CEREG?", 1200, &resp) && parse_cereg(resp, probed_stat)) {
                stat = probed_stat;
                health_fail_count = 0;
                bool now_ready = (stat == 1 || stat == 5);
                IdfModemStatus reg_patch;
                reg_patch.ceregStat = stat;
                reg_patch.modemReady = now_ready;
                reg_patch.phase = now_ready ? (post_register_done ? "ready" : "sampling") : "registering";
                update_status(reg_patch);
                if (now_ready) {
                    registered = true;
                    dereg_count = 0;
                    bool sms_reconfigured_now = false;
                    if (sms_reconfigure_pending) {
                        // The modem can rebuild its SMS stack after CPIN READY.
                        // Reassert PDU, CNMI, and CPMS after stable registration.
                        idf_log_line("network registration restored. Reasserting SMS setup");
                        const bool sms_ready_now = configure_sms_and_registration();
                        sms_reconfigure_pending = !sms_ready_now;
                        if (sms_ready_now) clear_health_reset_backoff();
                        sms_reconfigured_now = true;
                    }
                    if (!post_register_done) {
                        // Apply required network settings and overview data after late
                        // registration. Always rerun storage selection after network recovery.
                        if (!sms_reconfigured_now) s_sms_storage_pending = !select_sms_storage();
                        IdfSimSettingsView cfg = idf_config_get_sim_settings_view();
                        apply_startup_data_mode(stat);
                        apply_operator_if_configured(cfg, stat);
                        enforce_roaming_data_policy(cfg, stat);
                        sample_signal_once();
                        sample_signal_detail_once();
                        sample_identity_once(false, true);
                        last_identity = xTaskGetTickCount();
                        identity_retry_level = 0;
                        post_register_done = startup_sampling_done();
                        set_phase(post_register_done ? "ready" : "sampling");
                    }
                } else {
                    registered = false;
                    post_register_done = false;
                    sms_reconfigure_pending = true;
                    if (stat == 11) {
                        dereg_count = 0;
                        if (!rlos_only_seen) {
                            idf_log_line("modem reports CEREG RLOS-only stat=11. Continuing read-only registration probes");
                            rlos_only_seen = true;
                        }
                    } else {
                        rlos_only_seen = false;
                        if (!idf_modem_unregistered_reset_allowed(sim_present == 1, stat)) {
                            dereg_count = 0;
                        } else if (++dereg_count >= 60 && request_health_reset_with_backoff()) {
                            dereg_count = 0;
                            idf_log_line("modem remained unregistered. Requesting hard reset");
                        }
                    }
                }
            } else if (!idf_modem_health_reset_required(
                           idf_modem_get_status().atReady, sim_present == 1, sim_ready,
                           false, -1, true, true)) {
                health_fail_count = 0;
            } else if (++health_fail_count >= 3 && request_health_reset_with_backoff()) {
                health_fail_count = 0;
                idf_log_line("modem health probes failed repeatedly. Requesting hard reset");
            }
        }
        // Poll AT+CPIN? for SIM hot swaps. On insertion, reset the modem and clear
        // old identity. On removal, mark unavailable and clear old identity.
        if (sim_check_due) {
            last_sim_check = now;
            int present_now = query_sim_present();
            if (present_now < 0) {
                sim_present = -1;
            } else {
                const IdfModemSimPresenceEvent presence_event =
                    idf_modem_sim_presence_event(sim_confirmed_present, present_now);
                sim_confirmed_present = present_now;
                sim_present = present_now;
                if (presence_event == IdfModemSimPresenceEvent::inserted) {
                    // ML307 firmware can restore SMS defaults after CPIN READY while
                    // rebuilding the stack. Hard reset once to initialize the new SIM.
                    idf_log_line("SIM inserted. Hard-resetting modem to initialize the SMS stack");
                    idf_modem_invalidate_sim_identity();
                    registered = false;
                    post_register_done = false;
                    dereg_count = 0;
                    sms_reconfigure_pending = true;
                    idf_modem_request_reset(true);
                } else if (presence_event == IdfModemSimPresenceEvent::removed) {
                    idf_log_line("SIM removed");
                    invalidate_registration_state("registering", true);
                    registered = false;
                    post_register_done = false;
                    sms_reconfigure_pending = true;
                    sim_ready = false;
                    idf_modem_invalidate_sim_identity();
                    set_sim_status("absent", false, "SIM not detected");
                    set_phase("registering");
                }
            }
        }
        for (int i = 0; i < 10; ++i) {
            // Consume sampling requests only while AT is idle. Avoid a hot loop while
            // keep-alive downloads or eSIM work hold the channel.
            if (s_status_sample_requests.load(std::memory_order_relaxed) > 0 &&
                at_channel_idle_now()) break;
            // Wake on UART data and use a 500 ms timeout as fallback.
            uart_event_t evt;
            if (s_uart_evt_queue) {
                if (xQueueReceive(s_uart_evt_queue, &evt, pdMS_TO_TICKS(500)) == pdTRUE) {
                    do {
                        handle_uart_event_error(evt);
                    } while (xQueueReceive(s_uart_evt_queue, &evt, 0) == pdTRUE);
                }
            } else {
                vTaskDelay(pdMS_TO_TICKS(500));
            }
            while (owner_process_one_command(true)) {}
            if (owner_process_one_command(false)) break;
            // Sleep before retrying when a long task holds the AT lock.
            if (!poll_unsolicited_uart(20)) vTaskDelay(pdMS_TO_TICKS(100));
            // Handle reset or AT recovery without waiting for the five-second poll.
            if (s_reset_request.load(std::memory_order_relaxed) != 0) break;
            if (s_status_sample_requests.load(std::memory_order_relaxed) > 0 &&
                at_channel_idle_now()) break;
        }
    }
}

esp_err_t idf_modem_start(const IdfConfig& config)
{
    if (s_started) return ESP_OK;
    cleanup_start_resources();
    s_sim_unlock_request.store(0, std::memory_order_relaxed);
    s_last_pin_attempt_key.clear();
    // Keep caller order exclusive across eSIM CCHO/CGLA/CCHC commands. Only the owner uses UART.
    s_session_mutex = xSemaphoreCreateRecursiveMutex();
    s_command_mutex = xSemaphoreCreateMutex();
    s_status_mutex = xSemaphoreCreateMutex();
    s_urc_mutex = xSemaphoreCreateMutex();
    s_command_queue = xQueueCreate(OWNER_COMMAND_SLOTS, sizeof(int));
    s_priority_command_queue = xQueueCreate(OWNER_COMMAND_SLOTS, sizeof(int));
    for (auto& slot : s_command_slots) slot.completed = xSemaphoreCreateBinary();
    if (!s_event_sem) s_event_sem = xSemaphoreCreateBinary();
    bool slots_ready = true;
    for (const auto& slot : s_command_slots) slots_ready = slots_ready && slot.completed;
    if (!s_session_mutex || !s_command_mutex || !s_status_mutex || !s_urc_mutex ||
        !s_command_queue || !s_priority_command_queue || !slots_ready || !s_event_sem) {
        cleanup_start_resources();
        return ESP_ERR_NO_MEM;
    }
    if (!config.dataEnabled) set_status_cell_ip("");

    uart_config_t uart_cfg = {};
    uart_cfg.baud_rate = MODEM_BAUD;
    uart_cfg.data_bits = UART_DATA_8_BITS;
    uart_cfg.parity = UART_PARITY_DISABLE;
    uart_cfg.stop_bits = UART_STOP_BITS_1;
    uart_cfg.flow_ctrl = UART_HW_FLOWCTRL_DISABLE;
    uart_cfg.source_clk = UART_SCLK_DEFAULT;

    // Install an event queue so RX data wakes the idle modem task immediately.
    esp_err_t err = uart_driver_install(MODEM_UART, UART_RX_BUF, 0, 16, &s_uart_evt_queue, 0);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART driver install failed: %s", esp_err_to_name(err));
        idf_logf("modem UART driver install failed: %s", esp_err_to_name(err));
        cleanup_start_resources();
        return err;
    }
    err = uart_param_config(MODEM_UART, &uart_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART param config failed: %s", esp_err_to_name(err));
        idf_logf("modem UART parameter setup failed: %s", esp_err_to_name(err));
        uart_driver_delete(MODEM_UART);
        s_uart_evt_queue = nullptr;
        cleanup_start_resources();
        return err;
    }
    err = uart_set_pin(MODEM_UART, MODEM_TXD, MODEM_RXD, UART_PIN_NO_CHANGE, UART_PIN_NO_CHANGE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "UART pin config failed: %s", esp_err_to_name(err));
        idf_logf("modem UART pin setup failed: %s", esp_err_to_name(err));
        uart_driver_delete(MODEM_UART);
        s_uart_evt_queue = nullptr;
        cleanup_start_resources();
        return err;
    }
    s_started = true;

    BaseType_t ok = xTaskCreate(modem_task, "idf_modem", 8192, nullptr, 4, &s_owner_task);
    if (ok != pdPASS) {
        s_started = false;
        uart_driver_delete(MODEM_UART);
        s_uart_evt_queue = nullptr;
        cleanup_start_resources();
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

IdfModemStatus idf_modem_get_status(void)
{
    IdfModemStatus copy;
    if (!s_status_mutex) return copy;
    if (xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        copy = s_status;
        xSemaphoreGive(s_status_mutex);
    }
    return copy;
}

esp_err_t idf_modem_request_reset(bool hard_reset)
{
    if (!s_started || !s_command_mutex) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(s_command_mutex, portMAX_DELAY) != pdTRUE) return ESP_ERR_TIMEOUT;
    s_runtime_queue_ready.store(false, std::memory_order_release);
    s_reset_request.store(hard_reset ? 2 : 1, std::memory_order_release);
    xSemaphoreGive(s_command_mutex);
    invalidate_registration_state("powering", false);
    set_phase("powering");
    wake_owner_task();
    return ESP_OK;
}

esp_err_t idf_modem_request_sim_unlock(bool allow_puk)
{
    if (!s_started) return ESP_ERR_INVALID_STATE;
    s_sim_unlock_request.store(allow_puk ? 2 : 1, std::memory_order_relaxed);
    return ESP_OK;
}

bool idf_modem_at_idle(void)
{
    return at_channel_idle_now();
}

void idf_modem_request_status_sample(void)
{
    s_last_web_poll_us.store(esp_timer_get_time(), std::memory_order_relaxed);
    s_status_sample_requests.fetch_add(1, std::memory_order_relaxed);
}

void idf_modem_begin_esim_operation(void)
{
    s_esim_operation_depth.fetch_add(1, std::memory_order_relaxed);
    if (s_session_mutex) xSemaphoreTakeRecursive(s_session_mutex, portMAX_DELAY);
}

void idf_modem_end_esim_operation(void)
{
    if (s_session_mutex) xSemaphoreGiveRecursive(s_session_mutex);
    s_esim_operation_depth.fetch_sub(1, std::memory_order_relaxed);
}

bool idf_modem_esim_operation_active(void)
{
    return s_esim_operation_depth.load(std::memory_order_relaxed) != 0;
}

static std::atomic<void (*)(void)> s_sim_identity_hook{nullptr};

void idf_modem_set_sim_identity_hook(void (*hook)(void))
{
    s_sim_identity_hook.store(hook, std::memory_order_relaxed);
}

void idf_modem_invalidate_sim_identity(void)
{
    // Clear SIM-dependent identity after an eSIM profile change so sampling does
    // not reuse the old phone number, ICCID, or operator.
    if (s_status_mutex && xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
        s_status.iccid.clear();
        s_status.imsi.clear();
        s_status.phone.clear();
        s_status.operatorName.clear();
        s_status.apnSim.clear();
        s_status.identityFresh = false;
        xSemaphoreGive(s_status_mutex);
    }
    // Reset sampling attempts for network fields. Keep static model and IMEI values.
    reset_identity_sampling_state();
    idf_modem_request_status_sample();
    // Notify idf_esim so hot swaps also invalidate the EID cache.
    void (*hook)(void) = s_sim_identity_hook.load(std::memory_order_relaxed);
    if (hook) hook();
}

void idf_modem_power_off_for_restart(void)
{
    // Write the output register before direction so EN becomes low immediately.
    gpio_set_level(MODEM_EN, 0);
    modem_en_gpio_init();
    gpio_set_level(MODEM_EN, 0);
    // Match modem_power_cycle off-time so the ESP restart gets a clean modem cold start.
    vTaskDelay(pdMS_TO_TICKS(MODEM_POWERDOWN_MS));
}

bool idf_modem_wait_event(uint32_t timeout_ms)
{
    if (!s_event_sem) {
        vTaskDelay(pdMS_TO_TICKS(timeout_ms));
        return false;
    }
    return xSemaphoreTake(s_event_sem, pdMS_TO_TICKS(timeout_ms)) == pdTRUE;
}

void idf_modem_signal_event(void)
{
    if (s_event_sem) xSemaphoreGive(s_event_sem);
}

bool idf_modem_take_urc(std::string& out)
{
    out.clear();
    if (!s_urc_mutex) return false;
    if (xSemaphoreTake(s_urc_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    if (!s_urc_buffer.empty()) {
        out.swap(s_urc_buffer);
    }
    xSemaphoreGive(s_urc_mutex);
    return !out.empty();
}
