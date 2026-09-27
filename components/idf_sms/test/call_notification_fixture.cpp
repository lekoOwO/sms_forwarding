#include "idf_modem_query_filter.h"

#include <algorithm>
#include <cassert>
#include <cctype>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <string>
#include <vector>

using esp_err_t = int;
constexpr int ESP_OK = 0, ESP_FAIL = -1;
constexpr size_t MAX_PDU_HEX_CHARS = 600;
struct CallFixtureSmsProcessView { std::string numberBlackList; };
static int64_t now_us = 0;
static bool enabled = true, esim_active = false, forward_accepts = true;
static int query_result = ESP_OK;
static std::string blacklist, reply, queued_urcs, query_urcs;
static std::vector<std::string> commands, senders, messages, logs, events;
static int urc_takes = 0;
static int64_t esp_timer_get_time() { return now_us; }
static bool idf_config_call_notify_enabled() { return enabled; }
static bool idf_modem_esim_operation_active() { return esim_active; }
static CallFixtureSmsProcessView idf_config_get_sms_process_view() { return {blacklist}; }
static int idf_config_get_tz_offset() { return 0; }
static std::string idf_util_format_epoch_local(uint32_t, int) { return "synthetic time"; }
static std::string idf_util_trim_copy(const std::string& text)
{
    const auto first = text.find_first_not_of(" \r\n\t");
    return first == std::string::npos ? std::string() :
        text.substr(first, text.find_last_not_of(" \r\n\t") - first + 1);
}
static void idf_log_line(const char* line) { logs.emplace_back(line); }
static void idf_logf(const char* format, ...)
{
    char text[256];
    va_list args;
    va_start(args, format);
    vsnprintf(text, sizeof(text), format, args);
    va_end(args);
    logs.emplace_back(text);
}
static bool idf_push_enqueue_forward(const char* sender, const char* body, const char*, uint32_t)
{
    senders.emplace_back(sender);
    messages.emplace_back(body);
    events.emplace_back("forward");
    return forward_accepts;
}
static esp_err_t idf_modem_send_at(const std::string& command, uint32_t timeout, std::string& response)
{
    assert(timeout == 1500);
    commands.push_back(command);
    events.push_back(command);
    if (command == "AT+CNMA=0") { response = "OK\r\n"; return ESP_OK; }
    assert(command == "AT+CLCC");
    assert(!esim_active);
    response = reply;
    queued_urcs += query_urcs;
    return query_result;
}
static bool idf_modem_take_urc(std::string& text)
{
    ++urc_takes;
    text.clear();
    text.swap(queued_urcs);
    return !text.empty();
}
struct CallFixturePduDecodeOutcome {
    bool decoded, safe_to_delete, admission_blocked;
};
static CallFixturePduDecodeOutcome decode_pdu_line(const std::string& line, bool)
{
    return {line == "00112233445566778899AABBCCDDEEFF", true, false};
}
static void enqueue_index(int) {}
#define IdfSmsProcessView CallFixtureSmsProcessView
#define PduDecodeOutcome CallFixturePduDecodeOutcome
#include "call_runtime.inc"
#undef PduDecodeOutcome
#undef IdfSmsProcessView

static void test_repeated_ring_keeps_first_deadline()
{
    reply = "AT+CLCC\r\n+CLCC: 1,1,4,0,0,\"+15550101001\",145\r\nOK\r\n";
    process_urc_text("RING\r\n");
    for (int second = 1; second <= 2; ++second) {
        now_us = second * 1000000LL;
        process_urc_text("RING\r\n");
        flush_pending_call_notify();
        assert(commands.empty() && senders.empty());
    }
    now_us = 3000000;
    flush_pending_call_notify();
    assert(commands == std::vector<std::string>{"AT+CLCC"});
    assert(senders == std::vector<std::string>{"+15550101001"});
    assert(messages == std::vector<std::string>{"Incoming call: +15550101001"});
    process_urc_text("RING\r\n+CLIP: \"+15550101001\",145\r\n");
    now_us += 4000000;
    flush_pending_call_notify();
    assert(commands.size() == 1 && senders.size() == 1);
    for (const auto& log : logs) assert(log.find("15550101001") == std::string::npos);
}

static void next_call()
{
    now_us += 31000001;
    enabled = true;
    esim_active = false;
    forward_accepts = true;
    query_result = ESP_OK;
    blacklist.clear(); reply.clear(); queued_urcs.clear(); query_urcs.clear();
    commands.clear(); senders.clear(); messages.clear(); logs.clear(); events.clear();
    urc_takes = 0;
    expire_wait_pdu_window();
    process_urc_text("RING\r\n");
}

static void recover()
{
    now_us += 3000000;
    flush_pending_call_notify();
}

static void test_clip_fast_path_and_invalid_clip_recovery()
{
    next_call();
    process_urc_text("+CLIP: \"+15550101002\",145,\"\",0,\"Caller\",0\r\n");
    recover();
    assert(commands.empty() && senders == std::vector<std::string>{"+15550101002"});
    for (const auto& invalid : {
            "+CLIP: \"\",129", "+CLIP: \"letters\",129",
            "+CLIP: junk,129,\"+15550101002\"", "+CLIP: \"+15550101002\"",
            "+CLIP: \"+15550101002\",oops"}) {
        next_call();
        process_urc_text(std::string(invalid) + "\r\n");
        assert(senders.empty());
        reply = "+CLCC: 1,1,5,0,0,\"+15550101003\",145,\"Waiting\"\r\nOK\r\n";
        recover();
        assert(commands.size() == 1 && senders == std::vector<std::string>{"+15550101003"});
    }
}

static void test_clcc_contract_and_ambiguity()
{
    const std::vector<std::pair<std::string, std::string>> cases = {
        {"AT+CSQ\r\n+CLCC: 1,1,4,0,0,\"5550101004\",129\r\nOK\r\n", "Unknown number"},
        {"AT+CLCC\r\nAT+CLCC\r\n+CLCC: 1,1,4,0,0,\"5550101004\",129\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"5550101004\",129\r\nAT+CLCC\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"5550101004\",129\r\nOK\r\nunexpected\r\n", "Unknown number"},
        {"unexpected\r\n+CLCC: 1,1,4,0,0,\"5550101004\",129\r\nOK\r\n", "Unknown number"},
        {"00112233445566778899AABBCCDDEEFF00\r\n"
         "+CLCC: 1,1,4,0,0,\"5550101004\",129\r\nOK\r\n", "Unknown number"},
        {"AT+CLCC\r\n+CMT: ,16\r\n00112233445566778899AABBCCDDEEFF00\r\n"
         "+CLCC: 1,1,4,0,0,\"5550101004\",129\r\nOK\r\n+CEREG: 1\r\n"
         "+CMT: ,16\r\n00112233445566778899AABBCCDDEEFF00\r\n", "5550101004"},
        {"+CLCC: 1,0,2,0,0,\"+15550101999\",145\r\n"
         "+CLCC: 2,1,4,0,0,\"5550101004\",129\r\nOK\r\n", "5550101004"},
        {"+CLCC: 1,1,4,0,0\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"\",129,\"5550101004\"\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,0,0,0,\"5550101004\",129\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,0,4,0,0,\"5550101004\",129\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,x,0,\"5550101004\",129\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"5550101004\"\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"5550101004\",oops\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"5550101004\",129,junk\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"+15550101004\",145\r\n"
         "+CLCC: 2,1,5,0,0,\"+15550101005\",145\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"+15550101004\",145\r\n"
         "+CLCC: 2,1,5,0,0\r\nOK\r\n", "Unknown number"},
        {"OK\r\n+CLCC: 1,1,4,0,0,\"+15550101004\",145\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"+15550101004\",145\r\nERROR\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"+15550101004\",145\r\n", "Unknown number"},
        {"AT+CLCC\r\nRING\r\n+CEREG: 1\r\n"
         "+CLCC: 1,1,4,0,0,\"123\",129\r\nOK\r\n", "123"},
        {"+CLCC: 1,1,4,0,0,\"12345678901234567890\",129\r\nOK\r\n", "12345678901234567890"},
        {"+CLCC: 1,1,4,0,0,\"123456789012345678901\",129\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"12\",129\r\nOK\r\n", "Unknown number"},
        {"+CLCC: 1,1,4,0,0,\"12+345\",129\r\nOK\r\n", "Unknown number"},
    };
    for (const auto& test : cases) {
        next_call();
        reply = test.first;
        recover();
        assert(commands == std::vector<std::string>{"AT+CLCC"});
        assert(senders == std::vector<std::string>{test.second});
    }
}

static void test_busy_deferral_expiry_and_sms_priority()
{
    next_call();
    esim_active = true;
    recover();
    assert(commands.empty() && senders.empty());
    esim_active = false;
    process_urc_text("+CMT: ,16\r\n");
    flush_pending_call_notify();
    assert(commands.empty() && senders.empty());
    process_urc_text("00112233445566778899AABBCCDDEEFF\r\n");
    reply = "OK\r\n";
    flush_pending_call_notify();
    assert((commands == std::vector<std::string>{"AT+CNMA=0", "AT+CLCC"}));
    assert(senders == std::vector<std::string>{"Unknown number"});

    next_call();
    esim_active = true;
    now_us += 30000001;
    flush_pending_call_notify();
    assert(commands.empty() && senders == std::vector<std::string>{"Unknown number"});
    esim_active = false;
    flush_pending_call_notify();
    assert(commands.empty() && senders.size() == 1);

    next_call();
    reply = "OK\r\n";
    query_urcs = "+CMT: ,16\r\n00112233445566778899AABBCCDDEEFF\r\n"
                 "+CLIP: \"+15550101006\",145\r\n";
    recover();
    assert((events == std::vector<std::string>{"AT+CLCC", "AT+CNMA=0", "forward"}));
    assert(senders == std::vector<std::string>{"+15550101006"});
    assert(urc_takes == 1);
    flush_pending_call_notify();
    assert(senders.size() == 1 && commands.size() == 2 && urc_takes == 1);
}

static void test_failure_disabled_blocklist_and_queue_full()
{
    next_call();
    enabled = false;
    recover();
    assert(commands.empty() && senders.empty());
    next_call();
    query_result = ESP_FAIL;
    reply = "+CLCC: 1,1,4,0,0,\"+15550101007\",145\r\nOK\r\n";
    recover();
    flush_pending_call_notify();
    assert(commands.size() == 1 && senders == std::vector<std::string>{"Unknown number"});
    next_call();
    blacklist = "+15550101007";
    reply = "+CLCC: 1,1,4,0,0,\"+15550101007\",145\r\nOK\r\n";
    recover();
    assert(commands.size() == 1 && senders.empty());
    for (const auto& log : logs) assert(log.find("15550101007") == std::string::npos);
    next_call();
    forward_accepts = false;
    reply = "OK\r\n";
    recover();
    process_urc_text("RING\r\n+CLIP: \"+15550101007\",145\r\n");
    flush_pending_call_notify();
    assert(commands.size() == 1 && senders.size() == 1);
}

int main()
{
    test_repeated_ring_keeps_first_deadline();
    test_clip_fast_path_and_invalid_clip_recovery();
    test_clcc_contract_and_ambiguity();
    test_busy_deferral_expiry_and_sms_priority();
    test_failure_disabled_blocklist_and_queue_full();
}
