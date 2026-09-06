#include "idf_push_cellular.h"
#include "idf_push_core.h"
#include "idf_push_transport.h"
#include "idf_wifi.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <cassert>
#include <cstring>
#include <ctime>
#include <string>
#include <strings.h>
#include <vector>

using SemaphoreHandle_t = void*;
constexpr int pdTRUE = 1, portMAX_DELAY = -1;
#define pdMS_TO_TICKS(ms) (ms)
static bool locked = false;
static SemaphoreHandle_t xSemaphoreCreateMutex() { return reinterpret_cast<void*>(1); }
static SemaphoreHandle_t xSemaphoreCreateBinary() { return reinterpret_cast<void*>(2); }
static int xSemaphoreTake(SemaphoreHandle_t, int) { assert(!locked); locked = true; return pdTRUE; }
static void xSemaphoreGive(SemaphoreHandle_t) { assert(locked); locked = false; }
static int64_t now_us = 1000000;
static time_t epoch = 0;
static int64_t esp_timer_get_time() { return now_us; }
static time_t fixture_time(time_t*) { return epoch; }
static IdfPushNotifyView notify_config;
static IdfEmailSettingsView email_config;
static IdfWifiStatus wifi_status;
IdfPushNotifyView idf_config_get_push_notify_view() { return notify_config; }
IdfEmailSettingsView idf_config_get_email_settings_view() { return email_config; }
IdfWifiStatus idf_wifi_get_status() { return wifi_status; }
bool idf_config_get_push_channel(uint8_t channel, IdfPushChannel& out)
{
    if (channel >= IDF_MAX_PUSH_CHANNELS) return false;
    out = notify_config.pushChannels[channel];
    return true;
}
static void idf_log_line(const char*) {}
template<class... Args> static void idf_logf(const char*, Args...) {}
static std::vector<uint32_t> forwarded, not_forwarded;
static void idf_inbox_mark_forwarded(uint32_t id) { forwarded.push_back(id); }
static void idf_inbox_set_forwarded(uint32_t id, bool value)
{
    assert(!value);
    not_forwarded.push_back(id);
}
static bool low_heap_defer() { return false; }
static std::string format_local_time(int) { return {}; }
static unsigned push_sends = 0, smtp_sends = 0;
static std::vector<uint8_t> sent_types;
static bool send_success = false;
static bool send_to_channel(const IdfPushChannel& channel, const char*, const char*, const char*,
                            const IdfPushNotifyView&, const IdfWifiStatus&, IdfPushNetworkDecision,
                            bool = false, std::string* = nullptr, bool* permanent = nullptr,
                            std::string* = nullptr, IdfModemHttpsDiagnosticReason* = nullptr,
                            IdfModemHttpsDiagnosticReason* = nullptr, bool* = nullptr,
                            IdfPushTransportResult* transport = nullptr)
{
    assert(!locked);
    ++push_sends;
    sent_types.push_back(channel.type);
    if (permanent) *permanent = false;
    if (transport) transport->dispatchAttempted = true;
    return send_success;
}
static bool send_smtp_email(const IdfEmailSettingsView&, const std::string&, const std::string&)
{
    assert(!locked);
    ++smtp_sends;
    return send_success;
}

#define time fixture_time
#include "time_runtime.inc"
#undef time

static IdfPushChannel channel(uint8_t type, const std::string& url)
{
    IdfPushChannel result;
    result.enabled = true;
    result.type = type;
    result.url = url;
    result.key1 = "synthetic-key";
    result.key2 = "synthetic-recipient";
    if (type == PUSH_TYPE_CUSTOM) result.customBody = "{}";
    return result;
}
static void reset()
{
    assert(!locked);
    now_us = 1000000; epoch = 0;
    notify_config = {}; email_config = {}; wifi_status = {};
    notify_config.networkMode = NETWORK_MODE_WIFI_ONLY;
    wifi_status.staConnected = true;
    s_push_jobs = {}; s_email_jobs = {}; s_test_jobs = {}; s_forward_completions = {};
    s_next_completion_id = 0;
    std::fill(std::begin(s_channel_fails), std::end(s_channel_fails), 0);
    std::fill(std::begin(s_channel_cool_until_us), std::end(s_channel_cool_until_us), 0);
    push_sends = 0; smtp_sends = 0; send_success = false;
    sent_types.clear(); forwarded.clear(); not_forwarded.clear();
    ensure_init();
}
static void enqueue(const IdfPushChannel& target, uint8_t attempts = 0)
{
    notify_config.pushChannels[0] = target;
    const uint32_t completion = register_forward_completion_locked(42, 1);
    assert(completion != 0);
    assert(enqueue_push_job_locked(0, "sender", "message", "", attempts, 0, false, 42, completion));
}

static void test_https_wait_preserves_attempts_and_completion()
{
    reset();
    enqueue(channel(PUSH_TYPE_POST_JSON, "https://example.invalid/push"), 5);
    for (unsigned i = 0; i < 24; ++i) {
        assert(!process_push_one());
        assert(push_sends == 0 && s_push_jobs[0].used && s_push_jobs[0].attempts == 5);
        assert(s_forward_completions[0].used && forwarded.empty() && not_forwarded.empty());
        now_us += 5000000;
    }
    epoch = 1700000000;
    assert(process_push_one());
    assert(push_sends == 1 && !s_push_jobs[0].used && !s_forward_completions[0].used);
    assert(not_forwarded == std::vector<uint32_t>{42});
}

static void test_effective_https_defaults_and_http_overrides()
{
    for (uint8_t type : {PUSH_TYPE_POST_JSON, PUSH_TYPE_BARK, PUSH_TYPE_GET, PUSH_TYPE_PUSHPLUS,
                         PUSH_TYPE_SERVERCHAN, PUSH_TYPE_DINGTALK, PUSH_TYPE_CUSTOM,
                         PUSH_TYPE_FEISHU, PUSH_TYPE_TELEGRAM, PUSH_TYPE_GOTIFY,
                         PUSH_TYPE_DISCORD, PUSH_TYPE_NTFY}) {
        reset();
        auto target = channel(type, "https://example.invalid/push");
        target.cellularEnabled = false;
        target.cellularUrl = "http://cellular.invalid/override";
        enqueue(target);
        assert(!process_push_one() && push_sends == 0);
        now_us += 5000000; epoch = 1700000000; send_success = true;
        assert(process_push_one() && push_sends == 1);
        assert(forwarded == std::vector<uint32_t>{42});

        reset();
        target.url = "http://example.invalid/push";
        target.key1.clear();
        if (type != PUSH_TYPE_DINGTALK && type != PUSH_TYPE_FEISHU) target.key1 = "synthetic-key";
        enqueue(target);
        assert(process_push_one() && push_sends == 1);
    }
    for (uint8_t type : {PUSH_TYPE_PUSHPLUS, PUSH_TYPE_SERVERCHAN, PUSH_TYPE_TELEGRAM}) {
        reset();
        enqueue(channel(type, ""));
        assert(!process_push_one() && push_sends == 0);
    }
    for (uint8_t type : {PUSH_TYPE_DINGTALK, PUSH_TYPE_FEISHU}) {
        reset();
        enqueue(channel(type, "http://example.invalid/signed"));
        assert(!process_push_one() && push_sends == 0);
    }
    reset();
    enqueue(channel(PUSH_TYPE_POST_JSON, "https://example.invalid/push"));
    notify_config.pushChannels[1] = channel(PUSH_TYPE_GET, "http://example.invalid/get");
    assert(enqueue_push_job_locked(1, "sender", "message", "", 0, 0));
    assert(process_push_one());
    assert(sent_types == std::vector<uint8_t>{PUSH_TYPE_GET});
    assert(s_push_jobs[0].used && s_push_jobs[0].attempts == 0);
}

static void test_cellular_target_and_invalid_configuration()
{
    reset();
    notify_config.networkMode = NETWORK_MODE_4G_ONLY;
    auto target = channel(PUSH_TYPE_POST_JSON, "http://wifi.invalid/push");
    target.cellularUrl = "https://cellular.invalid/push";
    enqueue(target);
    assert(!process_push_one() && push_sends == 0);
    now_us += 5000000; epoch = 1700000000; send_success = true;
    assert(process_push_one() && push_sends == 1);

    for (const std::string url : {"http://cellular.invalid/push", "https://user@cellular.invalid/push"}) {
        reset();
        notify_config.networkMode = NETWORK_MODE_4G_ONLY;
        target.cellularUrl = url;
        enqueue(target);
        assert(process_push_one() && push_sends == 1);
    }
    reset();
    notify_config.networkMode = NETWORK_MODE_4G_ONLY;
    enqueue(channel(PUSH_TYPE_GET, "https://example.invalid/get"));
    assert(process_push_one() && push_sends == 0 && !s_push_jobs[0].used);
    assert(not_forwarded == std::vector<uint32_t>{42});
}

static void test_smtp_wait_and_disabled_cleanup()
{
    for (int port : {465, 587}) {
        reset();
        email_config.smtpPort = port;
        const uint32_t completion = register_forward_completion_locked(42, 1);
        assert(enqueue_email_job_locked("subject", "body", 5, 0, 42, completion));
        assert(!process_email_one());
        assert(smtp_sends == 0 && s_email_jobs[0].used && s_email_jobs[0].attempts == 5);
        assert(s_forward_completions[0].used);
        epoch = 1700000000;
        assert(process_email_one() && smtp_sends == 1);
        assert(!s_email_jobs[0].used && not_forwarded == std::vector<uint32_t>{42});
    }
    reset();
    const uint32_t completion = register_forward_completion_locked(42, 1);
    assert(enqueue_email_job_locked("subject", "body", 5, 0, 42, completion));
    email_config.emailEnabled = false;
    assert(!process_email_one());
    assert(smtp_sends == 0 && !s_email_jobs[0].used && !s_forward_completions[0].used);
}

static void test_pending_test_expires_while_waiting_for_time()
{
    reset();
    notify_config.pushChannels[0] = channel(PUSH_TYPE_POST_JSON, "https://example.invalid/push");
    s_test_jobs[0].pending = true;
    s_test_jobs[0].deadlineUs = now_us + 60000000;
    const int64_t deadline = s_test_jobs[0].deadlineUs;
    for (unsigned i = 0; i < 12; ++i) {
        assert(!process_test_one());
        assert(push_sends == 0 && s_test_jobs[0].pending && !s_test_jobs[0].running);
        assert(s_test_jobs[0].deadlineUs == deadline);
        now_us += 5000000;
    }
    assert(process_test_one());
    assert(push_sends == 0 && !s_test_jobs[0].pending && s_test_jobs[0].done);
    assert(!s_test_jobs[0].success && !s_test_jobs[0].dispatchAttempted);
    epoch = 1700000000;
    assert(!process_test_one() && push_sends == 0);

    reset();
    notify_config.pushChannels[0] = channel(PUSH_TYPE_POST_JSON, "https://example.invalid/push");
    s_test_jobs[0].pending = true;
    s_test_jobs[0].deadlineUs = now_us + 60000000;
    assert(!process_test_one());
    now_us += 5000000; epoch = 1700000000; send_success = true;
    assert(process_test_one() && push_sends == 1);
    assert(s_test_jobs[0].done && s_test_jobs[0].success && !s_test_jobs[0].pending);

    reset();
    enqueue(channel(PUSH_TYPE_POST_JSON, "https://example.invalid/push"));
    notify_config.pushEnabled = false;
    assert(process_push_one());
    assert(push_sends == 0 && !s_push_jobs[0].used && !s_forward_completions[0].used);
}

int main()
{
    test_https_wait_preserves_attempts_and_completion();
    test_effective_https_defaults_and_http_overrides();
    test_cellular_target_and_invalid_configuration();
    test_smtp_wait_and_disabled_cleanup();
    test_pending_test_expires_while_waiting_for_time();
}
