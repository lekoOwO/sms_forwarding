#include "idf_push.h"
#include "idf_push_core.h"
#include "idf_push_cellular.h"
#include "idf_push_transport.h"

#include <errno.h>
#include <fcntl.h>
#include <ctype.h>
#include <inttypes.h>
#include <regex.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <array>
#include <string>

#include "esp_crt_bundle.h"
#include "esp_err.h"
#include "esp_heap_caps.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "esp_tls.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "idf_config.h"
#include "idf_config_ca_store.h"
#include "idf_inbox.h"
#include "idf_log.h"
#include "idf_modem.h"
#include "idf_util.h"
#include "idf_wifi.h"
#include "esp_idf_version.h"
#include "mbedtls/base64.h"
#include "mbedtls/error.h"
#include "mbedtls/md.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/ssl.h"
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#endif
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static constexpr size_t PUSH_QUEUE_MAX = 16;
static constexpr size_t FWD_QUEUE_MAX = 10;
static constexpr size_t EMAIL_QUEUE_MAX = 5;
// Retry with exponential backoff at 20, 40, 80, 160, and 320 seconds. Six attempts cover about 10 minutes.
// This covers router restarts and brief network loss. A delayed SMS forward is better than a lost one.
static constexpr uint8_t PUSH_RETRY_MAX = 6;
static constexpr uint32_t PUSH_RETRY_BASE_SEC = 20;
static constexpr uint32_t PUSH_RETRY_MAX_SEC = 600;
static constexpr int HTTP_TIMEOUT_MS = 5000;
static constexpr int SMTP_TIMEOUT_MS = 15000;
// Hard limit for one SMTP session, shared by all send and receive steps.
// Without it, a server that transfers a few bytes at a time can block the only push worker indefinitely.
// The forwarding queue then fills, and a persistent s_busy state can suppress low-memory recovery.
static constexpr int64_t SMTP_SESSION_MAX_US = 120LL * 1000LL * 1000LL;
static int64_t s_smtp_session_deadline = 0;  // Accessed only by the push worker
static constexpr uint32_t PUSH_WORKER_STACK = 10240;
// Defer TLS if the largest free block is smaller than this value. An mbedTLS handshake needs about 40 KB at peak.
static constexpr size_t TLS_MIN_FREE_HEAP = 50000;
// Channel cooldown is 30 seconds per consecutive failure, with a 300-second limit. Success clears it.
// This prevents a dead endpoint from consuming HTTP timeouts and blocking the only send worker.
static constexpr uint32_t CHANNEL_COOL_STEP_SEC = 30;
static constexpr uint32_t CHANNEL_COOL_MAX_SEC = 300;
static constexpr int64_t PUSH_TEST_PENDING_MAX_US = 60LL * 1000LL * 1000LL;

struct PushJob {
    bool used = false;
    uint8_t channel = 0;
    uint8_t attempts = 0;
    bool notify = false;  // true: custom alert with the task name as title; false: forwarded SMS
    int64_t nextUs = 0;
    std::string sender;
    std::string text;
    std::string timestamp;
    uint32_t inboxId = 0;  // Related inbox item; mark it not forwarded after permanent failure
    uint32_t completionId = 0;
};

struct ForwardJob {
    bool used = false;
    bool pushQueued = false;
    uint8_t attempts = 0;
    int64_t nextUs = 0;
    std::string sender;
    std::string text;
    std::string timestamp;
    uint32_t inboxId = 0;
};

struct EmailJob {
    bool used = false;
    uint8_t attempts = 0;
    int64_t nextUs = 0;
    std::string subject;
    std::string body;
    uint32_t inboxId = 0;  // As in PushJob, clear the inbox forwarded flag after permanent failure
    uint32_t completionId = 0;
};

struct ForwardCompletion {
    bool used = false;
    uint32_t id = 0;
    uint32_t inboxId = 0;
    uint8_t remaining = 0;
};

struct TestJob {
    bool pending = false;
    bool running = false;
    bool done = false;
    bool success = false;
    int64_t nextUs = 0;
    int64_t deadlineUs = 0;
    std::string message;
};

struct ForwardDecision {
    bool matched = false;
    bool drop = false;
    uint32_t chMask = 0;
    bool email = false;
};

static SemaphoreHandle_t s_mutex = nullptr;
// Wake the worker when a new job enters the queue instead of waiting for the 100 ms idle poll.
static SemaphoreHandle_t s_wake_sem = nullptr;
static std::array<PushJob, PUSH_QUEUE_MAX> s_push_jobs;
static std::array<ForwardJob, FWD_QUEUE_MAX> s_forward_jobs;
static std::array<EmailJob, EMAIL_QUEUE_MAX> s_email_jobs;
static std::array<TestJob, IDF_MAX_PUSH_CHANNELS> s_test_jobs;
static std::array<ForwardCompletion, PUSH_QUEUE_MAX + EMAIL_QUEUE_MAX> s_forward_completions;
static bool s_started = false;
static uint32_t s_next_completion_id = 0;
static std::atomic<bool> s_busy{false};
static bool s_heartbeat_clock_started = false;
static int64_t s_last_heartbeat_us = 0;
static bool s_startup_email_pending = false;
static bool s_startup_email_done = false;
// Consecutive-failure cooldown state. Only the push worker accesses it, so it needs no lock.
static uint8_t s_channel_fails[IDF_MAX_PUSH_CHANNELS] = {};
static int64_t s_channel_cool_until_us[IDF_MAX_PUSH_CHANNELS] = {};

static bool ensure_init()
{
    if (!s_mutex) {
        s_mutex = xSemaphoreCreateMutex();
        if (!s_mutex) return false;
    }
    if (!s_wake_sem) {
        s_wake_sem = xSemaphoreCreateBinary();
        if (!s_wake_sem) return false;
    }
    return true;
}

static void cleanup_start_resources()
{
    if (s_wake_sem) {
        vSemaphoreDelete(s_wake_sem);
        s_wake_sem = nullptr;
    }
    if (s_mutex) {
        vSemaphoreDelete(s_mutex);
        s_mutex = nullptr;
    }
    s_push_jobs = {};
    s_forward_jobs = {};
    s_email_jobs = {};
    s_test_jobs = {};
    s_forward_completions = {};
    s_next_completion_id = 0;
    s_heartbeat_clock_started = false;
    s_last_heartbeat_us = 0;
    s_startup_email_pending = false;
    s_startup_email_done = false;
    memset(s_channel_fails, 0, sizeof(s_channel_fails));
    memset(s_channel_cool_until_us, 0, sizeof(s_channel_cool_until_us));
    s_busy.store(false, std::memory_order_relaxed);
}

static void wake_worker()
{
    if (s_wake_sem) xSemaphoreGive(s_wake_sem);
}

// Before TLS, defer a job when the largest free heap block is too small. Keep the job queued for retry.
static bool tls_heap_ok()
{
    return heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) >= TLS_MIN_FREE_HEAP;
}

static void note_channel_result(uint8_t ch, bool ok)
{
    if (ch >= IDF_MAX_PUSH_CHANNELS) return;
    if (ok) {
        s_channel_fails[ch] = 0;
        s_channel_cool_until_us[ch] = 0;
        return;
    }
    if (s_channel_fails[ch] < 255) s_channel_fails[ch]++;
    uint32_t cool = CHANNEL_COOL_STEP_SEC * s_channel_fails[ch];
    if (cool > CHANNEL_COOL_MAX_SEC) cool = CHANNEL_COOL_MAX_SEC;
    s_channel_cool_until_us[ch] = esp_timer_get_time() + static_cast<int64_t>(cool) * 1000000LL;
}

static bool channel_cooling(uint8_t ch, int64_t now)
{
    return ch < IDF_MAX_PUSH_CHANNELS && s_channel_cool_until_us[ch] > now;
}

static uint32_t register_forward_completion_locked(uint32_t inbox_id, uint8_t total_targets)
{
    if (inbox_id == 0 || total_targets == 0) return 0;
    for (auto& item : s_forward_completions) {
        if (item.used) continue;
        uint32_t next_id = ++s_next_completion_id;
        if (next_id == 0) next_id = ++s_next_completion_id;
        item.used = true;
        item.id = next_id;
        item.inboxId = inbox_id;
        item.remaining = total_targets;
        return item.id;
    }
    return 0;
}

static void note_forward_target_success(uint32_t completion_id)
{
    if (completion_id == 0) return;
    uint32_t inbox_id_to_mark = 0;
    ensure_init();
    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        for (auto& item : s_forward_completions) {
            if (!item.used || item.id != completion_id) continue;
            if (item.remaining > 0) --item.remaining;
            if (item.remaining == 0) {
                inbox_id_to_mark = item.inboxId;
                item = ForwardCompletion();
            }
            break;
        }
        xSemaphoreGive(s_mutex);
    }
    if (inbox_id_to_mark != 0) idf_inbox_mark_forwarded(inbox_id_to_mark);
}

static void cancel_forward_completion_locked(uint32_t completion_id)
{
    if (completion_id == 0) return;
    const auto item = std::find_if(s_forward_completions.begin(), s_forward_completions.end(),
                                   [completion_id](const auto& candidate) {
                                       return candidate.used && candidate.id == completion_id;
                                   });
    if (item != s_forward_completions.end()) *item = ForwardCompletion();
}

static void cancel_forward_completion(uint32_t completion_id)
{
    if (completion_id == 0) return;
    ensure_init();
    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        cancel_forward_completion_locked(completion_id);
        xSemaphoreGive(s_mutex);
    }
}

// Return local time as "YYYY-MM-DD HH:MM:SS", or an empty string if time is not synchronized.
static std::string format_local_time(int tz_offset_min)
{
    return idf_util_format_epoch_local(static_cast<uint32_t>(time(nullptr)), tz_offset_min);
}

static std::string format_utc_time(time_t epoch)
{
    struct tm utc = {};
    gmtime_r(&epoch, &utc);
    char text[24];
    strftime(text, sizeof(text), "%Y-%m-%d %H:%M:%S UTC", &utc);
    return text;
}

static std::string device_url(const IdfWifiStatus& wifi)
{
    const std::string& ip = wifi.staConnected ? wifi.ip : wifi.apIp;
    return ip.empty() ? std::string() : ("http://" + ip + "/");
}

static void build_startup_text(const IdfPushNotifyView& cfg, const std::string& url,
                               std::string& title, std::string& body)
{
    if (cfg.notificationLocale == NOTIFICATION_LOCALE_EN) {
        title = "SMS Forwarder started";
        body = "Device: " + cfg.deviceName + "\nStatus: Started\nDevice URL: " + url;
    } else if (cfg.notificationLocale == NOTIFICATION_LOCALE_ZH_CN) {
        title = "短信转发器已启动";
        body = "设备：" + cfg.deviceName + "\n状态：已启动\n设备网址：" + url;
    } else {
        title = "簡訊轉發器已啟動";
        body = "裝置：" + cfg.deviceName + "\n狀態：已啟動\n裝置網址：" + url;
    }
}

static void build_heartbeat_text(const IdfPushNotifyView& cfg, const IdfWifiStatus& wifi,
                                 const std::string& local_number, const std::string& event_time,
                                 std::string& title, std::string& body)
{
    const std::string url = device_url(wifi);
    if (cfg.notificationLocale == NOTIFICATION_LOCALE_EN) {
        title = "SMS Forwarder heartbeat";
        body = "Device: " + cfg.deviceName + "\nHostname: " + cfg.hostname +
               "\nLocal number: " + local_number + "\nNetwork address: " + wifi.ip +
               "\nDevice URL: " + url + "\nEvent: Device online\nTime: " + event_time;
    } else if (cfg.notificationLocale == NOTIFICATION_LOCALE_ZH_CN) {
        title = "短信转发器心跳";
        body = "设备：" + cfg.deviceName + "\n主机名：" + cfg.hostname +
               "\n本机号码：" + local_number + "\n网络地址：" + wifi.ip +
               "\n设备网址：" + url + "\n事件：设备在线\n时间：" + event_time;
    } else {
        title = "簡訊轉發器心跳";
        body = "裝置：" + cfg.deviceName + "\n主機名稱：" + cfg.hostname +
               "\n本機號碼：" + local_number + "\n網路位址：" + wifi.ip +
               "\n裝置網址：" + url + "\n事件：設備在線\n時間：" + event_time;
    }
}

// Truncate at a UTF-8 boundary so notification and email titles remain valid.
static std::string utf8_truncate(const std::string& value, size_t max_bytes)
{
    if (value.size() <= max_bytes) return value;
    size_t end = max_bytes;
    while (end > 0 && (static_cast<unsigned char>(value[end]) & 0xC0) == 0x80) --end;
    return value.substr(0, end) + "...";
}

static std::string local_phone_number()
{
    IdfModemStatus modem = idf_modem_get_status();
    if (!modem.phone.empty()) return modem.phone;
    return idf_config_get_status_view().phoneNumber;
}

static bool parse_push_channel_token(const std::string& value, uint8_t& channel)
{
    if (value.empty()) return false;
    uint32_t parsed = 0;
    for (char ch : value) {
        if (!isdigit(static_cast<unsigned char>(ch))) return false;
        parsed = parsed * 10U + static_cast<uint32_t>(ch - '0');
        if (parsed > IDF_MAX_PUSH_CHANNELS) return false;
    }
    if (parsed == 0) return false;
    channel = static_cast<uint8_t>(parsed);
    return true;
}

static std::string json_escape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    idf_util_json_escape_append(out, value);
    return out;
}

// SMS content is untrusted. Escape markup before it enters an HTML template such as pushplus.
static std::string html_escape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 16);
    for (char ch : value) {
        switch (ch) {
            case '&': out += "&amp;"; break;
            case '<': out += "&lt;"; break;
            case '>': out += "&gt;"; break;
            case '"': out += "&quot;"; break;
            default: out += ch; break;
        }
    }
    return out;
}

static void json_prop(std::string& out, const char* key, const std::string& value)
{
    out += "\"";
    out += key;
    out += "\":\"";
    idf_util_json_escape_append(out, value);
    out += "\"";
}

static std::string url_encode(const std::string& value)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size() * 3);
    for (unsigned char ch : value) {
        if (isalnum(ch)) out += static_cast<char>(ch);
        else if (ch == ' ') out += '+';
        else {
            out += '%';
            out += hex[ch >> 4];
            out += hex[ch & 0x0F];
        }
    }
    return out;
}

static std::string hmac_sha256_base64(const std::string& data, const std::string& key)
{
    unsigned char hmac[32] = {};
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (!info || mbedtls_md_hmac(info,
                                 reinterpret_cast<const unsigned char*>(key.data()), key.size(),
                                 reinterpret_cast<const unsigned char*>(data.data()), data.size(),
                                 hmac) != 0) return {};

    unsigned char out[64] = {};
    size_t out_len = 0;
    if (mbedtls_base64_encode(out, sizeof(out), &out_len, hmac, sizeof(hmac)) != 0) return {};
    return std::string(reinterpret_cast<char*>(out), out_len);
}

static bool sha256_matches(const std::vector<uint8_t>& data,
                           const std::array<uint8_t, 32>& expected)
{
    std::array<uint8_t, 32> actual{};
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    const bool ok = info && !data.empty() &&
        mbedtls_md(info, data.data(), data.size(), actual.data()) == 0 && actual == expected;
    std::fill(actual.begin(), actual.end(), 0);
    return ok;
}

static int64_t utc_millis()
{
    timeval tv = {};
    if (gettimeofday(&tv, nullptr) == 0) return static_cast<int64_t>(tv.tv_sec) * 1000LL + tv.tv_usec / 1000;
    return static_cast<int64_t>(time(nullptr)) * 1000LL;
}

static bool channel_valid(const IdfPushChannel& ch)
{
    if (!ch.enabled || ch.type < PUSH_TYPE_POST_JSON || ch.type > PUSH_TYPE_NTFY ||
        !idf_push_utf8_valid(ch.name) || !idf_push_utf8_valid(ch.url) ||
        !idf_push_utf8_valid(ch.key1) || !idf_push_utf8_valid(ch.key2) ||
        !idf_push_utf8_valid(ch.titleTemplate) || !idf_push_utf8_valid(ch.bodyTemplate) ||
        !idf_push_utf8_valid(ch.customBody) || ch.url.find_first_of("\r\n") != std::string::npos ||
        ch.key1.find_first_of("\r\n") != std::string::npos ||
        ch.key2.find_first_of("\r\n") != std::string::npos) return false;
    if (ch.type == PUSH_TYPE_CUSTOM) {
        if (ch.customBody.empty() || !ch.titleTemplate.empty() || !ch.bodyTemplate.empty()) return false;
    } else if (!ch.customBody.empty()) {
        return false;
    }
    switch (ch.type) {
        case PUSH_TYPE_POST_JSON:
        case PUSH_TYPE_BARK:
        case PUSH_TYPE_GET:
        case PUSH_TYPE_DINGTALK:
        case PUSH_TYPE_CUSTOM:
        case PUSH_TYPE_FEISHU:
        case PUSH_TYPE_DISCORD:
        case PUSH_TYPE_NTFY:
            return !ch.url.empty();
        case PUSH_TYPE_PUSHPLUS:
        case PUSH_TYPE_SERVERCHAN:
            return !ch.key1.empty();
        case PUSH_TYPE_GOTIFY:
            return !ch.url.empty() && !ch.key1.empty();
        case PUSH_TYPE_TELEGRAM:
            return !ch.key1.empty() && !ch.key2.empty();
        default:
            return false;
    }
}

static bool regex_search_case_insensitive(const std::string& pattern, const std::string& text)
{
    // Convert Perl-style \d, \w, and \s to POSIX character classes. idf_config uses the same conversion for validation.
    std::string posix = idf_config_translate_perl_classes(pattern);
    regex_t re = {};
    if (regcomp(&re, posix.c_str(), REG_EXTENDED | REG_ICASE | REG_NOSUB) != 0) return false;
    bool hit = regexec(&re, text.c_str(), 0, nullptr, 0) == 0;
    regfree(&re);
    return hit;
}

static ForwardDecision eval_forward_rules(const std::string& rules, const std::string& sender, const std::string& body)
{
    ForwardDecision d;
    size_t pos = 0;
    while (pos < rules.size()) {
        size_t end = rules.find('\n', pos);
        if (end == std::string::npos) end = rules.size();
        std::string line = idf_util_trim_copy(rules.substr(pos, end - pos));
        pos = end + (end < rules.size() ? 1 : 0);
        if (line.empty()) continue;

        size_t t1 = line.find('\t');
        size_t t2 = t1 == std::string::npos ? std::string::npos : line.find('\t', t1 + 1);
        if (t1 == std::string::npos || t2 == std::string::npos) continue;
        size_t t3 = line.find('\t', t2 + 1);
        std::string type = line.substr(0, t1);
        std::string pat = line.substr(t1 + 1, t2 - t1 - 1);
        std::string action = t3 == std::string::npos ? line.substr(t2 + 1) : line.substr(t2 + 1, t3 - t2 - 1);
        std::string enabled = t3 == std::string::npos ? "1" : idf_util_trim_copy(line.substr(t3 + 1));
        if (enabled == "0" || pat.empty()) continue;

        bool hit = false;
        if (type == "kw") hit = body.find(pat) != std::string::npos;
        else if (type == "from") hit = regex_search_case_insensitive(pat, sender);
        else if (type == "re") hit = regex_search_case_insensitive(pat, body);
        if (!hit) continue;

        d.matched = true;
        size_t ap = 0;
        while (ap <= action.size()) {
            size_t comma = action.find(',', ap);
            if (comma == std::string::npos) comma = action.size();
            std::string tok = idf_util_trim_copy(action.substr(ap, comma - ap));
            if (tok == "drop") d.drop = true;
            else if (tok == "email") d.email = true;
            else {
                uint8_t ch = 0;
                if (parse_push_channel_token(tok, ch)) d.chMask |= 1u << (ch - 1);
            }
            if (comma == action.size()) break;
            ap = comma + 1;
        }
        return d;
    }
    return d;
}

static uint32_t backoff_seconds(uint8_t attempts, uint32_t seed)
{
    uint32_t step = PUSH_RETRY_BASE_SEC;
    for (uint8_t i = 1; i < attempts && step < PUSH_RETRY_MAX_SEC; ++i) step <<= 1;
    if (step > PUSH_RETRY_MAX_SEC) step = PUSH_RETRY_MAX_SEC;
    uint32_t jitter = step / 4;
    return step + (jitter ? (seed % (jitter + 1)) : 0);
}

static esp_err_t http_request(const std::string& url, const char* method,
                              const char* content_type, const char* extra_header_name,
                              const std::string& extra_header_value, const std::string& body,
                              int& status_code)
{
    esp_http_client_config_t cfg = {};
    cfg.url = url.c_str();
    cfg.timeout_ms = HTTP_TIMEOUT_MS;
    cfg.crt_bundle_attach = esp_crt_bundle_attach;
    cfg.keep_alive_enable = false;
    // The default 512-byte TX buffer cannot hold a long percent-encoded GET request, which can exceed 1.4 KB.
    // Size it from the actual URL because multibyte SMS text can expand nine times during percent encoding.
    size_t tx_need = url.size() + 512;
    cfg.buffer_size_tx = static_cast<int>(tx_need < 2048 ? 2048 : tx_need);
    esp_http_client_handle_t client = esp_http_client_init(&cfg);
    if (!client) return ESP_ERR_NO_MEM;

    if (strcmp(method, "POST") == 0) {
        esp_http_client_set_method(client, HTTP_METHOD_POST);
        if (content_type) esp_http_client_set_header(client, "Content-Type", content_type);
        if (extra_header_name) {
            esp_err_t header_err = esp_http_client_set_header(client, extra_header_name,
                                                               extra_header_value.c_str());
            if (header_err != ESP_OK) {
                esp_http_client_cleanup(client);
                return header_err;
            }
        }
        esp_http_client_set_post_field(client, body.c_str(), body.size());
    } else {
        esp_http_client_set_method(client, HTTP_METHOD_GET);
    }

    esp_err_t err = esp_http_client_perform(client);
    status_code = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);
    return err;
}

static int push_wifi_request(const IdfPushHttpRequest& request, int& status_code)
{
    return static_cast<int>(http_request(request.url, request.method.c_str(),
                                         request.contentType.empty() ? nullptr : request.contentType.c_str(),
                                         request.headerName.empty() ? nullptr : request.headerName.c_str(),
                                         request.headerValue, request.body, status_code));
}

static int push_cellular_post(const IdfModemHttpsPostRequest& request,
                              IdfModemHttpsPostResult& result)
{
    return static_cast<int>(idf_modem_https_post(request, result));
}

static std::string base64_encode_string(const std::string& value)
{
    if (value.empty()) return {};
    size_t out_cap = ((value.size() + 2) / 3) * 4 + 1;
    std::string out(out_cap, '\0');
    size_t out_len = 0;
    int rc = mbedtls_base64_encode(reinterpret_cast<unsigned char*>(out.data()), out.size(), &out_len,
                                   reinterpret_cast<const unsigned char*>(value.data()), value.size());
    if (rc != 0) return {};
    out.resize(out_len);
    return out;
}

struct SmtpConn {
    esp_tls_t* implicitTls = nullptr;
    int sock = -1;
    bool startTlsActive = false;
    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
    // MbedTLS 3.x on IDF 5.x needs local entropy and ctr_drbg state as its TLS random source.
    mbedtls_ctr_drbg_context ctrDrbg;
    mbedtls_entropy_context entropy;
#endif

    SmtpConn()
    {
        mbedtls_net_init(&net);
        mbedtls_ssl_init(&ssl);
        mbedtls_ssl_config_init(&conf);
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
        mbedtls_ctr_drbg_init(&ctrDrbg);
        mbedtls_entropy_init(&entropy);
#endif
    }
};

static void smtp_conn_close(SmtpConn& conn)
{
    if (conn.implicitTls) {
        esp_tls_conn_destroy(conn.implicitTls);
        conn.implicitTls = nullptr;
    }
    if (conn.startTlsActive) {
        mbedtls_ssl_close_notify(&conn.ssl);
        conn.startTlsActive = false;
    }
    mbedtls_ssl_free(&conn.ssl);
    mbedtls_ssl_config_free(&conn.conf);
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
    mbedtls_ctr_drbg_free(&conn.ctrDrbg);
    mbedtls_entropy_free(&conn.entropy);
#endif
    if (conn.sock >= 0) {
        close(conn.sock);
        conn.sock = -1;
    }
    conn.net.fd = -1;
}

static void set_socket_timeouts(int sock, int timeout_ms)
{
    struct timeval tv = {};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

static bool socket_connect_with_timeout(int sock, const struct sockaddr* addr, socklen_t addr_len, int timeout_ms)
{
    int flags = fcntl(sock, F_GETFL, 0);
    if (flags < 0) flags = 0;
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

    int rc = connect(sock, addr, addr_len);
    if (rc == 0) {
        fcntl(sock, F_SETFL, flags);
        return true;
    }
    if (errno != EINPROGRESS) {
        fcntl(sock, F_SETFL, flags);
        return false;
    }

    fd_set wfds;
    FD_ZERO(&wfds);
    FD_SET(sock, &wfds);
    struct timeval tv = {};
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;
    rc = select(sock + 1, nullptr, &wfds, nullptr, &tv);
    if (rc <= 0) {
        fcntl(sock, F_SETFL, flags);
        return false;
    }

    int err = 0;
    socklen_t err_len = sizeof(err);
    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &err_len) != 0 || err != 0) {
        fcntl(sock, F_SETFL, flags);
        return false;
    }

    fcntl(sock, F_SETFL, flags);
    return true;
}

static bool smtp_tcp_connect(const std::string& host, int port, SmtpConn& conn)
{
    char port_buf[12];
    snprintf(port_buf, sizeof(port_buf), "%d", port);
    struct addrinfo hints = {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    struct addrinfo* res = nullptr;
    int gai = getaddrinfo(host.c_str(), port_buf, &hints, &res);
    if (gai != 0 || !res) {
        idf_logf("SMTP DNS lookup failed: %s", host.c_str());
        return false;
    }

    bool ok = false;
    for (struct addrinfo* ai = res; ai && !ok; ai = ai->ai_next) {
        int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (sock < 0) continue;
        set_socket_timeouts(sock, SMTP_TIMEOUT_MS);
        if (socket_connect_with_timeout(sock, ai->ai_addr, ai->ai_addrlen, SMTP_TIMEOUT_MS)) {
            conn.sock = sock;
            conn.net.fd = sock;
            ok = true;
        } else {
            close(sock);
        }
    }
    freeaddrinfo(res);
    if (!ok) idf_log_line("SMTP plaintext connection failed");
    return ok;
}

static bool smtp_starttls_upgrade(SmtpConn& conn, const std::string& host)
{
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
    // On IDF 5.x with MbedTLS 3.x, initialize CTR-DRBG and provide it through conf_rng.
    const char* pers = "sms-smtp-starttls";
    int ret = mbedtls_ctr_drbg_seed(&conn.ctrDrbg, mbedtls_entropy_func, &conn.entropy,
                                    reinterpret_cast<const unsigned char*>(pers), strlen(pers));
    if (ret != 0) {
        idf_logf("STARTTLS random source initialization failed: -0x%04x", -ret);
        return false;
    }
#else
    // On IDF 6.x with MbedTLS 4.x, the global PSA Crypto RNG replaces ctr_drbg and conf_rng.
    int ret = 0;
#endif
    ret = mbedtls_ssl_config_defaults(&conn.conf, MBEDTLS_SSL_IS_CLIENT,
                                      MBEDTLS_SSL_TRANSPORT_STREAM, MBEDTLS_SSL_PRESET_DEFAULT);
    if (ret != 0) {
        idf_logf("STARTTLS configuration initialization failed: -0x%04x", -ret);
        return false;
    }
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
    mbedtls_ssl_conf_rng(&conn.conf, mbedtls_ctr_drbg_random, &conn.ctrDrbg);
#endif
    mbedtls_ssl_conf_authmode(&conn.conf, MBEDTLS_SSL_VERIFY_REQUIRED);
    if (esp_crt_bundle_attach(&conn.conf) != ESP_OK) {
        idf_log_line("STARTTLS certificate bundle attachment failed");
        return false;
    }
    ret = mbedtls_ssl_setup(&conn.ssl, &conn.conf);
    if (ret != 0) {
        idf_logf("STARTTLS session initialization failed: -0x%04x", -ret);
        return false;
    }
    ret = mbedtls_ssl_set_hostname(&conn.ssl, host.c_str());
    if (ret != 0) {
        idf_logf("STARTTLS hostname setup failed: -0x%04x", -ret);
        return false;
    }
    mbedtls_ssl_set_bio(&conn.ssl, &conn.net, mbedtls_net_send, mbedtls_net_recv, nullptr);

    int64_t deadline = esp_timer_get_time() + static_cast<int64_t>(SMTP_TIMEOUT_MS) * 1000LL;
    while ((ret = mbedtls_ssl_handshake(&conn.ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            char errbuf[96];
            mbedtls_strerror(ret, errbuf, sizeof(errbuf));
            idf_logf("STARTTLS handshake failed: -0x%04x %s", -ret, errbuf);
            return false;
        }
        if (esp_timer_get_time() >= deadline) {
            idf_log_line("STARTTLS handshake timed out");
            return false;
        }
        vTaskDelay(pdMS_TO_TICKS(20));
    }

    uint32_t flags = mbedtls_ssl_get_verify_result(&conn.ssl);
    if (flags != 0) {
        char info[128];
        mbedtls_x509_crt_verify_info(info, sizeof(info), "", flags);
        idf_logf("STARTTLS certificate validation failed: %s", info);
        return false;
    }
    conn.startTlsActive = true;
    return true;
}

// Return >0 for data, 0 for a retryable lack of data, and -1 for a closed connection or fatal error.
static ssize_t smtp_conn_read(SmtpConn& conn, char* buf, size_t len)
{
    if (conn.implicitTls) {
        ssize_t ret = esp_tls_conn_read(conn.implicitTls, buf, len);
        if (ret > 0) return ret;
        if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) return 0;
        return -1;  // 0 means peer closed; a negative value is an error
    }
    if (conn.startTlsActive) {
        int ret = mbedtls_ssl_read(&conn.ssl, reinterpret_cast<unsigned char*>(buf), len);
        if (ret > 0) return ret;
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) return 0;
        return -1;  // 0 means EOF; other negative values are errors, including close_notify
    }
    if (conn.sock >= 0) {
        ssize_t ret = recv(conn.sock, buf, len, 0);
        if (ret > 0) return ret;
        if (ret == 0) return -1;  // Peer closed; greylisting and rate-limited servers commonly disconnect
        if (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR) return 0;
        return -1;
    }
    return -1;
}

static bool smtp_conn_write_all(SmtpConn& conn, const std::string& data)
{
    size_t sent = 0;
    int64_t deadline = esp_timer_get_time() + static_cast<int64_t>(SMTP_TIMEOUT_MS) * 1000LL;
    while (sent < data.size()) {
        ssize_t n = -1;
        if (conn.implicitTls) {
            ssize_t ret = esp_tls_conn_write(conn.implicitTls, data.data() + sent, data.size() - sent);
            if (ret > 0) n = ret;
            else if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) n = 0;
            else return false;  // The connection is closed; fail immediately
        } else if (conn.startTlsActive) {
            int ret = mbedtls_ssl_write(&conn.ssl,
                                        reinterpret_cast<const unsigned char*>(data.data() + sent),
                                        data.size() - sent);
            if (ret > 0) n = ret;
            else if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) n = 0;
            else return false;
        } else if (conn.sock >= 0) {
            ssize_t ret = send(conn.sock, data.data() + sent, data.size() - sent, 0);
            if (ret > 0) n = ret;
            else if (ret < 0 && (errno == EWOULDBLOCK || errno == EAGAIN || errno == EINTR)) n = 0;
            else return false;
        } else {
            return false;
        }

        if (n > 0) {
            sent += static_cast<size_t>(n);
            deadline = esp_timer_get_time() + static_cast<int64_t>(SMTP_TIMEOUT_MS) * 1000LL;
            // Enforce the session limit even after progress. A server cannot extend the deadline by reading a few bytes.
            if (s_smtp_session_deadline && esp_timer_get_time() >= s_smtp_session_deadline) return false;
            continue;
        }
        if (esp_timer_get_time() >= deadline) return false;
        if (s_smtp_session_deadline && esp_timer_get_time() >= s_smtp_session_deadline) return false;
        vTaskDelay(pdMS_TO_TICKS(20));
    }
    return true;
}

static bool smtp_final_line_code(const std::string& line, int& code)
{
    if (line.size() < 3 ||
        !isdigit(static_cast<unsigned char>(line[0])) ||
        !isdigit(static_cast<unsigned char>(line[1])) ||
        !isdigit(static_cast<unsigned char>(line[2]))) {
        return false;
    }
    code = (line[0] - '0') * 100 + (line[1] - '0') * 10 + (line[2] - '0');
    // RFC 5321 permits a final line with only a three-digit code. A '-' in position four marks an intermediate line.
    if (line.size() == 3) return true;
    return line[3] == ' ';
}

static int smtp_read_response(SmtpConn& conn, std::string& response, uint32_t timeout_ms = SMTP_TIMEOUT_MS)
{
    response.clear();
    response.reserve(256);
    char buf[128];
    int final_code = -1;
    int64_t deadline = esp_timer_get_time() + static_cast<int64_t>(timeout_ms) * 1000LL;
    if (s_smtp_session_deadline && s_smtp_session_deadline < deadline) deadline = s_smtp_session_deadline;
    while (esp_timer_get_time() < deadline) {
        ssize_t n = smtp_conn_read(conn, buf, sizeof(buf));
        if (n < 0) return final_code;  // The connection closed or failed; do not wait through the timeout
        if (n > 0) {
            response.append(buf, static_cast<size_t>(n));
            size_t pos = 0;
            while (pos < response.size()) {
                size_t eol = response.find('\n', pos);
                if (eol == std::string::npos) break;
                std::string line = response.substr(pos, eol - pos);
                while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
                int code = -1;
                if (smtp_final_line_code(line, code)) {
                    final_code = code;
                    return final_code;
                }
                pos = eol + 1;
            }
            // Discard parsed lines and keep the incomplete tail. This limits memory and preserves the final status line.
            if (pos > 0) response.erase(0, pos);
            if (response.size() >= 2048) return final_code;  // A line above 2 KB is invalid protocol data
        } else {
            vTaskDelay(pdMS_TO_TICKS(30));
        }
    }
    return final_code;
}

static bool smtp_code_ok(int code, int a, int b = -1, int c = -1)
{
    return code == a || (b >= 0 && code == b) || (c >= 0 && code == c);
}

static bool smtp_expect(SmtpConn& conn, int ok1, int ok2 = -1, int ok3 = -1)
{
    std::string resp;
    int code = smtp_read_response(conn, resp);
    if (smtp_code_ok(code, ok1, ok2, ok3)) return true;
    idf_logf("Unexpected SMTP response code=%d resp=%s", code, resp.c_str());
    return false;
}

static bool smtp_command(SmtpConn& conn, const std::string& command, int ok1, int ok2 = -1, int ok3 = -1)
{
    std::string wire = command;
    wire += "\r\n";
    if (!smtp_conn_write_all(conn, wire)) return false;
    return smtp_expect(conn, ok1, ok2, ok3);
}

static std::string header_safe(std::string value)
{
    std::replace_if(value.begin(), value.end(), [](char ch) { return ch == '\r' || ch == '\n'; }, ' ');
    return value;
}

static std::string email_addr_only(std::string value)
{
    value = idf_util_trim_copy(value);
    size_t lt = value.find('<');
    size_t gt = value.find('>', lt == std::string::npos ? 0 : lt + 1);
    if (lt != std::string::npos && gt != std::string::npos && gt > lt + 1) {
        value = value.substr(lt + 1, gt - lt - 1);
    }
    return header_safe(idf_util_trim_copy(value));
}

static std::string smtp_date_utc()
{
    time_t now = time(nullptr);
    struct tm tm_utc = {};
    gmtime_r(&now, &tm_utc);
    char buf[64];
    if (strftime(buf, sizeof(buf), "%a, %d %b %Y %H:%M:%S +0000", &tm_utc) == 0) return {};
    return std::string(buf);
}

// RFC 2047 limits one encoded-word to 75 characters. Split and fold long subjects at UTF-8 boundaries.
static std::string encode_subject_words(const std::string& subject)
{
    std::string out;
    size_t pos = 0;
    while (pos < subject.size()) {
        size_t take = subject.size() - pos;
        if (take > 45) take = 45;  // 45 bytes become 60 base64 characters, or 72 with wrappers
        // Do not split inside a UTF-8 continuation sequence
        while (take > 1 && pos + take < subject.size() &&
               (static_cast<unsigned char>(subject[pos + take]) & 0xC0) == 0x80) {
            --take;
        }
        std::string chunk64 = base64_encode_string(subject.substr(pos, take));
        if (chunk64.empty()) return {};
        if (!out.empty()) out += "\r\n ";
        out += "=?UTF-8?B?" + chunk64 + "?=";
        pos += take;
    }
    return out;
}

// Encode all bodies as base64 with 76-character lines. This avoids 8BITMIME and the 998-byte line limit.
// The base64 alphabet has no '.', so dot stuffing is unnecessary.
static std::string base64_wrap76(const std::string& data)
{
    std::string b64 = base64_encode_string(data);
    std::string out;
    out.reserve(b64.size() + b64.size() / 76 * 2 + 4);
    for (size_t i = 0; i < b64.size(); i += 76) {
        size_t take = b64.size() - i;
        if (take > 76) take = 76;
        out.append(b64, i, take);
        out += "\r\n";
    }
    return out;
}

static bool send_smtp_email(const IdfEmailSettingsView& cfg, const std::string& subject, const std::string& body)
{
    if (!cfg.emailConfigured) {
        idf_log_line("Email configuration is incomplete; skip send");
        return false;
    }
    if (!idf_wifi_get_status().staConnected) {
        idf_log_line("WiFi is disconnected; retry email later");
        return false;
    }

    std::string server = idf_util_trim_copy(cfg.smtpServer);
    std::string from = email_addr_only(cfg.smtpUser);
    std::string to = email_addr_only(cfg.smtpSendTo);
    if (server.empty() || from.empty() || to.empty()) {
        idf_log_line("Email configuration is incomplete; skip send");
        return false;
    }
    esp_tls_cfg_t tls_cfg = {};
    tls_cfg.crt_bundle_attach = esp_crt_bundle_attach;
    tls_cfg.timeout_ms = SMTP_TIMEOUT_MS;

    bool ok = false;
    SmtpConn conn;
    // Start the session limit before connection. DNS, TCP, TLS, and nine command rounds share 120 seconds.
    s_smtp_session_deadline = esp_timer_get_time() + SMTP_SESSION_MAX_US;
    idf_logf("Connecting to SMTP server: %s:%d", server.c_str(), cfg.smtpPort);
    if (cfg.smtpPort == 465) {
        conn.implicitTls = esp_tls_init();
        if (!conn.implicitTls) {
            idf_log_line("SMTP TLS handle allocation failed");
            return false;
        }
        if (esp_tls_conn_new_sync(server.c_str(), static_cast<int>(server.size()), cfg.smtpPort, &tls_cfg, conn.implicitTls) != 1) {
            idf_log_line("Email server TLS connection failed");
            smtp_conn_close(conn);
            return false;
        }
    } else {
        if (!smtp_tcp_connect(server, cfg.smtpPort, conn)) {
            smtp_conn_close(conn);
            return false;
        }
    }

    std::string user64 = base64_encode_string(cfg.smtpUser);
    std::string pass64 = base64_encode_string(cfg.smtpPass);
    std::string subject_words = encode_subject_words(header_safe(subject));
    std::string safe_subject = subject_words.empty() ? header_safe(subject) : subject_words;
    std::string message;
    message.reserve(body.size() * 2 + 512);
    message += "From: sms notify <" + from + ">\r\n";
    message += "To: <" + to + ">\r\n";
    message += "Subject: " + safe_subject + "\r\n";
    message += "Date: " + smtp_date_utc() + "\r\n";
    message += "MIME-Version: 1.0\r\n";
    message += "Content-Type: text/plain; charset=UTF-8\r\n";
    message += "Content-Transfer-Encoding: base64\r\n\r\n";
    message += base64_wrap76(body);
    message += ".\r\n";

    ok = smtp_expect(conn, 220) &&
         smtp_command(conn, "EHLO sms-forwarder", 250);
    if (ok && cfg.smtpPort != 465) {
        ok = smtp_command(conn, "STARTTLS", 220) &&
             smtp_starttls_upgrade(conn, server) &&
             smtp_command(conn, "EHLO sms-forwarder", 250);
    }
    ok = ok &&
         smtp_command(conn, "AUTH LOGIN", 334) &&
         smtp_command(conn, user64, 334) &&
         smtp_command(conn, pass64, 235) &&
         smtp_command(conn, "MAIL FROM:<" + from + ">", 250) &&
         smtp_command(conn, "RCPT TO:<" + to + ">", 250, 251) &&
         smtp_command(conn, "DATA", 354) &&
         smtp_conn_write_all(conn, message) &&
         smtp_expect(conn, 250);

    if (ok) smtp_command(conn, "QUIT", 221);
    else smtp_conn_write_all(conn, "QUIT\r\n");  // Do not wait for QUIT on failure; a dead connection must not consume 15 seconds
    smtp_conn_close(conn);
    s_smtp_session_deadline = 0;
    idf_log_line(ok ? "Email sent" : "Email send failed");
    return ok;
}

static void replace_all(std::string& value, const char* from, const char* to)
{
    size_t pos = 0;
    const size_t from_len = strlen(from);
    const size_t to_len = strlen(to);
    while ((pos = value.find(from, pos)) != std::string::npos) {
        value.replace(pos, from_len, to);
        pos += to_len;
    }
}

static bool send_to_channel(const IdfPushChannel& input_channel, const char* sender_raw,
                            const char* text_raw, const char* timestamp_raw,
                            const IdfPushNotifyView& cfg, const IdfWifiStatus& wifi,
                            IdfPushNetworkDecision network,
                            bool notify = false, std::string* failure_message = nullptr,
                            bool* permanent_failure = nullptr)
{
    if (permanent_failure) *permanent_failure = false;
    if (!channel_valid(input_channel)) return false;

    IdfPushCellularTarget cellular_target;
    std::vector<uint8_t> cellular_root_der;
    IdfConfigCaStatus cellular_ca_status;
    if (network == IdfPushNetworkDecision::Cellular) {
        if (!idf_push_prepare_cellular_target(input_channel, cellular_target) ||
            idf_config_ca_lookup(cellular_target.canonicalOrigin, cellular_root_der,
                                 &cellular_ca_status) != ESP_OK ||
            !cellular_ca_status.configured ||
            !sha256_matches(cellular_root_der, cellular_ca_status.sha256)) {
            if (failure_message) *failure_message = "Cellular CA is not provisioned";
            if (permanent_failure) *permanent_failure = true;
            return false;
        }
    }
    IdfPushChannel effective_channel = input_channel;
    if (network == IdfPushNetworkDecision::Cellular) {
        effective_channel.url = cellular_target.effectiveUrl;
    }
    const IdfPushChannel& channel = effective_channel;

    std::string sender = sender_raw ? sender_raw : "";
    std::string text = text_raw ? text_raw : "";
    std::string timestamp = timestamp_raw ? timestamp_raw : "";
    IdfPushTemplateValues values{
        sender, text, timestamp, cfg.deviceName, notify ? std::string() : local_phone_number(),
        wifi.ip, cfg.hostname, wifi.ssid,
    };
    std::string title;
    std::string notification_body;
    if (notify) {
        if (!idf_push_render_template("{sender}", values, MAX_RENDERED_TITLE_BYTES, true, title) ||
            !idf_push_render_template("{message}", values, MAX_RENDERED_BODY_BYTES, false,
                                      notification_body)) {
            idf_log_line("Push title or content is invalid UTF-8, has an invalid title newline, or exceeds the length limit");
            return false;
        }
    } else if (!idf_push_render_sms_notification(cfg.notificationLocale, channel.titleTemplate,
                                                  channel.bodyTemplate, values, title,
                                                  notification_body)) {
        idf_log_line("Rendered push template is invalid UTF-8, has an invalid title newline, or exceeds the length limit");
        return false;
    }

    const std::string title_json = json_escape(title);
    const std::string notification_body_json = json_escape(notification_body);
    std::string url;
    std::string body;
    const char* content_type = "application/json";
    std::string method = "POST";
    const char* extra_header_name = nullptr;
    std::string extra_header_value;

    switch (channel.type) {
        case PUSH_TYPE_POST_JSON: {
            url = channel.url;
            body = "{\"sender\":\"" + json_escape(sender) + "\",\"message\":\"" +
                   json_escape(text) + "\",\"timestamp\":\"" + json_escape(timestamp) +
                   "\",\"title\":\"" + title_json + "\",\"body\":\"" +
                   notification_body_json + "\"}";
            break;
        }
        case PUSH_TYPE_BARK:
            url = channel.url;
            body = "{\"title\":\"" + title_json + "\",\"body\":\"" +
                   notification_body_json + "\"}";
            break;
        case PUSH_TYPE_GET:
            method = "GET";
            url = channel.url + (channel.url.find('?') == std::string::npos ? "?" : "&") +
                  "sender=" + url_encode(sender) + "&message=" + url_encode(text) +
                  "&timestamp=" + url_encode(timestamp) + "&title=" + url_encode(title) +
                  "&body=" + url_encode(notification_body);
            break;
        case PUSH_TYPE_DINGTALK: {
            url = channel.url;
            if (!channel.key1.empty()) {
                if (time(nullptr) < 1700000000) return false;
                int64_t ts = utc_millis();
                std::string sign_data = std::to_string(ts) + "\n" + channel.key1;
                std::string sign = url_encode(hmac_sha256_base64(sign_data, channel.key1));
                if (sign.empty()) return false;
                url += (url.find('?') == std::string::npos ? "?" : "&");
                url += "timestamp=" + std::to_string(ts) + "&sign=" + sign;
            }
            body = "{\"msgtype\":\"text\",\"text\":{\"content\":\"" + title_json +
                   "\\n" + notification_body_json + "\"}}";
            break;
        }
        case PUSH_TYPE_PUSHPLUS: {
            url = channel.url.empty() ? "https://www.pushplus.plus/send" : channel.url;
            std::string push_channel = channel.key2.empty() ? "wechat" : channel.key2;
            if (push_channel != "wechat" && push_channel != "extension" && push_channel != "app") push_channel = "wechat";
            std::string title_html = html_escape(title);
            std::string body_html = html_escape(notification_body);
            replace_all(body_html, "\n", "<br>");
            body = "{\"token\":\"" + json_escape(channel.key1) + "\",\"title\":\"" +
                   json_escape(title_html) + "\",\"content\":\"" + json_escape(body_html) +
                   "\",\"channel\":\"" + json_escape(push_channel) + "\"}";
            break;
        }
        case PUSH_TYPE_SERVERCHAN: {
            url = channel.url.empty() ? ("https://sctapi.ftqq.com/" + channel.key1 + ".send") : channel.url;
            content_type = "application/x-www-form-urlencoded";
            body = "title=" + url_encode(title) + "&desp=" + url_encode(notification_body);
            break;
        }
        case PUSH_TYPE_CUSTOM: {
            url = channel.url;
            IdfPushTemplateValues escaped = values;
            escaped.sender = json_escape(escaped.sender);
            escaped.message = json_escape(escaped.message);
            escaped.timestamp = json_escape(escaped.timestamp);
            escaped.device = json_escape(escaped.device);
            escaped.localNumber = json_escape(escaped.localNumber);
            escaped.ip = json_escape(escaped.ip);
            escaped.hostname = json_escape(escaped.hostname);
            escaped.wifi = json_escape(escaped.wifi);
            if (!idf_push_render_template(channel.customBody, escaped,
                                          MAX_RENDERED_CUSTOM_BODY_BYTES, false, body)) {
                idf_log_line("Rendered custom push is invalid UTF-8 or exceeds the length limit");
                return false;
            }
            break;
        }
        case PUSH_TYPE_FEISHU: {
            url = channel.url;
            body = "{";
            if (!channel.key1.empty()) {
                if (time(nullptr) < 1700000000) return false;
                int64_t ts = time(nullptr);
                std::string sign = hmac_sha256_base64("", std::to_string(ts) + "\n" + channel.key1);
                if (sign.empty()) return false;
                body += "\"timestamp\":\"" + std::to_string(ts) + "\",\"sign\":\"" + sign + "\",";
            }
            body += "\"msg_type\":\"text\",\"content\":{\"text\":\"" + title_json +
                    "\\n" + notification_body_json + "\"}}";
            break;
        }
        case PUSH_TYPE_GOTIFY:
            {
                IdfPushHttpRequest gotify;
                if (!idf_push_build_gotify_request(channel, title, notification_body, gotify)) return false;
                url = gotify.url;
                body = gotify.body;
            }
            break;
        case PUSH_TYPE_TELEGRAM: {
            std::string base = channel.url.empty() ? "https://api.telegram.org" : channel.url;
            while (!base.empty() && base.back() == '/') base.pop_back();
            url = base + "/bot" + channel.key2 + "/sendMessage";
            body = "{\"chat_id\":\"" + json_escape(channel.key1) + "\",\"text\":\"" +
                   title_json + "\\n" + notification_body_json + "\"}";
            break;
        }
        case PUSH_TYPE_DISCORD: {
            const std::string content = title + "\n" + notification_body;
            if (idf_push_utf8_codepoint_count(content, 2000) > 2000) {
                idf_log_line("Discord push content exceeds 2,000 characters");
                return false;
            }
            body = "{\"content\":\"" + json_escape(content) +
                   "\",\"allowed_mentions\":{\"parse\":[]}}";
            url = channel.url;
            break;
        }
        case PUSH_TYPE_NTFY:
            url = channel.url;
            content_type = "text/plain";
            extra_header_name = "Title";
            extra_header_value = title;
            body = notification_body;
            break;
        default:
            return false;
    }

    std::string name = channel.name.empty() ? ("Channel " + std::to_string(channel.type)) : channel.name;
    IdfPushHttpRequest request;
    request.url = url;
    request.method = method;
    request.contentType = content_type ? content_type : "";
    request.headerName = extra_header_name ? extra_header_name : "";
    request.headerValue = extra_header_name ? extra_header_value : "";
    request.body = body;
    if (network == IdfPushNetworkDecision::Cellular) {
        request.rootCertificateDer = std::move(cellular_root_der);
        request.rootCertificateSha256 = cellular_ca_status.sha256;
    }
    const IdfConfigStatusView modem_config = network == IdfPushNetworkDecision::Cellular
                                                  ? idf_config_get_status_view()
                                                  : IdfConfigStatusView();
    IdfPushTransportResult transport;
    const bool dispatched = idf_push_dispatch_request(request, network, modem_config,
                                                       push_wifi_request, push_cellular_post,
                                                       transport);
    const esp_err_t err = static_cast<esp_err_t>(transport.error);
    const int code = transport.httpStatus;
    const bool ok = dispatched && transport.ok;
    if (!ok && failure_message && !transport.message.empty()) {
        *failure_message = transport.message;
    }
    // Combine the send and response lines. Keep the channel name and result in one concise log entry.
    if (err == ESP_OK) idf_logf("%s push %s (HTTP %d)", name.c_str(), ok ? "succeeded" : "failed", code);
    else idf_logf("%s push failed: %s", name.c_str(), esp_err_to_name(err));
    return ok;
}

static bool enqueue_push_job_locked(uint8_t ch, const std::string& sender, const std::string& text,
                                    const std::string& timestamp, uint8_t attempts, uint32_t delay_sec,
                                    bool notify = false, uint32_t inbox_id = 0,
                                    uint32_t completion_id = 0)
{
    int slot = -1;
    for (size_t i = 0; i < s_push_jobs.size(); ++i) {
        if (!s_push_jobs[i].used) {
            slot = static_cast<int>(i);
            break;
        }
    }
    if (slot < 0) {
        // An old job can represent a queued inbox SMS. Do not silently evict it for a new job.
        return false;
    }
    PushJob& job = s_push_jobs[slot];
    job.used = true;
    job.channel = ch;
    job.attempts = attempts;
    job.notify = notify;
    job.nextUs = esp_timer_get_time() + static_cast<int64_t>(delay_sec) * 1000000LL;
    job.sender = sender;
    job.text = text;
    job.timestamp = timestamp;
    job.inboxId = inbox_id;
    job.completionId = completion_id;
    return true;
}

static int push_queue_free_locked()
{
    return static_cast<int>(std::count_if(s_push_jobs.begin(), s_push_jobs.end(),
                                          [](const auto& job) { return !job.used; }));
}

static bool enqueue_email_job_locked(const std::string& subject, const std::string& body,
                                     uint8_t attempts = 0, uint32_t delay_sec = 0,
                                     uint32_t inbox_id = 0, uint32_t completion_id = 0)
{
    int slot = -1;
    for (size_t i = 0; i < s_email_jobs.size(); ++i) {
        if (!s_email_jobs[i].used) {
            slot = static_cast<int>(i);
            break;
        }
    }
    if (slot < 0) {
        // Match Arduino behavior: reject a new email when full instead of evicting one that is retrying.
        idf_log_line("Email queue is full; new email was not queued");
        return false;
    }
    EmailJob& job = s_email_jobs[slot];
    job.used = true;
    job.attempts = attempts;
    job.nextUs = esp_timer_get_time() + static_cast<int64_t>(delay_sec) * 1000000LL;
    job.subject = subject;
    job.body = body;
    job.inboxId = inbox_id;
    job.completionId = completion_id;
    return true;
}

static int queue_depth_locked(const std::array<PushJob, PUSH_QUEUE_MAX>& jobs)
{
    return static_cast<int>(std::count_if(jobs.begin(), jobs.end(),
                                          [](const auto& job) { return job.used; }));
}

static int email_queue_depth_locked()
{
    return static_cast<int>(std::count_if(s_email_jobs.begin(), s_email_jobs.end(),
                                          [](const auto& job) { return job.used; }));
}

static bool enqueue_forward_job_locked(const ForwardJob& src, uint32_t delay_sec)
{
    for (auto& job : s_forward_jobs) {
        if (job.used) continue;
        job = src;
        job.used = true;
        job.nextUs = esp_timer_get_time() + static_cast<int64_t>(delay_sec) * 1000000LL;
        return true;
    }
    return false;
}

static bool enqueue_forward_locked(const char* sender, const char* text, const char* timestamp, uint32_t inbox_id)
{
    ForwardJob job;
    job.sender = sender ? sender : "";
    job.text = text ? text : "";
    job.timestamp = timestamp ? timestamp : "";
    job.inboxId = inbox_id;
    return enqueue_forward_job_locked(job, 0);
}

static bool pop_forward_job(ForwardJob& out)
{
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return false;
    bool found = false;
    int64_t now = esp_timer_get_time();
    for (auto& job : s_forward_jobs) {
        if (!job.used || job.nextUs > now) continue;
        out = job;
        job = ForwardJob();
        found = true;
        break;
    }
    xSemaphoreGive(s_mutex);
    return found;
}

static void requeue_forward_later(ForwardJob& job, const char* reason, bool count_attempt = true)
{
    // A busy downstream queue is not a delivery failure because no send occurred. Do not consume retry attempts.
    if (count_attempt) job.attempts++;
    if (job.attempts >= PUSH_RETRY_MAX) {
        idf_logf("%s; forward id=%u exhausted %u retries and remains not forwarded for manual resend",
                 reason,
                 static_cast<unsigned>(job.inboxId),
                 static_cast<unsigned>(job.attempts));
        return;
    }

    uint32_t delay = backoff_seconds(job.attempts, job.inboxId + static_cast<uint32_t>(job.text.size()));
    bool queued = false;
    ensure_init();
    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        queued = enqueue_forward_job_locked(job, delay);
        xSemaphoreGive(s_mutex);
    }
    if (queued) {
        idf_logf("%s; retry forward id=%u in %u seconds",
                 reason,
                 static_cast<unsigned>(job.inboxId),
                 static_cast<unsigned>(delay));
        wake_worker();
    } else {
        idf_logf("%s and the forwarding queue is full; SMS id=%u remains not forwarded",
                 reason,
                 static_cast<unsigned>(job.inboxId));
    }
}

static bool process_forward_one()
{
    // busy covers the window between dequeue and enqueue so a maintenance restart cannot lose an in-flight SMS.
    s_busy.store(true, std::memory_order_relaxed);
    ForwardJob job;
    if (!pop_forward_job(job)) {
        s_busy.store(false, std::memory_order_relaxed);
        return false;
    }

    const IdfPushForwardView cfg = idf_config_get_push_forward_view();
    ForwardDecision fd = eval_forward_rules(cfg.forwardRules, job.sender, job.text);
    if (fd.matched && fd.drop) {
        idf_logf("Forwarding rule matched: discard SMS id=%u", static_cast<unsigned>(job.inboxId));
        idf_inbox_mark_forwarded(job.inboxId);
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }

    uint32_t mask = fd.matched ? fd.chMask : 0xFFFFFFFFu;
    bool email_selected = fd.matched ? fd.email : true;
    if (!cfg.pushEnabled) mask = 0;
    // The local number appears only in email. Skip the locked modem status query when email is not used.
    const std::string receiver = (email_selected && cfg.emailEnabled && cfg.emailConfigured)
                                     ? local_phone_number() : std::string();
    int dispatched = 0;
    bool email_queued = false;
    bool enqueue_failed = false;
    bool push_queue_busy = false;
    bool email_queue_busy = false;
    bool had_queued_target = job.pushQueued;

    std::string targets;  // Names of matched channels for the destination log entry
    ensure_init();
    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        int push_targets = 0;
        if (!job.pushQueued) {
            for (uint8_t i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
                if (!(mask & (1u << i))) continue;
                if (!channel_valid(cfg.pushChannels[i])) continue;
                ++push_targets;
            }
        }
        bool will_queue_email = email_selected && cfg.emailEnabled && cfg.emailConfigured;
        uint8_t total_targets = static_cast<uint8_t>(push_targets + (will_queue_email ? 1 : 0));
        if (push_targets > push_queue_free_locked()) {
            enqueue_failed = true;
            push_queue_busy = true;
        }
        if (will_queue_email && email_queue_depth_locked() >= static_cast<int>(EMAIL_QUEUE_MAX)) {
            enqueue_failed = true;
            email_queue_busy = true;
        }
        uint32_t completion_id = enqueue_failed ? 0 : register_forward_completion_locked(job.inboxId, total_targets);
        if (!enqueue_failed && total_targets > 0 && job.inboxId != 0 && completion_id == 0) enqueue_failed = true;
        if (!job.pushQueued) {
            for (uint8_t i = 0; i < IDF_MAX_PUSH_CHANNELS && !enqueue_failed; ++i) {
                if (!(mask & (1u << i))) continue;
                if (!channel_valid(cfg.pushChannels[i])) continue;
                if (enqueue_push_job_locked(i, job.sender, job.text, job.timestamp, 0, 0, false,
                                            job.inboxId, completion_id)) {
                    ++dispatched;
                    had_queued_target = true;
            if (!targets.empty()) targets += ", ";
                    targets += cfg.pushChannels[i].name.empty()
                                   ? ("Channel " + std::to_string(i + 1)) : cfg.pushChannels[i].name;
                } else {
                    enqueue_failed = true;
                    push_queue_busy = true;
                }
            }
            if (dispatched > 0) job.pushQueued = true;
        }
        if (!enqueue_failed && will_queue_email) {
            // Put only the start of the message in the subject. The body has the full text, and strict MTAs reject long subjects.
            std::string subject = "SMS";
            subject += job.sender;
            subject += ",";
            subject += utf8_truncate(job.text, 48);
            std::string body = "From: ";
            body += job.sender;
            if (!receiver.empty()) {
                body += ", local number: ";
                body += receiver;
            }
            if (!job.timestamp.empty()) {
                body += ", time: ";
                body += job.timestamp;
            }
            body += ", message: ";
            body += job.text;
            email_queued = enqueue_email_job_locked(subject, body, 0, 0, job.inboxId, completion_id);
            if (email_queued) had_queued_target = true;
            else {
                enqueue_failed = true;
                email_queue_busy = true;
            }
        }
        if (enqueue_failed && completion_id != 0) {
            cancel_forward_completion_locked(completion_id);
        }
        xSemaphoreGive(s_mutex);
    } else {
        enqueue_failed = true;
    }
    if (enqueue_failed) {
        const char* reason = push_queue_busy && email_queue_busy ? "Push and email queues are busy" :
                             (email_queue_busy ? "Email queue is busy" :
                              (push_queue_busy ? "Push queue is busy" : "Forwarding queue is busy"));
        requeue_forward_later(job, reason, false);
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }

    // List all push and email destinations in one forwarding log entry.
    if (email_queued) {
        if (!targets.empty()) targets += ", ";
        targets += "Email";
    }
    if (!targets.empty()) {
        idf_logf("Forward id=%u -> %s", static_cast<unsigned>(job.inboxId), targets.c_str());
    } else if (had_queued_target) {
        idf_logf("Forward id=%u -> queued destination", static_cast<unsigned>(job.inboxId));
    } else {
        idf_logf("Forward id=%u has no destination (no enabled channel or configured email)", static_cast<unsigned>(job.inboxId));
    }
    s_busy.store(false, std::memory_order_relaxed);
    return true;
}

static bool low_heap_defer()
{
    static bool warned = false;
    if (tls_heap_ok()) {
        warned = false;
        return false;
    }
    if (!warned) {
        warned = true;
        idf_logf("Heap block is too small (<%u); defer TLS send", static_cast<unsigned>(TLS_MIN_FREE_HEAP));
    }
    return true;
}

static bool channel_waits_for_time(const IdfPushChannel& channel)
{
    return !channel.key1.empty() &&
           (channel.type == PUSH_TYPE_DINGTALK || channel.type == PUSH_TYPE_FEISHU) &&
           time(nullptr) < 1700000000;
}

static void fail_push_job_without_retry(const PushJob& job, const char* reason)
{
    cancel_forward_completion(job.completionId);
    if (job.inboxId) idf_inbox_set_forwarded(job.inboxId, false);
    idf_logf("Channel %u %s", static_cast<unsigned>(job.channel + 1), reason);
}

static bool purge_push_jobs_disabled()
{
    std::array<uint32_t, PUSH_QUEUE_MAX> inbox_ids = {};
    size_t inbox_count = 0;
    bool purged = false;
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return false;
    for (auto& job : s_push_jobs) {
        if (!job.used) continue;
        purged = true;
        cancel_forward_completion_locked(job.completionId);
        if (job.inboxId && inbox_count < inbox_ids.size()) inbox_ids[inbox_count++] = job.inboxId;
        job = PushJob();
    }
    xSemaphoreGive(s_mutex);
    if (!purged) return false;
    for (size_t i = 0; i < inbox_count; ++i) idf_inbox_set_forwarded(inbox_ids[i], false);
    memset(s_channel_fails, 0, sizeof(s_channel_fails));
    memset(s_channel_cool_until_us, 0, sizeof(s_channel_cool_until_us));
    idf_log_line("Push is disabled; clear the pending push queue");
    return true;
}

static bool process_push_one()
{
    const IdfPushNotifyView cfg = idf_config_get_push_notify_view();
    const IdfWifiStatus wifi = idf_wifi_get_status();
    if (!cfg.pushEnabled) return purge_push_jobs_disabled();
    const IdfPushNetworkDecision network =
        idf_push_select_network(static_cast<NetworkMode>(cfg.networkMode), wifi.staConnected);
    if (network == IdfPushNetworkDecision::Defer) return false;
    if (network == IdfPushNetworkDecision::Wifi && low_heap_defer()) return false;
    int picked = -1;
    PushJob job;
    int64_t now = esp_timer_get_time();

    ensure_init();
    s_busy.store(true, std::memory_order_relaxed);
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) {
        s_busy.store(false, std::memory_order_relaxed);
        return false;
    }
    for (size_t i = 0; i < s_push_jobs.size(); ++i) {
        if (!s_push_jobs[i].used || s_push_jobs[i].nextUs > now) continue;
        if (channel_cooling(s_push_jobs[i].channel, now)) continue;
        const IdfPushChannel& channel = cfg.pushChannels[s_push_jobs[i].channel];
        if (channel_valid(channel) && channel_waits_for_time(channel)) {
            s_push_jobs[i].nextUs = now + 5000000LL;
            continue;
        }
        picked = static_cast<int>(i);
        job = s_push_jobs[i];
        s_push_jobs[i] = PushJob();
        break;
    }
    xSemaphoreGive(s_mutex);
    if (picked < 0) {
        s_busy.store(false, std::memory_order_relaxed);
        return false;
    }

    if (network == IdfPushNetworkDecision::Unsupported) {
        fail_push_job_without_retry(job, "Cellular push is not supported; task stopped");
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }

    IdfPushChannel channel;
    if (!idf_config_get_push_channel(job.channel, channel) || !channel_valid(channel)) {
        cancel_forward_completion(job.completionId);
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }
    if (network == IdfPushNetworkDecision::Cellular && channel.type == PUSH_TYPE_GET) {
        fail_push_job_without_retry(job, "GET-only provider is not supported over cellular; task stopped");
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }

    bool permanent_failure = false;
    bool ok = send_to_channel(channel, job.sender.c_str(), job.text.c_str(),
                              job.timestamp.c_str(), cfg, wifi, network, job.notify,
                              nullptr, &permanent_failure);
    note_channel_result(job.channel, ok);
    if (ok) {
        note_forward_target_success(job.completionId);
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }
    if (permanent_failure) {
        fail_push_job_without_retry(job, "Cellular CA is not provisioned; task stopped");
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }

    job.attempts++;
    if (job.attempts >= PUSH_RETRY_MAX) {
        idf_logf("Channel %u failed after %u retries; give up", static_cast<unsigned>(job.channel + 1), static_cast<unsigned>(job.attempts));
        cancel_forward_completion(job.completionId);
        // After permanent failure, mark the inbox item not forwarded so the user can see and resend it.
        if (job.inboxId) idf_inbox_set_forwarded(job.inboxId, false);
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }
    uint32_t delay = backoff_seconds(job.attempts, static_cast<uint32_t>(job.channel * 7 + job.attempts));
    bool requeued = false;
    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        requeued = enqueue_push_job_locked(job.channel, job.sender, job.text, job.timestamp,
                                           job.attempts, delay, job.notify, job.inboxId, job.completionId);
        xSemaphoreGive(s_mutex);
    }
    if (!requeued) {
        cancel_forward_completion(job.completionId);
        idf_logf("Push retry queue is full; channel %u retry was not retained", static_cast<unsigned>(job.channel + 1));
        if (job.inboxId) idf_inbox_set_forwarded(job.inboxId, false);
    }
    s_busy.store(false, std::memory_order_relaxed);
    return true;
}

static bool process_email_one()
{
    if (!idf_wifi_get_status().staConnected) return false;

    IdfEmailSettingsView cfg = idf_config_get_email_settings_view();
    ensure_init();
    if (!cfg.emailEnabled) {
        // Match Arduino behavior: clear queued email when email is disabled.
        if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
            bool purged = false;
            for (auto& j : s_email_jobs) {
                if (!j.used) continue;
                purged = true;
                // If the email leg is discarded, undo its completion count and keep the inbox item not forwarded.
                cancel_forward_completion_locked(j.completionId);
                j = EmailJob();
            }
            xSemaphoreGive(s_mutex);
            if (purged) idf_log_line("Email is disabled; clear the pending email queue");
        }
        return false;
    }
    if (low_heap_defer()) return false;

    int picked = -1;
    EmailJob job;
    int64_t now = esp_timer_get_time();

    s_busy.store(true, std::memory_order_relaxed);
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) {
        s_busy.store(false, std::memory_order_relaxed);
        return false;
    }
    for (size_t i = 0; i < s_email_jobs.size(); ++i) {
        if (!s_email_jobs[i].used || s_email_jobs[i].nextUs > now) continue;
        picked = static_cast<int>(i);
        job = s_email_jobs[i];
        s_email_jobs[i] = EmailJob();
        break;
    }
    xSemaphoreGive(s_mutex);
    if (picked < 0) {
        s_busy.store(false, std::memory_order_relaxed);
        return false;
    }

    bool ok = send_smtp_email(cfg, job.subject, job.body);
    if (ok) {
        note_forward_target_success(job.completionId);
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }

    job.attempts++;
    if (job.attempts >= PUSH_RETRY_MAX) {
        idf_logf("Email failed after %u retries; give up", static_cast<unsigned>(job.attempts));
        cancel_forward_completion(job.completionId);
        // As with push, mark permanent failure as not forwarded so the inbox does not report false delivery.
        if (job.inboxId) idf_inbox_set_forwarded(job.inboxId, false);
        s_busy.store(false, std::memory_order_relaxed);
        return true;
    }
    uint32_t delay = backoff_seconds(job.attempts, static_cast<uint32_t>(job.subject.size() + job.body.size()));
    bool requeued = false;
    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        requeued = enqueue_email_job_locked(job.subject, job.body, job.attempts, delay,
                                            job.inboxId, job.completionId);
        xSemaphoreGive(s_mutex);
    }
    if (!requeued) {
        cancel_forward_completion(job.completionId);
        idf_log_line("Email retry queue is full; retry was not retained");
        if (job.inboxId) idf_inbox_set_forwarded(job.inboxId, false);
    }
    s_busy.store(false, std::memory_order_relaxed);
    return true;
}

static bool fail_pending_tests(const char* message)
{
    bool failed = false;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    for (auto& job : s_test_jobs) {
        if (!job.pending && !job.running) continue;
        failed = true;
        job.pending = false;
        job.running = false;
        job.done = true;
        job.success = false;
        job.nextUs = 0;
        job.deadlineUs = 0;
        job.message = message;
    }
    xSemaphoreGive(s_mutex);
    return failed;
}

static bool expire_test_jobs_locked(int64_t now)
{
    bool expired = false;
    for (auto& job : s_test_jobs) {
        if (!job.pending || job.deadlineUs <= 0 || job.deadlineUs > now) continue;
        expired = true;
        job.pending = false;
        job.done = true;
        job.success = false;
        job.nextUs = 0;
        job.deadlineUs = 0;
        job.message = "Test push timed out before it could start";
    }
    return expired;
}

static bool process_test_one()
{
    const int64_t now = esp_timer_get_time();
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    const bool expired = expire_test_jobs_locked(now);
    xSemaphoreGive(s_mutex);
    if (expired) return true;
    const IdfPushNotifyView cfg = idf_config_get_push_notify_view();
    const IdfWifiStatus wifi = idf_wifi_get_status();
    if (!cfg.pushEnabled) return fail_pending_tests("Push is disabled; test canceled");
    const IdfPushNetworkDecision network =
        idf_push_select_network(static_cast<NetworkMode>(cfg.networkMode), wifi.staConnected);
    if (network == IdfPushNetworkDecision::Unsupported) {
        return fail_pending_tests("Cellular push is not supported; test stopped");
    }
    if (network == IdfPushNetworkDecision::Defer) return false;
    if (network == IdfPushNetworkDecision::Wifi && low_heap_defer()) return false;
    int picked = -1;
    IdfPushChannel channel;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    for (uint8_t i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        if (!s_test_jobs[i].pending || s_test_jobs[i].nextUs > now) continue;
        if (channel_waits_for_time(cfg.pushChannels[i])) {
            s_test_jobs[i].nextUs = now + 5000000LL;
            s_test_jobs[i].message = "Waiting for time synchronization before sending the test push";
            continue;
        }
        picked = i;
        s_test_jobs[i].pending = false;
        s_test_jobs[i].running = true;
        s_test_jobs[i].done = false;
        s_test_jobs[i].success = false;
        s_test_jobs[i].nextUs = 0;
        s_test_jobs[i].deadlineUs = 0;
        s_test_jobs[i].message = "Sending test push";
        channel = cfg.pushChannels[i];
        break;
    }
    xSemaphoreGive(s_mutex);
    if (picked < 0) return false;

    bool ok = false;
    std::string result;
    if (!channel_valid(channel)) {
        result = "Channel configuration changed or is disabled; test canceled";
    } else if (network == IdfPushNetworkDecision::Cellular && channel.type == PUSH_TYPE_GET) {
        result = "GET-only provider is not supported over cellular; test canceled";
    } else {
        s_busy.store(true, std::memory_order_relaxed);
        std::string ts = format_local_time(cfg.tzOffsetMin);
        ok = send_to_channel(channel, "Test", "This is a test push from SMS Forwarder",
                             ts.empty() ? "Time is not synchronized" : ts.c_str(), cfg, wifi,
                             network, false, &result);
        s_busy.store(false, std::memory_order_relaxed);
        if (ok) result = "Test push sent";
        else if (result.empty()) result = "Test push failed; see the log";
    }

    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        TestJob& job = s_test_jobs[picked];
        job.running = false;
        job.done = true;
        job.success = ok;
        job.message = result;
        xSemaphoreGive(s_mutex);
    }
    return true;
}

static bool process_startup_notification()
{
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    const bool pending = s_startup_email_pending;
    xSemaphoreGive(s_mutex);
    if (!pending) return false;

    const IdfWifiStatus wifi = idf_wifi_get_status();
    if (!wifi.staConnected) return false;
    const IdfPushNotifyView cfg = idf_config_get_push_notify_view();
    std::string title;
    std::string body;
    build_startup_text(cfg, device_url(wifi), title, body);
    if (!idf_push_enqueue_email(title.c_str(), body.c_str())) return false;

    if (s_mutex && xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        s_startup_email_pending = false;
        s_startup_email_done = true;
        xSemaphoreGive(s_mutex);
    }
    return true;
}

static void push_task(void*)
{
    while (true) {
        bool did = process_forward_one();
        if (!did) did = process_startup_notification();
        if (!did) did = process_push_one();
        if (!did) did = process_email_one();
        if (!did) did = process_test_one();
        if (did) {
            vTaskDelay(pdMS_TO_TICKS(10));
        } else if (s_wake_sem) {
            // Wait for a wake signal while idle. A 100 ms timeout still picks up backoff retries on time.
            xSemaphoreTake(s_wake_sem, pdMS_TO_TICKS(100));
        } else {
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }
}

esp_err_t idf_push_start(void)
{
    if (s_started) return ESP_OK;
    if (!ensure_init()) {
        cleanup_start_resources();
        return ESP_ERR_NO_MEM;
    }
    BaseType_t ok = xTaskCreate(push_task, "idf_push", PUSH_WORKER_STACK, nullptr, 3, nullptr);
    if (ok != pdPASS) {
        cleanup_start_resources();
        return ESP_ERR_NO_MEM;
    }
    s_started = true;
    idf_log_line("Push background worker started");
    return ESP_OK;
}

bool idf_push_enqueue_forward(const char* sender, const char* text, const char* timestamp, uint32_t inbox_id)
{
    if (!ensure_init()) return false;
    // Critical sections contain only short memory operations. Wait for the lock so contention cannot drop an SMS.
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return false;
    bool ok = enqueue_forward_locked(sender, text, timestamp, inbox_id);
    xSemaphoreGive(s_mutex);
    if (ok) wake_worker();
    else idf_log_line("Forwarding queue is full; SMS was not forwarded");
    return ok;
}

int idf_push_enqueue_notify(const char* title, const char* body, const char* timestamp)
{
    if (!ensure_init()) return 0;
    const IdfPushNotifyView cfg = idf_config_get_push_notify_view();
    if (!cfg.pushEnabled) return 0;

    std::string ts = timestamp ? timestamp : "";
    if (ts.empty()) ts = format_local_time(cfg.tzOffsetMin);
    if (ts.empty()) ts = "Time is not synchronized";

    int dispatched = 0;
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return 0;
    for (uint8_t i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        if (!channel_valid(cfg.pushChannels[i])) continue;
        if (enqueue_push_job_locked(i, title ? title : "System notification", body ? body : "", ts, 0, 0, true)) {
            ++dispatched;
        }
    }
    xSemaphoreGive(s_mutex);
    if (dispatched > 0) wake_worker();
    return dispatched;
}

bool idf_push_enqueue_email(const char* subject, const char* body)
{
    if (!ensure_init()) return false;
    if (!idf_config_email_configured()) {
        idf_log_line("Email configuration is incomplete; email was not queued");
        return false;
    }
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    bool ok = enqueue_email_job_locked(subject ? subject : "", body ? body : "");
    int depth = email_queue_depth_locked();
    xSemaphoreGive(s_mutex);
    if (ok) {
        wake_worker();
        idf_logf("Email queued; pending=%d", depth);
    }
    return ok;
}

bool idf_push_enqueue_startup_notification(void)
{
    const IdfEmailSettingsView email = idf_config_get_email_settings_view();
    if (!email.emailEnabled || !email.emailConfigured || !ensure_init()) return false;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    if (!s_startup_email_done) s_startup_email_pending = true;
    xSemaphoreGive(s_mutex);
    wake_worker();
    return true;
}

bool idf_push_heartbeat_tick(void)
{
    const IdfPushNotifyView cfg = idf_config_get_push_notify_view();
    const time_t epoch = time(nullptr);
    if (!cfg.heartbeatEnable || cfg.heartbeatInterval < 1 || epoch < 1700000000) {
        s_heartbeat_clock_started = false;
        return false;
    }

    const int64_t now = esp_timer_get_time();
    if (!s_heartbeat_clock_started) {
        s_heartbeat_clock_started = true;
        s_last_heartbeat_us = now;
        return false;
    }
    const int64_t interval_us = static_cast<int64_t>(cfg.heartbeatInterval) * 3600LL * 1000000LL;
    if (now - s_last_heartbeat_us < interval_us) return false;
    s_last_heartbeat_us = now;

    const IdfWifiStatus wifi = idf_wifi_get_status();
    const IdfPushNetworkDecision network = idf_push_select_network(
        static_cast<NetworkMode>(cfg.networkMode), wifi.staConnected);
    if (network == IdfPushNetworkDecision::Unsupported ||
        network == IdfPushNetworkDecision::Defer) return false;
    std::string title;
    std::string body;
    const std::string event_time = format_utc_time(epoch);
    build_heartbeat_text(cfg, wifi, local_phone_number(), event_time, title, body);
    return idf_push_enqueue_notify(title.c_str(), body.c_str(), event_time.c_str()) > 0;
}

int idf_push_forward_queue_depth(void)
{
    if (!ensure_init()) return 0;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return 0;
    const int n = static_cast<int>(std::count_if(s_forward_jobs.begin(), s_forward_jobs.end(),
                                                 [](const auto& job) { return job.used; }));
    xSemaphoreGive(s_mutex);
    return n;
}

int idf_push_retry_queue_depth(void)
{
    if (!ensure_init()) return 0;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return 0;
    int n = queue_depth_locked(s_push_jobs);
    xSemaphoreGive(s_mutex);
    return n;
}

int idf_push_email_queue_depth(void)
{
    if (!ensure_init()) return 0;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return 0;
    int n = email_queue_depth_locked();
    xSemaphoreGive(s_mutex);
    return n;
}

bool idf_push_busy(void)
{
    return s_busy.load(std::memory_order_relaxed);
}

bool idf_push_test_active(void)
{
    if (!ensure_init()) return true;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return true;
    expire_test_jobs_locked(esp_timer_get_time());
    const bool active = std::any_of(s_test_jobs.begin(), s_test_jobs.end(), [](const auto& job) {
        return job.pending || job.running;
    });
    xSemaphoreGive(s_mutex);
    return active;
}

bool idf_push_test_channel_active(uint8_t channel)
{
    if (channel >= IDF_MAX_PUSH_CHANNELS || !ensure_init()) return true;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return true;
    expire_test_jobs_locked(esp_timer_get_time());
    const bool active = s_test_jobs[channel].pending || s_test_jobs[channel].running;
    xSemaphoreGive(s_mutex);
    return active;
}

bool idf_push_enqueue_test(uint8_t channel, std::string& message)
{
    if (channel >= IDF_MAX_PUSH_CHANNELS) {
        message = "Channel number is invalid";
        return false;
    }
    if (!ensure_init()) {
        message = "Push queue initialization failed";
        return false;
    }
    if (!s_started) {
        message = "Push background worker is unavailable";
        return false;
    }
    bool busy = false;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        message = "Push queue is busy";
        return false;
    }
    expire_test_jobs_locked(esp_timer_get_time());
    busy = s_test_jobs[channel].pending || s_test_jobs[channel].running;
    xSemaphoreGive(s_mutex);
    if (busy) {
        message = "Channel test is already running in the background";
        return false;
    }
    const IdfPushNotifyView cfg = idf_config_get_push_notify_view();
    if (!cfg.pushEnabled) {
        message = "Push is disabled; test push is unavailable";
        return false;
    }
    const IdfPushNetworkDecision network = idf_push_select_network(
        static_cast<NetworkMode>(cfg.networkMode), idf_wifi_get_status().staConnected);
    if (network == IdfPushNetworkDecision::Unsupported) {
        message = "Cellular push is not supported; test was not queued";
        return false;
    }
    if (network == IdfPushNetworkDecision::Defer) {
        message = "WiFi is disconnected; test push is unavailable";
        return false;
    }
    if (network == IdfPushNetworkDecision::Cellular &&
        cfg.pushChannels[channel].type == PUSH_TYPE_GET) {
        message = "GET-only provider is not supported over cellular; test was not queued";
        return false;
    }
    bool valid = channel_valid(cfg.pushChannels[channel]);
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        message = "Push queue is busy";
        return false;
    }
    TestJob& job = s_test_jobs[channel];
    expire_test_jobs_locked(esp_timer_get_time());
    busy = job.pending || job.running;
    if (valid && !busy) {
        job.pending = true;
        job.running = false;
        job.done = false;
        job.success = false;
        job.nextUs = 0;
        job.deadlineUs = esp_timer_get_time() + PUSH_TEST_PENDING_MAX_US;
        job.message = "Test push queued; you can continue to refresh the page";
        message = job.message;
    }
    xSemaphoreGive(s_mutex);
    if (busy) {
        message = "Channel test is already running in the background";
        return false;
    }
    if (!valid) {
        message = "Channel is disabled or incomplete; save its configuration first";
        return false;
    }
    wake_worker();
    return true;
}

std::string idf_push_test_status_json(uint8_t channel)
{
    if (channel >= IDF_MAX_PUSH_CHANNELS) {
        return "{\"queued\":false,\"running\":false,\"done\":true,\"success\":false,\"message\":\"Channel number is invalid\"}";
    }
    if (!ensure_init()) {
        return "{\"queued\":false,\"running\":false,\"done\":true,\"success\":false,\"message\":\"Push queue initialization failed\"}";
    }
    if (!s_started) {
        return "{\"queued\":false,\"running\":false,\"done\":true,\"success\":false,\"message\":\"Push background worker is unavailable\"}";
    }
    TestJob copy;
    if (!s_mutex || xSemaphoreTake(s_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return "{\"queued\":false,\"running\":false,\"done\":true,\"success\":false,\"message\":\"Push test status is temporarily unavailable\"}";
    }
    expire_test_jobs_locked(esp_timer_get_time());
    copy = s_test_jobs[channel];
    xSemaphoreGive(s_mutex);
    std::string msg = copy.message.empty() ? "Test not started" : copy.message;
    std::string out = "{";
    out += "\"queued\":"; out += copy.pending ? "true" : "false"; out += ",";
    out += "\"running\":"; out += copy.running ? "true" : "false"; out += ",";
    out += "\"done\":"; out += copy.done ? "true" : "false"; out += ",";
    out += "\"success\":"; out += copy.success ? "true" : "false"; out += ",";
    json_prop(out, "message", msg);
    out += "}";
    return out;
}
