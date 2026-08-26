#include "idf_web.h"
#include "idf_web_core.h"
#include "idf_web_crypto.h"
#include "idf_web_ota.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <string>
#include <atomic>
#include <utility>
#include <vector>
#include <stdlib.h>
#include <new>

#include "driver/temperature_sensor.h"
#include "esp_core_dump.h"
#include "esp_partition.h"
#include "esp_heap_caps.h"
#include "esp_http_server.h"
#include "esp_log.h"
#include "esp_random.h"
#include "esp_system.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"
#include "idf_config.h"
#include "config_schema_generated.h"
#include "idf_esim.h"
#include "idf_inbox.h"
#include "idf_log.h"
#include "idf_modem.h"
#include "idf_push.h"
#include "idf_sms.h"
#include "idf_util.h"
#include "idf_wifi.h"
#include "mbedtls/base64.h"
#include "nvs.h"
#include "web_assets.h"

static const char* TAG = "idf_web";
static httpd_handle_t s_server = nullptr;
static SemaphoreHandle_t s_cell_job_mutex = nullptr;
static SemaphoreHandle_t s_api_job_mutex = nullptr;
static SemaphoreHandle_t s_backup_mutex = nullptr;
static bool s_scheduler_started = false;
static std::string s_csrf_token;

static constexpr size_t API_JOB_SLOTS = 6;
static constexpr size_t API_JOB_ACTIVE_MAX = 3;
static constexpr uint32_t API_JOB_TTL_MS = 60000;
static constexpr uint32_t BACKUP_TTL_MS = 120000;
static constexpr size_t BACKUP_CHUNK_BYTES = 8192;
static constexpr uint32_t OTA_TTL_MS = 120000;
static std::atomic<bool> s_device_restart_pending{false};
static std::atomic<bool> s_push_test_admission_active{false};
static std::atomic<bool> s_shared_admission_active{false};
static std::atomic<bool> s_restore_restart_pending{false};
static std::atomic<uint32_t> s_restore_restart_completed_ms{0};

static constexpr uint32_t RESTORE_PHASE_ACCEPTED = 1U << 0;
static constexpr uint32_t RESTORE_PHASE_STARTED = 1U << 1;
static constexpr uint32_t RESTORE_PHASE_DECRYPT = 1U << 2;
static constexpr uint32_t RESTORE_PHASE_CONFIG = 1U << 3;
static constexpr uint32_t RESTORE_PHASE_DONE = 1U << 4;
static constexpr uint32_t RESTORE_PHASE_MISMATCH = 1U << 5;
static constexpr uint32_t RESTORE_FIELD_UNKNOWN = UINT32_MAX;

struct ApiRestoreLifecycleSnapshot {
    uint32_t job_id = 0;
    uint32_t phases = 0;
    uint32_t decrypt_result = RESTORE_FIELD_UNKNOWN;
    int32_t config_err = INT32_MIN;
    uint32_t config_status = RESTORE_FIELD_UNKNOWN;
    uint32_t done_id = 0;
    uint32_t done_state = 0;
    uint32_t completed_ms = 0;
    uint32_t stack_hwm = 0;
    uint32_t mismatch_id = 0;
    uint32_t mismatch_state = 0;
    bool lookup_logged = false;
};

static ApiRestoreLifecycleSnapshot s_last_restore_job;

static bool device_restart_pending()
{
    return s_device_restart_pending.load(std::memory_order_relaxed) ||
           idf_web_ota_restart_pending();
}

static bool try_shared_admission(bool push_test_owner)
{
    if (!push_test_owner && s_push_test_admission_active.load(std::memory_order_acquire)) return false;
    return !s_shared_admission_active.exchange(true, std::memory_order_acq_rel);
}

static void release_shared_admission()
{
    s_shared_admission_active.store(false, std::memory_order_release);
}

static bool shared_admission_active()
{
    return s_shared_admission_active.load(std::memory_order_acquire) ||
           s_push_test_admission_active.load(std::memory_order_acquire);
}

static bool restore_restart_pending()
{
    return s_restore_restart_pending.load(std::memory_order_acquire);
}

static bool restore_restart_due(uint32_t now_ms)
{
    return restore_restart_pending() &&
           now_ms - s_restore_restart_completed_ms.load(std::memory_order_acquire) >= API_JOB_TTL_MS;
}

struct ApiJob {
    IdfWebJobSlotMeta meta;
    bool success = false;
    IdfWebOwnedJobInput input;
    IdfWebOwnedBytes binary;
    std::string result;
};

static ApiJob s_api_jobs[API_JOB_SLOTS];
static uint32_t s_next_api_job_id = 1;
static IdfWebTransfer s_backup_transfer;

struct WebAsyncJob {
    uint32_t id = 0;
    bool running = false;
    bool done = false;
    bool success = false;
    bool queued = false;
    std::string action;
    std::string message;
};

struct EsimWebCache {
    std::string eid;
    std::vector<IdfEsimProfile> profiles;
    std::vector<std::string> handles;
    uint32_t updatedAt = 0;
};

static WebAsyncJob s_keepalive_job;
static WebAsyncJob s_esim_job;
static WebAsyncJob s_sched_job;
static int s_sched_job_index = -1;
static EsimWebCache s_esim_cache;
static uint32_t s_next_esim_job_id = 1;
static bool s_modem_apply_running = false;
static bool s_web_modem_action_running = false;

static bool cell_job_lock(TickType_t ticks = pdMS_TO_TICKS(300));
static void cell_job_unlock(void);
static bool cellular_job_active_locked(bool allow_device_restart = false);
static bool cellular_job_active(bool allow_device_restart = false);
static void set_json_no_cache(httpd_req_t* req);
static bool get_query_param(httpd_req_t* req, const char* key, std::string& out, size_t max_query);
static esp_err_t enqueue_api_job(httpd_req_t* req, const char* type, const std::string& arg,
                                 IdfWebOwnedBytes binary = {}, bool admission_claimed = false);
static std::string run_save_job(const std::string& body);
static bool valid_ussd_code(const std::string& code);
static bool run_ussd(const std::string& code, std::string& resp_out);

static void restore_lifecycle_mark_locked(uint32_t job_id, uint32_t phase)
{
    if (s_last_restore_job.job_id == job_id) s_last_restore_job.phases |= phase;
}

static void restore_lifecycle_reset_locked(uint32_t job_id)
{
    s_last_restore_job = ApiRestoreLifecycleSnapshot();
    s_last_restore_job.job_id = job_id;
    s_last_restore_job.phases = RESTORE_PHASE_ACCEPTED;
}

static void restore_lifecycle_decrypt(uint32_t job_id, uint32_t result)
{
    if (!s_api_job_mutex || xSemaphoreTake(s_api_job_mutex, portMAX_DELAY) != pdTRUE) return;
    if (s_last_restore_job.job_id == job_id) {
        s_last_restore_job.decrypt_result = result;
        s_last_restore_job.phases |= RESTORE_PHASE_DECRYPT;
    }
    xSemaphoreGive(s_api_job_mutex);
}

static void restore_lifecycle_config(uint32_t job_id, int32_t err, uint32_t status)
{
    if (!s_api_job_mutex || xSemaphoreTake(s_api_job_mutex, portMAX_DELAY) != pdTRUE) return;
    if (s_last_restore_job.job_id == job_id) {
        s_last_restore_job.config_err = err;
        s_last_restore_job.config_status = status;
        s_last_restore_job.phases |= RESTORE_PHASE_CONFIG;
    }
    xSemaphoreGive(s_api_job_mutex);
}

static bool request_is_on_ap_interface(httpd_req_t* req)
{
    const int fd = httpd_req_to_sockfd(req);
    sockaddr_in local = {};
    socklen_t length = sizeof(local);
    if (fd < 0 || getsockname(fd, reinterpret_cast<sockaddr*>(&local), &length) != 0 ||
        local.sin_family != AF_INET) return false;
    const IdfWifiStatus wifi = idf_wifi_get_status();
    in_addr ap = {};
    return !wifi.apIp.empty() && inet_pton(AF_INET, wifi.apIp.c_str(), &ap) == 1 &&
           local.sin_addr.s_addr == ap.s_addr;
}

static void json_prop(std::string& out, const char* key, const std::string& value)
{
    out += "\"";
    out += key;
    out += "\":\"";
    idf_util_json_escape_append(out, value);
    out += "\"";
}

static bool epoch_valid(uint32_t epoch)
{
    return epoch >= 1700000000u;
}

static bool push_key_sensitive(uint8_t type, int slot)
{
    if (slot == 1) {
        return type == 2 || type == 4 || type == 5 || type == 6 || type == 8 || type == 9;
    }
    return slot == 2 && type == 10;
}

static std::string format_tz_offset(int tz_offset_min)
{
    if (tz_offset_min == 0) return "UTC";
    char buf[16];
    int total = tz_offset_min < 0 ? -tz_offset_min : tz_offset_min;
    int hh = total / 60;
    int mm = total % 60;
    if (mm == 0) {
        snprintf(buf, sizeof(buf), "UTC%c%d", tz_offset_min < 0 ? '-' : '+', hh);
    } else {
        snprintf(buf, sizeof(buf), "UTC%c%d:%02d", tz_offset_min < 0 ? '-' : '+', hh, mm);
    }
    return std::string(buf);
}

static std::string format_epoch_local(uint32_t epoch, int tz_offset_min)
{
    if (!epoch_valid(epoch)) return std::string();
    time_t shifted = static_cast<time_t>(static_cast<int64_t>(epoch) + static_cast<int64_t>(tz_offset_min) * 60LL);
    struct tm tmv = {};
    gmtime_r(&shifted, &tmv);
    char buf[48];
    snprintf(buf, sizeof(buf), "%04d-%02d-%02d %02d:%02d:%02d %s",
             tmv.tm_year + 1900, tmv.tm_mon + 1, tmv.tm_mday,
             tmv.tm_hour, tmv.tm_min, tmv.tm_sec,
             format_tz_offset(tz_offset_min).c_str());
    return std::string(buf);
}

// Internal chip temperature shown on the overview; load the driver lazily and do not retry after failure.
static bool read_chip_temp(float& out)
{
    static temperature_sensor_handle_t s_tsens = nullptr;
    static bool s_tsens_failed = false;
    if (!s_tsens && !s_tsens_failed) {
        temperature_sensor_config_t cfg = TEMPERATURE_SENSOR_CONFIG_DEFAULT(-10, 80);
        if (temperature_sensor_install(&cfg, &s_tsens) != ESP_OK ||
            temperature_sensor_enable(s_tsens) != ESP_OK) {
            s_tsens_failed = true;
            return false;
        }
    }
    return s_tsens && temperature_sensor_get_celsius(s_tsens, &out) == ESP_OK;
}

static bool auth_matches_config(const char* auth)
{
    static constexpr const char* prefix = "Basic ";
    if (strncmp(auth, prefix, strlen(prefix)) != 0) return false;

    unsigned char decoded[384] = {};
    size_t decoded_len = 0;
    const unsigned char* encoded = reinterpret_cast<const unsigned char*>(auth + strlen(prefix));
    int rc = mbedtls_base64_decode(decoded, sizeof(decoded) - 1, &decoded_len, encoded, strlen(auth + strlen(prefix)));
    if (rc != 0) return false;
    if (memchr(decoded, '\0', decoded_len)) return false;
    decoded[decoded_len] = '\0';

    char* decoded_text = reinterpret_cast<char*>(decoded);
    char* colon = static_cast<char*>(memchr(decoded, ':', decoded_len));
    if (!colon || colon == decoded_text || colon + 1 == decoded_text + decoded_len) return false;
    *colon = '\0';
    return idf_config_check_web_auth(decoded_text, colon + 1);
}

static bool check_auth(httpd_req_t* req, bool allow_ap = true)
{
    if (allow_ap && idf_web_ap_auth_bypass(idf_wifi_is_ap_mode(), request_is_on_ap_interface(req), req->uri)) return true;
    char auth[512] = {};
    if (httpd_req_get_hdr_value_str(req, "Authorization", auth, sizeof(auth)) == ESP_OK &&
        auth_matches_config(auth)) {
        return true;
    }

    httpd_resp_set_status(req, "401 Unauthorized");
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_set_hdr(req, "WWW-Authenticate", "Basic realm=\"SMS Forwarding\"");
    httpd_resp_sendstr(req, "Unauthorized");
    return false;
}

static bool check_auth_strict(httpd_req_t* req)
{
    return check_auth(req, false);
}

static bool check_csrf(httpd_req_t* req)
{
    char ap_token[4] = {};
    const bool ap_local = request_is_on_ap_interface(req);
    if (idf_wifi_is_ap_mode() && ap_local &&
        httpd_req_get_hdr_value_str(req, "X-SMS-CSRF", ap_token, sizeof(ap_token)) == ESP_OK &&
        idf_web_ap_csrf_bypass(true, ap_local, req->uri, ap_token)) {
        return true;
    }
    char token[40] = {};
    size_t token_len = httpd_req_get_hdr_value_len(req, "X-CSRF-Token");
    if (token_len < sizeof(token) &&
        httpd_req_get_hdr_value_str(req, "X-CSRF-Token", token, sizeof(token)) == ESP_OK &&
        idf_web_constant_time_equal(token, token_len, s_csrf_token)) {
        return true;
    }
    set_json_no_cache(req);
    httpd_resp_set_status(req, "403 Forbidden");
    httpd_resp_sendstr(req, "{\"success\":false,\"code\":\"ACTION_CSRF_INVALID\",\"data\":{},\"detail\":\"\"}");
    return false;
}

static bool etag_matches(httpd_req_t* req, const WebAsset& asset)
{
    char inm[96] = {};
    if (httpd_req_get_hdr_value_str(req, "If-None-Match", inm, sizeof(inm)) != ESP_OK) {
        return false;
    }
    return strstr(inm, asset.etag) != nullptr;
}

static bool cache_has_token(const char* cache_control, const char* token)
{
    return cache_control && strstr(cache_control, token) != nullptr;
}

static void set_no_cache_headers(httpd_req_t* req)
{
    httpd_resp_set_hdr(req, "Cache-Control", "no-store, max-age=0");
}

static void set_json_no_cache(httpd_req_t* req)
{
    httpd_resp_set_type(req, "application/json");
    set_no_cache_headers(req);
}

static bool reject_oversized_body(httpd_req_t* req)
{
    if (req->content_len <= 16384) return false;
    set_no_cache_headers(req);
    httpd_resp_set_hdr(req, "Connection", "close");
    httpd_resp_set_status(req, "413 Payload Too Large");
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_sendstr(req, "Body too large");
    return true;
}

static bool ensure_get_or_post(httpd_req_t* req)
{
    if (req->method == HTTP_GET) return true;
    if (req->method == HTTP_POST) return check_csrf(req);
    set_json_no_cache(req);
    httpd_resp_set_status(req, "405 Method Not Allowed");
    httpd_resp_set_hdr(req, "Allow", "GET, POST");
    httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"This endpoint only supports GET/POST\"}");
    return false;
}

static esp_err_t send_gzip_asset(httpd_req_t* req, const WebAsset& asset, const char* cache_control)
{
    const bool no_store = cache_has_token(cache_control, "no-store");
    httpd_resp_set_hdr(req, "Cache-Control", cache_control);
    if (!no_store) {
        httpd_resp_set_hdr(req, "ETag", asset.etag);
    }
    httpd_resp_set_hdr(req, "Vary", "Authorization, Accept-Encoding");

    if (!no_store && etag_matches(req, asset)) {
        httpd_resp_set_status(req, "304 Not Modified");
        return httpd_resp_send(req, nullptr, 0);
    }

    httpd_resp_set_type(req, asset.mime);
    httpd_resp_set_hdr(req, "Content-Encoding", "gzip");
    return httpd_resp_send(req, reinterpret_cast<const char*>(asset.data), asset.length);
}

static esp_err_t handle_root(httpd_req_t* req)
{
    // Provisioning AP mode serves only the self-contained passwordless setup page, never the full UI or saved configuration.
    if (idf_wifi_is_ap_mode() && request_is_on_ap_interface(req) &&
        strcspn(req->uri, "?") == 1 && req->uri[0] == '/') {
        return send_gzip_asset(req, WEB_AP, "no-store, max-age=0");
    }
    if (!check_auth(req)) return ESP_OK;
    return send_gzip_asset(req, WEB_INDEX, "no-store, max-age=0");
}

static esp_err_t handle_asset(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (strstr(req->uri, "/app.css")) {
        return send_gzip_asset(req, WEB_APP_CSS, "private, max-age=31536000, immutable");
    }
    if (strstr(req->uri, "/app.js")) {
        return send_gzip_asset(req, WEB_APP_JS, "private, max-age=31536000, immutable");
    }
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not Found");
    return ESP_OK;
}

static esp_err_t handle_ui_panel(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;

    char query[96] = {};
    char panel[32] = {};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, "panel", panel, sizeof(panel)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing panel");
        return ESP_OK;
    }

    const WebAsset* asset = findWebPanelAsset(panel);
    if (!asset) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Unknown panel");
        return ESP_OK;
    }
    return send_gzip_asset(req, *asset, "no-store, max-age=0");
}

static esp_err_t handle_status(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    char query[32] = {};
    char sample[8] = {};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "sample", sample, sizeof(sample)) == ESP_OK &&
        strcmp(sample, "1") == 0) {
        idf_modem_request_status_sample();
    }
    set_json_no_cache(req);

    // Use a narrow snapshot because /status is polled every 2s; copying all configuration would churn the heap.
    const IdfConfigStatusView cfg = idf_config_get_status_view();
    IdfWifiStatus wifi = idf_wifi_get_status();
    IdfModemStatus modem = idf_modem_get_status();
    IdfSmsStatus sms = idf_sms_get_status();
    time_t now = time(nullptr);
    uint64_t uptime = esp_timer_get_time() / 1000000ULL;

    std::string body;
    body.reserve(2350);
    char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"version\":\"%s\",\"idfPort\":true,\"modemReady\":%s,"
             "\"modemInitPhase\":\"%s\",\"ceregStat\":%d,"
             "\"signalFresh\":%s,\"identityFresh\":%s,"
             "\"webAssetHash\":\"%s\",",
             IDF_FW_VERSION,
             modem.modemReady ? "true" : "false",
             modem.phase.c_str(), modem.ceregStat,
             modem.signalFresh ? "true" : "false",
             modem.identityFresh ? "true" : "false",
             WEB_ASSET_HASH);
    body += buf;
    json_prop(body, "simState", modem.simState); body += ",";
    body += "\"simCredentialMatched\":";
    body += modem.simCredentialMatched ? "true," : "false,";
    json_prop(body, "simUnlockMessage", modem.simUnlockMessage); body += ",";
    snprintf(buf, sizeof(buf), "\"tz\":%d,", cfg.tzOffsetMin);
    body += buf;
    snprintf(buf, sizeof(buf), "\"nowEpoch\":%ld,", static_cast<long>(now));
    body += buf;
    snprintf(buf, sizeof(buf),
              "\"uptime\":%llu,\"resetReason\":%d,"
              "\"freeHeap\":%u,\"minFreeHeap\":%u,\"maxAllocHeap\":%u,\"httpStackFree\":%u,",
              static_cast<unsigned long long>(uptime), static_cast<int>(esp_reset_reason()),
              static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_8BIT)),
              static_cast<unsigned>(esp_get_minimum_free_heap_size()),
              static_cast<unsigned>(heap_caps_get_largest_free_block(MALLOC_CAP_8BIT)),
              static_cast<unsigned>(uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t)));
    body += buf;
    snprintf(buf, sizeof(buf),
             "\"smsTotal\":%u,\"lastSmsEpoch\":%u,",
             static_cast<unsigned>(sms.total),
             static_cast<unsigned>(sms.lastSmsEpoch));
    body += buf;
    snprintf(buf, sizeof(buf),
             "\"inboxCount\":%u,"
             "\"fwdQueueDepth\":%d,\"queueDepth\":%d,\"outSmsQueueDepth\":%d,\"emailQueueDepth\":%d,"
             "\"slowBusy\":%s,\"timeSynced\":%s,",
             static_cast<unsigned>(idf_inbox_count()),
             idf_push_forward_queue_depth(),
             idf_push_retry_queue_depth(),
             idf_sms_outgoing_queue_depth(),
             idf_push_email_queue_depth(),
             idf_push_busy() ? "true" : "false",
             now > 100000 ? "true" : "false");
    body += buf;
    if (modem.csq >= 0) {
        snprintf(buf, sizeof(buf), "\"csq\":%d,\"ber\":%d,", modem.csq, modem.ber);
        body += buf;
    } else {
        body += "\"csq\":null,\"ber\":99,";
    }
    if (modem.rsrp != 999) {
        snprintf(buf, sizeof(buf), "\"rsrp\":%d,", modem.rsrp);
        body += buf;
    } else {
        body += "\"rsrp\":null,";
    }
    if (modem.rsrq != 999) {
        snprintf(buf, sizeof(buf), "\"rsrq\":%d,", modem.rsrq);
        body += buf;
    } else {
        body += "\"rsrq\":null,";
    }
    if (modem.sinr != 999) {
        snprintf(buf, sizeof(buf), "\"sinr\":%d,", modem.sinr);
        body += buf;
    } else {
        body += "\"sinr\":null,";
    }

    snprintf(buf, sizeof(buf),
             "\"dataEnabled\":%s,\"emailEnabled\":%s,\"emailConfigured\":%s,"
             "\"pushEnabled\":%s,\"pushEnabledCount\":%d,\"apMode\":%s,",
             cfg.dataEnabled ? "true" : "false",
             cfg.emailEnabled ? "true" : "false",
             cfg.emailConfigured ? "true" : "false",
             cfg.pushEnabled ? "true" : "false",
             cfg.pushEnabledCount,
             wifi.apMode ? "true" : "false");
    body += buf;

    json_prop(body, "ssid", wifi.staConnected ? wifi.ssid : wifi.apSsid); body += ",";
    json_prop(body, "ip", wifi.staConnected ? wifi.ip : wifi.apIp); body += ",";
    json_prop(body, "gw", wifi.gw); body += ",";
    json_prop(body, "mask", wifi.mask); body += ",";
    json_prop(body, "dns", wifi.dns); body += ",";
    json_prop(body, "mac", wifi.mac); body += ",";
    json_prop(body, "bssid", wifi.bssid); body += ",";
    if (wifi.staConnected) {
        snprintf(buf, sizeof(buf), "\"rssi\":%d,\"chan\":%d,", wifi.rssi, wifi.channel);
        body += buf;
    } else {
        body += "\"rssi\":null,\"chan\":0,";
    }

    json_prop(body, "adminPhone", cfg.adminPhone); body += ",";
    json_prop(body, "phone", modem.phone.empty() ? cfg.phoneNumber : modem.phone); body += ",";
    json_prop(body, "apn", cfg.apn); body += ",";
    json_prop(body, "apnSim", modem.apnSim); body += ",";
    json_prop(body, "cellIp", modem.cellIp); body += ",";
    json_prop(body, "operator", modem.operatorName); body += ",";
    json_prop(body, "mfr", modem.mfr); body += ",";
    json_prop(body, "model", modem.model); body += ",";
    json_prop(body, "fwver", modem.fwver); body += ",";
    json_prop(body, "imei", modem.imei); body += ",";
    json_prop(body, "iccid", modem.iccid); body += ",";
    json_prop(body, "imsi", modem.imsi);
    float temp = 0;
    if (read_chip_temp(temp)) {
        snprintf(buf, sizeof(buf), ",\"chipTemp\":%.1f}", static_cast<double>(temp));
        body += buf;
    } else {
        body += ",\"chipTemp\":null}";
    }

    return httpd_resp_send(req, body.c_str(), body.size());
}

[[maybe_unused]] static esp_err_t send_config_json(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    set_json_no_cache(req);

    const IdfConfigWebView cfg = idf_config_get_web_view();
    std::string body;
    body.reserve(4096);
    char buf[256];
    body += "{";
    json_prop(body, "webUser", cfg.webUser); body += ",";
    // Password fields are form placeholders only; never echo plaintext in configuration JSON.
    json_prop(body, "webPass", ""); body += ",";
    json_prop(body, "smtpServer", cfg.smtpServer); body += ",";
    snprintf(buf, sizeof(buf), "\"smtpPort\":%d,", cfg.smtpPort); body += buf;
    json_prop(body, "smtpUser", cfg.smtpUser); body += ",";
    json_prop(body, "smtpPass", ""); body += ",";
    snprintf(buf, sizeof(buf), "\"smtpPassSet\":%s,", cfg.smtpPass.empty() ? "false" : "true");
    body += buf;
    json_prop(body, "smtpSendTo", cfg.smtpSendTo); body += ",";
    json_prop(body, "adminPhone", cfg.adminPhone); body += ",";
    json_prop(body, "numberBlackList", cfg.numberBlackList); body += ",";
    json_prop(body, "forwardRules", cfg.forwardRules); body += ",";
    snprintf(buf, sizeof(buf),
             "\"emailEnabled\":%s,\"emailConfigured\":%s,\"pushEnabled\":%s,"
             "\"pushEnabledCount\":%d,\"modemReady\":%s,\"inboxMax\":50,",
             cfg.emailEnabled ? "true" : "false",
              cfg.emailConfigured ? "true" : "false",
              cfg.pushEnabled ? "true" : "false",
              cfg.pushEnabledCount,
              idf_modem_get_status().modemReady ? "true" : "false");
    body += buf;
    json_prop(body, "ntpServer", cfg.ntpServer); body += ",";
    json_prop(body, "mdnsHost", cfg.mdnsHost); body += ",";
    snprintf(buf, sizeof(buf),
             "\"tzOffsetMin\":%d,\"rebootEnabled\":%s,\"rebootHour\":%d,"
             "\"hbEnabled\":%s,\"hbHour\":%d,"
             "\"smsHealthEnabled\":%s,\"smsHealthHour\":%d,\"smsHealthNotify\":%s,"
             "\"dataEnabled\":%s,\"roamingEnabled\":%s,"
             "\"kaEnabled\":%s,\"kaIntervalDays\":%d,\"kaTrafficKB\":%d,",
             cfg.tzOffsetMin,
             cfg.rebootEnabled ? "true" : "false", cfg.rebootHour,
             cfg.hbEnabled ? "true" : "false", cfg.hbHour,
             cfg.smsHealthEnabled ? "true" : "false", cfg.smsHealthHour,
             cfg.smsHealthNotify ? "true" : "false",
             cfg.dataEnabled ? "true" : "false",
             cfg.roamingEnabled ? "true" : "false",
             cfg.kaEnabled ? "true" : "false", cfg.kaIntervalDays, cfg.kaTrafficKB);
    body += buf;
    json_prop(body, "apn", cfg.apn); body += ",";
    json_prop(body, "phoneNumber", cfg.phoneNumber); body += ",";
    json_prop(body, "operatorPlmn", cfg.operatorPlmn); body += ",";
    json_prop(body, "kaProfile", cfg.kaProfile); body += ",";
    body += "\"netLedEnabled\":";
    body += cfg.netLedEnabled ? "true" : "false";
    body += ",";
    body += "\"callNotifyEnabled\":";
    body += cfg.callNotifyEnabled ? "true" : "false";
    body += ",";
    snprintf(buf, sizeof(buf), "\"wifiTxPowerQuarterDbm\":%u,", cfg.wifiTxPowerQuarterDbm);
    body += buf;
    body += "\"simCredentials\":[";
    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        if (i) body += ",";
        const IdfSimCredentialView& item = cfg.simCredentials[i];
        body += "{";
        json_prop(body, "iccid", item.iccid); body += ",";
        snprintf(buf, sizeof(buf),
                 "\"pinSet\":%s,\"pukSet\":%s,\"pinMax\":%u,\"pukMax\":%u,"
                 "\"pinFailed\":%u,\"pukFailed\":%u}",
                 item.pinSet ? "true" : "false", item.pukSet ? "true" : "false",
                 item.pinMaxAttempts, item.pukMaxAttempts,
                 item.pinFailedAttempts, item.pukFailedAttempts);
        body += buf;
    }
    body += "],";
    body += "\"wifiNetworks\":[";
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        if (i) body += ",";
        body += "{";
        json_prop(body, "ssid", cfg.wifiNetworks[i].ssid);
        body += ",\"passSet\":";
        body += cfg.wifiNetworks[i].passSet ? "true" : "false";
        body += "}";
    }
    body += "],";
    body += "\"pushChannels\":[";
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        if (i) body += ",";
        const IdfPushChannel& ch = cfg.pushChannels[i];
        snprintf(buf, sizeof(buf), "{\"enabled\":%s,\"type\":%u,",
                 ch.enabled ? "true" : "false", static_cast<unsigned>(ch.type));
        body += buf;
        bool key1_redacted = push_key_sensitive(ch.type, 1);
        bool key2_redacted = push_key_sensitive(ch.type, 2);
        json_prop(body, "name", ch.name); body += ",";
        json_prop(body, "url", ch.url); body += ",";
        json_prop(body, "key1", key1_redacted ? std::string() : ch.key1); body += ",";
        snprintf(buf, sizeof(buf), "\"key1Set\":%s,\"key1Redacted\":%s,",
                 ch.key1.empty() ? "false" : "true", key1_redacted ? "true" : "false");
        body += buf;
        json_prop(body, "key2", key2_redacted ? std::string() : ch.key2); body += ",";
        snprintf(buf, sizeof(buf), "\"key2Set\":%s,\"key2Redacted\":%s,",
                 ch.key2.empty() ? "false" : "true", key2_redacted ? "true" : "false");
        body += buf;
        json_prop(body, "customBody", ch.customBody);
        body += "}";
    }
    {
        uint64_t up_s = esp_timer_get_time() / 1000000ULL;
        unsigned days = static_cast<unsigned>(up_s / 86400ULL);
        unsigned hours = static_cast<unsigned>((up_s / 3600ULL) % 24ULL);
        unsigned mins = static_cast<unsigned>((up_s / 60ULL) % 60ULL);
        char up_buf[64];
        if (days > 0) snprintf(up_buf, sizeof(up_buf), "%ud %uh %um", days, hours, mins);
        else if (hours > 0) snprintf(up_buf, sizeof(up_buf), "%uh %um", hours, mins);
        else snprintf(up_buf, sizeof(up_buf), "%um", mins);
        body += "],\"uptimeText\":\"";
        body += up_buf;
        body += "\"}";
    }
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_api_config(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    const IdfConfigWebView cfg = idf_config_get_web_view();
    const IdfWifiStatus wifi = idf_wifi_get_status();
    const IdfModemStatus modem = idf_modem_get_status();

    std::string body;
    body.reserve(6144);
    char buf[256];
    body += "{";
    json_prop(body, "csrfToken", s_csrf_token);
    body += ",\"status\":{";
    json_prop(body, "ip", wifi.staConnected ? wifi.ip : wifi.apIp); body += ",";
    json_prop(body, "wifiSsid", wifi.staConnected ? wifi.ssid : wifi.apSsid);
    snprintf(buf, sizeof(buf),
             ",\"apMode\":%s,\"freeHeapKb\":%u,\"uptimeSeconds\":%llu,"
             "\"modemReady\":%s,\"emailConfigured\":%s,\"enabledPushChannels\":%d,",
             wifi.apMode ? "true" : "false",
             static_cast<unsigned>(esp_get_free_heap_size() / 1024),
             static_cast<unsigned long long>(esp_timer_get_time() / 1000000ULL),
             modem.modemReady ? "true" : "false",
             cfg.emailConfigured ? "true" : "false",
             cfg.pushEnabledCount);
    body += buf;
    json_prop(body, "firmwareVersion", IDF_FW_VERSION);
    body += "},\"config\":{";
    json_prop(body, "deviceName", cfg.deviceName); body += ",";
    json_prop(body, "hostname", cfg.hostname); body += ",";
    json_prop(body, "notificationLocale", cfg.notificationLocale); body += ",";
    snprintf(buf, sizeof(buf), "\"emailEnabled\":%s,\"pushEnabled\":%s,",
             cfg.emailEnabled ? "true" : "false", cfg.pushEnabled ? "true" : "false");
    body += buf;
    body += "\"webAccounts\":[";
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        if (i) body += ",";
        body += "{";
        json_prop(body, "username", cfg.webAccounts[i].username); body += ",";
        json_prop(body, "password", "");
        body += "}";
    }
    body += "],";
    json_prop(body, "smtpServer", cfg.smtpServer); body += ",";
    snprintf(buf, sizeof(buf), "\"smtpPort\":%d,", cfg.smtpPort); body += buf;
    json_prop(body, "smtpUser", cfg.smtpUser); body += ",";
    json_prop(body, "smtpPass", ""); body += ",";
    json_prop(body, "smtpSendTo", cfg.smtpSendTo); body += ",";
    json_prop(body, "adminPhone", cfg.adminPhone); body += ",";
    json_prop(body, "numberBlackList", cfg.numberBlackList); body += ",";
    json_prop(body, "forwardRules", cfg.forwardRules); body += ",";
    body += "\"wifiProfiles\":[";
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        if (i) body += ",";
        const IdfWifiNetworkView& profile = cfg.wifiNetworks[i];
        body += "{";
        json_prop(body, "ssid", profile.ssid); body += ",";
        json_prop(body, "password", "");
        body += ",\"open\":";
        body += (!profile.ssid.empty() && !profile.passSet) ? "true" : "false";
        body += "}";
    }
    snprintf(buf, sizeof(buf),
             "],\"networkMode\":%d,\"heartbeatEnable\":%s,\"heartbeatInterval\":%d,"
             "\"kaEnabled\":%s,\"kaIntervalDays\":%d,\"kaTrafficKB\":%d,",
             cfg.networkMode, cfg.heartbeatEnable ? "true" : "false", cfg.heartbeatInterval,
             cfg.kaEnabled ? "true" : "false", cfg.kaIntervalDays, cfg.kaTrafficKB);
    body += buf;
    body += "\"pushChannels\":[";
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        if (i) body += ",";
        const IdfPushChannel& channel = cfg.pushChannels[i];
        snprintf(buf, sizeof(buf), "{\"enabled\":%s,\"type\":%u,",
                 channel.enabled ? "true" : "false", static_cast<unsigned>(channel.type));
        body += buf;
        json_prop(body, "name", channel.name); body += ",";
        json_prop(body, "url", ""); body += ",\"urlSet\":";
        body += cfg.pushUrlSet[i] ? "true" : "false"; body += ",";
        json_prop(body, "key1", ""); body += ",\"key1Set\":";
        body += cfg.pushKey1Set[i] ? "true" : "false"; body += ",";
        json_prop(body, "key2", ""); body += ",\"key2Set\":";
        body += cfg.pushKey2Set[i] ? "true" : "false"; body += ",";
        json_prop(body, "customBody", ""); body += ",\"customBodySet\":";
        body += cfg.pushCustomBodySet[i] ? "true" : "false"; body += ",";
        json_prop(body, "titleTemplate", channel.titleTemplate); body += ",";
        json_prop(body, "bodyTemplate", channel.bodyTemplate);
        body += "}";
    }
    body += "]}}";
    set_json_no_cache(req);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_query(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    std::string type;
    if (!get_query_param(req, "type", type, 64) || type.size() > 32) {
        set_json_no_cache(req);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req,
            "{\"success\":false,\"code\":\"ACTION_INPUT_INVALID\",\"data\":{},\"detail\":\"type\"}");
    }
    if (!(type == "ati" || type == "signal" || type == "siminfo" ||
          type == "network" || type == "wifi")) {
        set_json_no_cache(req);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req,
            "{\"success\":false,\"code\":\"ACTION_QUERY_UNKNOWN\",\"data\":{},\"detail\":\"type\"}");
    }
    return enqueue_api_job(req, "query", type);
}

static esp_err_t read_body(httpd_req_t* req, std::string& body, size_t max_len = 8192)
{
    if (req->content_len > max_len) {
        set_no_cache_headers(req);
        httpd_resp_send_err(req, HTTPD_413_CONTENT_TOO_LARGE, "Body too large");
        return ESP_FAIL;
    }
    body.assign(req->content_len, '\0');
    size_t received = 0;
    int timeouts = 0;
    // Any received byte resets the consecutive timeout count, so a trickle client could hold the
    // sole httpd worker for hours. Enforce a hard total-duration limit as well.
    const TickType_t start_tick = xTaskGetTickCount();
    const TickType_t hard_span = pdMS_TO_TICKS(30000);
    while (received < body.size()) {
        if (static_cast<TickType_t>(xTaskGetTickCount() - start_tick) >= hard_span) {
            set_no_cache_headers(req);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Receive too slow");
            return ESP_FAIL;
        }
        int ret = httpd_req_recv(req, body.data() + received, body.size() - received);
        if (ret <= 0) {
            // Allow at most three timeouts (~15s). httpd handles requests serially, so one stalled
            // client can block the entire Web UI until restart.
            if (ret == HTTPD_SOCK_ERR_TIMEOUT && ++timeouts <= 3) continue;
            set_no_cache_headers(req);
            httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Receive failed");
            return ESP_FAIL;
        }
        timeouts = 0;
        received += static_cast<size_t>(ret);
    }
    return ESP_OK;
}

static void send_modem_busy_json(httpd_req_t* req)
{
    set_json_no_cache(req);
    httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"The modem or a cellular/eSIM task is busy; try again later\"}");
}

// Direct Web AT operations do not hold the state lock; a short-lived flag prevents eSIM/keepalive work from interleaving AT commands.
class WebModemActionGuard {
public:
    WebModemActionGuard() = default;
    WebModemActionGuard(const WebModemActionGuard&) = delete;
    WebModemActionGuard& operator=(const WebModemActionGuard&) = delete;

    bool begin(httpd_req_t* req)
    {
        if (!cell_job_lock()) {
            send_modem_busy_json(req);
            return false;
        }
        if (cellular_job_active_locked() || !idf_modem_at_idle()) {
            cell_job_unlock();
            send_modem_busy_json(req);
            return false;
        }
        s_web_modem_action_running = true;
        m_active = true;
        cell_job_unlock();
        return true;
    }

    ~WebModemActionGuard()
    {
        if (!m_active) return;
        if (cell_job_lock(portMAX_DELAY)) {
            s_web_modem_action_running = false;
            cell_job_unlock();
        }
    }

private:
    bool m_active = false;
};

static IdfFormFields parse_urlencoded(const std::string& body)
{
    return idf_web_decode_form(body, 48).fields;
}

static const std::string* find_field(const IdfFormFields& fields, const char* key)
{
    const auto field = std::find_if(fields.begin(), fields.end(), [key](const auto& item) {
        return item.first == key;
    });
    return field == fields.end() ? nullptr : &field->second;
}

static bool has_field(const IdfFormFields& fields, const char* key)
{
    return find_field(fields, key) != nullptr;
}

static std::string field_text(const IdfFormFields& fields, const char* key)
{
    const std::string* value = find_field(fields, key);
    return value ? *value : std::string();
}

static bool field_blank(const std::string& value)
{
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return isspace(static_cast<unsigned char>(ch));
    });
}

static bool parse_int_strict(const std::string& text, int& out)
{
    errno = 0;
    char* end = nullptr;
    long parsed = strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || errno == ERANGE || parsed < INT_MIN || parsed > INT_MAX) {
        return false;
    }
    while (*end != '\0') {
        if (!isspace(static_cast<unsigned char>(*end))) return false;
        ++end;
    }
    out = static_cast<int>(parsed);
    return true;
}

static bool parse_u32_strict(const char* raw, uint32_t& value, bool allow_zero)
{
    if (!raw || raw[0] == '\0') return false;
    uint32_t parsed = 0;
    for (size_t i = 0; raw[i] != '\0'; ++i) {
        if (!isdigit(static_cast<unsigned char>(raw[i]))) return false;
        uint8_t digit = static_cast<uint8_t>(raw[i] - '0');
        if (parsed > 429496729U || (parsed == 429496729U && digit > 5)) return false;
        parsed = parsed * 10U + digit;
    }
    if (!allow_zero && parsed == 0) return false;
    value = parsed;
    return true;
}

static int field_int(const IdfFormFields& fields, const char* key, int fallback)
{
    const std::string* value = find_field(fields, key);
    if (!value) return fallback;
    int parsed = fallback;
    return parse_int_strict(*value, parsed) ? parsed : fallback;
}

static uint8_t field_u8(const IdfFormFields& fields, const char* key, uint8_t fallback)
{
    int parsed = field_int(fields, key, fallback);
    if (parsed < 0 || parsed > 255) return fallback;
    return static_cast<uint8_t>(parsed);
}

static bool get_query_param(httpd_req_t* req, const char* key, std::string& out, size_t max_query = 192)
{
    std::string query(max_query, '\0');
    if (httpd_req_get_url_query_str(req, query.data(), query.size()) != ESP_OK) return false;
    char raw[512] = {};
    if (httpd_query_key_value(query.c_str(), key, raw, sizeof(raw)) != ESP_OK) return false;
    IdfWebFormDecodeResult decoded = idf_web_decode_form(std::string("x=") + raw, 1);
    if (!decoded.valid || decoded.fields.empty()) return false;
    out = std::move(decoded.fields[0].second);
    return true;
}

static std::string first_line_containing(const std::string& resp, const char* needle)
{
    size_t p = resp.find(needle);
    if (p == std::string::npos) return {};
    size_t start = resp.rfind('\n', p);
    start = (start == std::string::npos) ? 0 : start + 1;
    size_t end = resp.find('\n', p);
    if (end == std::string::npos) end = resp.size();
    std::string line = resp.substr(start, end - start);
    while (!line.empty() && (line.back() == '\r' || line.back() == '\n')) line.pop_back();
    while (!line.empty() && isspace(static_cast<unsigned char>(line.front()))) line.erase(0, 1);
    return line;
}

static std::string first_digits(const std::string& resp)
{
    size_t pos = 0;
    while (pos < resp.size()) {
        size_t end = resp.find('\n', pos);
        if (end == std::string::npos) end = resp.size();
        std::string line = resp.substr(pos, end - pos);
        while (!line.empty() && isspace(static_cast<unsigned char>(line.front()))) line.erase(0, 1);
        while (!line.empty() && isspace(static_cast<unsigned char>(line.back()))) line.pop_back();
        bool digits = !line.empty();
        for (char ch : line) digits = digits && isdigit(static_cast<unsigned char>(ch));
        if (digits && line.size() >= 14 && line.size() <= 17) return line;
        pos = end + 1;
    }

    size_t start = std::string::npos;
    for (size_t i = 0; i <= resp.size(); ++i) {
        bool digit = i < resp.size() && isdigit(static_cast<unsigned char>(resp[i]));
        if (digit && start == std::string::npos) start = i;
        if (!digit && start != std::string::npos) {
            size_t len = i - start;
            if (len >= 14 && len <= 17) return resp.substr(start, len);
            start = std::string::npos;
        }
    }
    return {};
}

static bool parse_cfun_mode_line(const std::string& line, int& mode)
{
    const char* p = strstr(line.c_str(), "+CFUN:");
    if (!p) return false;
    int parsed = -1;
    if (!parse_int_strict(std::string(p + strlen("+CFUN:")), parsed)) return false;
    if (parsed < 0 || parsed > 4) return false;
    mode = parsed;
    return true;
}

static bool parse_csq_line(const std::string& line, int& rssi, int& ber)
{
    const char* p = strstr(line.c_str(), "+CSQ:");
    if (!p) return false;
    std::string rest = p + strlen("+CSQ:");
    size_t comma = rest.find(',');
    if (comma == std::string::npos) return false;
    int parsed_rssi = 99;
    int parsed_ber = 99;
    if (!parse_int_strict(rest.substr(0, comma), parsed_rssi)) return false;
    if (!parse_int_strict(rest.substr(comma + 1), parsed_ber)) return false;
    if (!((parsed_rssi >= 0 && parsed_rssi <= 31) || parsed_rssi == 99)) return false;
    if (!((parsed_ber >= 0 && parsed_ber <= 7) || parsed_ber == 99)) return false;
    rssi = parsed_rssi;
    ber = parsed_ber;
    return true;
}

static std::string action_result(bool success, const char* code,
                                 const std::string& data = {}, const std::string& detail = {})
{
    std::string out = "{\"success\":";
    out += success ? "true" : "false";
    out += ",";
    json_prop(out, "code", code);
    out += ",\"data\":{";
    out += data;
    out += "},";
    json_prop(out, "detail", detail);
    out += "}";
    return out;
}

static uint32_t web_now_ms()
{
    return static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
}

static uint32_t next_transfer_id()
{
    uint32_t id = esp_random();
    return id == 0 ? 1 : id;
}

static bool backup_lock(TickType_t ticks = pdMS_TO_TICKS(300))
{
    return s_backup_mutex && xSemaphoreTake(s_backup_mutex, ticks) == pdTRUE;
}

static void backup_unlock()
{
    xSemaphoreGive(s_backup_mutex);
}

static void backup_clear_claim()
{
    if (!backup_lock(portMAX_DELAY)) return;
    idf_web_transfer_clear(s_backup_transfer);
    backup_unlock();
}

static void backup_cancel_upload(uint32_t id)
{
    if (!backup_lock(portMAX_DELAY)) return;
    idf_web_transfer_expire(s_backup_transfer, web_now_ms(), BACKUP_TTL_MS);
    idf_web_transfer_cancel_upload(s_backup_transfer, id);
    backup_unlock();
}

static bool backup_transfer_active()
{
    if (!backup_lock()) return true;
    idf_web_transfer_expire(s_backup_transfer, web_now_ms(), BACKUP_TTL_MS);
    const bool active = s_backup_transfer.mode != IdfWebTransferMode::None;
    backup_unlock();
    return active;
}

static bool api_jobs_active()
{
    if (!s_api_job_mutex || xSemaphoreTake(s_api_job_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return true;
    IdfWebJobSlotMeta metas[API_JOB_SLOTS];
    for (size_t i = 0; i < API_JOB_SLOTS; ++i) metas[i] = s_api_jobs[i].meta;
    const bool active = idf_web_count_active_jobs(metas, API_JOB_SLOTS) != 0;
    xSemaphoreGive(s_api_job_mutex);
    return active;
}

static bool api_jobs_visible()
{
    if (!s_api_job_mutex || xSemaphoreTake(s_api_job_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return true;
    IdfWebJobSlotMeta metas[API_JOB_SLOTS];
    for (size_t i = 0; i < API_JOB_SLOTS; ++i) metas[i] = s_api_jobs[i].meta;
    const uint32_t now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
    const bool visible = idf_web_count_visible_jobs(metas, API_JOB_SLOTS, now_ms, API_JOB_TTL_MS) != 0;
    xSemaphoreGive(s_api_job_mutex);
    return visible;
}

static bool ota_active()
{
    idf_web_ota_expire(web_now_ms(), OTA_TTL_MS);
    return idf_web_ota_active();
}

static void clear_api_job_sensitive(ApiJob& job)
{
    idf_web_secure_clear(job.input.payload);
    idf_web_secure_clear(job.binary);
}

static std::string run_backup_export_job(const std::string& passphrase)
{
    uint32_t export_id = 0;
    if (backup_lock(portMAX_DELAY)) {
        if (s_backup_transfer.mode == IdfWebTransferMode::Export) export_id = s_backup_transfer.id;
        backup_unlock();
    }
    if (export_id == 0) return action_result(false, "ACTION_BUSY");

    IdfWebOwnedBytes plaintext;
    if (!idf_web_allocate_owned_bytes(plaintext, MAX_CONFIG_BLOB_SIZE)) {
        backup_clear_claim();
        return action_result(false, "ACTION_CONFIG_EXPORT_FAILED");
    }
    size_t written = 0;
    const esp_err_t err = idf_config_export_portable(
        plaintext.data.get(), plaintext.capacity, &written);
    if (err != ESP_OK ||
        !idf_web_finalize_owned_bytes(plaintext, written, MAX_CONFIG_BLOB_SIZE)) {
        idf_web_secure_clear(plaintext);
        backup_clear_claim();
        return action_result(false, "ACTION_CONFIG_EXPORT_FAILED");
    }
    uint8_t salt[BACKUP_SALT_BYTES] = {};
    uint8_t iv[BACKUP_IV_BYTES] = {};
    esp_fill_random(salt, sizeof(salt));
    esp_fill_random(iv, sizeof(iv));
    IdfWebOwnedBytes encrypted;
    const IdfWebCryptoResult crypto = idf_web_encrypt_backup(
        plaintext.data.get(), plaintext.size, passphrase, salt, iv, encrypted);
    idf_web_secure_clear(plaintext);
    memset(salt, 0, sizeof(salt));
    memset(iv, 0, sizeof(iv));
    if (crypto != IdfWebCryptoResult::Ok) {
        idf_web_secure_clear(encrypted);
        backup_clear_claim();
        return action_result(false, "ACTION_CONFIG_EXPORT_FAILED");
    }
    bool stored = false;
    if (backup_lock(portMAX_DELAY)) {
        if (s_backup_transfer.mode == IdfWebTransferMode::Export &&
            s_backup_transfer.id == export_id) {
            s_backup_transfer.bytes = std::move(encrypted);
            s_backup_transfer.expected_size = s_backup_transfer.bytes.size;
            s_backup_transfer.started_ms = web_now_ms();
            stored = true;
        }
        backup_unlock();
    }
    idf_web_secure_clear(encrypted);
    if (!stored) return action_result(false, "ACTION_CONFIG_EXPORT_FAILED");
    return action_result(true, "ACTION_CONFIG_EXPORT_READY",
                         "\"exportId\":" + std::to_string(export_id));
}

static std::string run_backup_restore_job(uint32_t job_id, const std::string& passphrase,
                                          IdfWebOwnedBytes& encrypted)
{
    IdfWebOwnedBytes plaintext;
    const IdfWebCryptoResult crypto = idf_web_decrypt_backup(
        encrypted.data.get(), encrypted.size, passphrase, plaintext);
    restore_lifecycle_decrypt(job_id, static_cast<uint32_t>(crypto));
    idf_logf("API restore decrypt id=%u result=%u", static_cast<unsigned>(job_id),
             static_cast<unsigned>(crypto));
    idf_web_secure_clear(encrypted);
    if (crypto != IdfWebCryptoResult::Ok) {
        idf_web_secure_clear(plaintext);
        return action_result(false, crypto == IdfWebCryptoResult::InvalidPassphrase ?
            "ACTION_CONFIG_PASSPHRASE_INVALID" : "ACTION_CONFIG_RESTORE_INVALID");
    }
    IdfPortableConfigStatus status = IdfPortableConfigStatus::Invalid;
    const esp_err_t err = idf_config_restore_portable(plaintext.data.get(), plaintext.size, &status);
    restore_lifecycle_config(job_id, static_cast<int32_t>(err), static_cast<uint32_t>(status));
    idf_logf("API restore config id=%u err=%d status=%u", static_cast<unsigned>(job_id),
             static_cast<int>(err), static_cast<unsigned>(status));
    idf_web_secure_clear(plaintext);
    if (err == ESP_OK) return action_result(true, "ACTION_CONFIG_RESTORED");
    if (status == IdfPortableConfigStatus::UnsupportedVersion) {
        return action_result(false, "ACTION_CONFIG_RESTORE_INVALID", {}, "unsupportedVersion");
    }
    if (status == IdfPortableConfigStatus::Invalid) {
        return action_result(false, "ACTION_CONFIG_RESTORE_INVALID");
    }
    return action_result(false, "ACTION_CONFIG_RESTORE_SAVE_FAILED");
}

static const char* ota_action_code(IdfWebOtaCode code)
{
    switch (code) {
        case IdfWebOtaCode::Ok: return "ACTION_OTA_READY";
        case IdfWebOtaCode::HashInvalid: return "ACTION_OTA_HASH_INVALID";
        case IdfWebOtaCode::FinalizeFailed: return "ACTION_OTA_FINALIZE_FAILED";
        case IdfWebOtaCode::MetadataFailed:
        case IdfWebOtaCode::BootFailed: return "ACTION_OTA_METADATA_FAILED";
        case IdfWebOtaCode::WriteFailed: return "ACTION_OTA_WRITE_FAILED";
        default: return "ACTION_OTA_SESSION_INVALID";
    }
}

static std::string run_ota_finish_job(const std::string& raw_id)
{
    uint32_t id = 0;
    if (!parse_u32_strict(raw_id.c_str(), id, false)) {
        return action_result(false, "ACTION_OTA_SESSION_INVALID");
    }
    const IdfWebOtaCode result = idf_web_ota_finish(id);
    return action_result(result == IdfWebOtaCode::Ok, ota_action_code(result));
}

static std::string run_query_job(const std::string& type)
{
    std::string data;
    char buf[192];
    if (type == "wifi") {
        const IdfWifiStatus wifi = idf_wifi_get_status();
        snprintf(buf, sizeof(buf), "\"wifiStatus\":%d,", wifi.staConnected ? 3 : 6);
        data += buf;
        json_prop(data, "ssid", wifi.staConnected ? wifi.ssid : wifi.apSsid); data += ",";
        snprintf(buf, sizeof(buf), "\"rssiDbm\":%d,", wifi.rssi); data += buf;
        json_prop(data, "ip", wifi.staConnected ? wifi.ip : wifi.apIp); data += ",";
        json_prop(data, "gateway", wifi.gw); data += ",";
        json_prop(data, "netmask", wifi.mask); data += ",";
        json_prop(data, "dns", wifi.dns); data += ",";
        json_prop(data, "mac", wifi.mac); data += ",";
        json_prop(data, "bssid", wifi.bssid); data += ",";
        snprintf(buf, sizeof(buf), "\"channel\":%d", wifi.channel); data += buf;
        return action_result(true, "ACTION_QUERY_OK", data);
    }

    const IdfModemStatus modem = idf_modem_get_status();
    if (type == "ati") {
        json_prop(data, "manufacturer", modem.mfr); data += ",";
        json_prop(data, "model", modem.model); data += ",";
        json_prop(data, "revision", modem.fwver);
    } else if (type == "signal") {
        if (modem.rsrp == 999) data += "\"rsrpDbm\":null,";
        else { snprintf(buf, sizeof(buf), "\"rsrpDbm\":%d,", modem.rsrp); data += buf; }
        if (modem.rsrq == 999) data += "\"rsrqDb\":null,";
        else { snprintf(buf, sizeof(buf), "\"rsrqDb\":%d,", modem.rsrq); data += buf; }
        snprintf(buf, sizeof(buf), "\"cesq\":\"%d,%d,%d\"", modem.rsrp, modem.rsrq, modem.csq);
        data += buf;
    } else if (type == "siminfo") {
        json_prop(data, "imsi", modem.imsi); data += ",";
        json_prop(data, "iccid", modem.iccid); data += ",";
        json_prop(data, "msisdn", modem.phone);
    } else if (type == "network") {
        if (modem.ceregStat < 0) data += "\"registration\":null,";
        else { snprintf(buf, sizeof(buf), "\"registration\":%d,", modem.ceregStat); data += buf; }
        json_prop(data, "operator", modem.operatorName); data += ",\"pdpActive\":";
        data += modem.cellIp.empty() ? "false," : "true,";
        json_prop(data, "apn", modem.apnSim);
    } else {
        return action_result(false, "ACTION_QUERY_UNKNOWN", {}, "type");
    }
    return action_result(true, "ACTION_QUERY_OK", data);
}

static std::string run_at_job(const std::string& cmd)
{
    if (cmd.empty()) return action_result(false, "ACTION_AT_REQUIRED");
    std::string response;
    esp_err_t err = idf_modem_send_at(cmd, 5000, response);
    std::string data;
    json_prop(data, "raw", response);
    return action_result(err == ESP_OK, err == ESP_OK ? "ACTION_AT_OK" : "ACTION_AT_TIMEOUT", data);
}

static std::string run_sms_job(const std::string& body)
{
    const IdfWebFormDecodeResult decoded = idf_web_decode_form(body, 48);
    if (!decoded.valid) return action_result(false, decoded.too_many_fields ?
        "ACTION_TOO_MANY_FIELDS" : "ACTION_INPUT_INVALID");
    std::string phone = idf_util_trim_copy(field_text(decoded.fields, "phone"));
    std::string content = idf_util_trim_copy(field_text(decoded.fields, "content"));
    if (phone.empty()) return action_result(false, "ACTION_SMS_PHONE_REQUIRED");
    if (content.empty()) return action_result(false, "ACTION_SMS_CONTENT_REQUIRED");
    std::string message;
    const esp_err_t err = idf_sms_enqueue_outgoing(phone, content, message);
    return action_result(err == ESP_OK, err == ESP_OK ? "ACTION_SMS_SENT" : "ACTION_SMS_FAILED",
                         {}, err == ESP_OK ? std::string() : message);
}

static std::string run_ping_job()
{
    return action_result(false, "ACTION_PING_UNSUPPORTED");
}

static std::string run_wifi_job(const std::string& action)
{
    if (action != "restart") return action_result(false, "ACTION_UNKNOWN", {}, "action");
    const esp_err_t err = idf_wifi_reconnect();
    if (err == ESP_OK) idf_log_line("Web UI requested WiFi reconnection");
    return action_result(err == ESP_OK, err == ESP_OK ? "ACTION_WIFI_RESTARTING" : "ACTION_JOB_FAILED");
}

static std::string run_flight_job(const std::string& action)
{
    std::string response;
    int mode = -1;
    bool ok = idf_modem_send_at("AT+CFUN?", 3000, response) == ESP_OK &&
              parse_cfun_mode_line(first_line_containing(response, "+CFUN:"), mode);
    if (ok && action != "query") {
        int target = action == "on" ? 4 : action == "off" ? 1 : mode == 1 ? 4 : 1;
        char cmd[20];
        snprintf(cmd, sizeof(cmd), "AT+CFUN=%d", target);
        ok = idf_modem_send_at(cmd, 8000, response) == ESP_OK;
        if (ok) mode = target;
    }
    if (!(action == "query" || action == "toggle" || action == "on" || action == "off")) {
        return action_result(false, "ACTION_UNKNOWN", {}, "action");
    }
    std::string data = "\"mode\":" + std::to_string(mode);
    const char* code = "ACTION_FLIGHT_FAILED";
    if (ok && action == "query") {
        code = mode == 0 ? "ACTION_FLIGHT_STATUS_OFF" : mode == 1 ? "ACTION_FLIGHT_STATUS_NORMAL" :
               mode == 4 ? "ACTION_FLIGHT_STATUS_ON" : "ACTION_FLIGHT_STATUS_UNKNOWN";
    } else if (ok) {
        code = mode == 4 ? "ACTION_FLIGHT_ENABLED" : "ACTION_FLIGHT_DISABLED";
    }
    return action_result(ok, code, data, ok ? std::string() : response);
}

static std::string run_modem_job(const std::string& action)
{
    std::string response;
    bool ok = false;
    std::string data;
    if (action == "restart" || action == "hardreset") {
        ok = idf_modem_request_reset(action == "hardreset") == ESP_OK;
    } else if (action == "signal") {
        int rssi = 99;
        int ber = 99;
        ok = idf_modem_send_at("AT+CSQ", 3000, response) == ESP_OK &&
             parse_csq_line(first_line_containing(response, "+CSQ:"), rssi, ber);
        if (ok) {
            char buf[96];
            snprintf(buf, sizeof(buf), "\"rssi\":%d,\"ber\":%d,\"signalDbm\":%d",
                     rssi, ber, rssi == 99 ? -999 : -113 + rssi * 2);
            data = buf;
        }
    } else if (action == "operator") {
        idf_modem_send_at("AT+COPS=3,0", 3000, response);
        ok = idf_modem_send_at("AT+COPS?", 5000, response) == ESP_OK;
        json_prop(data, "operator", first_line_containing(response, "+COPS:"));
    } else if (action == "imei") {
        ok = idf_modem_send_at("AT+CGSN", 3000, response) == ESP_OK;
        json_prop(data, "imei", first_digits(response));
    } else {
        return action_result(false, "ACTION_UNKNOWN", {}, "action");
    }
    return action_result(ok, ok ? "ACTION_MODEM_OK" : "ACTION_MODEM_FAILED", data,
                         ok ? std::string() : response);
}

static bool api_job_modem_begin()
{
    if (!cell_job_lock()) return false;
    bool available = !cellular_job_active_locked() && idf_modem_at_idle();
    if (available) s_web_modem_action_running = true;
    cell_job_unlock();
    return available;
}

static void api_job_modem_end()
{
    if (cell_job_lock(portMAX_DELAY)) {
        s_web_modem_action_running = false;
        cell_job_unlock();
    }
}

static void api_job_task(void* raw)
{
    size_t index = reinterpret_cast<uintptr_t>(raw) - 1;
    ApiJob job;
    if (s_api_job_mutex && xSemaphoreTake(s_api_job_mutex, portMAX_DELAY) == pdTRUE) {
        ApiJob& slot = s_api_jobs[index];
        slot.meta.state = IdfWebJobState::Running;
        job.meta = slot.meta;
        job.input.type = slot.input.type;
        job.input.payload = std::move(slot.input.payload);
        job.binary = std::move(slot.binary);
        if (job.input.type == "backup_restore") {
            restore_lifecycle_mark_locked(slot.meta.id, RESTORE_PHASE_STARTED);
        }
        xSemaphoreGive(s_api_job_mutex);
    }
    idf_logf("API job start id=%u restore=%u", static_cast<unsigned>(job.meta.id),
             job.input.type == "backup_restore" ? 1U : 0U);

    const bool needs_modem = job.input.type == "at" || job.input.type == "flight" ||
                             job.input.type == "modem";
    std::string result;
    if (needs_modem && !api_job_modem_begin()) {
        result = action_result(false, "ACTION_MODEM_BUSY");
    } else {
        if (job.input.type == "query") result = run_query_job(job.input.payload);
        else if (job.input.type == "at") result = run_at_job(job.input.payload);
        else if (job.input.type == "flight") result = run_flight_job(job.input.payload);
        else if (job.input.type == "modem") result = run_modem_job(job.input.payload);
        else if (job.input.type == "sms") result = run_sms_job(job.input.payload);
        else if (job.input.type == "ping") result = run_ping_job();
        else if (job.input.type == "wifi") result = run_wifi_job(job.input.payload);
        else if (job.input.type == "save") result = run_save_job(job.input.payload);
        else if (job.input.type == "backup_export") result = run_backup_export_job(job.input.payload);
        else if (job.input.type == "backup_restore") {
            result = run_backup_restore_job(job.meta.id, job.input.payload, job.binary);
        }
        else if (job.input.type == "ota_finish") result = run_ota_finish_job(job.input.payload);
        else result = action_result(false, "ACTION_JOB_FAILED");
        if (needs_modem) api_job_modem_end();
    }
    uint32_t stack_hwm_bytes = 0;
    if (job.input.type == "backup_export" || job.input.type == "backup_restore" ||
        job.input.type == "ota_finish") {
        stack_hwm_bytes = static_cast<uint32_t>(uxTaskGetStackHighWaterMark(nullptr) * sizeof(StackType_t));
        idf_logf("Configuration encryption task stack remaining: %u bytes",
                 static_cast<unsigned>(stack_hwm_bytes));
    }
    clear_api_job_sensitive(job);
    if (result.size() > 2048) result = action_result(false, "ACTION_JOB_FAILED");
    const bool ota_success = job.input.type == "ota_finish" &&
                             result.find("\"success\":true") != std::string::npos;

    bool completed = false;
    bool completion_success = false;
    bool completion_mismatch = false;
    uint32_t completed_ms = 0;
    uint32_t current_slot_id = 0;
    IdfWebJobState current_slot_state = IdfWebJobState::Empty;
    if (s_api_job_mutex && xSemaphoreTake(s_api_job_mutex, portMAX_DELAY) == pdTRUE) {
        ApiJob& slot = s_api_jobs[index];
        if (slot.meta.id == job.meta.id) {
            completion_success = result.find("\"success\":true") != std::string::npos;
            slot.result = std::move(result);
            slot.success = completion_success;
            slot.meta.completed_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
            slot.meta.state = IdfWebJobState::Done;
            if (job.input.type == "backup_restore" && s_last_restore_job.job_id == job.meta.id) {
                s_last_restore_job.done_id = job.meta.id;
                s_last_restore_job.done_state = static_cast<uint32_t>(slot.meta.state);
                s_last_restore_job.completed_ms = slot.meta.completed_ms;
                s_last_restore_job.stack_hwm = stack_hwm_bytes;
                s_last_restore_job.phases |= RESTORE_PHASE_DONE;
            }
            if (job.input.type == "backup_restore" && completion_success) {
                s_restore_restart_completed_ms.store(slot.meta.completed_ms, std::memory_order_release);
                s_restore_restart_pending.store(true, std::memory_order_release);
            }
            completed = true;
            completed_ms = slot.meta.completed_ms;
        } else {
            if (job.input.type == "backup_restore" && s_last_restore_job.job_id == job.meta.id) {
                s_last_restore_job.mismatch_id = slot.meta.id;
                s_last_restore_job.mismatch_state = static_cast<uint32_t>(slot.meta.state);
                s_last_restore_job.phases |= RESTORE_PHASE_MISMATCH;
            }
            completion_mismatch = true;
            current_slot_id = slot.meta.id;
            current_slot_state = slot.meta.state;
        }
        xSemaphoreGive(s_api_job_mutex);
    }
    if (job.input.type == "backup_restore") backup_clear_claim();
    if (completed) {
        idf_logf("API job done id=%u ok=%u completed_ms=%u stack_hwm=%u",
                 static_cast<unsigned>(job.meta.id),
                 completion_success ? 1U : 0U,
                 static_cast<unsigned>(completed_ms), static_cast<unsigned>(stack_hwm_bytes));
    } else if (completion_mismatch) {
        idf_logf("API job completion mismatch id=%u slot_id=%u slot_state=%u",
                 static_cast<unsigned>(job.meta.id), static_cast<unsigned>(current_slot_id),
                 static_cast<unsigned>(current_slot_state));
    }
    if (ota_success) {
        auto reboot = [](void*) {
            vTaskDelay(pdMS_TO_TICKS(2000));
            esp_restart();
        };
        if (xTaskCreate(reboot, "ota_restart", 3072, nullptr, 1, nullptr) != pdPASS) {
            idf_log_line("OTA completed, but the delayed restart task could not be created; restart manually");
        }
    }
    vTaskDelete(nullptr);
}

static esp_err_t enqueue_api_job(httpd_req_t* req, const char* type, const std::string& arg,
                                 IdfWebOwnedBytes binary, bool admission_claimed)
{
    set_json_no_cache(req);
    if (!admission_claimed && !try_shared_admission(false)) {
        idf_web_secure_clear(binary);
        httpd_resp_set_status(req, "409 Conflict");
        return httpd_resp_sendstr(req, "{\"success\":false,\"code\":\"ACTION_BUSY\",\"data\":{},\"detail\":\"\"}");
    }
    const bool backup_job = strcmp(type, "backup_export") == 0 || strcmp(type, "backup_restore") == 0;
    const bool crypto_job = backup_job || strcmp(type, "ota_finish") == 0;
    const bool ota_job = strcmp(type, "ota_finish") == 0;
    const bool restore_job = strcmp(type, "backup_restore") == 0;
    if ((ota_active() && !ota_job) ||
        ((device_restart_pending() || restore_restart_pending()) && strcmp(type, "query") != 0)) {
        idf_web_secure_clear(binary);
        if (backup_job) backup_clear_claim();
        release_shared_admission();
        httpd_resp_set_status(req, "409 Conflict");
        return httpd_resp_sendstr(req, "{\"success\":false,\"code\":\"ACTION_BUSY\",\"data\":{},\"detail\":\"\"}");
    }
    if (!s_api_job_mutex || xSemaphoreTake(s_api_job_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        idf_web_secure_clear(binary);
        if (backup_job) backup_clear_claim();
        if (ota_job) { uint32_t id = 0; if (parse_u32_strict(arg.c_str(), id, false)) idf_web_ota_cancel_finish(id); }
        release_shared_admission();
        httpd_resp_set_status(req, "429 Too Many Requests");
        return httpd_resp_sendstr(req, "{\"success\":false,\"code\":\"ACTION_JOB_QUEUE_FULL\",\"data\":{},\"detail\":\"\"}");
    }
    IdfWebJobSlotMeta metas[API_JOB_SLOTS];
    for (size_t i = 0; i < API_JOB_SLOTS; ++i) metas[i] = s_api_jobs[i].meta;
    int slot_index = idf_web_count_active_jobs(metas, API_JOB_SLOTS) < API_JOB_ACTIVE_MAX
        ? idf_web_select_job_slot(metas, API_JOB_SLOTS,
                                  static_cast<uint32_t>(esp_timer_get_time() / 1000ULL), API_JOB_TTL_MS)
        : -1;
    if (slot_index < 0) {
        xSemaphoreGive(s_api_job_mutex);
        idf_web_secure_clear(binary);
        if (backup_job) backup_clear_claim();
        if (ota_job) { uint32_t id = 0; if (parse_u32_strict(arg.c_str(), id, false)) idf_web_ota_cancel_finish(id); }
        release_shared_admission();
        httpd_resp_set_status(req, "429 Too Many Requests");
        return httpd_resp_sendstr(req, "{\"success\":false,\"code\":\"ACTION_JOB_QUEUE_FULL\",\"data\":{},\"detail\":\"\"}");
    }
    ApiJob& slot = s_api_jobs[slot_index];
    clear_api_job_sensitive(slot);
    slot = ApiJob();
    slot.meta.id = s_next_api_job_id++;
    if (slot.meta.id == 0) slot.meta.id = s_next_api_job_id++;
    slot.meta.state = IdfWebJobState::Queued;
    slot.input = idf_web_own_job_input(type, arg.data(), arg.size());
    slot.binary = std::move(binary);
    uint32_t id = slot.meta.id;
    if (restore_job) restore_lifecycle_reset_locked(id);
    xSemaphoreGive(s_api_job_mutex);

    if (xTaskCreate(api_job_task, "idf_web_job", crypto_job ? 8192 : 6144,
                    reinterpret_cast<void*>(static_cast<uintptr_t>(slot_index + 1)), 3, nullptr) != pdPASS) {
        xSemaphoreTake(s_api_job_mutex, portMAX_DELAY);
        if (s_api_jobs[slot_index].meta.id == id) {
            clear_api_job_sensitive(s_api_jobs[slot_index]);
            s_api_jobs[slot_index] = ApiJob();
        }
        xSemaphoreGive(s_api_job_mutex);
        if (backup_job) backup_clear_claim();
        if (ota_job) { uint32_t upload_id = 0; if (parse_u32_strict(arg.c_str(), upload_id, false)) idf_web_ota_cancel_finish(upload_id); }
        release_shared_admission();
        httpd_resp_set_status(req, "429 Too Many Requests");
        return httpd_resp_sendstr(req, "{\"success\":false,\"code\":\"ACTION_JOB_QUEUE_FULL\",\"data\":{},\"detail\":\"\"}");
    }
    char response[160];
    snprintf(response, sizeof(response),
             "{\"success\":true,\"code\":\"ACTION_JOB_ACCEPTED\",\"data\":{\"jobId\":%u},\"detail\":\"\"}",
             static_cast<unsigned>(id));
    idf_logf("API job accepted id=%u restore=%u", static_cast<unsigned>(id), restore_job ? 1U : 0U);
    release_shared_admission();
    httpd_resp_set_status(req, "202 Accepted");
    return httpd_resp_sendstr(req, response);
}

static esp_err_t handle_api_job(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    set_json_no_cache(req);
    std::string raw;
    uint32_t id = 0;
    if (!get_query_param(req, "id", raw, 64) || !parse_u32_strict(raw.c_str(), id, false)) {
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "{\"success\":false,\"code\":\"ACTION_JOB_NOT_FOUND\",\"data\":{},\"detail\":\"\"}");
    }
    IdfWebJobSlotMeta meta;
    bool success = false;
    std::string type;
    std::string result;
    bool found = false;
    IdfWebJobState observed_state = IdfWebJobState::Empty;
    uint32_t observed_completed_ms = 0;
    bool observed_expired = false;
    bool emit_restore_lifecycle_miss = false;
    ApiRestoreLifecycleSnapshot restore_lifecycle_miss;
    xSemaphoreTake(s_api_job_mutex, portMAX_DELAY);
    const uint32_t now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
    for (ApiJob& slot : s_api_jobs) {
        if (slot.meta.id == id && slot.meta.state != IdfWebJobState::Empty) {
            observed_state = slot.meta.state;
            observed_completed_ms = slot.meta.completed_ms;
            if (slot.meta.state == IdfWebJobState::Done &&
                now_ms - slot.meta.completed_ms >= API_JOB_TTL_MS) {
                observed_expired = true;
                clear_api_job_sensitive(slot);
                slot = ApiJob();
                break;
            }
            meta = slot.meta;
            success = slot.success;
            type = slot.input.type;
            result = slot.result;
            found = true;
            break;
        }
    }
    if (!found && s_last_restore_job.job_id == id && !s_last_restore_job.lookup_logged) {
        s_last_restore_job.lookup_logged = true;
        restore_lifecycle_miss = s_last_restore_job;
        emit_restore_lifecycle_miss = true;
    }
    xSemaphoreGive(s_api_job_mutex);
    if (!found) {
        const uint32_t age_ms = observed_state == IdfWebJobState::Done
            ? now_ms - observed_completed_ms : 0;
        idf_logf("API job lookup miss id=%u state=%u age_ms=%u expired=%u",
                 static_cast<unsigned>(id), static_cast<unsigned>(observed_state),
                 static_cast<unsigned>(age_ms), observed_expired ? 1U : 0U);
        if (emit_restore_lifecycle_miss) {
            idf_logf("API restore lifecycle miss id=%u p=%u d=%u ce=%d cs=%u di=%u ds=%u "
                     "cm=%u h=%u mi=%u ms=%u",
                     static_cast<unsigned>(restore_lifecycle_miss.job_id),
                     static_cast<unsigned>(restore_lifecycle_miss.phases),
                     static_cast<unsigned>(restore_lifecycle_miss.decrypt_result),
                     static_cast<int>(restore_lifecycle_miss.config_err),
                     static_cast<unsigned>(restore_lifecycle_miss.config_status),
                     static_cast<unsigned>(restore_lifecycle_miss.done_id),
                     static_cast<unsigned>(restore_lifecycle_miss.done_state),
                     static_cast<unsigned>(restore_lifecycle_miss.completed_ms),
                     static_cast<unsigned>(restore_lifecycle_miss.stack_hwm),
                     static_cast<unsigned>(restore_lifecycle_miss.mismatch_id),
                     static_cast<unsigned>(restore_lifecycle_miss.mismatch_state));
        }
        httpd_resp_set_status(req, "404 Not Found");
        return httpd_resp_sendstr(req, "{\"success\":false,\"code\":\"ACTION_JOB_NOT_FOUND\",\"data\":{},\"detail\":\"\"}");
    }
    const char* state = meta.state == IdfWebJobState::Queued ? "queued" :
                        meta.state == IdfWebJobState::Running ? "running" :
                        success ? "succeeded" : "failed";
    std::string response = "{\"id\":" + std::to_string(meta.id) + ",";
    json_prop(response, "type", type); response += ",";
    json_prop(response, "state", state);
    if (meta.state == IdfWebJobState::Done) response += ",\"result\":" + result;
    response += "}";
    return httpd_resp_send(req, response.c_str(), response.size());
}

static void clear_form_fields(IdfWebFormDecodeResult& decoded)
{
    for (auto& field : decoded.fields) {
        idf_web_secure_clear(field.first);
        idf_web_secure_clear(field.second);
    }
    decoded.fields.clear();
}

static esp_err_t send_backup_result(httpd_req_t* req, const char* status, bool success,
                                    const char* code, const std::string& data = {})
{
    set_json_no_cache(req);
    httpd_resp_set_status(req, status);
    const std::string body = action_result(success, code, data);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static bool reject_restart_while_backup_active(httpd_req_t* req)
{
    if (!backup_transfer_active() && !ota_active() && !device_restart_pending() &&
        !restore_restart_pending() &&
        !api_jobs_active() && !shared_admission_active() && !idf_push_test_active()) return false;
    send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    return true;
}

static esp_err_t handle_config_export(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    if (req->method == HTTP_GET) {
        std::string raw;
        uint32_t id = 0;
        if (!get_query_param(req, "id", raw, 96) || !parse_u32_strict(raw.c_str(), id, false)) {
            return send_backup_result(req, "404 Not Found", false, "ACTION_CONFIG_EXPORT_NOT_FOUND");
        }
        IdfWebOwnedBytes download;
        if (backup_lock(portMAX_DELAY)) {
            idf_web_transfer_expire(s_backup_transfer, web_now_ms(), BACKUP_TTL_MS);
            if (s_backup_transfer.mode == IdfWebTransferMode::Export && s_backup_transfer.id == id &&
                s_backup_transfer.bytes.size == s_backup_transfer.expected_size) {
                download = std::move(s_backup_transfer.bytes);
                s_backup_transfer = IdfWebTransfer();
            }
            backup_unlock();
        }
        if (!download.data) {
            return send_backup_result(req, "404 Not Found", false, "ACTION_CONFIG_EXPORT_NOT_FOUND");
        }
        httpd_resp_set_type(req, CONFIG_MIME_TYPE);
        set_no_cache_headers(req);
        httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=config.smscfg");
        const esp_err_t err = httpd_resp_send(req,
            reinterpret_cast<const char*>(download.data.get()), download.size);
        idf_web_secure_clear(download);
        return err;
    }
    if (req->method != HTTP_POST) {
        return send_backup_result(req, "405 Method Not Allowed", false, "ACTION_INPUT_INVALID");
    }
    if (!try_shared_admission(false)) {
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    if (ota_active() || device_restart_pending() || restore_restart_pending() ||
        idf_push_test_active()) {
        release_shared_admission();
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    std::string body;
    if (read_body(req, body, 1024) != ESP_OK) {
        idf_web_secure_clear(body);
        release_shared_admission();
        return ESP_OK;
    }
    IdfWebFormDecodeResult decoded = idf_web_decode_form(body, 1);
    idf_web_secure_clear(body);
    std::string passphrase = decoded.valid && decoded.fields.size() == 1 &&
        decoded.fields[0].first == "passphrase" ? decoded.fields[0].second : std::string();
    clear_form_fields(decoded);
    if (!idf_web_valid_backup_passphrase(passphrase)) {
        idf_web_secure_clear(passphrase);
        release_shared_admission();
        return send_backup_result(req, "400 Bad Request", false, "ACTION_CONFIG_PASSPHRASE_INVALID");
    }
    bool claimed = false;
    if (backup_lock(portMAX_DELAY)) {
        idf_web_transfer_expire(s_backup_transfer, web_now_ms(), BACKUP_TTL_MS);
        if (s_backup_transfer.mode == IdfWebTransferMode::None) {
            s_backup_transfer.mode = IdfWebTransferMode::Export;
            s_backup_transfer.id = next_transfer_id();
            s_backup_transfer.started_ms = web_now_ms();
            claimed = true;
        }
        backup_unlock();
    }
    if (!claimed) {
        idf_web_secure_clear(passphrase);
        release_shared_admission();
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    release_shared_admission();
    const esp_err_t err = enqueue_api_job(req, "backup_export", passphrase);
    idf_web_secure_clear(passphrase);
    return err;
}

static esp_err_t handle_config_restore_start(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    if (!try_shared_admission(false)) {
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    if (ota_active() || device_restart_pending() || restore_restart_pending() || idf_push_test_active() ||
        backup_transfer_active()) {
        release_shared_admission();
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    std::string body;
    if (read_body(req, body, 1024) != ESP_OK) {
        release_shared_admission();
        return ESP_OK;
    }
    IdfWebFormDecodeResult decoded = idf_web_decode_form(body, 1);
    idf_web_secure_clear(body);
    uint32_t size = 0;
    const bool valid = decoded.valid && decoded.fields.size() == 1 && decoded.fields[0].first == "size" &&
        parse_u32_strict(decoded.fields[0].second.c_str(), size, false) &&
        size >= BACKUP_HEADER_BYTES + BACKUP_TAG_BYTES && size <= MAX_ENCRYPTED_CONFIG_BYTES;
    clear_form_fields(decoded);
    if (!valid) {
        release_shared_admission();
        return send_backup_result(req, "400 Bad Request", false, "ACTION_CONFIG_RESTORE_INVALID");
    }
    if (heap_caps_get_largest_free_block(MALLOC_CAP_8BIT) < size) {
        release_shared_admission();
        return send_backup_result(req, "409 Conflict", false, "ACTION_CONFIG_RESTORE_START_FAILED");
    }
    const uint32_t id = next_transfer_id();
    bool started = false;
    if (backup_lock(portMAX_DELAY)) {
        idf_web_transfer_expire(s_backup_transfer, web_now_ms(), BACKUP_TTL_MS);
        started = idf_web_transfer_start(s_backup_transfer, IdfWebTransferMode::Restore,
                                         id, size, web_now_ms());
        backup_unlock();
    }
    if (!started) {
        release_shared_admission();
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    release_shared_admission();
    const std::string data = "\"uploadId\":" + std::to_string(id) +
        ",\"chunkSize\":" + std::to_string(BACKUP_CHUNK_BYTES) + ",\"nextOffset\":0";
    return send_backup_result(req, "201 Created", true, "ACTION_CONFIG_RESTORE_STARTED", data);
}

static bool valid_base64_text(const std::string& value, size_t& raw_size)
{
    if (value.size() < 4 || value.size() > 10924 || value.size() % 4 != 0) return false;
    size_t padding = 0;
    if (!value.empty() && value.back() == '=') ++padding;
    if (value.size() > 1 && value[value.size() - 2] == '=') ++padding;
    if (!std::all_of(value.begin(), value.end() - padding, [](char value) {
            const unsigned char ch = static_cast<unsigned char>(value);
            return isalnum(ch) || ch == '+' || ch == '/';
        })) return false;
    if (!std::all_of(value.end() - padding, value.end(), [](char ch) { return ch == '='; })) return false;
    raw_size = value.size() / 4 * 3 - padding;
    return raw_size > 0 && raw_size <= BACKUP_CHUNK_BYTES;
}

static esp_err_t handle_config_restore_chunk(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    std::string raw_id, raw_offset;
    uint32_t id = 0, offset = 0;
    if (!get_query_param(req, "id", raw_id, 128) || !parse_u32_strict(raw_id.c_str(), id, false) ||
        !get_query_param(req, "offset", raw_offset, 128) || !parse_u32_strict(raw_offset.c_str(), offset, true)) {
        return send_backup_result(req, "409 Conflict", false, "ACTION_CONFIG_RESTORE_CHUNK_INVALID");
    }
    std::string body;
    if (read_body(req, body, 10924) != ESP_OK) {
        idf_web_secure_clear(body);
        backup_cancel_upload(id);
        return ESP_OK;
    }
    size_t raw_size = 0;
    if (!valid_base64_text(body, raw_size)) {
        idf_web_secure_clear(body);
        backup_cancel_upload(id);
        return send_backup_result(req, "409 Conflict", false, "ACTION_CONFIG_RESTORE_CHUNK_INVALID");
    }
    IdfWebOwnedBytes chunk;
    if (!idf_web_allocate_owned_bytes(chunk, raw_size)) {
        idf_web_secure_clear(body);
        backup_cancel_upload(id);
        return send_backup_result(req, "409 Conflict", false, "ACTION_CONFIG_RESTORE_CHUNK_INVALID");
    }
    chunk.size = raw_size;
    size_t decoded_size = 0;
    const int decode_err = mbedtls_base64_decode(chunk.data.get(), chunk.size, &decoded_size,
        reinterpret_cast<const unsigned char*>(body.data()), body.size());
    idf_web_secure_clear(body);
    if (decode_err != 0 || decoded_size != raw_size) {
        idf_web_secure_clear(chunk);
        backup_cancel_upload(id);
        return send_backup_result(req, "409 Conflict", false, "ACTION_CONFIG_RESTORE_CHUNK_INVALID");
    }
    bool appended = false;
    size_t next_offset = 0;
    if (backup_lock(portMAX_DELAY)) {
        idf_web_transfer_expire(s_backup_transfer, web_now_ms(), BACKUP_TTL_MS);
        appended = idf_web_transfer_append(s_backup_transfer, id, offset,
                                           chunk.data.get(), chunk.size, BACKUP_CHUNK_BYTES);
        next_offset = s_backup_transfer.bytes.size;
        backup_unlock();
    }
    idf_web_secure_clear(chunk);
    if (!appended) return send_backup_result(req, "409 Conflict", false, "ACTION_CONFIG_RESTORE_CHUNK_INVALID");
    return send_backup_result(req, "200 OK", true, "ACTION_CONFIG_RESTORE_CHUNK_OK",
                              "\"nextOffset\":" + std::to_string(next_offset));
}

static esp_err_t handle_config_restore_finish(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    std::string raw_id;
    uint32_t id = 0;
    if (!get_query_param(req, "id", raw_id, 96) || !parse_u32_strict(raw_id.c_str(), id, false)) {
        return send_backup_result(req, "409 Conflict", false, "ACTION_CONFIG_RESTORE_FINISH_INVALID");
    }
    std::string body;
    if (read_body(req, body, 1024) != ESP_OK) {
        idf_web_secure_clear(body);
        backup_cancel_upload(id);
        return ESP_OK;
    }
    IdfWebFormDecodeResult decoded = idf_web_decode_form(body, 1);
    idf_web_secure_clear(body);
    std::string passphrase = decoded.valid && decoded.fields.size() == 1 &&
        decoded.fields[0].first == "passphrase" ? decoded.fields[0].second : std::string();
    clear_form_fields(decoded);
    if (!idf_web_valid_backup_passphrase(passphrase)) {
        idf_web_secure_clear(passphrase);
        backup_cancel_upload(id);
        return send_backup_result(req, "400 Bad Request", false, "ACTION_CONFIG_PASSPHRASE_INVALID");
    }
    if (!try_shared_admission(false)) {
        idf_web_secure_clear(passphrase);
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    IdfWebOwnedBytes encrypted;
    bool complete = false;
    if (backup_lock(portMAX_DELAY)) {
        idf_web_transfer_expire(s_backup_transfer, web_now_ms(), BACKUP_TTL_MS);
        if (s_backup_transfer.mode == IdfWebTransferMode::Restore) {
            complete = idf_web_transfer_take_complete(s_backup_transfer, id, encrypted);
            if (complete) {
                s_backup_transfer.started_ms = web_now_ms();
            }
        }
        backup_unlock();
    }
    if (!complete) {
        idf_web_secure_clear(passphrase);
        release_shared_admission();
        return send_backup_result(req, "409 Conflict", false, "ACTION_CONFIG_RESTORE_FINISH_INVALID");
    }
    const esp_err_t err = enqueue_api_job(req, "backup_restore", passphrase, std::move(encrypted), true);
    idf_web_secure_clear(passphrase);
    idf_web_secure_clear(encrypted);
    return err;
}

static esp_err_t send_ota_result(httpd_req_t* req, const char* status, bool success,
                                 const char* code, const std::string& data = {})
{
    set_json_no_cache(req);
    httpd_resp_set_status(req, status);
    const std::string body = action_result(success, code, data);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static bool decode_lower_hex_signature(const std::string& text, uint8_t output[72], size_t& size)
{
    if (text.size() < 16 || text.size() > 144 || (text.size() & 1U)) return false;
    size = text.size() / 2;
    for (size_t i = 0; i < size; ++i) {
        auto nibble = [](char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
            return -1;
        };
        const int high = nibble(text[i * 2]);
        const int low = nibble(text[i * 2 + 1]);
        if (high < 0 || low < 0) { memset(output, 0, 72); size = 0; return false; }
        output[i] = static_cast<uint8_t>((high << 4) | low);
    }
    return true;
}

static esp_err_t handle_ota_start(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req) || !check_csrf(req)) return ESP_OK;
    if (!try_shared_admission(false)) {
        return send_ota_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    if (device_restart_pending() || restore_restart_pending() || ota_active() || backup_transfer_active() ||
        idf_push_test_active() ||
        api_jobs_active() || cellular_job_active()) {
        release_shared_admission();
        return send_ota_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    std::string body;
    if (read_body(req, body, 1024) != ESP_OK) {
        release_shared_admission();
        return ESP_OK;
    }
    IdfWebFormDecodeResult decoded = idf_web_decode_form(body, 2);
    idf_web_secure_clear(body);
    std::string manifest;
    std::string signature_hex;
    if (decoded.valid && decoded.fields.size() == 2) {
        for (const auto& field : decoded.fields) {
            if (field.first == "manifest" && manifest.empty()) manifest = field.second;
            else if (field.first == "signature" && signature_hex.empty()) signature_hex = field.second;
            else { manifest.clear(); signature_hex.clear(); break; }
        }
    }
    clear_form_fields(decoded);
    if (manifest.empty() || manifest.size() > IDF_WEB_OTA_MAX_MANIFEST_BYTES) {
        idf_web_secure_clear(manifest); idf_web_secure_clear(signature_hex);
        release_shared_admission();
        return send_ota_result(req, "400 Bad Request", false, "ACTION_OTA_MANIFEST_INVALID");
    }
    uint8_t signature[72] = {};
    size_t signature_size = 0;
    if (!decode_lower_hex_signature(signature_hex, signature, signature_size)) {
        idf_web_secure_clear(manifest); idf_web_secure_clear(signature_hex);
        release_shared_admission();
        return send_ota_result(req, "400 Bad Request", false, "ACTION_OTA_SIGNATURE_INVALID");
    }
    idf_web_secure_clear(signature_hex);
    const uint32_t id = next_transfer_id();
    const IdfWebOtaCode result = idf_web_ota_start(manifest, signature, signature_size,
                                                   id, web_now_ms());
    memset(signature, 0, sizeof(signature));
    idf_web_secure_clear(manifest);
    if (result == IdfWebOtaCode::Ok) {
        release_shared_admission();
        return send_ota_result(req, "201 Created", true, "ACTION_OTA_UPLOAD_STARTED",
            "\"uploadId\":" + std::to_string(id) + ",\"chunkSize\":" +
            std::to_string(IDF_WEB_OTA_CHUNK_BYTES) + ",\"nextOffset\":0");
    }
    if (result == IdfWebOtaCode::SignatureInvalid) {
        release_shared_admission();
        return send_ota_result(req, "400 Bad Request", false, "ACTION_OTA_SIGNATURE_INVALID");
    }
    if (result == IdfWebOtaCode::ManifestInvalid || result == IdfWebOtaCode::Replay) {
        release_shared_admission();
        return send_ota_result(req, "400 Bad Request", false, "ACTION_OTA_MANIFEST_INVALID");
    }
    if (result == IdfWebOtaCode::Busy) {
        release_shared_admission();
        return send_ota_result(req, "409 Conflict", false, "ACTION_OTA_BUSY");
    }
    release_shared_admission();
    return send_ota_result(req, "500 Internal Server Error", false,
        result == IdfWebOtaCode::MetadataFailed ? "ACTION_OTA_METADATA_FAILED" : "ACTION_OTA_BEGIN_FAILED");
}

static esp_err_t handle_ota_chunk(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req) || !check_csrf(req)) return ESP_OK;
    if (shared_admission_active() || cellular_job_active()) {
        return send_ota_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    std::string raw_id, raw_offset;
    uint32_t id = 0, offset = 0;
    if (!get_query_param(req, "id", raw_id, 128) || !parse_u32_strict(raw_id.c_str(), id, false) ||
        !get_query_param(req, "offset", raw_offset, 128) || !parse_u32_strict(raw_offset.c_str(), offset, true)) {
        return send_ota_result(req, "409 Conflict", false, "ACTION_OTA_SESSION_INVALID");
    }
    std::string body;
    if (read_body(req, body, 10924) != ESP_OK) { idf_web_ota_cancel_upload(id); return ESP_OK; }
    size_t raw_size = 0;
    if (!valid_base64_text(body, raw_size)) {
        idf_web_secure_clear(body);
        idf_web_ota_cancel_upload(id);
        return send_ota_result(req, "400 Bad Request", false, "ACTION_OTA_CHUNK_INVALID");
    }
    IdfWebOwnedBytes chunk;
    if (!idf_web_allocate_owned_bytes(chunk, raw_size)) {
        idf_web_secure_clear(body);
        idf_web_ota_cancel_upload(id);
        return send_ota_result(req, "500 Internal Server Error", false, "ACTION_OTA_WRITE_FAILED");
    }
    chunk.size = raw_size;
    size_t decoded_size = 0;
    const int decoded_error = mbedtls_base64_decode(chunk.data.get(), chunk.size, &decoded_size,
        reinterpret_cast<const uint8_t*>(body.data()), body.size());
    idf_web_secure_clear(body);
    if (decoded_error != 0 || decoded_size != raw_size) {
        idf_web_secure_clear(chunk);
        idf_web_ota_cancel_upload(id);
        return send_ota_result(req, "400 Bad Request", false, "ACTION_OTA_CHUNK_INVALID");
    }
    size_t next_offset = 0;
    const IdfWebOtaCode result = idf_web_ota_append(id, offset, chunk.data.get(), chunk.size,
                                                    web_now_ms(), &next_offset);
    idf_web_secure_clear(chunk);
    if (result == IdfWebOtaCode::Ok) {
        return send_ota_result(req, "200 OK", true, "ACTION_OTA_CHUNK_OK",
                               "\"nextOffset\":" + std::to_string(next_offset));
    }
    if (result == IdfWebOtaCode::SessionInvalid) {
        return send_ota_result(req, "409 Conflict", false, "ACTION_OTA_SESSION_INVALID");
    }
    return send_ota_result(req, result == IdfWebOtaCode::WriteFailed ?
        "500 Internal Server Error" : "400 Bad Request", false,
        result == IdfWebOtaCode::WriteFailed ? "ACTION_OTA_WRITE_FAILED" : "ACTION_OTA_CHUNK_INVALID");
}

static esp_err_t handle_ota_finish(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req) || !check_csrf(req)) return ESP_OK;
    std::string raw_id;
    uint32_t id = 0;
    if (!get_query_param(req, "id", raw_id, 96) || !parse_u32_strict(raw_id.c_str(), id, false)) {
        return send_ota_result(req, "409 Conflict", false, "ACTION_OTA_SESSION_INVALID");
    }
    const IdfWebOtaCode result = idf_web_ota_prepare_finish(id);
    if (result != IdfWebOtaCode::Ok) {
        return send_ota_result(req, "409 Conflict", false, "ACTION_OTA_SESSION_INVALID");
    }
    return enqueue_api_job(req, "ota_finish", raw_id);
}

static esp_err_t handle_at(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    std::string cmd;
    if (!get_query_param(req, "cmd", cmd, 384) || !idf_web_at_command_allowed(cmd)) {
        set_json_no_cache(req);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req,
            "{\"success\":false,\"code\":\"ACTION_AT_REJECTED\",\"data\":{},\"detail\":\"cmd\"}");
    }
    return enqueue_api_job(req, "at", cmd);
}

static esp_err_t handle_flight(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    std::string action;
    get_query_param(req, "action", action);
    if (action.empty()) action = "query";
    if (!(action == "query" || action == "toggle" || action == "on" || action == "off")) {
        set_json_no_cache(req);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req,
            "{\"success\":false,\"code\":\"ACTION_UNKNOWN\",\"data\":{},\"detail\":\"action\"}");
    }
    return enqueue_api_job(req, "flight", action);
}

static esp_err_t handle_modem_control(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!ensure_get_or_post(req)) return ESP_OK;
    std::string action;
    get_query_param(req, "action", action);
    bool success = false;
    std::string message;

    WebModemActionGuard modem_action;
    bool needs_modem = (action == "restart" || action == "hardreset" ||
                        action == "signal" || action == "operator" || action == "imei");
    if ((action == "restart" || action == "hardreset" || action == "sim-puk") && req->method != HTTP_POST) {
        set_json_no_cache(req);
        return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"This action requires POST\"}");
    }
    if (needs_modem && !modem_action.begin(req)) return ESP_OK;

    if (action == "sim-puk") {
        esp_err_t err = idf_modem_request_sim_unlock(true);
        success = err == ESP_OK;
        message = success ? "PUK unlock requested; check SIM status" : esp_err_to_name(err);
        if (success) idf_log_line("Web UI confirmed a SIM PUK unlock attempt");
    } else if (action == "restart" || action == "hardreset") {
        bool hard = action == "hardreset";
        esp_err_t err = idf_modem_request_reset(hard);
        success = (err == ESP_OK);
        if (success) idf_logf("Web UI requested a %s modem restart", hard ? "hard" : "soft");
        message = success
            ? (hard ? "Hard-restarting the modem; refresh in about 15 seconds" : "Soft-restarting the modem; refresh in about 15 seconds")
            : esp_err_to_name(err);
    } else if (action == "signal") {
        std::string resp;
        esp_err_t err = idf_modem_send_at("AT+CSQ", 3000, resp);
        std::string line = first_line_containing(resp, "+CSQ:");
        int rssi = 99;
        int ber = 99;
        if (err == ESP_OK && parse_csq_line(line, rssi, ber)) {
            int dbm = (rssi == 99) ? -999 : (-113 + rssi * 2);
            char buf[96];
            snprintf(buf, sizeof(buf), "Signal strength (RSSI): %d dBm, raw CSQ: %d, BER: %d", dbm, rssi, ber);
            message = buf;
            success = true;
        } else {
            message = resp.empty() ? esp_err_to_name(err) : resp;
        }
    } else if (action == "operator") {
        std::string resp;
        // Select the long-name format first; otherwise COPS? in automatic mode may return only +COPS: 0 without the operator name.
        idf_modem_send_at("AT+COPS=3,0", 3000, resp);
        esp_err_t err = idf_modem_send_at("AT+COPS?", 5000, resp);
        std::string line = first_line_containing(resp, "+COPS:");
        if (err == ESP_OK && !line.empty()) {
            size_t q1 = line.find('"');
            size_t q2 = q1 == std::string::npos ? std::string::npos : line.find('"', q1 + 1);
            message = (q1 != std::string::npos && q2 != std::string::npos) ? line.substr(q1 + 1, q2 - q1 - 1) : line;
            success = true;
        } else {
            message = resp.empty() ? esp_err_to_name(err) : resp;
        }
    } else if (action == "imei") {
        std::string resp;
        esp_err_t err = idf_modem_send_at("AT+CGSN", 3000, resp);
        message = first_digits(resp);
        success = (err == ESP_OK && !message.empty());
        if (!success) message = resp.empty() ? esp_err_to_name(err) : resp;
    } else {
        message = "Unknown action: " + action;
    }

    std::string body = "{\"success\":";
    body += success ? "true" : "false";
    body += ",";
    json_prop(body, "message", message);
    body += "}";
    set_json_no_cache(req);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_modem_api(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    std::string action;
    if (!get_query_param(req, "action", action, 64) ||
        !(action == "restart" || action == "hardreset" || action == "signal" ||
          action == "operator" || action == "imei")) {
        set_json_no_cache(req);
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req,
            "{\"success\":false,\"code\":\"ACTION_UNKNOWN\",\"data\":{},\"detail\":\"action\"}");
    }
    return enqueue_api_job(req, "modem", action);
}

static esp_err_t handle_ussd(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!ensure_get_or_post(req)) return ESP_OK;
    if (req->method != HTTP_POST) {
        set_json_no_cache(req);
        return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"USSD queries require POST\"}");
    }
    std::string code;
    get_query_param(req, "code", code);
    if (!valid_ussd_code(code)) {
        set_json_no_cache(req);
        return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"USSD code is empty or contains invalid characters\"}");
    }
    WebModemActionGuard modem_action;
    if (!modem_action.begin(req)) return ESP_OK;

    idf_logf("Web UI started a USSD query: %s", code.c_str());
    std::string message;
    bool success = run_ussd(code, message);
    std::string body = "{\"success\":";
    body += success ? "true" : "false";
    body += ",";
    json_prop(body, "message", message);
    body += "}";
    set_json_no_cache(req);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static bool plmn_valid(const std::string& plmn)
{
    if (plmn.empty()) return true;
    if (plmn.size() < 5 || plmn.size() > 6) return false;
    return std::all_of(plmn.begin(), plmn.end(), [](char ch) {
        return isdigit(static_cast<unsigned char>(ch));
    });
}

static bool apn_valid_for_at(const std::string& apn)
{
    return apn.size() <= 96 && apn.find('"') == std::string::npos &&
           apn.find('\r') == std::string::npos && apn.find('\n') == std::string::npos;
}

struct ModemApplyTaskArg {
    bool dataChanged = false;
    bool operatorChanged = false;
    bool dataEnabled = false;
    bool roamingEnabled = true;
    std::string apn;
    std::string operatorPlmn;
};

static void modem_apply_task(void* raw)
{
    ModemApplyTaskArg* arg = static_cast<ModemApplyTaskArg*>(raw);
    bool data_changed = arg->dataChanged;
    bool operator_changed = arg->operatorChanged;
    bool data_enabled = arg->dataEnabled;
    bool roaming_enabled = arg->roamingEnabled;
    std::string apn = std::move(arg->apn);
    std::string operator_plmn = std::move(arg->operatorPlmn);
    delete arg;

    bool claimed = false;
    if (cell_job_lock()) {
        if (cellular_job_active_locked()) {
            cell_job_unlock();
            idf_log_line("SIM settings saved; cellular/eSIM task busy, so COPS/CGACT was not applied immediately");
            vTaskDelete(nullptr);
            return;
        }
        s_modem_apply_running = true;
        claimed = true;
        cell_job_unlock();
    } else {
        idf_log_line("SIM settings saved; cellular task lock busy, so COPS/CGACT was not applied immediately");
        vTaskDelete(nullptr);
        return;
    }

    auto finish = [&]() {
        if (claimed && cell_job_lock(portMAX_DELAY)) {
            s_modem_apply_running = false;
            cell_job_unlock();
        }
        vTaskDelete(nullptr);
    };

    IdfModemStatus modem = idf_modem_get_status();
    if (!modem.modemReady) {
        idf_log_line("SIM settings saved; modem not registered, so COPS/CGACT was not applied");
        finish();
        return;
    }

    std::string resp;
    if (operator_changed) {
        if (!plmn_valid(operator_plmn)) {
            idf_log_line("Invalid operator PLMN; COPS was not applied");
        } else if (operator_plmn.empty()) {
            idf_modem_send_at("AT+COPS=0", 30000, resp);
            idf_log_line("Operator: automatic registration (COPS=0)");
        } else {
            std::string cmd = "AT+COPS=1,2,\"" + operator_plmn + "\"";
            esp_err_t err = idf_modem_send_at(cmd, 30000, resp);
            idf_logf("Operator: lock PLMN %s %s", operator_plmn.c_str(),
                     err == ESP_OK ? "succeeded" : "failed (possibly unreachable)");
        }
    }

    if (data_changed) {
        if (data_enabled && !roaming_enabled && modem.ceregStat == 5) {
            // When data roaming is disabled while roaming, leave the data PDP inactive; SMS availability still depends on the SIM, modem, and network.
            idf_modem_send_at("AT+CGACT=0,1", 5000, resp);
            idf_log_line("Data roaming disabled while roaming; cellular data was not activated");
        } else if (data_enabled) {
            if (!apn.empty() && apn_valid_for_at(apn)) {
                std::string cmd = "AT+CGDCONT=1,\"IP\",\"" + apn + "\"";
                idf_modem_send_at(cmd, 3000, resp);
            } else if (!apn.empty()) {
                idf_log_line("APN contains invalid characters; CGDCONT was not applied");
            }
            idf_modem_send_at("AT+CGACT=1,1", 10000, resp);
            std::string ip_resp;
            idf_modem_send_at("AT+CGPADDR=1", 3000, ip_resp);
            idf_logf("Cellular data enabled (APN=%s)", apn.empty() ? "automatic" : apn.c_str());
        } else {
            idf_modem_send_at("AT+CGACT=0,1", 5000, resp);
            idf_log_line("Cellular data disabled (zero traffic)");
        }
    }
    finish();
}

static void preserve_redacted_push_key(const IdfFormFields& fields,
                                       const IdfPushChannel& previous,
                                       int index,
                                       int slot,
                                       IdfPushChannel& next)
{
    char name[32];
    snprintf(name, sizeof(name), "push%dkey%dKeep", index, slot);
    bool keep = field_text(fields, name) == "1";
    snprintf(name, sizeof(name), "push%dkey%dClear", index, slot);
    bool clear = has_field(fields, name);
    std::string& value = (slot == 1) ? next.key1 : next.key2;
    const std::string& old_value = (slot == 1) ? previous.key1 : previous.key2;
    if (clear) {
        value.clear();
        return;
    }
    if (keep && next.type == previous.type && field_blank(value)) {
        value = old_value;
    }
}

static void parse_push_channels_form(const IdfFormFields& fields,
                                     const IdfPushChannel previous[IDF_MAX_PUSH_CHANNELS],
                                     IdfPushChannel channels[IDF_MAX_PUSH_CHANNELS])
{
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        char key[24];
        snprintf(key, sizeof(key), "push%ddelete", i);
        if (has_field(fields, key)) {
            // Deletion takes precedence over other fields in the form so redacted-secret retention cannot restore the old value.
            channels[i] = IdfPushChannel{};
            continue;
        }
        snprintf(key, sizeof(key), "push%den", i);
        channels[i].enabled = has_field(fields, key);
        snprintf(key, sizeof(key), "push%dtype", i);
        channels[i].type = field_u8(fields, key, 1);
        snprintf(key, sizeof(key), "push%durl", i);
        channels[i].url = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dname", i);
        channels[i].name = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dkey1", i);
        channels[i].key1 = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dkey2", i);
        channels[i].key2 = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dbody", i);
        channels[i].customBody = field_text(fields, key);
        preserve_redacted_push_key(fields, previous[i], i, 1, channels[i]);
        preserve_redacted_push_key(fields, previous[i], i, 2, channels[i]);
    }
}

static void parse_sched_tasks_form(const IdfFormFields& fields,
                                   IdfSchedTask tasks[IDF_MAX_SCHED_TASKS])
{
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        char key[24];
        snprintf(key, sizeof(key), "st%dEn", i);
        tasks[i].enabled = has_field(fields, key);
        snprintf(key, sizeof(key), "st%dName", i);
        tasks[i].name = field_text(fields, key);
        snprintf(key, sizeof(key), "st%dProf", i);
        tasks[i].profile = field_text(fields, key);
        snprintf(key, sizeof(key), "st%dBack", i);
        tasks[i].switchBack = has_field(fields, key);
        snprintf(key, sizeof(key), "st%dDays", i);
        tasks[i].intervalDays = field_int(fields, key, 30);
        snprintf(key, sizeof(key), "st%dAct", i);
        tasks[i].action = field_u8(fields, key, 0);
        snprintf(key, sizeof(key), "st%dTgt", i);
        tasks[i].target = field_text(fields, key);
        snprintf(key, sizeof(key), "st%dPay", i);
        tasks[i].payload = field_text(fields, key);
    }
}

static void parse_sim_credentials_form(const IdfFormFields& fields,
                                       IdfSimCredential items[IDF_MAX_SIM_CREDENTIALS])
{
    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        char key[20];
        snprintf(key, sizeof(key), "sim%dIccid", i); items[i].iccid = field_text(fields, key);
        snprintf(key, sizeof(key), "sim%dPin", i); items[i].pin = field_text(fields, key);
        snprintf(key, sizeof(key), "sim%dPuk", i); items[i].puk = field_text(fields, key);
        snprintf(key, sizeof(key), "sim%dPinMax", i); items[i].pinMaxAttempts = field_u8(fields, key, 1);
        snprintf(key, sizeof(key), "sim%dPukMax", i); items[i].pukMaxAttempts = field_u8(fields, key, 1);
        snprintf(key, sizeof(key), "sim%dResetPin", i); if (has_field(fields, key)) items[i].pinFailedAttempts = UINT8_MAX;
        snprintf(key, sizeof(key), "sim%dResetPuk", i); if (has_field(fields, key)) items[i].pukFailedAttempts = UINT8_MAX;
    }
}

enum class ModernSaveFamily : uint8_t {
    Unknown,
    Identity,
    Locale,
    Email,
    Push,
    Routing,
    Wifi,
    Network,
    Heartbeat,
    Keepalive,
    Accounts,
};

static int indexed_save_key(const std::string& key, const char* prefix, const char* suffix, int count)
{
    const size_t prefix_len = strlen(prefix);
    const size_t suffix_len = strlen(suffix);
    if (key.size() != prefix_len + 1 + suffix_len || key.compare(0, prefix_len, prefix) != 0 ||
        key.compare(prefix_len + 1, suffix_len, suffix) != 0) return -1;
    const char digit = key[prefix_len];
    return digit >= '0' && digit < '0' + count ? digit - '0' : -1;
}

static ModernSaveFamily modern_save_field_family(const std::string& key)
{
    if (key == "deviceName" || key == "hostname") return ModernSaveFamily::Identity;
    if (key == "notificationLocale") return ModernSaveFamily::Locale;
    if (key == "emailEnabled" || key == "smtpServer" || key == "smtpPort" || key == "smtpUser" ||
        key == "smtpPass" || key == "smtpSendTo") return ModernSaveFamily::Email;
    if (key == "pushEnabled") return ModernSaveFamily::Push;
    if (key == "adminPhone" || key == "numberBlackList" || key == "forwardRules") {
        return ModernSaveFamily::Routing;
    }
    if (key == "networkMode") return ModernSaveFamily::Network;
    if (key == "heartbeatEnable" || key == "heartbeatInterval") return ModernSaveFamily::Heartbeat;
    if (key == "kaEnabled" || key == "kaIntervalDays" || key == "kaTrafficKB") {
        return ModernSaveFamily::Keepalive;
    }
    for (const char* suffix : {"en", "type", "name", "url", "key1", "key2", "body", "title", "template"}) {
        if (indexed_save_key(key, "push", suffix, IDF_MAX_PUSH_CHANNELS) >= 0) return ModernSaveFamily::Push;
    }
    for (const char* suffix : {"ssid", "pass", "open"}) {
        if (indexed_save_key(key, "wifi", suffix, IDF_MAX_WIFI_NETWORKS) >= 0) return ModernSaveFamily::Wifi;
    }
    for (const char* suffix : {"user", "pass"}) {
        if (indexed_save_key(key, "account", suffix, IDF_MAX_WEB_ACCOUNTS) >= 0) return ModernSaveFamily::Accounts;
    }
    return ModernSaveFamily::Unknown;
}

static size_t modern_field_limit(const std::string& key)
{
    if (key == "deviceName") return 64;
    if (key == "hostname") return 32;
    if (key == "notificationLocale") return 16;
    if (key == "smtpServer") return 253;
    if (key == "emailEnabled" || key == "pushEnabled" || key == "smtpPort" ||
        key == "networkMode" || key == "heartbeatEnable" ||
        key == "heartbeatInterval" || key == "kaEnabled" || key == "kaIntervalDays" ||
        key == "kaTrafficKB") return 32;
    if (key == "smtpUser") return 254;
    if (key == "smtpSendTo") return MAX_SMTP_RECIPIENT_BYTES;
    if (key == "smtpPass") return 256;
    if (key == "adminPhone") return MAX_ADMIN_PHONE_BYTES;
    if (key == "numberBlackList") return 1024;
    if (key == "forwardRules") return MAX_FORWARD_RULES_BYTES;
    for (const char* suffix : {"ssid", "pass", "open"}) {
        if (indexed_save_key(key, "wifi", suffix, IDF_MAX_WIFI_NETWORKS) >= 0) {
            return strcmp(suffix, "ssid") == 0 ? 31 : strcmp(suffix, "pass") == 0 ? 63 : 32;
        }
    }
    for (const char* suffix : {"user", "pass"}) {
        if (indexed_save_key(key, "account", suffix, IDF_MAX_WEB_ACCOUNTS) >= 0) {
            return strcmp(suffix, "user") == 0 ? 64 : 96;
        }
    }
    for (const char* suffix : {"en", "type", "name", "url", "key1", "key2", "body", "title", "template"}) {
        if (indexed_save_key(key, "push", suffix, IDF_MAX_PUSH_CHANNELS) >= 0) {
            if (strcmp(suffix, "url") == 0) return 512;
            if (strcmp(suffix, "key1") == 0 || strcmp(suffix, "key2") == 0 || strcmp(suffix, "title") == 0) return 256;
            if (strcmp(suffix, "body") == 0 || strcmp(suffix, "template") == 0) return 2048;
            return strcmp(suffix, "name") == 0 ? 64 : 32;
        }
    }
    return 0;
}

static bool validate_modern_fields(const IdfFormFields& fields, std::string& detail, const char*& code)
{
    for (size_t i = 0; i < fields.size(); ++i) {
        const size_t limit = modern_field_limit(fields[i].first);
        if (limit == 0) { detail = fields[i].first; code = "ACTION_INPUT_INVALID"; return false; }
        if (fields[i].second.size() > limit) { detail = fields[i].first; code = "ACTION_INPUT_TOO_LONG"; return false; }
        for (size_t j = 0; j < i; ++j) {
            if (fields[i].first == fields[j].first) {
                detail = fields[i].first; code = "ACTION_INPUT_INVALID"; return false;
            }
        }
    }
    return true;
}

static esp_err_t send_modern_save_result(httpd_req_t* req, esp_err_t err, const char* detail = "")
{
    if (!req) return err;
    set_json_no_cache(req);
    const bool ok = err == ESP_OK;
    if (!ok) httpd_resp_set_status(req, err == ESP_ERR_INVALID_ARG ? "400 Bad Request" : "500 Internal Server Error");
    std::string body = action_result(ok, ok ? "ACTION_CONFIG_SAVED" :
                                     err == ESP_ERR_INVALID_ARG ? "ACTION_CONFIG_INVALID" : "ACTION_CONFIG_SAVE_FAILED",
                                     {}, ok ? std::string() : detail);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_modern_save(httpd_req_t* req, const IdfFormFields& fields)
{
    ModernSaveFamily family = ModernSaveFamily::Unknown;
    for (size_t i = 0; i < fields.size(); ++i) {
        ModernSaveFamily next = modern_save_field_family(fields[i].first);
        if (next == ModernSaveFamily::Unknown ||
            (family != ModernSaveFamily::Unknown && family != next)) {
            return send_modern_save_result(req, ESP_ERR_INVALID_ARG, fields[i].first.c_str());
        }
        for (size_t j = 0; j < i; ++j) {
            if (fields[i].first == fields[j].first) {
                return send_modern_save_result(req, ESP_ERR_INVALID_ARG, fields[i].first.c_str());
            }
        }
        family = next;
    }
    if (family == ModernSaveFamily::Unknown) return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "form");

    if (family == ModernSaveFamily::Identity) {
        const IdfConfigWebView current = idf_config_get_web_view();
        return send_modern_save_result(req,
            idf_config_save_identity(has_field(fields, "deviceName") ? field_text(fields, "deviceName") : current.deviceName,
                                     has_field(fields, "hostname") ? field_text(fields, "hostname") : current.hostname),
            "identity");
    }

    if (family == ModernSaveFamily::Locale) {
        if (fields.size() != 1) return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "notificationLocale");
        return send_modern_save_result(req,
            idf_config_save_notification_locale(field_text(fields, "notificationLocale")),
            "notificationLocale");
    }

    if (family == ModernSaveFamily::Network) {
        int mode = -1;
        if (fields.size() != 1 || !parse_int_strict(field_text(fields, "networkMode"), mode) ||
            mode < 0 || mode > 2) {
            return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "networkMode");
        }
        return send_modern_save_result(req, idf_config_save_network_mode(mode), "networkMode");
    }

    if (family == ModernSaveFamily::Heartbeat) {
        const IdfConfigWebView current = idf_config_get_web_view();
        int interval = current.heartbeatInterval;
        if ((has_field(fields, "heartbeatInterval") &&
             !parse_int_strict(field_text(fields, "heartbeatInterval"), interval)) ||
            interval < 1 || interval > 240) {
            return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "heartbeatInterval");
        }
        return send_modern_save_result(req,
            idf_config_save_heartbeat(has_field(fields, "heartbeatEnable"), interval), "heartbeat");
    }

    if (family == ModernSaveFamily::Keepalive) {
        const IdfKeepaliveRunView current = idf_config_get_keepalive_run_view();
        int interval = current.kaIntervalDays;
        int traffic = current.kaTrafficKB;
        if ((has_field(fields, "kaIntervalDays") &&
             !parse_int_strict(field_text(fields, "kaIntervalDays"), interval)) ||
            interval < 1 || interval > 3650) {
            return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "kaIntervalDays");
        }
        if ((has_field(fields, "kaTrafficKB") &&
             !parse_int_strict(field_text(fields, "kaTrafficKB"), traffic)) ||
            traffic < MIN_KEEPALIVE_TRAFFIC_KB || traffic > MAX_KEEPALIVE_TRAFFIC_KB) {
            return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "kaTrafficKB");
        }
        return send_modern_save_result(req,
            idf_config_save_keepalive(has_field(fields, "kaEnabled"), interval, current.kaAction,
                                      current.kaTarget, current.kaUrl, current.kaProfile, traffic),
            "keepalive");
    }

    if (family == ModernSaveFamily::Email) {
        const IdfConfigWebView current = idf_config_get_web_view();
        bool enabled = current.emailEnabled;
        int port = current.smtpPort;
        if (has_field(fields, "emailEnabled")) {
            const std::string emailEnabled = field_text(fields, "emailEnabled");
            if (emailEnabled != "0" && emailEnabled != "1") {
                return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "emailEnabled");
            }
            enabled = emailEnabled == "1";
        }
        if ((has_field(fields, "smtpPort") && !parse_int_strict(field_text(fields, "smtpPort"), port)) ||
            port < 1 || port > 65535) {
            return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "smtpPort");
        }
        const bool has_pass = has_field(fields, "smtpPass");
        esp_err_t err = idf_config_save_email(enabled,
            has_field(fields, "smtpServer") ? field_text(fields, "smtpServer") : current.smtpServer, port,
            has_field(fields, "smtpUser") ? field_text(fields, "smtpUser") : current.smtpUser,
            field_text(fields, "smtpPass"),
            has_field(fields, "smtpSendTo") ? field_text(fields, "smtpSendTo") : current.smtpSendTo,
            !has_pass);
        return send_modern_save_result(req, err, "email");
    }

    if (family == ModernSaveFamily::Routing) {
        if (has_field(fields, "forwardRules")) {
            if (fields.size() != 1) return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "forwardRules");
            return send_modern_save_result(req,
                idf_config_save_forward_rules(field_text(fields, "forwardRules")), "forwardRules");
        }
        const IdfConfigWebView current = idf_config_get_web_view();
        return send_modern_save_result(req,
            idf_config_save_filter(has_field(fields, "adminPhone") ? field_text(fields, "adminPhone") : current.adminPhone,
                                   has_field(fields, "numberBlackList") ? field_text(fields, "numberBlackList") : current.numberBlackList),
            "routing");
    }

    if (family == ModernSaveFamily::Push) {
        int index = -1;
        for (const auto& field : fields) {
            if (field.first == "pushEnabled") continue;
            int parsed = -1;
            for (const char* suffix : {"en", "type", "name", "url", "key1", "key2", "body", "title", "template"}) {
                parsed = indexed_save_key(field.first, "push", suffix, IDF_MAX_PUSH_CHANNELS);
                if (parsed >= 0) break;
            }
            if (index >= 0 && parsed != index) return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "push");
            index = parsed;
        }
        const IdfConfigWebView current = idf_config_get_web_view();
        bool enabled = current.pushEnabled;
        if (has_field(fields, "pushEnabled")) {
            const std::string pushEnabled = field_text(fields, "pushEnabled");
            if (pushEnabled != "0" && pushEnabled != "1") {
                return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "pushEnabled");
            }
            enabled = pushEnabled == "1";
        }
        IdfPushChannel channels[IDF_MAX_PUSH_CHANNELS];
        for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) channels[i] = current.pushChannels[i];
        if (index < 0) {
            return send_modern_save_result(req, idf_config_save_push(enabled, channels), "push");
        }
        char key[24];
        snprintf(key, sizeof(key), "push%dtype", index);
        int type = current.pushChannels[index].type;
        if ((has_field(fields, key) && !parse_int_strict(field_text(fields, key), type)) || type < 1 || type > 12) {
            return send_modern_save_result(req, ESP_ERR_INVALID_ARG, key);
        }
        IdfPushChannel next = type == current.pushChannels[index].type
            ? current.pushChannels[index] : IdfPushChannel();
        next.type = static_cast<uint8_t>(type);
        snprintf(key, sizeof(key), "push%den", index); next.enabled = has_field(fields, key);
        snprintf(key, sizeof(key), "push%dname", index); if (has_field(fields, key)) next.name = field_text(fields, key);
        snprintf(key, sizeof(key), "push%durl", index); if (!field_text(fields, key).empty()) next.url = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dkey1", index); if (!field_text(fields, key).empty()) next.key1 = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dkey2", index); if (!field_text(fields, key).empty()) next.key2 = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dbody", index); if (!field_text(fields, key).empty()) next.customBody = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dtitle", index); if (has_field(fields, key)) next.titleTemplate = field_text(fields, key);
        snprintf(key, sizeof(key), "push%dtemplate", index); if (has_field(fields, key)) next.bodyTemplate = field_text(fields, key);
        channels[index] = std::move(next);
        return send_modern_save_result(req, idf_config_save_push(enabled, channels), "push");
    }

    if (family == ModernSaveFamily::Wifi) {
        int index = -1;
        for (const auto& field : fields) {
            int parsed = indexed_save_key(field.first, "wifi", "ssid", IDF_MAX_WIFI_NETWORKS);
            if (parsed < 0) parsed = indexed_save_key(field.first, "wifi", "pass", IDF_MAX_WIFI_NETWORKS);
            if (parsed < 0) parsed = indexed_save_key(field.first, "wifi", "open", IDF_MAX_WIFI_NETWORKS);
            if (index >= 0 && parsed != index) return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "wifi");
            index = parsed;
        }
        char ssid_key[20], pass_key[20], open_key[20];
        snprintf(ssid_key, sizeof(ssid_key), "wifi%dssid", index);
        snprintf(pass_key, sizeof(pass_key), "wifi%dpass", index);
        snprintf(open_key, sizeof(open_key), "wifi%dopen", index);
        const IdfConfigWebView current = idf_config_get_web_view();
        const std::string ssid = has_field(fields, ssid_key) ? field_text(fields, ssid_key) :
                                 current.wifiNetworks[index].ssid;
        const std::string pass = field_text(fields, pass_key);
        const bool open = has_field(fields, open_key);
        const bool retain_password = !open && pass.empty() &&
                                     ssid == current.wifiNetworks[index].ssid &&
                                     current.wifiNetworks[index].passSet;
        if (!ssid.empty() && !open && pass.empty() && !retain_password) {
            return send_modern_save_result(req, ESP_ERR_INVALID_ARG, pass_key);
        }
        return send_modern_save_result(req,
            idf_config_save_wifi_profile(index, ssid, pass, open, retain_password), "wifi");
    }

    if (family == ModernSaveFamily::Accounts) {
        const IdfConfigWebView current = idf_config_get_web_view();
        IdfWebAccount accounts[IDF_MAX_WEB_ACCOUNTS];
        for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
            char user_key[24], pass_key[24];
            snprintf(user_key, sizeof(user_key), "account%duser", i);
            snprintf(pass_key, sizeof(pass_key), "account%dpass", i);
            accounts[i].username = has_field(fields, user_key) ? field_text(fields, user_key) : current.webAccounts[i].username;
            accounts[i].password = field_text(fields, pass_key);
            if (accounts[i].username.empty()) accounts[i].password.clear();
        }
        return send_modern_save_result(req, idf_config_save_accounts(accounts, true), "accounts");
    }

    return send_modern_save_result(req, ESP_ERR_INVALID_ARG, "form");
}

static std::string run_save_job(const std::string& body)
{
    const IdfWebFormDecodeResult decoded = idf_web_decode_form(body, 51);
    if (!decoded.valid) return action_result(false, decoded.too_many_fields ?
        "ACTION_TOO_MANY_FIELDS" : "ACTION_INPUT_INVALID");
    const esp_err_t err = handle_modern_save(nullptr, decoded.fields);
    if (err == ESP_OK) return action_result(true, "ACTION_CONFIG_SAVED");
    bool account_update = false;
    for (const auto& field : decoded.fields) {
        account_update = account_update || field.first.compare(0, 7, "account") == 0;
    }
    return action_result(false,
        account_update && err == ESP_ERR_INVALID_ARG ? "ACTION_CONFIG_ACCOUNT_REQUIRED" :
        err == ESP_ERR_INVALID_ARG ? "ACTION_CONFIG_INVALID" : "ACTION_CONFIG_SAVE_FAILED");
}

static esp_err_t send_action_error(httpd_req_t* req, const char* code, const std::string& detail,
                                   const char* status = "400 Bad Request")
{
    set_json_no_cache(req);
    httpd_resp_set_status(req, status);
    const std::string result = action_result(false, code, {}, detail);
    return httpd_resp_send(req, result.c_str(), result.size());
}

static esp_err_t handle_save(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    if (idf_push_test_active()) return send_action_error(req, "ACTION_BUSY", {}, "409 Conflict");
    std::string body;
    // 16KB: five custom push templates plus URL-encoded forwarding rules can exceed 8KB.
    if (read_body(req, body, 16384) != ESP_OK) return ESP_OK;
    const IdfWebFormDecodeResult decoded = idf_web_decode_form(body, 51);
    if (!decoded.valid) return send_action_error(req, decoded.too_many_fields ?
        "ACTION_TOO_MANY_FIELDS" : "ACTION_INPUT_INVALID", "form");
    std::string detail;
    const char* code = "ACTION_INPUT_INVALID";
    if (!validate_modern_fields(decoded.fields, detail, code)) return send_action_error(req, code, detail);
    if (decoded.fields.empty()) return send_action_error(req, "ACTION_INPUT_INVALID", "form");
    IdfFormFields fields = decoded.fields;
    return enqueue_api_job(req, "save", body);

    // Kept only as source reference during migration; marker-based forms are not reachable.
    const bool modern = std::none_of(fields.begin(), fields.end(), [](const auto& field) {
        return field.first.size() >= 4 && field.first.compare(field.first.size() - 4, 4, "Form") == 0;
    });
    if (modern) return handle_modern_save(req, fields);

    const bool account_form = has_field(fields, "accountForm");
    const bool tz_form = has_field(fields, "tzForm");
    const bool led_form = has_field(fields, "ledForm");
    const bool email_form = has_field(fields, "emailForm");
    const bool push_form = has_field(fields, "pushForm");
    const bool filter_form = has_field(fields, "filterForm");
    const bool rules_form = has_field(fields, "rulesForm");
    const bool ka_form = has_field(fields, "kaForm");
    const bool st_form = has_field(fields, "stForm");
    const bool system_sched_form = has_field(fields, "systemSchedForm");
    const bool sim_form = has_field(fields, "simForm");
    const bool call_form = has_field(fields, "callForm");
    const bool mdns_form = has_field(fields, "mdnsForm");
    const bool wifi_list_form = has_field(fields, "wifiListForm");
    const int form_count = (account_form ? 1 : 0) + (tz_form ? 1 : 0) +
                           (led_form ? 1 : 0) + (email_form ? 1 : 0) +
                           (push_form ? 1 : 0) + (filter_form ? 1 : 0) +
                           (rules_form ? 1 : 0) + (ka_form ? 1 : 0) +
                           (st_form ? 1 : 0) + (system_sched_form ? 1 : 0) +
                           (sim_form ? 1 : 0) + (call_form ? 1 : 0) +
                           (mdns_form ? 1 : 0) + (wifi_list_form ? 1 : 0);
    if (form_count != 1) {
        idf_log_line(form_count == 0 ? "Web save request missing form marker; ignored"
                                     : "Web save request contains multiple form markers; rejected");
        set_no_cache_headers(req);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            form_count == 0 ? "unknown save form" : "multiple save forms");
        return ESP_OK;
    }

    auto fail = [&](esp_err_t err) -> esp_err_t {
        set_no_cache_headers(req);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, esp_err_to_name(err));
        return ESP_OK;
    };
    auto ok = [&](const char* log_line) -> esp_err_t {
        httpd_resp_set_type(req, "text/plain");
        set_no_cache_headers(req);
        httpd_resp_sendstr(req, "OK");
        idf_log_line(log_line);
        return ESP_OK;
    };

    if (account_form) {
        esp_err_t err = idf_config_save_account(field_text(fields, "webUser"),
                                                field_text(fields, "webPass"));
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved administrator account");
    }

    if (tz_form) {
        esp_err_t err = idf_config_save_time(field_int(fields, "tzOffsetMin", 480),
                                             field_text(fields, "ntpServer"));
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved time settings");
    }

    if (mdns_form) {
        // idf_config_save_mdns_host normalizes case, strips .local, and filters invalid characters.
        // After saving, the mDNS responder switches hostnames within one second without a restart.
        esp_err_t err = idf_config_save_mdns_host(field_text(fields, "mdnsHost"));
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved mDNS hostname");
    }

    if (wifi_list_form) {
        // Legacy full WiFi-list save: an empty SSID deletes the slot; an empty password preserves the saved password.
        // Updating the list does not interrupt the current connection; reconnect or restart uses the new list.
        IdfWifiNetwork nets[IDF_MAX_WIFI_NETWORKS];
        for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
            char key[16];
            snprintf(key, sizeof(key), "wifi%dSsid", i);
            nets[i].ssid = field_text(fields, key);
            snprintf(key, sizeof(key), "wifi%dPass", i);
            nets[i].pass = field_text(fields, key);
        }
        uint8_t wifi_tx_power = field_u8(fields, "wifiTxPowerQuarterDbm", 34);
        esp_err_t err = idf_config_save_wifi_networks(nets, true, wifi_tx_power);
        if (err == ESP_ERR_INVALID_ARG) {
            set_no_cache_headers(req);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                "Invalid WiFi network or transmit-power setting");
            return ESP_OK;
        }
        if (err != ESP_OK) return fail(err);
        esp_err_t apply_err = idf_wifi_set_tx_power(wifi_tx_power);
        if (apply_err != ESP_OK) idf_logf("WiFi power saved but could not be applied immediately: %s", esp_err_to_name(apply_err));
        return ok("Web UI saved WiFi network list");
    }

    if (led_form) {
        bool enabled = has_field(fields, "netLedEnabled");
        esp_err_t err = idf_config_set_net_led_enabled(enabled);
        if (err != ESP_OK) {
            return fail(err);
        }
        httpd_resp_set_type(req, "text/plain");
        set_no_cache_headers(req);
        httpd_resp_sendstr(req, "OK");
        idf_logf("Web UI saved NET indicator setting: %s", enabled ? "enabled" : "disabled");
        return ESP_OK;
    }

    if (call_form) {
        bool enabled = has_field(fields, "callNotifyEnabled");
        esp_err_t err = idf_config_set_call_notify_enabled(enabled);
        if (err != ESP_OK) return fail(err);
        httpd_resp_set_type(req, "text/plain");
        set_no_cache_headers(req);
        httpd_resp_sendstr(req, "OK");
        idf_logf("Web UI saved call notification setting: %s", enabled ? "enabled" : "disabled");
        return ESP_OK;
    }

    if (email_form) {
        std::string smtp_pass = field_text(fields, "smtpPass");
        bool preserve_smtp_pass = field_blank(smtp_pass);
        esp_err_t err = idf_config_save_email(has_field(fields, "emailEnabled"),
                                              field_text(fields, "smtpServer"),
                                              field_int(fields, "smtpPort", 465),
                                              field_text(fields, "smtpUser"),
                                              smtp_pass,
                                              field_text(fields, "smtpSendTo"),
                                              preserve_smtp_pass);
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved email settings");
    }

    if (push_form) {
        IdfPushChannel channels[IDF_MAX_PUSH_CHANNELS];
        IdfConfigWebView current = idf_config_get_web_view();
        parse_push_channels_form(fields, current.pushChannels, channels);
        esp_err_t err = idf_config_save_push(has_field(fields, "pushEnabled"), channels);
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved push channels");
    }

    if (filter_form) {
        // The administrator number and blacklist are separate forms that submit only their own fields.
        // Preserve omitted fields from current configuration so saving either form does not clear the other.
        IdfConfigWebView cur = idf_config_get_web_view();
        std::string admin = has_field(fields, "adminPhone")
                                ? field_text(fields, "adminPhone") : cur.adminPhone;
        std::string blacklist = has_field(fields, "numberBlackList")
                                    ? field_text(fields, "numberBlackList") : cur.numberBlackList;
        esp_err_t err = idf_config_save_filter(admin, blacklist);
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved permissions and filters");
    }

    if (rules_form) {
        std::string rules = field_text(fields, "forwardRules");
        std::string rule_error;
        esp_err_t err = idf_config_validate_forward_rules(rules, &rule_error);
        if (err != ESP_OK) {
            set_no_cache_headers(req);
            std::string msg = "Invalid forwarding rule format";
            if (!rule_error.empty()) msg += ": " + rule_error;
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, msg.c_str());
            return ESP_OK;
        }
        err = idf_config_save_forward_rules(rules);
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved forwarding rules");
    }

    if (ka_form) {
        const IdfKeepaliveRunView current = idf_config_get_keepalive_run_view();
        esp_err_t err = idf_config_save_keepalive(has_field(fields, "kaEnabled"),
                                                  field_int(fields, "kaIntervalDays", current.kaIntervalDays),
                                                  field_u8(fields, "kaAction", 1),
                                                  field_text(fields, "kaTarget"),
                                                  field_text(fields, "kaUrl"),
                                                  field_text(fields, "kaProfile"),
                                                  field_int(fields, "kaTrafficKB", current.kaTrafficKB));
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved SIM keepalive settings");
    }

    if (st_form) {
        IdfSchedTask tasks[IDF_MAX_SCHED_TASKS];
        parse_sched_tasks_form(fields, tasks);
        esp_err_t err = idf_config_save_sched_tasks(tasks);
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved custom scheduled tasks");
    }

    if (system_sched_form) {
        esp_err_t err = idf_config_save_system_schedule(has_field(fields, "rebootEnabled"),
                                                        field_int(fields, "rebootHour", 4),
                                                        has_field(fields, "hbEnabled"),
                                                        field_int(fields, "hbHour", 9),
                                                        has_field(fields, "smsHealthEnabled"),
                                                        field_int(fields, "smsHealthHour", 10),
                                                        has_field(fields, "smsHealthNotify"));
        if (err != ESP_OK) return fail(err);
        return ok("Web UI saved system schedule");
    }

    if (sim_form) {
        IdfSimSettingsView before = idf_config_get_sim_settings_view();
        IdfSimCredential credentials[IDF_MAX_SIM_CREDENTIALS];
        parse_sim_credentials_form(fields, credentials);
        esp_err_t err = idf_config_save_sim(has_field(fields, "dataEnabled"),
                                            has_field(fields, "roamingEnabled"),
                                            field_text(fields, "apn"),
                                            field_text(fields, "operatorPlmn"),
                                            field_text(fields, "phoneNumber"),
                                            credentials);
        if (err == ESP_ERR_INVALID_ARG) {
            set_no_cache_headers(req);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid SIM ICCID/PIN/PUK format");
            return ESP_OK;
        }
        if (err != ESP_OK) return fail(err);
        IdfSimSettingsView after = idf_config_get_sim_settings_view();
        bool data_changed = before.dataEnabled != after.dataEnabled || before.apn != after.apn ||
                            before.roamingEnabled != after.roamingEnabled;
        bool operator_changed = before.operatorPlmn != after.operatorPlmn;
        bool credentials_changed = false;
        for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
            const IdfSimCredential& a = before.credentials[i];
            const IdfSimCredential& b = after.credentials[i];
            credentials_changed = credentials_changed || a.iccid != b.iccid || a.pin != b.pin ||
                                  a.puk != b.puk || a.pinMaxAttempts != b.pinMaxAttempts ||
                                  a.pukMaxAttempts != b.pukMaxAttempts ||
                                  a.pinFailedAttempts != b.pinFailedAttempts ||
                                  a.pukFailedAttempts != b.pukFailedAttempts;
        }

        httpd_resp_set_type(req, "text/plain");
        set_no_cache_headers(req);
        httpd_resp_sendstr(req, "OK");
        idf_log_line("Web UI saved cellular settings");
        if (credentials_changed) idf_modem_request_sim_unlock(false);
        if (!data_changed && !operator_changed) return ESP_OK;

        ModemApplyTaskArg* arg = new (std::nothrow) ModemApplyTaskArg();
        if (arg) {
            arg->dataChanged = data_changed;
            arg->operatorChanged = operator_changed;
            arg->dataEnabled = after.dataEnabled;
            arg->roamingEnabled = after.roamingEnabled;  // Required for the immediate roaming-disable guard.
            arg->apn = after.apn;
            arg->operatorPlmn = after.operatorPlmn;
            if (xTaskCreate(modem_apply_task, "idf_sim_apply", 4096, arg, 3, nullptr) != pdPASS) {
                delete arg;
                idf_log_line("SIM settings saved, but the background AT apply task could not be created");
            }
        } else {
            idf_log_line("SIM settings saved, but memory was insufficient for the background AT apply task");
        }
        return ESP_OK;
    }

    return ESP_OK;
}


static void restart_task(void*)
{
    vTaskDelay(pdMS_TO_TICKS(1200));
    // Power off the modem before a planned restart so restarting the device still recovers a stuck modem.
    // Reserve the modem warm-start path for unexpected resets such as crashes and watchdogs.
    idf_modem_power_off_for_restart();
    esp_restart();
}

static bool claim_restart_owner()
{
    bool expected = false;
    if (s_device_restart_pending.compare_exchange_strong(
            expected, true, std::memory_order_acq_rel)) return true;
    idf_log_line("Restart already pending; keeping the existing restart owner");
    return false;
}

static void release_restart_owner()
{
    s_device_restart_pending.store(false, std::memory_order_release);
}

static bool schedule_restart_or_now(const char* task_name, bool already_claimed)
{
    if (!already_claimed && !claim_restart_owner()) return false;
    if (xTaskCreate(restart_task, task_name, 3072, nullptr, 1, nullptr) == pdPASS) return true;
    idf_log_line("Restart task creation failed; restarting from the current task");
    restart_task(nullptr);
    return true;
}

static esp_err_t handle_factory_reset(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    if (reject_restart_while_backup_active(req)) return ESP_OK;
    if (!claim_restart_owner()) return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    esp_err_t err = idf_config_factory_reset();
    if (err == ESP_OK) idf_log_line("Web UI requested factory reset; all configuration cleared, restarting");
    set_json_no_cache(req);
    if (err != ESP_OK) {
        release_restart_owner();
        std::string body = "{\"success\":false,";
        json_prop(body, "message", std::string("Factory reset failed: ") + esp_err_to_name(err));
        body += "}";
        return httpd_resp_send(req, body.c_str(), body.size());
    }
    if (!schedule_restart_or_now("factory_restart", true)) {
        release_restart_owner();
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    esp_err_t send_err = httpd_resp_sendstr(req, "{\"success\":true,\"message\":\"Configuration cleared; device will restart with default settings\"}");
    return send_err;
}

static esp_err_t handle_wifi_config(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    const bool ap_mode = idf_wifi_is_ap_mode();
    if (!ap_mode && reject_restart_while_backup_active(req)) return ESP_OK;
    std::string body;
    if (read_body(req, body, 1024) != ESP_OK) return ESP_OK;
    IdfFormFields fields = parse_urlencoded(body);
    std::string ssid_s = field_text(fields, "ssid");
    std::string pass_s = field_text(fields, "pass");
    set_json_no_cache(req);
    const bool valid_password = pass_s.empty() ||
        (pass_s.size() >= 8 && pass_s.size() <= MAX_WIFI_PASSWORD_BYTES &&
         std::all_of(pass_s.begin(), pass_s.end(), [](unsigned char ch) {
             return ch >= 0x20 && ch <= 0x7E;
         }));
    if (ssid_s.empty() || ssid_s.size() > MAX_WIFI_SSID_BYTES || !valid_password ||
        ssid_s.find('\0') != std::string::npos) {
        httpd_resp_set_status(req, "400 Bad Request");
        std::string msg = "{\"success\":false,\"message\":\"Invalid WiFi configuration\"}";
        return httpd_resp_send(req, msg.c_str(), msg.size());
    }
    if (!ap_mode && !claim_restart_owner()) {
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    // Persist the exact provisioning slot before touching the runtime driver.
    esp_err_t err = idf_config_save_wifi_profile(0, ssid_s, pass_s, pass_s.empty(), false);
    if (err != ESP_OK) {
        if (!ap_mode) release_restart_owner();
        httpd_resp_set_status(req, "500 Internal Server Error");
        std::string msg = "{\"success\":false,\"message\":\"WiFi configuration could not be saved; retry\"}";
        return httpd_resp_send(req, msg.c_str(), msg.size());
    }
    if (ap_mode) {
        // ESP_OK only means startup was accepted; authentication completes asynchronously.
        const esp_err_t connect_err = idf_wifi_provision_connect(ssid_s, pass_s);
        if (connect_err != ESP_OK) {
            httpd_resp_set_status(req,
                connect_err == ESP_ERR_NOT_FOUND || connect_err == ESP_ERR_INVALID_STATE
                    ? "409 Conflict" : "500 Internal Server Error");
            std::string msg = "{\"success\":false,\"message\":\"WiFi credentials were saved, but connection startup failed; credentials retained and AP remains available\"}";
            return httpd_resp_send(req, msg.c_str(), msg.size());
        }
        std::string msg = "{\"success\":true,\"message\":\"Saved; connecting\"}";
        return httpd_resp_send(req, msg.c_str(), msg.size());
    }
    std::string msg = "{\"success\":true,\"message\":\"WiFi saved; device will restart\"}";
    if (!schedule_restart_or_now("wifi_restart", true)) {
        release_restart_owner();
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    esp_err_t send_err = httpd_resp_send(req, msg.c_str(), msg.size());
    return send_err;
}

// Minimal provisioning status: return only connection state and local STA IP, never saved configuration.
static esp_err_t handle_apstatus(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;  // AP mode is allowlisted without a password; STA mode still requires login.
    IdfWifiStatus wifi = idf_wifi_get_status();
    set_json_no_cache(req);
    std::string body = "{\"apMode\":";
    body += wifi.apMode ? "true" : "false";
    body += ",\"connected\":";
    body += (wifi.staConnected && !wifi.ip.empty()) ? "true" : "false";
    body += ",\"ip\":\"";
    body += wifi.ip;
    body += "\"}";
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_wifi(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    char query[64] = {};
    char action[24] = {};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        httpd_query_key_value(query, "action", action, sizeof(action));
    }
    if (strcmp(action, "restart") == 0) return enqueue_api_job(req, "wifi", action);
    return send_action_error(req, "ACTION_UNKNOWN", "action");
}

static esp_err_t handle_wifi_scan(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    set_json_no_cache(req);
    std::string poll;
    const bool poll_only = get_query_param(req, "poll", poll, 96) && poll == "1";
    const esp_err_t request_err = poll_only ? ESP_OK : idf_wifi_scan_request();
    IdfWifiScanSnapshot snapshot = idf_wifi_scan_get_snapshot();
    httpd_resp_set_hdr(req, "X-WiFi-Scan-Busy", snapshot.busy ? "1" : "0");
    httpd_resp_set_hdr(req, "X-WiFi-Scan-Ready", snapshot.ready ? "1" : "0");
    const esp_err_t error = request_err != ESP_OK ? request_err : snapshot.error;
    if (error != ESP_OK && !snapshot.ready && !snapshot.busy) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, esp_err_to_name(error));
        return ESP_OK;
    }
    return httpd_resp_send(req, snapshot.json.c_str(), snapshot.json.size());
}


static esp_err_t handle_send_sms(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    std::string raw;
    if (read_body(req, raw, 16384) != ESP_OK) return ESP_OK;
    const IdfWebFormDecodeResult decoded = idf_web_decode_form(raw, 48);
    if (!decoded.valid) return send_action_error(req, decoded.too_many_fields ?
        "ACTION_TOO_MANY_FIELDS" : "ACTION_INPUT_INVALID", "form");
    for (const auto& field : decoded.fields) {
        const size_t limit = field.first == "phone" ? 32 : field.first == "content" ? 2048 : 0;
        if (limit == 0) return send_action_error(req, "ACTION_INPUT_INVALID", field.first);
        if (field.second.size() > limit) return send_action_error(req, "ACTION_INPUT_TOO_LONG", field.first);
    }
    return enqueue_api_job(req, "sms", raw);
}

static esp_err_t handle_messages(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    char query[96] = {};
    char box_raw[16] = {};
    char limit_raw[16] = {};
    bool sent_box = false;
    int limit = 0;
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK) {
        if (httpd_query_key_value(query, "box", box_raw, sizeof(box_raw)) == ESP_OK &&
            strcmp(box_raw, "sent") == 0) {
            sent_box = true;
        }
        if (httpd_query_key_value(query, "limit", limit_raw, sizeof(limit_raw)) == ESP_OK) {
            int parsed_limit = 0;
            if (parse_int_strict(limit_raw, parsed_limit)) limit = parsed_limit;
        }
    }
    set_json_no_cache(req);
    std::string body = idf_inbox_json(sent_box, limit);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_empty_log(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    set_json_no_cache(req);
    std::string raw;
    uint32_t cursor = 0;
    const bool has_cursor = get_query_param(req, "cursor", raw, 96);
    if (has_cursor && !parse_u32_strict(raw.c_str(), cursor, true)) {
        httpd_resp_set_status(req, "400 Bad Request");
        return httpd_resp_sendstr(req, "{\"entries\":[],\"nextCursor\":null,\"hasMore\":false}");
    }
    size_t limit = 50;
    if (get_query_param(req, "limit", raw, 96)) {
        int parsed = 0;
        if (!parse_int_strict(raw, parsed) || parsed < 1 || parsed > 50) {
            httpd_resp_set_status(req, "400 Bad Request");
            return httpd_resp_sendstr(req, "{\"entries\":[],\"nextCursor\":null,\"hasMore\":false}");
        }
        limit = static_cast<size_t>(parsed);
    }
    std::string body = idf_web_paginate_log_json(idf_log_json_since(0), has_cursor, cursor, limit);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_log_download(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    set_no_cache_headers(req);
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=sms_idf_log.txt");
    std::string body = idf_log_text_dump();
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_prev_log(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    set_no_cache_headers(req);
    char query[32] = {};
    char dl_raw[8] = {};
    // Download as an attachment with ?dl=1; otherwise display in the browser.
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) == ESP_OK &&
        httpd_query_key_value(query, "dl", dl_raw, sizeof(dl_raw)) == ESP_OK &&
        strcmp(dl_raw, "1") == 0) {
        httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=sms_idf_prev_log.txt");
    }
    std::string body = idf_log_prev_dump();
    if (body.empty()) {
        body = "No previous-run log is available; the device may have just powered on without a saved abnormal-reset log.";
    }
    return httpd_resp_send(req, body.c_str(), body.size());
}

// Download the raw crash dump image and parse the full backtrace on a computer with:
// espcoredump.py info_corefile --core coredump.bin --core-format raw
static esp_err_t handle_coredump_download(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    size_t addr = 0;
    size_t size = 0;
    if (esp_core_dump_image_get(&addr, &size) != ESP_OK || size == 0) {
        httpd_resp_set_type(req, "text/plain; charset=utf-8");
        set_no_cache_headers(req);
        return httpd_resp_sendstr(req, "No crash dump is available; the device did not crash last run or the dump has not been written.");
    }
    const esp_partition_t* part = esp_partition_find_first(
        ESP_PARTITION_TYPE_DATA, ESP_PARTITION_SUBTYPE_DATA_COREDUMP, nullptr);
    if (!part) {
        httpd_resp_set_type(req, "text/plain; charset=utf-8");
        set_no_cache_headers(req);
        return httpd_resp_sendstr(req, "Coredump partition not found.");
    }
    httpd_resp_set_type(req, "application/octet-stream");
    set_no_cache_headers(req);
    httpd_resp_set_hdr(req, "Content-Disposition", "attachment; filename=coredump.bin");
    // Stream chunks to avoid copying the entire dump (up to 64KB) into the heap.
    char chunk[1024];
    size_t offset = addr >= part->address ? addr - part->address : 0;
    size_t remaining = size;
    while (remaining > 0) {
        size_t n = remaining > sizeof(chunk) ? sizeof(chunk) : remaining;
        if (esp_partition_read(part, offset, chunk, n) != ESP_OK) {
            // Disconnect on read failure. Ending chunked transfer would make the browser accept a
            // truncated file and defer the confusing failure to espcoredump.py.
            idf_logf("Crash dump read failed at offset=%u; download aborted", static_cast<unsigned>(offset));
            return ESP_FAIL;
        }
        if (httpd_resp_send_chunk(req, chunk, n) != ESP_OK) return ESP_FAIL;
        offset += n;
        remaining -= n;
    }
    return httpd_resp_send_chunk(req, nullptr, 0);
}

static esp_err_t handle_coredump_clear(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    set_json_no_cache(req);
    esp_err_t err = esp_core_dump_image_erase();
    if (err == ESP_OK) {
        idf_log_line("Crash dump cleared");
        return httpd_resp_sendstr(req, "{\"success\":true,\"message\":\"Crash dump cleared\"}");
    }
    char body[128];
    snprintf(body, sizeof(body), "{\"success\":false,\"message\":\"Clear failed: %s\"}", esp_err_to_name(err));
    return httpd_resp_send(req, body, strlen(body));
}

static bool query_u32(httpd_req_t* req, const char* key, uint32_t& value)
{
    char query[96] = {};
    char raw[24] = {};
    if (httpd_req_get_url_query_str(req, query, sizeof(query)) != ESP_OK ||
        httpd_query_key_value(query, key, raw, sizeof(raw)) != ESP_OK) {
        return false;
    }
    return parse_u32_strict(raw, value, false);
}

static esp_err_t handle_delete_message(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    uint32_t id = 0;
    bool ok = query_u32(req, "id", id) && idf_inbox_delete(id);
    set_json_no_cache(req);
    return httpd_resp_sendstr(req, ok
        ? "{\"success\":true,\"message\":\"Deleted\"}"
        : "{\"success\":false,\"message\":\"Not found\"}");
}

static esp_err_t handle_resend_message(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    uint32_t id = 0;
    IdfInboxEntry entry;
    bool found = query_u32(req, "id", id) && idf_inbox_get_by_id(id, entry);
    set_json_no_cache(req);
    if (!found) {
        return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"SMS not found\"}");
    }
    bool ok = idf_push_enqueue_forward(entry.sender.c_str(), entry.text.c_str(), entry.ts.c_str(), entry.id);
    idf_logf("Web UI manually retried SMS id=%u: %s", static_cast<unsigned>(id), ok ? "queued" : "queue failed");
    return httpd_resp_sendstr(req, ok
        ? "{\"success\":true,\"message\":\"Requeued for forwarding\"}"
        : "{\"success\":false,\"message\":\"Forwarding queue is busy; try again later\"}");
}

static esp_err_t send_push_test_failure(httpd_req_t* req, const char* status,
                                        const std::string& message)
{
    set_json_no_cache(req);
    httpd_resp_set_status(req, status);
    std::string body = "{\"queued\":false,\"running\":false,\"done\":true,\"success\":false,";
    json_prop(body, "message", message);
    body += "}";
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_test_push(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (req->method != HTTP_GET && req->method != HTTP_POST) {
        httpd_resp_set_hdr(req, "Allow", "GET, POST");
        return send_push_test_failure(req, "405 Method Not Allowed", "Push tests require GET or POST");
    }
    if (req->method == HTTP_POST && !check_csrf(req)) return ESP_OK;
    if (req->method == HTTP_POST && req->content_len != 0) {
        return send_push_test_failure(req, "400 Bad Request", "Push test request body is not allowed");
    }
    std::string channel_raw;
    int channel_value = -1;
    if (!get_query_param(req, "channel", channel_raw, 64) ||
        !parse_int_strict(channel_raw, channel_value) ||
        channel_value < 0 || channel_value >= IDF_MAX_PUSH_CHANNELS) {
        return send_push_test_failure(req, "400 Bad Request", "Invalid channel index");
    }
    const uint8_t channel = static_cast<uint8_t>(channel_value);
    if (req->method == HTTP_GET) {
        set_json_no_cache(req);
        const std::string body = idf_push_test_status_json(channel);
        return httpd_resp_send(req, body.c_str(), body.size());
    }
    if (idf_push_test_channel_active(channel)) {
        httpd_resp_set_status(req, "409 Conflict");
        set_json_no_cache(req);
        const std::string body = idf_push_test_status_json(channel);
        return httpd_resp_send(req, body.c_str(), body.size());
    }
    if (s_push_test_admission_active.exchange(true, std::memory_order_acq_rel)) {
        return send_push_test_failure(req, "409 Conflict", "Device is busy; try again later");
    }
    if (!try_shared_admission(true)) {
        s_push_test_admission_active.store(false, std::memory_order_release);
        return send_push_test_failure(req, "409 Conflict", "Device is busy; try again later");
    }

    std::string message;
    const bool blocked = backup_transfer_active() || ota_active() || device_restart_pending() ||
        restore_restart_pending() || api_jobs_active();
    const bool queued = !blocked && idf_push_enqueue_test(channel, message);
    release_shared_admission();
    s_push_test_admission_active.store(false, std::memory_order_release);
    if (blocked) {
        return send_push_test_failure(req, "409 Conflict", "Device is busy; try again later");
    }
    if (!queued) {
        if (message != "Channel test is already running in the background") {
            return send_push_test_failure(req, "409 Conflict", message);
        }
        httpd_resp_set_status(req, "409 Conflict");
    } else {
        httpd_resp_set_status(req, "202 Accepted");
    }
    set_json_no_cache(req);
    const std::string body = idf_push_test_status_json(channel);
    return httpd_resp_send(req, body.c_str(), body.size());
}

static bool cell_job_lock(TickType_t ticks)
{
    return s_cell_job_mutex && xSemaphoreTake(s_cell_job_mutex, ticks) == pdTRUE;
}

static void cell_job_unlock(void)
{
    xSemaphoreGive(s_cell_job_mutex);
}

static bool cellular_job_active_locked(bool allow_device_restart)
{
    const bool restart_busy =
        (!allow_device_restart && s_device_restart_pending.load(std::memory_order_relaxed)) ||
        idf_web_ota_restart_pending();
    return restart_busy || ota_active() ||
           s_keepalive_job.running || s_keepalive_job.queued ||
           s_esim_job.running || s_esim_job.queued ||
           s_sched_job.running || s_sched_job.queued ||
           s_modem_apply_running ||
           s_web_modem_action_running;
}

struct EsimTaskArg {
    std::string action;
    std::string identifier;
    std::string nickname;
};

static std::string esim_action_label(const std::string& action)
{
    if (action == "refresh") return "Refresh eSIM profiles";
    if (action == "info") return "Query eSIM information";
    if (action == "enable") return "Enable eSIM profile";
    if (action == "disable") return "Disable eSIM profile";
    if (action == "delete") return "Delete eSIM profile";
    if (action == "nickname") return "Update eSIM nickname";
    if (action == "switch") return "Switch eSIM profile";
    return "eSIM action";
}

static void copy_esim_cache(std::string& eid,
                            std::vector<IdfEsimProfile>& profiles,
                            std::vector<std::string>& handles,
                            uint32_t& updated_at)
{
    if (cell_job_lock()) {
        eid = s_esim_cache.eid;
        profiles = s_esim_cache.profiles;
        handles = s_esim_cache.handles;
        updated_at = s_esim_cache.updatedAt;
        cell_job_unlock();
    }
}

static std::string new_esim_handle()
{
    char buf[20];
    snprintf(buf, sizeof(buf), "p%08x%08x", static_cast<unsigned>(esp_random()),
             static_cast<unsigned>(esp_random()));
    return buf;
}

static const char* modern_esim_state(const std::string& state)
{
    if (state == "enabled") return "enabled";
    if (state == "disabled") return "disabled";
    return "unknown";
}

static const char* modern_esim_class(const std::string& profile_class)
{
    if (profile_class == "operational") return "operational";
    if (profile_class == "provisioning") return "provisioning";
    return "unknown";
}

static bool wait_esim_modem_ready_and_idle(uint32_t timeout_ms)
{
    const uint64_t deadline = esp_timer_get_time() + static_cast<uint64_t>(timeout_ms) * 1000ULL;
    while (esp_timer_get_time() < deadline) {
        const IdfModemStatus status = idf_modem_get_status();
        if (status.atReady && status.modemReady && idf_modem_at_idle()) return true;
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    return false;
}

static bool esim_transition_can_succeed(bool operation_ok, bool modem_ready, esp_err_t refresh_err)
{
    return operation_ok && modem_ready && refresh_err == ESP_OK;
}

static bool resolve_esim_handle(const std::string& handle, std::string& identifier)
{
    if (handle.size() != 17 || handle[0] != 'p' ||
        !std::all_of(handle.begin() + 1, handle.end(), [](char ch) {
            return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
        })) return false;
    if (!cell_job_lock()) return false;
    auto it = std::find(s_esim_cache.handles.begin(), s_esim_cache.handles.end(), handle);
    const size_t index = it == s_esim_cache.handles.end()
        ? s_esim_cache.handles.size() : static_cast<size_t>(it - s_esim_cache.handles.begin());
    const bool found = index < s_esim_cache.profiles.size();
    if (found) {
        const IdfEsimProfile& profile = s_esim_cache.profiles[index];
        identifier = profile.iccid.empty() ? profile.isdpAid : profile.iccid;
    }
    cell_job_unlock();
    return found && !identifier.empty();
}

static void append_modern_esim_profile_json(std::string& body,
                                            const IdfEsimProfile& p,
                                            const std::string& handle)
{
    body += "{";
    json_prop(body, "handle", handle); body += ",";
    // The display value is intentionally non-identifying. The opaque handle is
    // the only value that can select a profile for a later action.
    json_prop(body, "displayId", "••••"); body += ",";
    json_prop(body, "state", modern_esim_state(p.state)); body += ",";
    json_prop(body, "nickname", p.nickname); body += ",";
    json_prop(body, "profileClass", modern_esim_class(p.profileClass));
    body += "}";
}

static void esim_task(void* arg_raw)
{
    EsimTaskArg* arg = static_cast<EsimTaskArg*>(arg_raw);
    std::string action = arg->action;
    std::string identifier = arg->identifier;
    std::string nickname = arg->nickname;
    delete arg;

    if (cell_job_lock()) {
        s_esim_job.queued = false;
        s_esim_job.running = true;
        s_esim_job.message = esim_action_label(action) + " in progress";
        cell_job_unlock();
    }

    std::string message;
    std::string eid;
    std::vector<IdfEsimProfile> profiles;
    esp_err_t err = ESP_ERR_INVALID_ARG;
    bool cache_eid_only = false;
    if (action != "refresh" && action != "info") {
        // Re-read the list before every opaque-handle mutation. A cached index
        // is not sufficient after profile deletion or remote profile changes.
        std::vector<IdfEsimProfile> current;
        std::string current_eid;
        std::string current_message;
        bool current_match = false;
        if (idf_esim_list_profiles(current, current_eid, current_message) == ESP_OK) {
            for (const IdfEsimProfile& profile : current) {
                const std::string current_identifier = profile.iccid.empty() ? profile.isdpAid : profile.iccid;
                if (!current_identifier.empty() && current_identifier == identifier) {
                    current_match = true;
                    break;
                }
            }
        }
        if (!current_match) {
            message = "Profile handle is stale";
            err = ESP_ERR_NOT_FOUND;
        }
    }
    if (err == ESP_ERR_INVALID_ARG && action == "refresh") {
        err = idf_esim_list_profiles(profiles, eid, message);
    } else if (err == ESP_ERR_INVALID_ARG && action == "info") {
        err = idf_esim_get_eid(eid, message);
        cache_eid_only = (err == ESP_OK);
    } else if (err == ESP_ERR_INVALID_ARG && action == "enable") {
        err = idf_esim_enable_profile(identifier, message);
    } else if (err == ESP_ERR_INVALID_ARG && action == "disable") {
        err = idf_esim_disable_profile(identifier, message);
    } else if (err == ESP_ERR_INVALID_ARG && action == "delete") {
        err = idf_esim_delete_profile(identifier, message);
    } else if (err == ESP_ERR_INVALID_ARG && action == "nickname") {
        err = idf_esim_set_nickname(identifier, nickname, message);
    } else if (err == ESP_ERR_INVALID_ARG && action == "switch") {
        err = idf_esim_switch_profile(identifier, message);
    } else if (err == ESP_ERR_INVALID_ARG) {
        message = "Unknown eSIM action";
    }

    bool ok = (err == ESP_OK);
    // Enable, switch, and disable change the active card; reload the number, ICCID, and operator to avoid stale overview data.
    bool sim_changed = ok && (action == "enable" || action == "switch" || action == "disable");
    bool transition_ready = true;
    esp_err_t transition_refresh_err = ESP_OK;
    if (sim_changed) {
        idf_modem_invalidate_sim_identity();
        transition_ready = wait_esim_modem_ready_and_idle(90000);
        if (transition_ready) {
            std::string refresh_message;
            transition_refresh_err = idf_esim_list_profiles(profiles, eid, refresh_message);
        } else {
            transition_refresh_err = ESP_ERR_TIMEOUT;
        }
        ok = esim_transition_can_succeed(ok, transition_ready, transition_refresh_err);
        if (!ok) {
            message = transition_ready ? "eSIM profile state refresh failed" :
                "eSIM profile state refresh timed out";
        }
    }
    bool cache_ready = false;
    if (ok && sim_changed) {
        cache_ready = true;
    } else if (ok && (action == "delete" || action == "nickname")) {
        // For actions that do not affect the current UICC session, refresh the list cache immediately.
        std::string refresh_msg;
        std::vector<IdfEsimProfile> refreshed;
        std::string refreshed_eid;
        if (idf_esim_list_profiles(refreshed, refreshed_eid, refresh_msg) == ESP_OK) {
            profiles = std::move(refreshed);
            eid = std::move(refreshed_eid);
            cache_ready = true;
        } else {
            message += "; failed to refresh the list after the action: " + refresh_msg;
        }
    } else if (ok && !sim_changed) {
        cache_ready = true;
    }
    // sim_changed: a successful switch immediately soft-restarts the modem to reset UICC (issue #17).
    // Reading now would contend for AT and become stale immediately, so leave cache_ready false and clear the cache below.

    std::string final_message = message.empty()
        ? (ok ? "eSIM action completed" : "eSIM action failed")
        : message;
    if (cell_job_lock(portMAX_DELAY)) {
        if (cache_eid_only) {
            s_esim_cache.eid = eid;
            s_esim_cache.updatedAt = static_cast<uint32_t>(time(nullptr));
        } else if (cache_ready) {
            s_esim_cache.eid = eid;
            s_esim_cache.profiles = profiles;
            s_esim_cache.handles.clear();
            s_esim_cache.handles.reserve(profiles.size());
            for (size_t i = 0; i < profiles.size(); ++i) s_esim_cache.handles.push_back(new_esim_handle());
            s_esim_cache.updatedAt = static_cast<uint32_t>(time(nullptr));
        } else if (sim_changed) {
            // After a successful switch or enable-state change, the modem restarts on the new card.
            // Clear the stale list so it cannot prompt duplicate actions; refresh after the modem is ready.
            s_esim_cache.profiles.clear();
            s_esim_cache.handles.clear();
            s_esim_cache.updatedAt = static_cast<uint32_t>(time(nullptr));
        }
        s_esim_job.running = false;
        s_esim_job.queued = false;
        s_esim_job.done = true;
        s_esim_job.success = ok;
        s_esim_job.message = final_message;
        cell_job_unlock();
    }
    idf_logf("%s: %s", esim_action_label(action).c_str(), ok ? "completed" : "failed");
    release_shared_admission();
    vTaskDelete(nullptr);
}

static bool start_esim_job(const std::string& action,
                           const std::string& identifier,
                           const std::string& nickname,
                           std::string& message,
                           bool& already_running)
{
    already_running = false;
    if (!try_shared_admission(false)) {
        already_running = true;
        message = "A device operation is already running";
        return false;
    }
    if (backup_transfer_active() || ota_active() || device_restart_pending() ||
        restore_restart_pending() || api_jobs_active() || idf_push_test_active()) {
        already_running = true;
        message = "A device operation is already running";
        release_shared_admission();
        return false;
    }
    if (!cell_job_lock()) {
        message = "eSIM task state lock is busy";
        release_shared_admission();
        return false;
    }
    if (cellular_job_active_locked()) {
        already_running = true;
        message = "A cellular/eSIM task is already running in the background";
        cell_job_unlock();
        release_shared_admission();
        return false;
    }
    s_esim_job = WebAsyncJob();
    s_esim_job.id = s_next_esim_job_id++;
    if (s_esim_job.id == 0) s_esim_job.id = s_next_esim_job_id++;
    s_esim_job.queued = true;
    s_esim_job.done = false;
    s_esim_job.success = false;
    s_esim_job.action = action;
    s_esim_job.message = esim_action_label(action) + " queued";
    cell_job_unlock();

    EsimTaskArg* arg = new (std::nothrow) EsimTaskArg();
    if (!arg) {
        if (cell_job_lock(portMAX_DELAY)) {
            s_esim_job.queued = false;
            s_esim_job.done = true;
            s_esim_job.success = false;
            s_esim_job.message = "Could not create eSIM task: insufficient memory";
            cell_job_unlock();
        }
        message = "Could not create eSIM task: insufficient memory";
        release_shared_admission();
        return false;
    }
    arg->action = action;
    arg->identifier = identifier;
    arg->nickname = nickname;
    if (xTaskCreate(esim_task, "idf_esim", 8192, arg, 3, nullptr) != pdPASS) {
        delete arg;
        if (cell_job_lock(portMAX_DELAY)) {
            s_esim_job.queued = false;
            s_esim_job.done = true;
            s_esim_job.success = false;
            s_esim_job.message = "Could not create eSIM task";
            cell_job_unlock();
        }
        message = "Could not create eSIM task";
        release_shared_admission();
        return false;
    }
    message = esim_action_label(action) + " queued";
    idf_logf("%s queued", esim_action_label(action).c_str());
    return true;
}

static bool valid_ussd_code(const std::string& code)
{
    if (code.empty() || code.size() > 24) return false;
    return std::all_of(code.begin(), code.end(), [](char ch) {
        return isdigit(static_cast<unsigned char>(ch)) || ch == '*' || ch == '#';
    });
}

// Shared USSD sender for Web, keepalive, and scheduled tasks. resp_out contains raw +CUSD or an error name.
static bool run_ussd(const std::string& code, std::string& resp_out)
{
    std::string cmd = "AT+CUSD=1,\"" + code + "\",15";
    std::string resp;
    esp_err_t err = idf_modem_send_at_until(cmd, "+CUSD:", 20000, resp);
    resp_out = resp.empty() ? std::string(esp_err_to_name(err)) : resp;
    return err == ESP_OK && resp.find("+CUSD:") != std::string::npos;
}

struct KeepAliveTaskArg {
    IdfKeepaliveRunView config;
};

static std::string keepalive_profile_note(const IdfKeepaliveRunView& cfg)
{
    if (cfg.kaProfile.empty()) return std::string();
    return std::string("Target eSIM: ") + idf_esim_mask_profile_id(cfg.kaProfile);
}

static void enqueue_maintenance_notice(int tz_offset_min, bool email_enabled, const char* title,
                                       const std::string& body, uint32_t now)
{
    std::string ts = format_epoch_local(now, tz_offset_min);
    int pushed = idf_push_enqueue_notify(title, body.c_str(), ts.c_str());
    if (pushed > 0) idf_logf("%s push queued on %d channels", title, pushed);
    else idf_logf("%s has no valid push channels", title);

    if (!email_enabled) return;
    idf_push_enqueue_email(title, body.c_str());
}

static void keepalive_set_job_message(const std::string& message)
{
    if (cell_job_lock()) {
        s_keepalive_job.message = message;
        cell_job_unlock();
    }
}

static bool wait_registered_for(uint32_t timeout_ms)
{
    // Use registration state maintained by the modem task; do not send CEREG while the modem soft-restarts after a switch.
    // Competing for AT only slows restart, and modemReady is cleared when restart is accepted so the old profile's
    // registration cannot be mistaken for a completed switch (issue #17).
    uint64_t deadline = esp_timer_get_time() + static_cast<uint64_t>(timeout_ms) * 1000ULL;
    while (esp_timer_get_time() < deadline) {
        if (idf_modem_get_status().modemReady) return true;
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
    return false;
}

static bool wait_registered_after_esim_switch(std::string& message)
{
    // idf_esim already requested a soft restart after the switch; wait for registration on the new profile.
    if (wait_registered_for(90000)) {
        message = "Network registered after eSIM switch";
        return true;
    }
    // Timeout fallback: restart the modem once more to reattach.
    idf_logf("Network not registered 90s after eSIM switch; restarting modem to reattach");
    if (idf_modem_request_reset(false) == ESP_OK && wait_registered_for(90000)) {
        message = "Network registered after restarting the modem following eSIM switch";
        return true;
    }
    message = "eSIM switched, but network registration timed out";
    return false;
}

// Switch record: select the target profile before the task and restore the original afterward when needed.
struct EsimJobSwitch {
    bool switched = false;
    std::string original;  // ICCID enabled before execution; empty means unknown and cannot be restored.
};

// When profile is set, switch to it and await registration. Use one list read to find both the current
// and target profiles. Do nothing if the target is already enabled.
static bool esim_prepare_profile(const std::string& profile,
                                 EsimJobSwitch& sw,
                                 std::string& message)
{
    sw = EsimJobSwitch();
    if (profile.empty()) return true;

    std::vector<IdfEsimProfile> profiles;
    std::string eid;
    std::string list_msg;
    if (idf_esim_list_profiles(profiles, eid, list_msg) != ESP_OK) {
        message = "Failed to read eSIM profile list: " + list_msg;
        return false;
    }
    const IdfEsimProfile* target = nullptr;
    for (const IdfEsimProfile& p : profiles) {
        if (p.state == "enabled" && sw.original.empty()) sw.original = p.iccid;
        if (!target && idf_esim_profile_matches(p, profile)) target = &p;
    }
    std::string enable_id;
    if (target) {
        if (target->state == "enabled") {
            message = "Target eSIM profile is already active: " + idf_esim_mask_profile_id(target->iccid);
            return true;
        }
        // Some cards omit ICCID (5A) from list entries; fall back to enabling by ISD-P AID.
        enable_id = target->iccid.empty() ? target->isdpAid : target->iccid;
        if (enable_id.empty()) {
            message = "Target profile lacks ICCID/AID and cannot be selected";
            return false;
        }
    } else {
        // If the list has no match, try the raw input as /esim does. Some cards return incomplete list
        // fields even though direct ICCID/AID enablement works.
        enable_id = profile;
    }

    idf_logf("Task preparing to switch eSIM: %s", idf_esim_mask_profile_id(enable_id).c_str());
    std::string switch_msg;
    if (idf_esim_enable_profile(enable_id, switch_msg) != ESP_OK) {
        message = (target ? "eSIM switch failed: " : "Target profile not found and direct enablement failed: ") + switch_msg;
        return false;
    }
    sw.switched = true;
    std::string wait_msg;
    if (!wait_registered_after_esim_switch(wait_msg)) {
        message = wait_msg;
        return false;  // Keep sw.switched true so the caller still attempts restoration.
    }
    std::string display_id = target ? (target->iccid.empty() ? enable_id : target->iccid) : enable_id;
    message = "Switched to " + idf_esim_mask_profile_id(display_id) + "; " + wait_msg;
    return true;
}

static void esim_restore_profile(const EsimJobSwitch& sw, std::string& message)
{
    if (!sw.switched) return;
    if (sw.original.empty()) {
        message = "Original profile is unknown; keeping the target profile active";
        return;
    }
    std::string masked = idf_esim_mask_profile_id(sw.original);
    idf_logf("Task complete; restoring original eSIM: %s", masked.c_str());
    std::string msg;
    if (idf_esim_enable_profile(sw.original, msg) != ESP_OK) {
        message = "Failed to restore original profile: " + msg;
        return;
    }
    std::string wait_msg;
    wait_registered_after_esim_switch(wait_msg);
    message = "Restored original profile " + masked + "; " + wait_msg;
}

static bool keepalive_prepare_esim(const IdfKeepaliveRunView& cfg, EsimJobSwitch& sw, std::string& message)
{
    if (cfg.kaProfile.empty()) return true;
    keepalive_set_job_message("Keepalive action in progress; switching eSIM: " + idf_esim_mask_profile_id(cfg.kaProfile));
    return esim_prepare_profile(cfg.kaProfile, sw, message);
}

static bool keepalive_traffic_preflight(const IdfKeepaliveRunView& cfg, std::string& message)
{
    if (cfg.kaTrafficKB < MIN_KEEPALIVE_TRAFFIC_KB ||
        cfg.kaTrafficKB > MAX_KEEPALIVE_TRAFFIC_KB) {
        message = "Keepalive traffic setting is outside the supported range";
        return false;
    }
    if (cfg.kaTrafficKB > static_cast<int>(IDF_MODEM_KEEPALIVE_MAX_RUNTIME_KB)) {
        message = "Keepalive traffic exceeds the safe 512 KB UART runtime limit";
        return false;
    }
    return true;
}

static void keepalive_task(void* arg_raw)
{
    KeepAliveTaskArg* arg = static_cast<KeepAliveTaskArg*>(arg_raw);
    IdfKeepaliveRunView cfg = std::move(arg->config);
    delete arg;

    if (cell_job_lock()) {
        s_keepalive_job.queued = false;
        s_keepalive_job.running = true;
        std::string note = keepalive_profile_note(cfg);
        s_keepalive_job.message = note.empty() ? "Keepalive action in progress" : std::string("Keepalive action in progress; ") + note;
        cell_job_unlock();
    }

    bool ok = false;
    bool terminal_unsupported = false;
    std::string message;
    std::string profile_note = keepalive_profile_note(cfg);
    if (!profile_note.empty()) idf_logf("Keepalive task %s", profile_note.c_str());
    EsimJobSwitch esim_switch;
    if (cfg.kaAction == 1) {
        terminal_unsupported = true;
        message = "Cellular HTTP keepalive is not supported";
    } else {
        const bool traffic_ready = cfg.kaAction == 2 || cfg.kaAction == 3 ||
                                   keepalive_traffic_preflight(cfg, message);
        bool esim_ready = traffic_ready && keepalive_prepare_esim(cfg, esim_switch, message);
        if (!traffic_ready) {
            ok = false;
        } else if (!esim_ready) {
            ok = false;
        } else if (cfg.kaAction == 2) {
            if (cfg.kaTarget.empty()) {
                message = "Keepalive SMS destination is empty";
            } else {
                std::string prefix = message;
                std::string sms_msg;
                esp_err_t err = idf_sms_send_text(cfg.kaTarget, "keepalive", sms_msg);
                ok = (err == ESP_OK);
                message = prefix.empty() ? sms_msg : (prefix + "; " + sms_msg);
            }
        } else if (cfg.kaAction == 3) {
            if (!valid_ussd_code(cfg.kaTarget)) {
                message = "USSD code is empty or contains invalid characters";
            } else {
                std::string prefix = message.empty() ? std::string() : (message + "; ");
                std::string ussd_msg;
                ok = run_ussd(cfg.kaTarget, ussd_msg);
                message = prefix + ussd_msg;
            }
        } else {
            terminal_unsupported = true;
            message = "Cellular HTTP keepalive is not supported";
        }
    }
    // Restore the previously active profile after keepalive work; the device primarily forwards SMS from the main card.
    if (esim_switch.switched) {
        keepalive_set_job_message("Keepalive action complete; restoring original eSIM profile");
        std::string back_msg;
        esim_restore_profile(esim_switch, back_msg);
        if (!back_msg.empty()) message += "; " + back_msg;
    }

    if (!profile_note.empty()) {
        message = message.empty() ? profile_note : (profile_note + "; " + message);
    }

    if (ok) {
        uint32_t now = static_cast<uint32_t>(time(nullptr));
        if (now >= 1700000000u && idf_config_set_keepalive_last(now) == ESP_OK) {
            message += "; keepalive baseline date updated";
        }
        idf_log_line("Keepalive action succeeded");
        std::string notice = "Keepalive action completed successfully.\nMethod: ";
        notice += (cfg.kaAction == 2 ? "Send SMS" : (cfg.kaAction == 3 ? "USSD query" : "Cellular data traffic"));
        notice += "\nResult: " + message;
        enqueue_maintenance_notice(cfg.tzOffsetMin, cfg.emailEnabled, "Keepalive action completed", notice, now);
    } else {
        idf_logf("Keepalive action failed: %s", message.c_str());
        // Retry profile-switching keepalive failures the next day. Hourly retries would repeatedly switch cards
        // and restart the modem, taking the main card offline for minutes each hour; ordinary keepalive still retries hourly.
        uint32_t now = static_cast<uint32_t>(time(nullptr));
        if (!terminal_unsupported && !cfg.kaProfile.empty() && epoch_valid(now) && cfg.kaIntervalDays > 0) {
            uint64_t back = static_cast<uint64_t>(cfg.kaIntervalDays - 1) * 86400ULL;
            uint32_t base = back < now ? now - static_cast<uint32_t>(back) : now;
            if (idf_config_set_keepalive_last(base) == ESP_OK) {
                idf_log_line("Keepalive failure backed off until the next day");
            }
        }
    }

    // The final state must be written. Abandoning it when the lock is busy leaves the job running forever,
    // rejecting all later keepalive and diagnostic requests until restart.
    if (cell_job_lock(portMAX_DELAY)) {
        s_keepalive_job.running = false;
        s_keepalive_job.queued = false;
        s_keepalive_job.done = true;
        s_keepalive_job.success = ok;
        s_keepalive_job.message = ok ? (message.empty() ? "Keepalive action completed" : message)
                                     : (message.empty() ? "Keepalive action failed; check the log" : message);
        cell_job_unlock();
    }
    vTaskDelete(nullptr);
}

static bool start_keepalive_job(const IdfKeepaliveRunView& cfg, const char* queued_message,
                                std::string& message, bool& already_running)
{
    already_running = false;
    if (!cell_job_lock()) {
        message = "Keepalive task state lock is busy";
        return false;
    }
    if (cellular_job_active_locked()) {
        already_running = true;
        message = "A cellular/keepalive task is already running in the background";
        cell_job_unlock();
        return false;
    }
    s_keepalive_job = WebAsyncJob();
    s_keepalive_job.queued = true;
    s_keepalive_job.done = false;
    s_keepalive_job.success = false;
    std::string queued = queued_message ? queued_message : "";
    std::string note = keepalive_profile_note(cfg);
    if (!note.empty()) queued += ", " + note;
    s_keepalive_job.message = queued;
    cell_job_unlock();

    KeepAliveTaskArg* arg = new (std::nothrow) KeepAliveTaskArg();
    if (!arg) {
        if (cell_job_lock(portMAX_DELAY)) {
            s_keepalive_job.queued = false;
            s_keepalive_job.done = true;
            s_keepalive_job.success = false;
            s_keepalive_job.message = "Could not create keepalive task: insufficient memory";
            cell_job_unlock();
        }
        message = "Could not create keepalive task: insufficient memory";
        return false;
    }
    arg->config = cfg;
    // 8192: the kaProfile path runs the full eSIM list, switch, and TLV parsing chain; 6144 is insufficient.
    if (xTaskCreate(keepalive_task, "idf_keepalive", 8192, arg, 3, nullptr) != pdPASS) {
        delete arg;
        if (cell_job_lock(portMAX_DELAY)) {
            s_keepalive_job.queued = false;
            s_keepalive_job.done = true;
            s_keepalive_job.success = false;
            s_keepalive_job.message = "Could not create keepalive task";
            cell_job_unlock();
        }
        message = "Could not create keepalive task";
        return false;
    }
    message = queued;
    idf_log_line("Keepalive action queued");
    return true;
}

static bool keepalive_due(uint32_t last_ts, uint32_t now, uint32_t interval_days)
{
    if (!epoch_valid(now) || interval_days == 0) return false;
    if (!epoch_valid(last_ts)) return true;
    if (last_ts > now) return false;  // Avoid now-last underflow appearing immediately due after an NTP rollback.
    return (now - last_ts) >= interval_days * 86400u;
}

static bool system_idle_for_maintenance(bool include_done = false,
                                         bool allow_restore_restart = false,
                                         bool allow_device_restart = false)
{
    const bool restart_busy =
        (!allow_device_restart && s_device_restart_pending.load(std::memory_order_relaxed)) ||
        idf_web_ota_restart_pending();
    const bool jobs_busy = include_done && !allow_restore_restart
        ? api_jobs_visible() : api_jobs_active();
    return !backup_transfer_active() && !ota_active() &&
           !restart_busy &&
           (allow_restore_restart || !restore_restart_pending()) && !jobs_busy &&
           !s_push_test_admission_active.load(std::memory_order_acquire) &&
           !shared_admission_active() &&
           !idf_push_busy() && !idf_push_test_active() &&
           idf_push_forward_queue_depth() == 0 &&
           idf_push_retry_queue_depth() == 0 &&
           idf_sms_outgoing_queue_depth() == 0 &&
           idf_push_email_queue_depth() == 0 &&
           !cellular_job_active(allow_device_restart);
}

static bool cellular_job_active(bool allow_device_restart)
{
    // Treat lock failure as busy (fail-safe) before maintenance restart. A false idle result could restart
    // during eSIM switch or keepalive work and leave the device on the wrong card.
    bool active = true;
    if (cell_job_lock()) {
        active = cellular_job_active_locked(allow_device_restart);
        cell_job_unlock();
    }
    return active;
}

// ========== Advanced scheduled tasks: select profile, execute, restore ==========

struct SchedTaskArg {
    IdfSchedRunView config;
    int index = 0;
};

static const char* sched_action_name(uint8_t action)
{
    switch (action) {
        case 0: return "Push notification";
        case 1: return "Cellular HTTP";
        case 2: return "Send SMS";
        case 3: return "USSD query";
        default: return "Unknown action";
    }
}

static std::string sched_task_label(const IdfSchedTask& t, int index)
{
    if (!t.name.empty()) return t.name;
    char buf[32];
    snprintf(buf, sizeof(buf), "Scheduled task %d", index + 1);
    return buf;
}

static void sched_set_job_message(const std::string& message)
{
    if (cell_job_lock()) {
        s_sched_job.message = message;
        cell_job_unlock();
    }
}

static bool sched_run_action(const IdfSchedRunView& cfg,
                             const IdfSchedTask& t,
                             const std::string& label,
                             std::string& message)
{
    uint32_t now = static_cast<uint32_t>(time(nullptr));
    switch (t.action) {
        case 0: {  // Send a custom notification over WiFi without cellular dependency.
            std::string body = t.payload.empty() ? ("Scheduled reminder triggered: " + label) : t.payload;
            std::string ts = format_epoch_local(now, cfg.tzOffsetMin);
            int pushed = idf_push_enqueue_notify(label.c_str(), body.c_str(), ts.c_str());
            bool email = cfg.emailEnabled && cfg.emailConfigured;
            if (email) idf_push_enqueue_email(label.c_str(), body.c_str());
            if (pushed > 0 || email) {
                char buf[96];
                snprintf(buf, sizeof(buf), "Reminder queued on %d push channels%s", pushed, email ? " + email" : "");
                message = buf;
                return true;
            }
            message = "No push channel or email configuration is available";
            return false;
        }
        case 1: {  // Cellular HTTP download (ping).
            (void)cfg;
            message = "Cellular HTTP scheduled tasks are not supported";
            return false;
        }
        case 2: {  // Send SMS.
            if (t.target.empty()) {
                message = "SMS destination is empty";
                return false;
            }
            std::string sms_msg;
            esp_err_t err = idf_sms_send_text(t.target,
                                              t.payload.empty() ? std::string("scheduled task") : t.payload,
                                              sms_msg);
            message = sms_msg;
            return err == ESP_OK;
        }
        case 3: {  // USSD query.
            if (!valid_ussd_code(t.target)) {
                message = "USSD code is empty or contains invalid characters";
                return false;
            }
            return run_ussd(t.target, message);
        }
        default:
            message = "Unknown action type";
            return false;
    }
}

static void sched_task_worker(void* arg_raw)
{
    SchedTaskArg* arg = static_cast<SchedTaskArg*>(arg_raw);
    IdfSchedRunView cfg = std::move(arg->config);
    int index = arg->index;
    delete arg;
    const IdfSchedTask& t = cfg.task;
    std::string label = sched_task_label(t, index);

    if (cell_job_lock()) {
        s_sched_job.queued = false;
        s_sched_job.running = true;
        s_sched_job.message = label + " in progress";
        cell_job_unlock();
    }
    idf_logf("Scheduled task started: %s (%s)", label.c_str(), sched_action_name(t.action));

    std::string message;
    bool ok = false;
    EsimJobSwitch sw;
    bool prep_ok = true;
    if (t.action == 1) {
        message = "Cellular HTTP scheduled tasks are not supported";
    } else {
        if (!t.profile.empty()) {
            sched_set_job_message(label + ": switching eSIM profile");
            std::string prep_msg;
            prep_ok = esim_prepare_profile(t.profile, sw, prep_msg);
            if (!prep_msg.empty()) message = prep_msg;
        }
        if (prep_ok) {
            sched_set_job_message(label + ": executing " + sched_action_name(t.action));
            std::string act_msg;
            ok = sched_run_action(cfg, t, label, act_msg);
            if (!act_msg.empty()) message = message.empty() ? act_msg : (message + "; " + act_msg);
        }
    }

    if (sw.switched && t.switchBack) {
        sched_set_job_message(label + ": restoring original eSIM profile");
        std::string back_msg;
        esim_restore_profile(sw, back_msg);
        if (!back_msg.empty()) message += "; " + back_msg;
    }

    uint32_t now = static_cast<uint32_t>(time(nullptr));
    if (epoch_valid(now) && t.action != 1) {
        if (ok) {
            idf_config_set_sched_last(index, now);
        } else {
            // Retry failures tomorrow; hourly retries would repeatedly switch profiles, send SMS, or consume data.
            uint32_t days = t.intervalDays > 0 ? static_cast<uint32_t>(t.intervalDays) : 1u;
            uint64_t back = static_cast<uint64_t>(days - 1) * 86400ULL;
            uint32_t base = back < now ? now - static_cast<uint32_t>(back) : now;
            idf_config_set_sched_last(index, base);
        }
    }

    // A successful push task is already a notification; send one result notification for all other cases.
    if (t.action != 1 && (t.action != 0 || !ok)) {
        std::string notice = "Task: " + label +
            "\nAction: " + std::string(sched_action_name(t.action)) +
            "\nResult: " + (message.empty() ? (ok ? "Success" : "Failure") : message);
        enqueue_maintenance_notice(cfg.tzOffsetMin, cfg.emailEnabled,
                                   ok ? "Scheduled task completed" : "Scheduled task failed", notice, now);
    }

    if (cell_job_lock(portMAX_DELAY)) {
        s_sched_job.running = false;
        s_sched_job.queued = false;
        s_sched_job.done = true;
        s_sched_job.success = ok;
        s_sched_job.message = message.empty() ? (ok ? "Scheduled task completed" : "Scheduled task failed") : message;
        cell_job_unlock();
    }
    if (ok) idf_logf("Scheduled task completed: %s", label.c_str());
    else idf_logf("Scheduled task failed: %s: %s", label.c_str(), message.c_str());
    vTaskDelete(nullptr);
}

static bool start_sched_job(const IdfSchedRunView& cfg, int index, std::string& message, bool& already_running)
{
    already_running = false;
    if (index < 0 || index >= IDF_MAX_SCHED_TASKS) {
        message = "Invalid task index";
        return false;
    }
    if (!cfg.valid) {
        message = "Task configuration is unavailable";
        return false;
    }
    if (!cell_job_lock()) {
        message = "Task state lock is busy";
        return false;
    }
    if (cellular_job_active_locked()) {
        already_running = true;
        message = "A cellular/eSIM task is already running in the background";
        cell_job_unlock();
        return false;
    }
    s_sched_job = WebAsyncJob();
    s_sched_job.queued = true;
    s_sched_job.message = "Scheduled task queued";
    s_sched_job_index = index;
    cell_job_unlock();

    SchedTaskArg* arg = new (std::nothrow) SchedTaskArg();
    if (!arg) {
        if (cell_job_lock(portMAX_DELAY)) {
            s_sched_job.queued = false;
            s_sched_job.done = true;
            s_sched_job.success = false;
            s_sched_job.message = "Could not create scheduled task: insufficient memory";
            cell_job_unlock();
        }
        message = "Could not create scheduled task: insufficient memory";
        return false;
    }
    arg->config = cfg;
    arg->index = index;
    if (xTaskCreate(sched_task_worker, "idf_schedtask", 8192, arg, 3, nullptr) != pdPASS) {
        delete arg;
        if (cell_job_lock(portMAX_DELAY)) {
            s_sched_job.queued = false;
            s_sched_job.done = true;
            s_sched_job.success = false;
            s_sched_job.message = "Could not create scheduled task";
            cell_job_unlock();
        }
        message = "Could not create scheduled task";
        return false;
    }
    message = "Scheduled task queued";
    return true;
}

// Persist each daily task's last-run date because restart clears in-memory state and could repeat it within the same hour.
// Each task writes at most once per day, so NVS wear is negligible.
static int64_t load_daily_last_day(const char* key)
{
    nvs_handle_t h;
    if (nvs_open("sms_state", NVS_READONLY, &h) != ESP_OK) return -1;
    uint32_t v = 0;
    int64_t day = (nvs_get_u32(h, key, &v) == ESP_OK) ? static_cast<int64_t>(v) : -1;
    nvs_close(h);
    return day;
}

static void store_daily_last_day(const char* key, int64_t day)
{
    nvs_handle_t h;
    if (nvs_open("sms_state", NVS_READWRITE, &h) != ESP_OK) return;
    nvs_set_u32(h, key, static_cast<uint32_t>(day));
    nvs_commit(h);
    nvs_close(h);
}

static void scheduler_task(void*)
{
    uint32_t last_ka_check_ms = 0;
    bool prev_ka_enabled = false;
    int64_t health_last_day = load_daily_last_day("health_day");
    int64_t rb_last_day = -1;

    while (true) {
        idf_push_heartbeat_tick();

        // Run the low-heap guard unconditionally every 5s. Provisioning and offline periods are especially
        // memory-constrained, so gating on NTP would remove recovery when it is most needed.
        if (heap_caps_get_free_size(MALLOC_CAP_8BIT) < 20000U && system_idle_for_maintenance()) {
            idf_logf("Free heap below threshold (%u<20000); preparing orderly restart",
                     static_cast<unsigned>(heap_caps_get_free_size(MALLOC_CAP_8BIT)));
            bool expected = false;
            const bool claimed = s_device_restart_pending.compare_exchange_strong(
                expected, true, std::memory_order_acq_rel);
            if (claimed && system_idle_for_maintenance(false, false, true)) {
                vTaskDelay(pdMS_TO_TICKS(300));
                idf_modem_power_off_for_restart();
                esp_restart();
            }
            if (claimed) s_device_restart_pending.store(false, std::memory_order_release);
        }

        const uint32_t maintenance_now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);
        if (restore_restart_due(maintenance_now_ms) && claim_restart_owner()) {
            if (system_idle_for_maintenance(false, true, true)) {
                idf_log_line("Configuration restore completed; restarting after API job TTL");
                if (schedule_restart_or_now("restore_restart", true)) {
                    s_restore_restart_pending.store(false, std::memory_order_release);
                } else {
                    release_restart_owner();
                }
            } else {
                release_restart_owner();
            }
        }

        uint32_t now = static_cast<uint32_t>(time(nullptr));
        if (epoch_valid(now)) {
            IdfSchedulerView cfg = idf_config_get_scheduler_view();
            uint32_t now_ms = static_cast<uint32_t>(esp_timer_get_time() / 1000ULL);

            // Check immediately when keepalive is enabled (legacy behavior), then hourly.
            if (cfg.kaEnabled && !prev_ka_enabled) last_ka_check_ms = 0;
            prev_ka_enabled = cfg.kaEnabled;
            if (last_ka_check_ms == 0 || now_ms - last_ka_check_ms >= 3600000UL) {
                last_ka_check_ms = now_ms;
                bool retry_due_soon = false;
                if (cfg.kaEnabled && cfg.kaAction != 1 && !epoch_valid(cfg.kaLastTime)) {
                    // On first enable or without a baseline, establish only the baseline date. Running immediately
                    // could send SMS, issue USSD, or consume data and incur charges.
                    idf_config_set_keepalive_last(now);
                    idf_log_line("Keepalive baseline date established; no action on first enable");
                } else if (cfg.kaEnabled && cfg.kaAction != 1 && cfg.kaIntervalDays > 0 &&
                           keepalive_due(cfg.kaLastTime, now, static_cast<uint32_t>(cfg.kaIntervalDays))) {
                    std::string msg;
                    bool already = false;
                    IdfKeepaliveRunView run_cfg = idf_config_get_keepalive_run_view();
                    bool still_due = run_cfg.kaEnabled && run_cfg.kaIntervalDays > 0 &&
                        keepalive_due(run_cfg.kaLastTime, now, static_cast<uint32_t>(run_cfg.kaIntervalDays));
                    if (still_due) {
                        if (start_keepalive_job(run_cfg, "Scheduled keepalive action queued", msg, already)) {
                            idf_log_line("Keepalive due; action triggered");
                        } else {
                            // If cellular/eSIM work or memory blocks a due action, retry before the next hourly tick.
                            retry_due_soon = true;
                        }
                    }
                }
                for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
                    const IdfSchedTask& t = cfg.schedTasks[i];
                    if (!t.enabled || t.intervalDays <= 0 || t.action == 1) continue;
                    if (!epoch_valid(t.lastRun)) {
                        // For legacy configurations or tasks enabled before time sync, establish the baseline without running.
                        idf_config_set_sched_last(i, now);
                        continue;
                    }
                    if (!keepalive_due(t.lastRun, now, static_cast<uint32_t>(t.intervalDays))) continue;
                    std::string msg;
                    bool already = false;
                    IdfSchedRunView run_cfg = idf_config_get_sched_run_view(i);
                    const IdfSchedTask& latest = run_cfg.task;
                    bool still_due = run_cfg.valid && latest.enabled && latest.intervalDays > 0 &&
                        epoch_valid(latest.lastRun) &&
                        keepalive_due(latest.lastRun, now, static_cast<uint32_t>(latest.intervalDays));
                    if (still_due) {
                        if (start_sched_job(run_cfg, i, msg, already)) {
                            idf_logf("Scheduled task %d due and queued", i + 1);
                        } else {
                            retry_due_soon = true;
                        }
                    }
                    break;  // Start one cellular-exclusive task per pass; check the rest next pass.
                }
                if (retry_due_soon) {
                    // Recheck due work on the next 5s tick so mutual exclusion cannot delay it for an hour.
                    last_ka_check_ms = now_ms - 3595000UL;
                }
            }

            int64_t local = static_cast<int64_t>(now) + static_cast<int64_t>(cfg.tzOffsetMin) * 60LL;
            int hour = static_cast<int>((local / 3600LL) % 24LL);
            if (hour < 0) hour += 24;
            int64_t day = local / 86400LL;
            if (local < 0 && (local % 86400LL) != 0) --day;

            if (cfg.smsHealthEnabled && hour == cfg.smsHealthHour &&
                day > health_last_day && idf_modem_at_idle()) {
                health_last_day = day;
                store_daily_last_day("health_day", day);
                std::string health;
                bool health_ok = idf_modem_sms_health_check(health);
                if (!health_ok && cfg.smsHealthNotify) {
                    enqueue_maintenance_notice(cfg.tzOffsetMin, cfg.emailEnabled,
                                               "Daily device SMS health check abnormal", health, now);
                }
            }

            uint64_t uptime_ms = static_cast<uint64_t>(esp_timer_get_time() / 1000ULL);
            if (cfg.rebootEnabled && hour == cfg.rebootHour && day > rb_last_day &&
                uptime_ms >= 7200000ULL && system_idle_for_maintenance(true)) {
                idf_log_line("Daily scheduled restart...");
                bool expected = false;
                const bool claimed = s_device_restart_pending.compare_exchange_strong(
                    expected, true, std::memory_order_acq_rel);
                if (claimed && system_idle_for_maintenance(true, false, true)) {
                    rb_last_day = day;
                    vTaskDelay(pdMS_TO_TICKS(300));
                    // Daily restart is the unattended recovery fallback and must cold-start the modem too.
                    idf_modem_power_off_for_restart();
                    esp_restart();
                }
                if (claimed) s_device_restart_pending.store(false, std::memory_order_release);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(5000));
    }
}

static esp_err_t handle_ping(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    return enqueue_api_job(req, "ping", "");
}

static const char* modern_esim_job_code(const WebAsyncJob& job)
{
    if (job.id == 0) return "ACTION_ESIM_IDLE";
    if (job.queued || job.running) return "ACTION_ESIM_RUNNING";
    return job.success ? "ACTION_ESIM_COMPLETE" : "ACTION_ESIM_FAILED";
}

static esp_err_t send_modern_esim_error(httpd_req_t* req, const char* status,
                                        const char* code, const char* detail = "")
{
    set_json_no_cache(req);
    httpd_resp_set_status(req, status);
    return httpd_resp_sendstr(req, action_result(false, code, {}, detail).c_str());
}

static esp_err_t handle_api_esim(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth_strict(req)) return ESP_OK;
    if (req->method != HTTP_GET && req->method != HTTP_POST) {
        set_json_no_cache(req);
        httpd_resp_set_status(req, "405 Method Not Allowed");
        httpd_resp_set_hdr(req, "Allow", "GET, POST");
        return httpd_resp_sendstr(req, action_result(false, "ACTION_INPUT_INVALID", {}, "method").c_str());
    }
    if (req->method == HTTP_POST && !check_csrf(req)) return ESP_OK;
    if (strchr(req->uri, '?')) return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_INVALID", "query");
    if (req->method == HTTP_GET) {
        if (req->content_len != 0) return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_INVALID", "body");
        WebAsyncJob job;
        std::string eid;
        std::vector<IdfEsimProfile> profiles;
        std::vector<std::string> handles;
        uint32_t updated_at = 0;
        if (cell_job_lock()) {
            job = s_esim_job;
            cell_job_unlock();
        }
        copy_esim_cache(eid, profiles, handles, updated_at);
        (void)updated_at;
        std::string body = "{\"eid\":{";
        body += "\"available\":";
        body += eid.empty() ? "false" : "true";
        body += ",\"state\":\"";
        body += eid.empty() ? "unavailable" : "available";
        body += "\",\"length\":";
        body += std::to_string(eid.empty() ? 0 : eid.size());
        body += "},\"profiles\":[";
        const size_t count = std::min(profiles.size(), handles.size());
        for (size_t i = 0; i < count; ++i) {
            if (i) body += ",";
            append_modern_esim_profile_json(body, profiles[i], handles[i]);
        }
        body += "],\"job\":{";
        body += "\"id\":" + std::to_string(job.id) + ",\"state\":\"";
        body += job.id == 0 ? "idle" : (job.queued ? "queued" : (job.running ? "running" : (job.done ? (job.success ? "succeeded" : "failed") : "idle")));
        body += "\",";
        json_prop(body, "action", job.action);
        body += ",\"success\":";
        body += job.success ? "true" : "false";
        body += ",";
        json_prop(body, "code", modern_esim_job_code(job));
        body += "}}";
        set_json_no_cache(req);
        return httpd_resp_send(req, body.c_str(), body.size());
    }

    if (req->content_len == 0) return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_INVALID", "body");
    std::string raw;
    if (read_body(req, raw, 512) != ESP_OK) return ESP_OK;
    const IdfWebFormDecodeResult decoded = idf_web_decode_form(raw, 3);
    if (!decoded.valid || decoded.fields.empty() || decoded.too_many_fields) {
        return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_INVALID", "body");
    }
    std::string action;
    std::string handle;
    std::string nickname;
    for (const auto& field : decoded.fields) {
        if (field.first == "action" && action.empty()) action = field.second;
        else if (field.first == "handle" && handle.empty()) handle = field.second;
        else if (field.first == "nickname" && nickname.empty()) nickname = field.second;
        else return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_INVALID", "body");
    }
    if (!(action == "refresh" || action == "info" || action == "enable" || action == "disable" ||
          action == "delete" || action == "nickname" || action == "switch")) {
        return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_INVALID", "action");
    }
    if ((action == "refresh" || action == "info") ? !handle.empty() || !nickname.empty()
                                                    : handle.empty()) {
        return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_INVALID", "handle");
    }
    if (action != "nickname" && !nickname.empty()) {
        return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_INVALID", "nickname");
    }
    if (nickname.size() > 64 || nickname.find_first_of("\r\n\t") != std::string::npos) {
        return send_modern_esim_error(req, "400 Bad Request", "ACTION_INPUT_TOO_LONG", "nickname");
    }

    std::string identifier;
    if (!handle.empty() && !resolve_esim_handle(handle, identifier)) {
        return send_modern_esim_error(req, "409 Conflict", "ACTION_ESIM_HANDLE_STALE");
    }
    std::string message;
    bool already_running = false;
    const bool ok = start_esim_job(action, identifier, nickname, message, already_running);
    if (!ok) {
        return send_modern_esim_error(req, "409 Conflict", "ACTION_ESIM_BUSY");
    }
    WebAsyncJob job;
    if (cell_job_lock()) {
        job = s_esim_job;
        cell_job_unlock();
    }
    set_json_no_cache(req);
    httpd_resp_set_status(req, "202 Accepted");
    return httpd_resp_sendstr(req, action_result(true, "ACTION_JOB_ACCEPTED",
                                                   std::string("\"jobId\":") + std::to_string(job.id)).c_str());
}

static esp_err_t handle_keepalive(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!ensure_get_or_post(req)) return ESP_OK;
    std::string action;
    get_query_param(req, "action", action);
    set_json_no_cache(req);
    if (action == "reset") {
        if (req->method != HTTP_POST) {
            return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"This action requires POST\"}");
        }
        IdfKeepaliveRunView reset_cfg = idf_config_get_keepalive_run_view();
        if (reset_cfg.kaAction == 1) {
            return httpd_resp_sendstr(req,
                "{\"success\":false,\"message\":\"Cellular HTTP keepalive is not supported\"}");
        }
        uint32_t now = static_cast<uint32_t>(time(nullptr));
        if (now < 1700000000u) {
            // Writing zero before time sync makes keepalive_due immediately due and can trigger unplanned
            // cellular data or SMS keepalive work, so reject it.
            return httpd_resp_sendstr(req,
                "{\"success\":false,\"message\":\"Device time is not synchronized; wait for NTP before resetting the baseline date\"}");
        }
        esp_err_t err = idf_config_set_keepalive_last(now);
        if (err == ESP_OK) {
            int tz = idf_config_get_tz_offset();
            std::string local = format_epoch_local(now, tz);
            idf_logf("Web UI reset keepalive baseline date to %s", local.empty() ? "current time" : local.c_str());
            std::string body = "{\"success\":true,";
            json_prop(body, "message", local.empty() ? "Baseline date reset" : std::string("Baseline date reset to ") + local);
            char buf[64];
            snprintf(buf, sizeof(buf), ",\"lastTime\":%u,", static_cast<unsigned>(now));
            body += buf;
            json_prop(body, "lastTimeLocal", local);
            body += "}";
            return httpd_resp_send(req, body.c_str(), body.size());
        }
        std::string body = "{\"success\":false,";
        json_prop(body, "message", std::string("Baseline date reset failed: ") + esp_err_to_name(err));
        body += "}";
        return httpd_resp_send(req, body.c_str(), body.size());
    }
    if (action == "run") {
        if (req->method != HTTP_POST) {
            return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"This action requires POST\"}");
        }
        std::string message;
        bool already_running = false;
        IdfKeepaliveRunView run_cfg = idf_config_get_keepalive_run_view();
        if (run_cfg.kaAction == 1) {
            return httpd_resp_sendstr(req,
                "{\"success\":false,\"queued\":false,\"message\":\"Cellular HTTP keepalive is not supported\"}");
        }
        bool ok = start_keepalive_job(run_cfg, "Keepalive action queued; you may continue refreshing the page",
                                      message, already_running);
        std::string body = "{\"success\":";
        body += (ok || already_running) ? "true" : "false";
        body += ",\"queued\":";
        body += (ok || already_running) ? "true" : "false";
        body += ",";
        json_prop(body, "message", message);
        body += "}";
        return httpd_resp_send(req, body.c_str(), body.size());
    }

    const IdfKeepaliveRunView cfg = idf_config_get_keepalive_run_view();
    uint32_t now = static_cast<uint32_t>(time(nullptr));
    bool time_valid = now >= 1700000000u;
    int days_left = 0;
    uint32_t next_time = 0;
    if (time_valid && cfg.kaLastTime >= 1700000000u && cfg.kaIntervalDays > 0) {
        uint64_t next64 = static_cast<uint64_t>(cfg.kaLastTime) + static_cast<uint64_t>(cfg.kaIntervalDays) * 86400ULL;
        next_time = next64 > UINT32_MAX ? UINT32_MAX : static_cast<uint32_t>(next64);
        uint32_t elapsed_days = now > cfg.kaLastTime ? (now - cfg.kaLastTime) / 86400u : 0;
        days_left = cfg.kaIntervalDays > static_cast<int>(elapsed_days)
            ? cfg.kaIntervalDays - static_cast<int>(elapsed_days)
            : 0;
    }
    WebAsyncJob job;
    if (cell_job_lock()) {
        job = s_keepalive_job;
        cell_job_unlock();
    }
    std::string body;
    body.reserve(840);
    char buf[160];
    snprintf(buf, sizeof(buf),
             "{\"enabled\":%s,\"intervalDays\":%d,\"trafficKB\":%d,\"action\":%u,",
             cfg.kaEnabled ? "true" : "false", cfg.kaIntervalDays,
             cfg.kaTrafficKB,
             static_cast<unsigned>(cfg.kaAction));
    body += buf;
    json_prop(body, "target", cfg.kaTarget); body += ",";
    json_prop(body, "url", cfg.kaUrl); body += ",";
    json_prop(body, "profile", cfg.kaProfile); body += ",";
    snprintf(buf, sizeof(buf),
             "\"timeValid\":%s,\"tz\":%d,\"nowEpoch\":%u,",
             time_valid ? "true" : "false",
             cfg.tzOffsetMin,
             static_cast<unsigned>(time_valid ? now : 0));
    body += buf;
    json_prop(body, "nowLocal", format_epoch_local(time_valid ? now : 0, cfg.tzOffsetMin)); body += ",";
    snprintf(buf, sizeof(buf),
             "\"lastTime\":%u,\"nextTime\":%u,\"daysLeft\":%d,",
             static_cast<unsigned>(cfg.kaLastTime),
             static_cast<unsigned>(next_time),
             days_left);
    body += buf;
    json_prop(body, "lastTimeLocal", format_epoch_local(cfg.kaLastTime, cfg.tzOffsetMin)); body += ",";
    snprintf(buf, sizeof(buf),
             "\"jobQueued\":%s,\"jobRunning\":%s,\"jobDone\":%s,"
             "\"jobSuccess\":%s,\"success\":%s,\"queued\":%s,",
             job.queued ? "true" : "false",
             job.running ? "true" : "false",
             job.done ? "true" : "false",
             job.success ? "true" : "false",
             job.success ? "true" : "false",
             (job.queued || job.running) ? "true" : "false");
    body += buf;
    json_prop(body, "jobMessage", job.message); body += ",";
    json_prop(body, "message", job.message);
    body += "}";
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_schedtask(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!ensure_get_or_post(req)) return ESP_OK;
    std::string action;
    get_query_param(req, "action", action);
    set_json_no_cache(req);

    if (action == "run" || action == "reset") {
        // Mutating actions accept POST only; prefetching or cross-site GET links could silently switch profiles or send SMS.
        if (req->method != HTTP_POST) {
            return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"This action requires POST\"}");
        }
        std::string idx_str;
        get_query_param(req, "index", idx_str);
        int index = -1;
        if (idx_str.size() == 1 && idx_str[0] >= '0' && idx_str[0] <= '9') index = idx_str[0] - '0';
        if (index < 0 || index >= IDF_MAX_SCHED_TASKS) {
            return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"Invalid task index\"}");
        }
        if (action == "reset") {
            IdfSchedRunView reset_cfg = idf_config_get_sched_run_view(index);
            if (reset_cfg.valid && reset_cfg.task.action == 1) {
                return httpd_resp_sendstr(req,
                    "{\"success\":false,\"queued\":false,\"message\":\"Cellular HTTP scheduled tasks are not supported\"}");
            }
            uint32_t now = static_cast<uint32_t>(time(nullptr));
            if (!epoch_valid(now)) {
                return httpd_resp_sendstr(req,
                    "{\"success\":false,\"message\":\"Device time is not synchronized; baseline date cannot be reset\"}");
            }
            bool ok = idf_config_set_sched_last(index, now) == ESP_OK;
            idf_logf("Scheduled task %d baseline date reset to today", index + 1);
            std::string body = "{\"success\":";
            body += ok ? "true" : "false";
            body += ",\"message\":\"";
            body += ok ? "Baseline date reset to today" : "Write failed";
            body += "\"}";
            return httpd_resp_send(req, body.c_str(), body.size());
        }
        std::string message;
        bool already = false;
        IdfSchedRunView run_cfg = idf_config_get_sched_run_view(index);
        if (run_cfg.valid && run_cfg.task.action == 1) {
            return httpd_resp_sendstr(req,
                "{\"success\":false,\"queued\":false,\"message\":\"Cellular HTTP scheduled tasks are not supported\"}");
        }
        bool ok = start_sched_job(run_cfg, index, message, already);
        if (ok) idf_logf("Web UI manually triggered scheduled task %d", index + 1);
        std::string body = "{\"success\":";
        body += (ok || already) ? "true" : "false";
        body += ",\"queued\":";
        body += (ok || already) ? "true" : "false";
        body += ",";
        json_prop(body, "message", message);
        body += "}";
        return httpd_resp_send(req, body.c_str(), body.size());
    }

    // status: task configuration, countdown, and background state in a narrow snapshot polled every 2s during work.
    IdfSchedulerView cfg = idf_config_get_scheduler_view();
    uint32_t now = static_cast<uint32_t>(time(nullptr));
    bool time_valid = epoch_valid(now);
    WebAsyncJob job;
    int job_index = -1;
    if (cell_job_lock()) {
        job = s_sched_job;
        job_index = s_sched_job_index;
        cell_job_unlock();
    }

    std::string body;
    body.reserve(512 + IDF_MAX_SCHED_TASKS * 420);
    char buf[160];
    snprintf(buf, sizeof(buf),
             "{\"timeValid\":%s,\"jobIndex\":%d,"
             "\"jobQueued\":%s,\"jobRunning\":%s,\"jobDone\":%s,\"jobSuccess\":%s,",
             time_valid ? "true" : "false", job_index,
             job.queued ? "true" : "false",
             job.running ? "true" : "false",
             job.done ? "true" : "false",
             job.success ? "true" : "false");
    body += buf;
    json_prop(body, "jobMessage", job.message); body += ",";
    body += "\"tasks\":[";
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        const IdfSchedTask& t = cfg.schedTasks[i];
        int days_left = -1;  // -1 means no baseline date.
        if (time_valid && epoch_valid(t.lastRun) && t.intervalDays > 0) {
            uint32_t elapsed_days = now > t.lastRun ? (now - t.lastRun) / 86400u : 0;
            days_left = t.intervalDays > static_cast<int>(elapsed_days)
                ? t.intervalDays - static_cast<int>(elapsed_days)
                : 0;
        }
        if (i) body += ",";
        snprintf(buf, sizeof(buf),
                 "{\"enabled\":%s,\"switchBack\":%s,\"intervalDays\":%d,"
                 "\"action\":%u,\"daysLeft\":%d,\"lastTime\":%u,",
                 t.enabled ? "true" : "false",
                 t.switchBack ? "true" : "false",
                 t.intervalDays,
                 static_cast<unsigned>(t.action),
                 days_left,
                 static_cast<unsigned>(t.lastRun));
        body += buf;
        json_prop(body, "name", t.name); body += ",";
        json_prop(body, "profile", t.profile); body += ",";
        json_prop(body, "target", t.target); body += ",";
        json_prop(body, "payload", t.payload); body += ",";
        json_prop(body, "lastLocal", format_epoch_local(t.lastRun, cfg.tzOffsetMin));
        body += "}";
    }
    body += "]}";
    return httpd_resp_send(req, body.c_str(), body.size());
}

// Immediate NET indicator toggle sends AT without saving configuration. The modem may remember the state,
// but firmware initialization reapplies the saved setting each time.
static esp_err_t handle_netled(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    set_json_no_cache(req);
    if (req->method != HTTP_POST) {
        return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"This action requires POST\"}");
    }
    std::string action;
    get_query_param(req, "action", action);
    bool on = (action == "on");
    if (!on && action != "off") {
        return httpd_resp_sendstr(req, "{\"success\":false,\"message\":\"Unknown action\"}");
    }
    WebModemActionGuard modem_action;
    if (!modem_action.begin(req)) return ESP_OK;
    std::string resp;
    esp_err_t err = idf_modem_send_at(on ? "AT+MLED=0,1" : "AT+MLED=0,0", 3000, resp);
    bool ok = (err == ESP_OK && resp.find("OK") != std::string::npos);
    idf_logf("NET indicator %s: %s", on ? "enabled" : "disabled", ok ? "succeeded" : "failed (unsupported or modem busy)");
    std::string body = "{\"success\":";
    body += ok ? "true" : "false";
    body += ",";
    json_prop(body, "message", ok ? (on ? "NET indicator enabled; restart reapplies the saved setting"
                                        : "NET indicator disabled; restart reapplies the saved setting")
                                  : "Action failed: modem does not support AT+MLED or is busy");
    body += "}";
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_ntp(httpd_req_t* req)
{
    if (!check_auth(req)) return ESP_OK;
    if (!check_csrf(req)) return ESP_OK;
    set_json_no_cache(req);
    esp_err_t err = idf_wifi_resync_ntp();
    uint32_t now = static_cast<uint32_t>(time(nullptr));
    const IdfConfigStatusView cfg = idf_config_get_status_view();
    std::string body = "{\"success\":";
    body += (err == ESP_OK) ? "true" : "false";
    body += ",";
    if (err == ESP_OK) {
        json_prop(body, "message", "Time synchronization started; device time updates when it completes");
    } else {
        json_prop(body, "message", "WiFi is disconnected; time cannot be synchronized");
    }
    body += ",";
    json_prop(body, "nowLocal", format_epoch_local(now, cfg.tzOffsetMin));
    body += "}";
    return httpd_resp_send(req, body.c_str(), body.size());
}

static esp_err_t handle_reboot(httpd_req_t* req)
{
    if (reject_oversized_body(req)) return ESP_OK;
    if (!check_auth(req)) return ESP_OK;
    if (req->method != HTTP_POST) {
        set_json_no_cache(req);
        httpd_resp_set_status(req, "405 Method Not Allowed");
        httpd_resp_set_hdr(req, "Allow", "POST");
        const std::string body = action_result(false, "ACTION_INPUT_INVALID", {}, "method");
        return httpd_resp_send(req, body.c_str(), body.size());
    }
    if (!check_csrf(req)) return ESP_OK;
    if (req->content_len != 0) return send_action_error(req, "ACTION_INPUT_INVALID", "body");

    if (!claim_restart_owner()) {
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }
    if (backup_transfer_active() || ota_active() || idf_web_ota_restart_pending() ||
        restore_restart_pending() || api_jobs_active() ||
        shared_admission_active() || s_push_test_admission_active.load(std::memory_order_acquire) ||
        idf_push_test_active()) {
        release_restart_owner();
        return send_backup_result(req, "409 Conflict", false, "ACTION_BUSY");
    }

    idf_log_line("Web UI requested device restart");
    set_json_no_cache(req);
    httpd_resp_set_status(req, "200 OK");
    const std::string body = action_result(true, "ACTION_DEVICE_RESTARTING");
    esp_err_t send_err = httpd_resp_send(req, body.c_str(), body.size());
    schedule_restart_or_now("web_restart", true);
    return send_err;
}

static esp_err_t handle_not_found(httpd_req_t* req)
{
    if (idf_wifi_get_status().apMode) {
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_set_hdr(req, "Location", "http://192.168.1.1/");
        return httpd_resp_send(req, nullptr, 0);
    }
    httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "Not Found");
    return ESP_OK;
}

static esp_err_t register_handler(httpd_handle_t server, const char* uri, int method,
                                  esp_err_t (*handler)(httpd_req_t*))
{
    httpd_uri_t item = {};
    item.uri = uri;
    item.method = static_cast<httpd_method_t>(method);
    item.handler = handler;
    return httpd_register_uri_handler(server, &item);
}

esp_err_t idf_web_start(void)
{
    if (s_server) return ESP_OK;
    s_last_restore_job = ApiRestoreLifecycleSnapshot();
    s_shared_admission_active.store(false, std::memory_order_release);
    s_push_test_admission_active.store(false, std::memory_order_release);
    s_restore_restart_pending.store(false, std::memory_order_release);
    s_restore_restart_completed_ms.store(0, std::memory_order_release);
    if (s_csrf_token.empty()) {
        uint8_t random[16];
        esp_fill_random(random, sizeof(random));
        static const char hex[] = "0123456789abcdef";
        s_csrf_token.resize(sizeof(random) * 2);
        for (size_t i = 0; i < sizeof(random); ++i) {
            s_csrf_token[i * 2] = hex[random[i] >> 4];
            s_csrf_token[i * 2 + 1] = hex[random[i] & 0x0f];
        }
        memset(random, 0, sizeof(random));
    }
    if (!s_cell_job_mutex) {
        s_cell_job_mutex = xSemaphoreCreateMutex();
        if (!s_cell_job_mutex) return ESP_ERR_NO_MEM;
    }
    if (!s_api_job_mutex) {
        s_api_job_mutex = xSemaphoreCreateMutex();
        if (!s_api_job_mutex) return ESP_ERR_NO_MEM;
    }
    if (!s_backup_mutex) {
        s_backup_mutex = xSemaphoreCreateMutex();
        if (!s_backup_mutex) return ESP_ERR_NO_MEM;
    }
    const esp_err_t ota_init_err = idf_web_ota_init();
    if (ota_init_err != ESP_OK) return ota_init_err;

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.uri_match_fn = httpd_uri_match_wildcard;
    config.lru_purge_enable = true;
    // Multi-method endpoints share one HTTP_ANY route. About 37 routes leave headroom while reducing HTTPD table memory.
    config.max_uri_handlers = 48;
    config.stack_size = 8192;
    // HTTPD reserves three sockets internally; resident mDNS/DNS/SNTP plus push/SMTP also need headroom.
    // Existing build/sdkconfig may retain an old limit such as LWIP=10. Forcing 13 can make httpd_start fail,
    // while 7 can make accept fail with ENFILE=23.
    int reserved_non_http_sockets = 3;
    int http_socket_cap = CONFIG_LWIP_MAX_SOCKETS - 3 - reserved_non_http_sockets;
    if (http_socket_cap < 2) http_socket_cap = 2;
    int desired_http_sockets = 13;
    config.max_open_sockets = desired_http_sockets < http_socket_cap ? desired_http_sockets : http_socket_cap;
    ESP_LOGI(TAG, "HTTP sockets: open=%d, lwip=%d", config.max_open_sockets, CONFIG_LWIP_MAX_SOCKETS);
    // TCP keepalive reclaims half-open connections left by WiFi loss or sleeping tabs in about 24s;
    // otherwise they occupy sockets until passive LRU eviction.
    config.keep_alive_enable = CONFIG_LWIP_MAX_SOCKETS > 10;
    config.keep_alive_idle = 15;      // Probe after 15s idle.
    config.keep_alive_interval = 3;   // Probe every 3s.
    config.keep_alive_count = 3;      // Disconnect after three missed probes.

    esp_err_t err = httpd_start(&s_server, &config);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "httpd_start failed: %s", esp_err_to_name(err));
        return err;
    }

    auto register_checked = [&](const char* name, esp_err_t reg_err) -> esp_err_t {
        if (reg_err == ESP_OK) return ESP_OK;
        ESP_LOGE(TAG, "Failed to register HTTP route %s: %s", name, esp_err_to_name(reg_err));
        idf_logf("Failed to register HTTP route %s: %s", name, esp_err_to_name(reg_err));
        httpd_stop(s_server);
        s_server = nullptr;
        return reg_err;
    };

#define IDF_WEB_TRY_REGISTER(name, expr) do { \
        esp_err_t _reg_err = register_checked((name), (expr)); \
        if (_reg_err != ESP_OK) return _reg_err; \
    } while (0)

    IDF_WEB_TRY_REGISTER("/", register_handler(s_server, "/", HTTP_GET, handle_root));
    IDF_WEB_TRY_REGISTER("/tools", register_handler(s_server, "/tools", HTTP_GET, handle_root));
    IDF_WEB_TRY_REGISTER("/sms", register_handler(s_server, "/sms", HTTP_GET, handle_root));
    IDF_WEB_TRY_REGISTER("/assets/*", register_handler(s_server, "/assets/*", HTTP_GET, handle_asset));
    IDF_WEB_TRY_REGISTER("/api/config", register_handler(s_server, "/api/config", HTTP_GET, handle_api_config));
    IDF_WEB_TRY_REGISTER("/api/esim", register_handler(s_server, "/api/esim", HTTP_ANY, handle_api_esim));
    IDF_WEB_TRY_REGISTER("/api/jobs", register_handler(s_server, "/api/jobs", HTTP_GET, handle_api_job));
    IDF_WEB_TRY_REGISTER("/api/config/export", register_handler(s_server, "/api/config/export", HTTP_ANY, handle_config_export));
    IDF_WEB_TRY_REGISTER("/api/config/restore/start", register_handler(s_server, "/api/config/restore/start", HTTP_POST, handle_config_restore_start));
    IDF_WEB_TRY_REGISTER("/api/config/restore/chunk", register_handler(s_server, "/api/config/restore/chunk", HTTP_POST, handle_config_restore_chunk));
    IDF_WEB_TRY_REGISTER("/api/config/restore/finish", register_handler(s_server, "/api/config/restore/finish", HTTP_POST, handle_config_restore_finish));
    IDF_WEB_TRY_REGISTER("/api/ota/start", register_handler(s_server, "/api/ota/start", HTTP_POST, handle_ota_start));
    IDF_WEB_TRY_REGISTER("/api/ota/chunk", register_handler(s_server, "/api/ota/chunk", HTTP_POST, handle_ota_chunk));
    IDF_WEB_TRY_REGISTER("/api/ota/finish", register_handler(s_server, "/api/ota/finish", HTTP_POST, handle_ota_finish));
    IDF_WEB_TRY_REGISTER("/api/device/restart", register_handler(s_server, "/api/device/restart", HTTP_ANY, handle_reboot));
    IDF_WEB_TRY_REGISTER("/api/push/test", register_handler(s_server, "/api/push/test", HTTP_ANY, handle_test_push));
    IDF_WEB_TRY_REGISTER("/query", register_handler(s_server, "/query", HTTP_GET, handle_query));
    IDF_WEB_TRY_REGISTER("/save", register_handler(s_server, "/save", HTTP_POST, handle_save));
    IDF_WEB_TRY_REGISTER("/wifi", register_handler(s_server, "/wifi", HTTP_GET, handle_wifi));
    IDF_WEB_TRY_REGISTER("/wifiscan", register_handler(s_server, "/wifiscan", HTTP_GET, handle_wifi_scan));
    IDF_WEB_TRY_REGISTER("/wificonfig", register_handler(s_server, "/wificonfig", HTTP_POST, handle_wifi_config));
    IDF_WEB_TRY_REGISTER("/apstatus", register_handler(s_server, "/apstatus", HTTP_GET, handle_apstatus));
    IDF_WEB_TRY_REGISTER("/log", register_handler(s_server, "/log", HTTP_GET, handle_empty_log));
    IDF_WEB_TRY_REGISTER("/at", register_handler(s_server, "/at", HTTP_GET, handle_at));
    IDF_WEB_TRY_REGISTER("/ping", register_handler(s_server, "/ping", HTTP_POST, handle_ping));
    IDF_WEB_TRY_REGISTER("/flight", register_handler(s_server, "/flight", HTTP_GET, handle_flight));
    IDF_WEB_TRY_REGISTER("/modem", register_handler(s_server, "/modem", HTTP_GET, handle_modem_api));
    IDF_WEB_TRY_REGISTER("/sendsms", register_handler(s_server, "/sendsms", HTTP_POST, handle_send_sms));
    IDF_WEB_TRY_REGISTER("/*", register_handler(s_server, "/*", HTTP_GET, handle_not_found));

#undef IDF_WEB_TRY_REGISTER
    if (!s_scheduler_started) {
        BaseType_t ok = xTaskCreate(scheduler_task, "idf_sched", 8192, nullptr, 2, nullptr);
        if (ok == pdPASS) {
            s_scheduler_started = true;
            idf_log_line("Scheduled-task scheduler started");
        } else {
            ESP_LOGW(TAG, "scheduler task start failed");
            idf_log_line("Scheduled-task scheduler failed to start");
            httpd_stop(s_server);
            s_server = nullptr;
            return ESP_ERR_NO_MEM;
        }
    }
    ESP_LOGI(TAG, "ESP-IDF web server registered UI and bootstrap dynamic routes");
    idf_log_line("HTTP server started");
    return ESP_OK;
}
