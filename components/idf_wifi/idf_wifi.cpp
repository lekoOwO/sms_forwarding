#include "idf_wifi.h"

#include <stdio.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <algorithm>
#include <new>
#include <array>
#include <atomic>
#include <utility>
#include <vector>

#include "driver/gpio.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_log.h"
#include "esp_mac.h"
#include "esp_netif.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_wifi_default.h"
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "config_schema_generated.h"
#include "idf_log.h"
#include "idf_util.h"
#include "idf_wifi_core.h"
#include "apps/esp_sntp.h"
#include "lwip/inet.h"
#include "lwip/sockets.h"

static const char* TAG = "idf_wifi";
static constexpr EventBits_t WIFI_CONNECTED_BIT = BIT0;
static constexpr EventBits_t WIFI_DISCONNECTED_BIT = BIT1;
static constexpr int WIFI_CONNECT_TIMEOUT_MS = 20000;
static constexpr const char* AP_SSID_PREFIX = "SMS-Forwarder-";
static constexpr const char* AP_PASSWORD = "sms-forwarder-setup";
static constexpr gpio_num_t PROVISION_BUTTON_PIN = GPIO_NUM_9;
static constexpr uint32_t PROVISION_BUTTON_HOLD_MS = 5000;
static constexpr uint16_t WIFI_SCAN_RECORD_LIMIT = 40;
static constexpr uint32_t WIFI_RECOVERY_SYNC_TIMEOUT_MS = 2000;

static EventGroupHandle_t s_wifi_event_group = nullptr;
static SemaphoreHandle_t s_state_mutex = nullptr;
static SemaphoreHandle_t s_recovery_mutex = nullptr;
static SemaphoreHandle_t s_wifi_driver_mutex = nullptr;
static esp_netif_t* s_sta_netif = nullptr;
static esp_netif_t* s_ap_netif = nullptr;
static std::atomic<bool> s_started{false};
static bool s_ap_mode = false;
static bool s_ap_manual_mode = false;
static std::atomic<bool> s_has_sta_credentials{false};
static std::atomic<bool> s_sta_configured{false};
static std::string s_ap_ssid;
static std::atomic<bool> s_dns_task_started{false};
static std::atomic<bool> s_mdns_task_started{false};
static std::atomic<bool> s_button_task_started{false};
static std::atomic<bool> s_sntp_started{false};
static std::atomic<bool> s_sta_connected{false};
static std::atomic<bool> s_current_profile_open{false};
static std::atomic<bool> s_scan_running{false};
static std::atomic<bool> s_scan_refresh_pending{false};
static std::atomic<int> s_scan_cleanup_error{ESP_ERR_NO_MEM};
static std::atomic<bool> s_scan_cleanup_retry_pending{false};
static std::atomic<bool> s_select_running{false};
static bool s_scan_cache_ready = false;
static esp_err_t s_scan_cache_error = ESP_OK;
static std::string s_scan_cache_json = "[]";
static std::array<wifi_ap_record_t, WIFI_SCAN_RECORD_LIMIT> s_scan_cache_records = {};
static std::array<wifi_ap_record_t, WIFI_SCAN_RECORD_LIMIT> s_scan_collect_records = {};
static uint16_t s_scan_cache_count = 0;
static std::atomic<uint32_t> s_candidate_attempt{0};
static std::atomic<int> s_disconnect_streak{0};
static std::atomic<int64_t> s_sta_outage_since_us{-1};
static std::atomic<uint32_t> s_sta_outage_generation{0};
static std::atomic<bool> s_recovery_ap_started{false};
static std::atomic<int64_t> s_recovery_ap_last_attempt_us{-1};
static bool s_recovery_ap_inflight = false;  // Protected by s_recovery_mutex.
static uint32_t s_recovery_claim_generation = 0;  // Protected by s_recovery_mutex.
static std::atomic<bool> s_recovery_completion_retry_pending{false};
static std::atomic<uint32_t> s_recovery_completion_generation{0};
static std::atomic<bool> s_recovery_ap_close_failed{false};
static std::atomic<int64_t> s_last_beacon_log_us{0};
static std::atomic<uint32_t> s_suppressed_beacon_logs{0};
static std::atomic<bool> s_suppress_next_connect_log{false};
static esp_timer_handle_t s_reconnect_timer = nullptr;
static char s_ntp_server[128] = "ntp.aliyun.com";
static esp_timer_handle_t s_ap_close_timer = nullptr;
static esp_timer_handle_t s_scan_cleanup_timer = nullptr;
static std::atomic<bool> s_ap_close_pending{false};
static std::atomic<uint32_t> s_provisioning_validation_generation{0};
static std::atomic<bool> s_provisioning{false};  // Provisioning-page connection in progress; close AP after a delay on success.
static constexpr uint32_t AP_PROVISION_HOLD_MS = 20000;  // Keep AP long enough for the page to display the IP.

class WifiDriverOperation {
public:
    explicit WifiDriverOperation(TickType_t timeout, bool scan_owner = false)
    {
        if (!scan_owner && s_scan_running.load(std::memory_order_acquire)) return;
        if (s_wifi_driver_mutex == nullptr) {
            held_ = true;
            return;
        }
        if (xSemaphoreTake(s_wifi_driver_mutex, timeout) != pdTRUE) return;
        if (!scan_owner && s_scan_running.load(std::memory_order_acquire)) {
            xSemaphoreGive(s_wifi_driver_mutex);
            return;
        }
        held_ = true;
    }

    ~WifiDriverOperation()
    {
        if (held_ && s_wifi_driver_mutex) xSemaphoreGive(s_wifi_driver_mutex);
    }

    explicit operator bool() const { return held_; }

private:
    bool held_ = false;
};

static esp_err_t wifi_connect_locked()
{
    return esp_wifi_connect();
}

// Event callbacks must not wait behind a task that is synchronously changing mode/configuration.
static esp_err_t wifi_connect_now()
{
    WifiDriverOperation operation(0);
    if (!operation) return ESP_ERR_TIMEOUT;
    return wifi_connect_locked();
}

static esp_err_t start_provisioning_ap(bool manual = false);
static esp_err_t start_provisioning_ap_locked(bool manual, TickType_t state_timeout);
static void wifi_event_handler(void*, esp_event_base_t event_base, int32_t event_id, void* event_data);
static void schedule_ap_close(uint32_t delay_ms);
static void schedule_scan_cleanup(esp_err_t err);
static void scan_cleanup_timer_cb(void*);
static void start_wifi_select_once(void);
static void wifi_remember_task(void*);
static void wifi_scan_collect_task(void*);

struct ApState {
    bool mode = false;
    bool manual = false;
    std::string ssid;
};

struct RecoveryClaim {
    bool claimed = false;
    bool ap_was_active = false;
    uint32_t generation = 0;
};

struct ProvisioningTarget {
    bool active = false;
    uint32_t generation = 0;
    std::string ssid;
    bool bssidSet = false;
    std::array<uint8_t, 6> bssid = {};
};

static ProvisioningTarget s_provisioning_target;
static std::atomic<uint32_t> s_provisioning_generation{0};

class WifiScanLease {
public:
    WifiScanLease()
    {
        bool expected = false;
        held_ = s_scan_running.compare_exchange_strong(expected, true, std::memory_order_relaxed);
    }

    ~WifiScanLease()
    {
        if (held_) s_scan_running.store(false, std::memory_order_relaxed);
    }

    explicit operator bool() const { return held_; }
    void release()
    {
        if (held_) s_scan_running.store(false, std::memory_order_relaxed);
        held_ = false;
    }
    void detach() { held_ = false; }

private:
    bool held_ = false;
};

static esp_err_t public_scan_error(esp_err_t err)
{
    return err == ESP_ERR_WIFI_STATE ? ESP_ERR_INVALID_STATE : err;
}

static bool ap_state_snapshot(ApState& state, TickType_t timeout)
{
    if (!s_state_mutex) return true;
    if (xSemaphoreTake(s_state_mutex, timeout) != pdTRUE) return false;
    state.mode = s_ap_mode;
    state.manual = s_ap_manual_mode;
    state.ssid = s_ap_ssid;
    xSemaphoreGive(s_state_mutex);
    return true;
}

static void set_ap_state(bool mode, bool manual, const std::string& ssid)
{
    if (s_state_mutex && xSemaphoreTake(s_state_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        s_ap_mode = mode;
        s_ap_manual_mode = manual;
        s_ap_ssid = ssid;
        xSemaphoreGive(s_state_mutex);
    }
}

static bool provisioning_target_snapshot(ProvisioningTarget& target, TickType_t timeout)
{
    if (!s_state_mutex) return true;
    if (xSemaphoreTake(s_state_mutex, timeout) != pdTRUE) return false;
    target = s_provisioning_target;
    xSemaphoreGive(s_state_mutex);
    return true;
}

static uint32_t replace_provisioning_target(const ProvisioningTarget& target, TickType_t timeout)
{
    bool state_locked = false;
    if (s_state_mutex) {
        if (xSemaphoreTake(s_state_mutex, timeout) != pdTRUE) return 0;
        state_locked = true;
    }
    s_provisioning.store(false, std::memory_order_release);
    uint32_t generation = s_provisioning_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
    {
        s_provisioning_target = target;
        s_provisioning_target.generation = generation;
    }
    if (state_locked) {
        xSemaphoreGive(s_state_mutex);
    }
    s_provisioning.store(target.active, std::memory_order_release);
    return generation;
}

static bool complete_provisioning_target(uint32_t generation, TickType_t timeout)
{
    bool completed = false;
    if (s_state_mutex && xSemaphoreTake(s_state_mutex, timeout) == pdTRUE) {
        if (s_provisioning_target.active && s_provisioning_target.generation == generation) {
            s_provisioning_target = ProvisioningTarget();
            s_provisioning_target.generation =
                s_provisioning_generation.fetch_add(1, std::memory_order_acq_rel) + 1;
            s_provisioning.store(false, std::memory_order_release);
            completed = true;
        }
        xSemaphoreGive(s_state_mutex);
    }
    return completed;
}

static bool bind_provisioning_bssid(uint32_t generation, const uint8_t bssid[6], TickType_t timeout)
{
    bool bound = false;
    if (s_state_mutex && xSemaphoreTake(s_state_mutex, timeout) == pdTRUE) {
        if (s_provisioning_target.active && s_provisioning_target.generation == generation) {
            memcpy(s_provisioning_target.bssid.data(), bssid, s_provisioning_target.bssid.size());
            s_provisioning_target.bssidSet = true;
            bound = true;
        }
        xSemaphoreGive(s_state_mutex);
    }
    return bound;
}

enum class ProvisioningValidationResult {
    NoAction,
    Retry,
    Matched,
};

// Caller holds WifiDriverOperation. The target and AP snapshot are checked again so a stale GOT_IP
// cannot close a manual AP or a newer provisioning target.
static ProvisioningValidationResult validate_provisioning_target_locked(uint32_t generation)
{
    if (!s_provisioning.load(std::memory_order_acquire)) return ProvisioningValidationResult::NoAction;
    ProvisioningTarget target;
    ApState ap;
    const TickType_t timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
    if (!provisioning_target_snapshot(target, timeout) || !ap_state_snapshot(ap, timeout)) {
        return ProvisioningValidationResult::Retry;
    }
    if (!target.active || target.generation != generation || !ap.mode || ap.manual) {
        return ProvisioningValidationResult::NoAction;
    }

    wifi_ap_record_t connected_ap = {};
    if (esp_wifi_sta_get_ap_info(&connected_ap) != ESP_OK) {
        return ProvisioningValidationResult::Retry;
    }
    std::array<uint8_t, 6> connected_bssid = {};
    memcpy(connected_bssid.data(), connected_ap.bssid, connected_bssid.size());
    if (!idf_wifi_provision_target_matches(
            target.ssid, target.bssidSet, target.bssid,
            reinterpret_cast<const char*>(connected_ap.ssid), connected_bssid)) {
        return ProvisioningValidationResult::NoAction;
    }
    return complete_provisioning_target(generation, timeout)
               ? ProvisioningValidationResult::Matched
               : ProvisioningValidationResult::Retry;
}

// Delay AP shutdown after provisioning succeeds so the page can display the IP before switching to STA-only.
static void ap_close_timer_cb(void*)
{
    const uint32_t validation_generation =
        s_provisioning_validation_generation.exchange(0, std::memory_order_acq_rel);
    if (validation_generation != 0) {
        WifiDriverOperation operation(0);
        if (!operation) {
            s_provisioning_validation_generation.store(validation_generation, std::memory_order_release);
            schedule_ap_close(1000);
            return;
        }
        const ProvisioningValidationResult result =
            validate_provisioning_target_locked(validation_generation);
        if (result == ProvisioningValidationResult::Retry) {
            s_provisioning_validation_generation.store(validation_generation, std::memory_order_release);
            schedule_ap_close(1000);
        } else if (result == ProvisioningValidationResult::Matched) {
            schedule_ap_close(AP_PROVISION_HOLD_MS);
            idf_logf("Provisioning connection succeeded; AP closes in %lu seconds",
                     static_cast<unsigned long>(AP_PROVISION_HOLD_MS / 1000));
        } else {
            s_ap_close_pending.store(false, std::memory_order_release);
        }
        return;
    }
    if (s_provisioning.load(std::memory_order_acquire)) {
        schedule_ap_close(1000);
        return;
    }
    WifiDriverOperation operation(0);
    if (!operation) {
        schedule_ap_close(1000);
        return;
    }
    ApState ap;
    if (!ap_state_snapshot(ap, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))) {
        schedule_ap_close(1000);
        return;
    }
    if (!ap.mode || ap.manual || s_provisioning.load(std::memory_order_acquire)) {
        s_ap_close_pending.store(false, std::memory_order_release);
        return;
    }
    if (esp_wifi_set_mode(WIFI_MODE_STA) == ESP_OK) {
        set_ap_state(false, false, std::string());
        s_ap_close_pending.store(false, std::memory_order_release);
        char host[33] = {};
        idf_config_copy_mdns_host(host, sizeof(host));
        idf_logf("Provisioning AP closed; use the device IP or http://%s.local", host);
    } else {
        schedule_ap_close(1000);
    }
}

static void schedule_ap_close(uint32_t delay_ms)
{
    if (!s_ap_close_timer) {
        const esp_timer_create_args_t targs = {
            .callback = &ap_close_timer_cb,
            .arg = nullptr,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "ap_close",
            .skip_unhandled_events = true,
        };
        if (esp_timer_create(&targs, &s_ap_close_timer) != ESP_OK) {
            s_ap_close_pending.store(true, std::memory_order_release);
            return;
        }
    }
    esp_timer_stop(s_ap_close_timer);
    if (esp_timer_start_once(s_ap_close_timer, static_cast<uint64_t>(delay_ms) * 1000ULL) != ESP_OK) {
        s_ap_close_pending.store(true, std::memory_order_release);
        return;
    }
    s_ap_close_pending.store(false, std::memory_order_release);
}

static void schedule_scan_cleanup(esp_err_t err)
{
    s_scan_cleanup_error.store(static_cast<int>(err), std::memory_order_relaxed);
    if (!s_scan_cleanup_timer) {
        s_scan_cleanup_retry_pending.store(true, std::memory_order_release);
        return;
    }
    esp_timer_stop(s_scan_cleanup_timer);
    if (esp_timer_start_once(s_scan_cleanup_timer, 1000ULL * 1000ULL) != ESP_OK) {
        s_scan_cleanup_retry_pending.store(true, std::memory_order_release);
        return;
    }
    s_scan_cleanup_retry_pending.store(false, std::memory_order_release);
}

static bool sta_can_connect()
{
    return s_has_sta_credentials.load(std::memory_order_relaxed) &&
           s_sta_configured.load(std::memory_order_relaxed);
}

static bool close_recovery_ap_if_active_locked(
    TickType_t timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))
{
    ApState ap;
    if (!ap_state_snapshot(ap, timeout)) return false;
    if (!ap.mode || ap.manual || s_provisioning.load(std::memory_order_acquire)) return true;
    if (esp_wifi_set_mode(WIFI_MODE_STA) == ESP_OK) {
        set_ap_state(false, false, std::string());
        idf_log_line("Recovery provisioning AP cancelled");
        return true;
    }
    return false;
}

static bool close_recovery_ap_if_active(TickType_t timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))
{
    WifiDriverOperation operation(timeout);
    if (!operation) return false;
    return close_recovery_ap_if_active_locked(timeout);
}

// Invalidate recovery before an intentional/configuration state change. The AP close is kept outside
// the recovery lock because esp_wifi_set_mode can synchronously deliver events back to this component.
static bool reset_recovery_state(bool close_ap, bool driver_locked = false,
                                 TickType_t timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))
{
    bool close_started_ap = false;
    if (s_recovery_mutex && xSemaphoreTake(s_recovery_mutex, timeout) == pdTRUE) {
        close_started_ap = close_ap && s_recovery_ap_started.load(std::memory_order_relaxed);
        s_recovery_ap_inflight = false;
        s_recovery_claim_generation = 0;
        s_recovery_completion_generation.store(0, std::memory_order_relaxed);
        s_recovery_completion_retry_pending.store(false, std::memory_order_release);
        s_sta_outage_since_us.store(-1, std::memory_order_relaxed);
        s_sta_outage_generation.fetch_add(1, std::memory_order_relaxed);
        s_recovery_ap_started.store(false, std::memory_order_relaxed);
        s_recovery_ap_last_attempt_us.store(-1, std::memory_order_relaxed);
        s_recovery_ap_close_failed.store(false, std::memory_order_relaxed);
        xSemaphoreGive(s_recovery_mutex);
    } else if (s_recovery_mutex) {
        return false;
    } else {
        s_recovery_ap_inflight = false;
        s_recovery_claim_generation = 0;
        s_recovery_completion_generation.store(0, std::memory_order_relaxed);
        s_recovery_completion_retry_pending.store(false, std::memory_order_release);
        s_sta_outage_since_us.store(-1, std::memory_order_relaxed);
        s_sta_outage_generation.fetch_add(1, std::memory_order_relaxed);
        s_recovery_ap_started.store(false, std::memory_order_relaxed);
        s_recovery_ap_last_attempt_us.store(-1, std::memory_order_relaxed);
    }
    if (close_started_ap && !(driver_locked ? close_recovery_ap_if_active_locked(timeout)
                                             : close_recovery_ap_if_active(timeout))) {
        s_recovery_ap_close_failed.store(true, std::memory_order_relaxed);
    }
    return !s_recovery_ap_close_failed.load(std::memory_order_relaxed);
}

static RecoveryClaim claim_recovery_ap_if_due(int64_t now_us, uint32_t outage_generation,
                                              TickType_t timeout)
{
    RecoveryClaim claim;
    if (!s_recovery_mutex || xSemaphoreTake(s_recovery_mutex, timeout) != pdTRUE) return claim;

    if (!s_recovery_ap_inflight) {
        ApState ap;
        if (!ap_state_snapshot(ap, timeout)) {
            xSemaphoreGive(s_recovery_mutex);
            return claim;
        }
        const IdfWifiRecoveryPolicy policy = {
            now_us,
            s_sta_outage_since_us.load(std::memory_order_relaxed),
            outage_generation,
            s_sta_outage_generation.load(std::memory_order_relaxed),
            s_recovery_ap_last_attempt_us.load(std::memory_order_relaxed),
            s_recovery_ap_started.load(std::memory_order_relaxed),
            s_sta_connected.load(std::memory_order_relaxed),
            s_sta_configured.load(std::memory_order_relaxed),
            ap.mode,
            s_provisioning.load(std::memory_order_acquire),
            s_select_running.load(std::memory_order_relaxed),
        };
        if (idf_wifi_recovery_ap_due(policy)) {
            s_recovery_ap_inflight = true;
            s_recovery_claim_generation = policy.currentGeneration;
            s_recovery_ap_last_attempt_us.store(now_us, std::memory_order_relaxed);
            s_recovery_ap_close_failed.store(false, std::memory_order_relaxed);
            claim.claimed = true;
            claim.ap_was_active = ap.mode;
            claim.generation = policy.currentGeneration;
        }
    }

    xSemaphoreGive(s_recovery_mutex);
    return claim;
}

static bool recovery_claim_is_current(const RecoveryClaim& claim,
                                      TickType_t timeout)
{
    if (!s_recovery_mutex || xSemaphoreTake(s_recovery_mutex, timeout) != pdTRUE) return false;
    const bool current =
        s_recovery_ap_inflight && s_recovery_claim_generation == claim.generation &&
        s_sta_outage_generation.load(std::memory_order_relaxed) == claim.generation &&
        s_sta_configured.load(std::memory_order_relaxed) &&
        !s_sta_connected.load(std::memory_order_relaxed) &&
        !s_provisioning.load(std::memory_order_acquire);
    xSemaphoreGive(s_recovery_mutex);
    return current;
}

static bool finish_recovery_ap_claim(const RecoveryClaim& claim, esp_err_t ap_err,
                                     bool driver_locked,
                                     TickType_t timeout)
{
    if (!claim.claimed) return false;
    ApState ap;
    const bool state_known = ap_state_snapshot(ap, timeout);
    const bool may_close_stale_ap =
        !claim.ap_was_active && !s_provisioning.load(std::memory_order_acquire);
    // A timed-out snapshot is unknown, never "AP inactive". Keep the close deferred so a late AP start
    // cannot strand the recovery network if the state lock is still busy.
    bool close_stale_ap = !state_known && may_close_stale_ap;
    if (!state_known && may_close_stale_ap) schedule_ap_close(1000);
    const bool claim_lock_acquired =
        s_recovery_mutex && xSemaphoreTake(s_recovery_mutex, timeout) == pdTRUE;
    if (claim_lock_acquired) {
        const bool claim_valid = state_known &&
            s_recovery_ap_inflight && s_recovery_claim_generation == claim.generation &&
            s_sta_outage_generation.load(std::memory_order_relaxed) == claim.generation &&
            !s_sta_connected.load(std::memory_order_relaxed) && ap_err == ESP_OK &&
            ap.mode && !ap.manual;
        if (claim_valid) {
            s_recovery_ap_started.store(true, std::memory_order_relaxed);
        } else if ((ap_err == ESP_OK && ap.mode && !ap.manual) && may_close_stale_ap) {
            // A reset may have invalidated the claim while start_provisioning_ap was in flight.
            close_stale_ap = true;
        }
        xSemaphoreGive(s_recovery_mutex);
    } else if (may_close_stale_ap) {
        close_stale_ap = true;
    }
    if (close_stale_ap) {
        const bool closed = driver_locked ? close_recovery_ap_if_active_locked(timeout)
                                          : close_recovery_ap_if_active(timeout);
        s_recovery_ap_close_failed.store(!closed, std::memory_order_relaxed);
        if (!closed) schedule_ap_close(1000);
    }
    if (s_recovery_mutex && xSemaphoreTake(s_recovery_mutex, timeout) == pdTRUE) {
        s_recovery_ap_inflight = false;
        s_recovery_claim_generation = 0;
        s_recovery_completion_generation.store(0, std::memory_order_relaxed);
        s_recovery_completion_retry_pending.store(false, std::memory_order_release);
        xSemaphoreGive(s_recovery_mutex);
    } else if (s_recovery_mutex) {
        s_recovery_completion_generation.store(claim.generation, std::memory_order_relaxed);
        s_recovery_completion_retry_pending.store(true, std::memory_order_release);
    }
    return close_stale_ap;
}

static void retry_recovery_claim_completion(TickType_t timeout)
{
    if (!s_recovery_completion_retry_pending.load(std::memory_order_acquire) || !s_recovery_mutex) {
        return;
    }
    if (xSemaphoreTake(s_recovery_mutex, timeout) != pdTRUE) return;
    const uint32_t generation =
        s_recovery_completion_generation.load(std::memory_order_relaxed);
    if (s_recovery_ap_inflight && s_recovery_claim_generation == generation) {
        s_recovery_ap_inflight = false;
        s_recovery_claim_generation = 0;
    }
    s_recovery_completion_generation.store(0, std::memory_order_relaxed);
    s_recovery_completion_retry_pending.store(false, std::memory_order_release);
    xSemaphoreGive(s_recovery_mutex);
}

static std::atomic<bool> s_ntp_first_logged{false};
static std::atomic<int64_t> s_ntp_manual_us{-1};

static void cleanup_wifi_start_resources(bool wifi_inited,
                                         bool wifi_event_registered,
                                         bool ip_event_registered)
{
    if (s_scan_cleanup_timer) {
        esp_timer_stop(s_scan_cleanup_timer);
        esp_timer_delete(s_scan_cleanup_timer);
        s_scan_cleanup_timer = nullptr;
    }
    s_scan_cleanup_retry_pending.store(false, std::memory_order_release);
    s_ap_close_pending.store(false, std::memory_order_release);
    s_provisioning_validation_generation.store(0, std::memory_order_release);
    if (ip_event_registered) {
        esp_event_handler_unregister(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler);
    }
    if (wifi_event_registered) {
        esp_event_handler_unregister(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler);
    }
    if (wifi_inited) esp_wifi_deinit();
    if (s_sta_netif) {
        esp_netif_destroy_default_wifi(s_sta_netif);
        s_sta_netif = nullptr;
    }
    if (s_ap_netif) {
        esp_netif_destroy_default_wifi(s_ap_netif);
        s_ap_netif = nullptr;
    }
    if (s_wifi_event_group) {
        vEventGroupDelete(s_wifi_event_group);
        s_wifi_event_group = nullptr;
    }
    reset_recovery_state(false);
    if (s_recovery_mutex) {
        vSemaphoreDelete(s_recovery_mutex);
        s_recovery_mutex = nullptr;
    }
    if (s_wifi_driver_mutex) {
        vSemaphoreDelete(s_wifi_driver_mutex);
        s_wifi_driver_mutex = nullptr;
    }
    if (s_state_mutex) {
        vSemaphoreDelete(s_state_mutex);
        s_state_mutex = nullptr;
    }
    s_has_sta_credentials.store(false, std::memory_order_relaxed);
    s_sta_configured.store(false, std::memory_order_relaxed);
    s_sta_connected.store(false, std::memory_order_relaxed);
    s_current_profile_open.store(false, std::memory_order_relaxed);
    s_scan_running.store(false, std::memory_order_relaxed);
    s_scan_refresh_pending.store(false, std::memory_order_relaxed);
    s_candidate_attempt.store(0, std::memory_order_relaxed);
}

static void sntp_sync_cb(timeval*)
{
    // Log only the first successful sync or a manual sync; periodic sync remains quiet.
    // Allow ten minutes for slow SNTP retries on weak networks, then clear the marker after one match.
    bool first = !s_ntp_first_logged.exchange(true, std::memory_order_relaxed);
    int64_t manual_us = s_ntp_manual_us.load(std::memory_order_relaxed);
    bool manual = manual_us >= 0 && (esp_timer_get_time() - manual_us) < 600000000LL;
    if (manual) s_ntp_manual_us.store(-1, std::memory_order_relaxed);
    if (!first && !manual) return;

    time_t now = time(nullptr);
    // This callback runs on the small tiT (lwIP) stack; read only the timezone and never deep-copy IdfConfig.
    std::string local = idf_util_format_epoch_local(static_cast<uint32_t>(now), idf_config_get_tz_offset());
    if (local.empty()) {
        idf_logf("NTP time synchronized, epoch=%ld", static_cast<long>(now));
    } else {
        idf_logf("NTP time synchronized: %s (epoch=%ld)", local.c_str(), static_cast<long>(now));
    }
}

static void start_sntp_once()
{
    bool expected = false;
    if (!s_sntp_started.compare_exchange_strong(expected, true, std::memory_order_relaxed)) return;

    // This runs on the 4KB system-event stack; read only the NTP server name instead of deep-copying IdfConfig.
    std::string server = idf_config_get_ntp_server();
    if (server.empty()) server = "ntp.aliyun.com";
    strlcpy(s_ntp_server, server.c_str(), sizeof(s_ntp_server));

    esp_sntp_setoperatingmode(SNTP_OPMODE_POLL);
    esp_sntp_set_time_sync_notification_cb(sntp_sync_cb);
    esp_sntp_setservername(0, s_ntp_server);
    // Fallback servers prevent one unreachable NTP host from disabling every time-based task.
    // Requires CONFIG_LWIP_SNTP_MAX_SERVERS>=3; see sdkconfig.defaults.
    esp_sntp_setservername(1, "ntp.ntsc.ac.cn");
    esp_sntp_setservername(2, "pool.ntp.org");
    // ESP32-C3 oscillator drift is seconds per day while scheduling is daily, so syncing every 24h is sufficient.
    esp_sntp_set_sync_interval(24 * 3600 * 1000);
    esp_sntp_init();
    idf_logf("NTP synchronization started: primary=%s, fallback=ntp.ntsc.ac.cn,pool.ntp.org", s_ntp_server);
}

static std::string ip4_to_string(const esp_ip4_addr_t& addr)
{
    char buf[16];
    snprintf(buf, sizeof(buf), IPSTR, IP2STR(&addr));
    return std::string(buf);
}

static std::string mac_to_string(const uint8_t mac[6])
{
    char buf[18];
    snprintf(buf, sizeof(buf), "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    return std::string(buf);
}

static const char* wifi_disconnect_reason_name(uint8_t reason)
{
    switch (reason) {
        case WIFI_REASON_UNSPECIFIED: return "unspecified";
        case WIFI_REASON_AUTH_EXPIRE: return "authentication expired";
        case WIFI_REASON_AUTH_LEAVE: return "authentication left";
        case WIFI_REASON_DISASSOC_DUE_TO_INACTIVITY: return "inactive";
        case WIFI_REASON_ASSOC_TOOMANY: return "AP client limit reached";
        case WIFI_REASON_ASSOC_LEAVE: return "association left";
        case WIFI_REASON_ASSOC_NOT_AUTHED: return "association not authenticated";
        case WIFI_REASON_4WAY_HANDSHAKE_TIMEOUT: return "four-way handshake timeout";
        case WIFI_REASON_GROUP_KEY_UPDATE_TIMEOUT: return "group-key update timeout";
        case WIFI_REASON_IE_IN_4WAY_DIFFERS: return "four-way handshake IE mismatch";
        case WIFI_REASON_802_1X_AUTH_FAILED: return "802.1X authentication failed";
        case WIFI_REASON_TIMEOUT: return "link timeout";
        case WIFI_REASON_PEER_INITIATED: return "peer disconnected";
        case WIFI_REASON_AP_INITIATED: return "AP disconnected client";
        case WIFI_REASON_BEACON_TIMEOUT: return "beacon timeout";
        case WIFI_REASON_NO_AP_FOUND: return "AP not found";
        case WIFI_REASON_AUTH_FAIL: return "authentication failed";
        case WIFI_REASON_ASSOC_FAIL: return "association failed";
        case WIFI_REASON_HANDSHAKE_TIMEOUT: return "handshake timeout";
        case WIFI_REASON_CONNECTION_FAIL: return "connection failed";
        case WIFI_REASON_AP_TSF_RESET: return "AP clock reset";
        case WIFI_REASON_ROAMING: return "roaming switch";
        case WIFI_REASON_ASSOC_COMEBACK_TIME_TOO_LONG: return "association wait too long";
        case WIFI_REASON_SA_QUERY_TIMEOUT: return "SA query timeout";
        case WIFI_REASON_NO_AP_FOUND_W_COMPATIBLE_SECURITY: return "no AP with compatible security";
        case WIFI_REASON_NO_AP_FOUND_IN_AUTHMODE_THRESHOLD: return "authentication mode mismatch";
        case WIFI_REASON_NO_AP_FOUND_IN_RSSI_THRESHOLD: return "signal below threshold";
        default: return "unknown reason";
    }
}

static void log_wifi_disconnect_once(uint8_t reason, int8_t rssi)
{
    static constexpr int64_t BEACON_LOG_INTERVAL_US = 5LL * 60LL * 1000000LL;
    bool beacon_timeout = reason == WIFI_REASON_BEACON_TIMEOUT;
    int64_t now_us = esp_timer_get_time();
    uint32_t suppressed = 0;

    if (beacon_timeout) {
        int64_t last_us = s_last_beacon_log_us.load(std::memory_order_relaxed);
        if (last_us > 0 && now_us - last_us < BEACON_LOG_INTERVAL_US) {
            s_suppressed_beacon_logs.fetch_add(1, std::memory_order_relaxed);
            s_suppress_next_connect_log.store(true, std::memory_order_relaxed);
            return;
        }
        s_last_beacon_log_us.store(now_us, std::memory_order_relaxed);
        suppressed = s_suppressed_beacon_logs.exchange(0, std::memory_order_relaxed);
    } else {
        suppressed = s_suppressed_beacon_logs.exchange(0, std::memory_order_relaxed);
    }

    char rssi_text[24] = {};
    if (rssi < 0) {
        snprintf(rssi_text, sizeof(rssi_text), "%d dBm", static_cast<int>(rssi));
    } else {
        snprintf(rssi_text, sizeof(rssi_text), "unknown");
    }
    const char* reason_name = wifi_disconnect_reason_name(reason);
    char tail[80] = {};
    if (suppressed) {
        snprintf(tail, sizeof(tail), "; %lu earlier beacon drops coalesced",
                 static_cast<unsigned long>(suppressed));
    }
    idf_logf("WiFi disconnected: %s (%u), RSSI=%s, auto-reconnect%s",
             reason_name, static_cast<unsigned>(reason), rssi_text, tail);
    s_suppress_next_connect_log.store(false, std::memory_order_relaxed);
}

static std::string wifi_scan_records_json(const wifi_ap_record_t* records, size_t count);

static bool finish_scan_refresh_error(esp_err_t err, TickType_t timeout)
{
    if (s_state_mutex && xSemaphoreTake(s_state_mutex, timeout) != pdTRUE) return false;
    if (s_state_mutex) {
        s_scan_cache_error = err;
        xSemaphoreGive(s_state_mutex);
    }
    s_scan_running.store(false, std::memory_order_release);
    s_scan_refresh_pending.store(false, std::memory_order_release);
    s_scan_cleanup_retry_pending.store(false, std::memory_order_release);
    return true;
}

static bool finish_scan_refresh_success(const wifi_ap_record_t* records, uint16_t count,
                                        std::string&& json,
                                        TickType_t timeout)
{
    if (s_state_mutex && xSemaphoreTake(s_state_mutex, timeout) != pdTRUE) return false;
    if (s_state_mutex) {
        s_scan_cache_records = {};
        std::copy_n(records, count, s_scan_cache_records.begin());
        s_scan_cache_count = count;
        s_scan_cache_json = std::move(json);
        s_scan_cache_ready = true;
        s_scan_cache_error = ESP_OK;
        xSemaphoreGive(s_state_mutex);
    }
    s_scan_running.store(false, std::memory_order_release);
    s_scan_refresh_pending.store(false, std::memory_order_release);
    s_scan_cleanup_retry_pending.store(false, std::memory_order_release);
    return true;
}

static void wifi_scan_collect_once()
{
    uint16_t count = 0;
    esp_err_t err = ESP_OK;
    {
        WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS), true);
        if (!operation) {
            schedule_scan_cleanup(ESP_ERR_TIMEOUT);
            return;
        }
        uint16_t total = 0;
        err = esp_wifi_scan_get_ap_num(&total);
        count = std::min<uint16_t>(total, WIFI_SCAN_RECORD_LIMIT);
        if (err == ESP_OK && count) {
            err = esp_wifi_scan_get_ap_records(&count, s_scan_collect_records.data());
        }
        const esp_err_t clear_err = esp_wifi_clear_ap_list();
        if (err == ESP_OK && clear_err != ESP_OK) err = clear_err;
    }
    s_scan_running.store(false, std::memory_order_release);
    if (err != ESP_OK) {
        if (!finish_scan_refresh_error(err, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))) {
            schedule_scan_cleanup(err);
        }
        return;
    }
    // Build the cache JSON after releasing the driver gate; a string allocation cannot strand scan ownership.
    std::string cache_json = wifi_scan_records_json(s_scan_collect_records.data(), count);
    if (!finish_scan_refresh_success(
            s_scan_collect_records.data(), count, std::move(cache_json),
            pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))) {
        schedule_scan_cleanup(ESP_ERR_TIMEOUT);
    }
}

static void scan_cleanup_timer_cb(void*)
{
    if (!s_scan_refresh_pending.load(std::memory_order_acquire)) return;
    WifiDriverOperation operation(0, true);
    if (!operation) {
        schedule_scan_cleanup(static_cast<esp_err_t>(s_scan_cleanup_error.load(std::memory_order_relaxed)));
        return;
    }
    esp_wifi_clear_ap_list();
    if (!finish_scan_refresh_error(
            static_cast<esp_err_t>(s_scan_cleanup_error.load(std::memory_order_relaxed)),
            pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))) {
        schedule_scan_cleanup(static_cast<esp_err_t>(s_scan_cleanup_error.load(std::memory_order_relaxed)));
    }
}

static void wifi_event_handler(void*, esp_event_base_t event_base, int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE &&
        s_scan_refresh_pending.load(std::memory_order_acquire)) {
        if (xTaskCreate(wifi_scan_collect_task, "idf_wifi_scan", 4096, nullptr, 2, nullptr) != pdPASS) {
            schedule_scan_cleanup(ESP_ERR_NO_MEM);
        }
        return;
    }
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        if (sta_can_connect()) wifi_connect_now();
        return;
    }
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        s_sta_connected.store(false, std::memory_order_relaxed);
        if (s_wifi_event_group) {
            xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
            xEventGroupSetBits(s_wifi_event_group, WIFI_DISCONNECTED_BIT);
        }
        // Disable auto-reconnect while switching credentials; apply the new configuration after the caller sees this event.
        if (!s_sta_configured.load(std::memory_order_relaxed)) return;
        int64_t outage_expected = -1;
        if (s_sta_outage_since_us.compare_exchange_strong(
                outage_expected, esp_timer_get_time(), std::memory_order_relaxed)) {
            s_sta_outage_generation.fetch_add(1, std::memory_order_relaxed);
        }
        // Reconnect immediately after the first few drops, then back off to the 15s watchdog.
        // This avoids a tight connection storm disrupting the provisioning AP and scans on bad credentials or weak signal.
        int streak = s_disconnect_streak.fetch_add(1, std::memory_order_relaxed) + 1;
        if (streak == 1 && event_data) {
            // Write one Web log per disconnect chain and coalesce repeated beacon drops.
            auto* ev = static_cast<wifi_event_sta_disconnected_t*>(event_data);
            log_wifi_disconnect_once(ev->reason, ev->rssi);
        }
        if (streak <= 3 && sta_can_connect()) {
            wifi_connect_now();
            ESP_LOGW(TAG, "STA disconnected; reconnecting immediately (attempt %d)", streak);
        } else {
            ESP_LOGW(TAG, "STA disconnected %d consecutive times; switching to timed reconnect", streak);
        }
        return;
    }
    if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        auto* event = static_cast<ip_event_got_ip_t*>(event_data);
        s_sta_connected.store(true, std::memory_order_relaxed);
        s_disconnect_streak.store(0, std::memory_order_relaxed);
        s_candidate_attempt.store(0, std::memory_order_relaxed);
        const TickType_t callback_timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
        if (s_provisioning.load(std::memory_order_acquire)) {
            const uint32_t generation = s_provisioning_generation.load(std::memory_order_acquire);
            if (generation != 0) {
                s_provisioning_validation_generation.store(generation, std::memory_order_release);
            }
        }
        if (!reset_recovery_state(false, false, callback_timeout)) {
            if (s_provisioning.load(std::memory_order_acquire) &&
                s_provisioning_validation_generation.load(std::memory_order_acquire) == 0) {
                s_provisioning_validation_generation.store(
                    s_provisioning_generation.load(std::memory_order_acquire), std::memory_order_release);
            }
            schedule_ap_close(1000);
            return;
        }
        ESP_LOGI(TAG, "STA acquired IP: " IPSTR, IP2STR(&event->ip_info.ip));
        if (!s_suppress_next_connect_log.exchange(false, std::memory_order_relaxed)) {
            idf_logf("WiFi connected, IP=" IPSTR, IP2STR(&event->ip_info.ip));
        }
        start_sntp_once();
        // Remember successful networks like a phone. The task deduplicates known networks without writing NVS.
        // This path handles a temporary WiFi-history array and NVS, so use a separate 8KB stack instead of the 4KB event stack.
        if (xTaskCreate(wifi_remember_task, "idf_wifi_mem", 8192, nullptr, 2, nullptr) != pdPASS) {
            ESP_LOGW(TAG, "Could not create WiFi remember task; this connection will not be added to history");
        }
        if (s_wifi_event_group) {
            xEventGroupClearBits(s_wifi_event_group, WIFI_DISCONNECTED_BIT);
            xEventGroupSetBits(s_wifi_event_group, WIFI_CONNECTED_BIT);
        }
        ApState ap;
        if (!ap_state_snapshot(ap, callback_timeout)) {
            if (s_provisioning.load(std::memory_order_acquire) &&
                s_provisioning_validation_generation.load(std::memory_order_acquire) == 0) {
                s_provisioning_validation_generation.store(
                    s_provisioning_generation.load(std::memory_order_acquire), std::memory_order_release);
            }
            schedule_ap_close(1000);
            return;
        }
        if (s_provisioning.load(std::memory_order_acquire) &&
            s_provisioning_validation_generation.load(std::memory_order_acquire) == 0) {
            s_provisioning_validation_generation.store(
                s_provisioning_generation.load(std::memory_order_acquire), std::memory_order_release);
        }
        if (ap.mode && s_has_sta_credentials.load(std::memory_order_relaxed)) {
            if (s_provisioning.load(std::memory_order_acquire)) {
                ProvisioningTarget target;
                if (!provisioning_target_snapshot(target, callback_timeout)) {
                    schedule_ap_close(1000);
                    return;
                }
                WifiDriverOperation operation(0);
                ProvisioningValidationResult result = ProvisioningValidationResult::NoAction;
                const uint32_t validation_generation =
                    s_provisioning_validation_generation.load(std::memory_order_acquire);
                if (target.active && validation_generation != 0) {
                    result = operation ? validate_provisioning_target_locked(validation_generation)
                                       : ProvisioningValidationResult::Retry;
                }
                if (result == ProvisioningValidationResult::Matched) {
                    // Close the AP only when this submitted target gets an IP; fallback to old credentials is not provisioning success.
                    schedule_ap_close(AP_PROVISION_HOLD_MS);
                    idf_logf("Provisioning connection succeeded; AP closes in %lu seconds",
                             static_cast<unsigned long>(AP_PROVISION_HOLD_MS / 1000));
                } else if (result == ProvisioningValidationResult::Retry && !ap.manual) {
                    s_provisioning_validation_generation.store(validation_generation, std::memory_order_release);
                    schedule_ap_close(1000);
                } else {
                    s_provisioning_validation_generation.store(0, std::memory_order_release);
                    ESP_LOGW(TAG, "Ignoring GOT_IP from a non-current provisioning target; keeping AP open");
                }
            } else if (!ap.manual) {
                schedule_ap_close(1);  // Defer until the driver boundary is available; timer rechecks manual state.
            }
        } else if (s_provisioning.load(std::memory_order_acquire) &&
                   s_provisioning_validation_generation.load(std::memory_order_acquire) != 0) {
            schedule_ap_close(1000);
        }
    }
}

// After STA gets an IP, remember its credentials like a phone. idf_config_note_wifi_connected writes only
// new networks or password changes. Run this in a one-shot task because the event stack is small and NVS
// writes must not block the event loop.
static void wifi_remember_once()
{
    wifi_config_t cfg = {};
    WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS));
    if (operation && esp_wifi_get_config(WIFI_IF_STA, &cfg) == ESP_OK && cfg.sta.ssid[0]) {
        char ssid[33] = {};
        char pass[65] = {};
        memcpy(ssid, cfg.sta.ssid, sizeof(cfg.sta.ssid));
        memcpy(pass, cfg.sta.password, sizeof(cfg.sta.password));
        idf_config_note_wifi_connected(ssid, pass);
    }
}

static void wifi_remember_task(void*)
{
    wifi_remember_once();
    vTaskDelete(nullptr);
}

// A 15s reconnect watchdog recovers when any disconnect-to-reconnect event step fails and no later event fires.
// With multiple saved networks, rescan because the device may have moved. Open the existing provisioning AP only
// after a bounded outage so a device can recover without serial access.
static void reconnect_watchdog_cb(void*)
{
    if (!s_started.load(std::memory_order_relaxed)) return;
    const TickType_t driver_timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
    if (s_scan_cleanup_retry_pending.load(std::memory_order_acquire) &&
        s_scan_refresh_pending.load(std::memory_order_acquire)) {
        scan_cleanup_timer_cb(nullptr);
    }
    if (s_ap_close_pending.load(std::memory_order_acquire)) {
        ap_close_timer_cb(nullptr);
    }
    retry_recovery_claim_completion(driver_timeout);
    if (!sta_can_connect()) return;
    if (s_sta_connected.load(std::memory_order_relaxed)) return;
    const int64_t now_us = esp_timer_get_time();
    int64_t outage_since_us = s_sta_outage_since_us.load(std::memory_order_relaxed);
    uint32_t outage_generation = s_sta_outage_generation.load(std::memory_order_relaxed);
    if (outage_since_us < 0) {
        int64_t expected = -1;
        if (s_sta_outage_since_us.compare_exchange_strong(
                expected, now_us, std::memory_order_relaxed)) {
            outage_generation = s_sta_outage_generation.fetch_add(1, std::memory_order_relaxed) + 1;
        } else {
            outage_generation = s_sta_outage_generation.load(std::memory_order_relaxed);
        }
    }
    static uint32_t tick = 0;  // esp_timer callbacks run serially.
    ++tick;
    ApState ap;
    if (!ap_state_snapshot(ap, driver_timeout)) return;
    // Slow to 60s while the provisioning AP is open because STA connection attempts disrupt AP clients and scans.
    if (ap.mode && (tick % 4) != 0) return;
    if (s_provisioning.load(std::memory_order_acquire)) {
        // During provisioning, retry only the applied driver configuration; do not select a saved network as a false success.
        esp_err_t err = wifi_connect_now();
        if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
            ESP_LOGW(TAG, "Could not start provisioning reconnect: %s", esp_err_to_name(err));
        }
        return;
    }

    // Claim recovery before launching a selector. The claim and selector-start gate share one mutex, so a selector
    // that is already running defers recovery, while a newly-started selector cannot race a claimed AP start.
    const int64_t action_now_us = esp_timer_get_time();
    const RecoveryClaim recovery_claim = claim_recovery_ap_if_due(action_now_us, outage_generation, driver_timeout);
    if (recovery_claim.claimed) {
        WifiDriverOperation operation(driver_timeout);
        const bool driver_locked = static_cast<bool>(operation);
        esp_err_t ap_err = ESP_ERR_TIMEOUT;
        if (operation && recovery_claim_is_current(recovery_claim, driver_timeout)) {
            ap_err = start_provisioning_ap_locked(false, driver_timeout);
        } else if (operation) {
            ap_err = ESP_ERR_INVALID_STATE;
        }
        finish_recovery_ap_claim(recovery_claim, ap_err, driver_locked, driver_timeout);
        if (ap_err != ESP_OK) {
            ESP_LOGW(TAG, "Recovery provisioning AP failed to start: %s", esp_err_to_name(ap_err));
        }
    }

    if (idf_config_wifi_network_count() > 1 ||
        s_current_profile_open.load(std::memory_order_relaxed)) {
        start_wifi_select_once();  // Scan for about 2-3s in a small task without blocking esp_timer.
    } else {
        esp_err_t err = wifi_connect_now();
        if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
            ESP_LOGW(TAG, "Watchdog reconnect failed to start: %s", esp_err_to_name(err));
        }
    }
}

static void dns_captive_task(void*)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        s_dns_task_started.store(false, std::memory_order_relaxed);
        idf_log_line("Could not create provisioning DNS socket");
        vTaskDelete(nullptr);
        return;
    }

    timeval timeout = {};
    timeout.tv_sec = 1;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(53);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        idf_log_line("Could not bind provisioning DNS to port 53");
        close(sock);
        s_dns_task_started.store(false, std::memory_order_relaxed);
        vTaskDelete(nullptr);
        return;
    }

    uint8_t req[512];
    int ap_off_seconds = 0;
    while (true) {
        sockaddr_in from = {};
        socklen_t from_len = sizeof(from);
        int len = recvfrom(sock, req, sizeof(req), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
        // Yield after immediate errors such as ENOMEM; otherwise the missing receive timeout creates a busy loop.
        if (len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) vTaskDelay(pdMS_TO_TICKS(200));
        ApState ap;
        if (!ap_state_snapshot(ap, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (!ap.mode) {
            // Release port 53 and exit about 10s after provisioning ends; recreate on next provisioning.
            if (++ap_off_seconds >= 10) break;
            continue;
        }
        ap_off_seconds = 0;
        if (len < 12) continue;

        uint16_t qd = (static_cast<uint16_t>(req[4]) << 8) | req[5];
        if (qd == 0) continue;
        int pos = 12;
        while (pos < len && req[pos] != 0) {
            pos += req[pos] + 1;
        }
        if (pos + 5 > len) continue;
        int question_end = pos + 5;
        uint8_t resp[560];
        if (question_end + 16 > static_cast<int>(sizeof(resp))) continue;
        memcpy(resp, req, question_end);
        resp[2] = 0x81; resp[3] = 0x80;  // standard response, no error
        resp[4] = 0x00; resp[5] = 0x01;  // Only the first question is copied, so qdcount must be one.
        resp[6] = 0x00; resp[7] = 0x01;  // one A answer
        resp[8] = resp[9] = resp[10] = resp[11] = 0;
        int out = question_end;
        resp[out++] = 0xC0; resp[out++] = 0x0C;  // name pointer
        resp[out++] = 0x00; resp[out++] = 0x01;  // A
        resp[out++] = 0x00; resp[out++] = 0x01;  // IN
        resp[out++] = 0x00; resp[out++] = 0x00; resp[out++] = 0x00; resp[out++] = 0x3C;  // TTL
        resp[out++] = 0x00; resp[out++] = 0x04;
        resp[out++] = 192; resp[out++] = 168; resp[out++] = 1; resp[out++] = 1;
        sendto(sock, resp, out, 0, reinterpret_cast<sockaddr*>(&from), from_len);
    }

    close(sock);
    s_dns_task_started.store(false, std::memory_order_relaxed);
    idf_log_line("Provisioning ended; DNS portal task exited");
    vTaskDelete(nullptr);
}

static void start_dns_task_once()
{
    bool expected = false;
    if (!s_dns_task_started.compare_exchange_strong(expected, true, std::memory_order_relaxed)) return;
    BaseType_t ok = xTaskCreate(dns_captive_task, "idf_dns", 3072, nullptr, 2, nullptr);
    if (ok != pdPASS) {
        s_dns_task_started.store(false, std::memory_order_relaxed);
        idf_log_line("Provisioning DNS task failed to start");
    }
}

// Lightweight mDNS responder for configurable <host>.local (default sms; issue #9).
// Rejoin multicast every 60s to refresh IGMP snooping, join on STA and AP, unicast legacy and QU queries,
// answer AAAA with NSEC for A-only support, and announce twice after joining.

// DNS-encoded hostname is "\xNN<host>\x05local"; refresh every second and announce changes without restart.
static constexpr size_t MDNS_NAME_CAP = 40;  // 1 + 32 hostname limit + 1 + 5 ("local") = 39.

static size_t mdns_encode_name(const char* host, uint8_t* out)
{
    size_t host_len = strlen(host);
    if (host_len == 0 || host_len > 32) { host = "sms"; host_len = 3; }
    size_t n = 0;
    out[n++] = static_cast<uint8_t>(host_len);
    memcpy(out + n, host, host_len);
    n += host_len;
    out[n++] = 5;
    memcpy(out + n, "local", 5);
    return n + 5;
}

static bool mdns_query_matches_host(const uint8_t* packet, int len, int offset,
                                    const uint8_t* name, size_t name_len)
{
    // Compare bytewise; length bytes <=32 cannot be mistaken for uppercase letters.
    int pos = offset;
    for (size_t i = 0; i < name_len; ++i) {
        if (pos >= len) return false;
        char a = static_cast<char>(packet[pos++]);
        char b = static_cast<char>(name[i]);
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
        if (a != b) return false;
    }
    return pos < len && packet[pos] == 0;
}

// Advertise the AP IP on the AP subnet and the STA IP elsewhere.
static bool mdns_pick_ip(uint32_t from_addr, uint8_t out[4])
{
    ApState ap_state;
    if (!ap_state_snapshot(ap_state, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))) return false;
    bool ap = ap_state.mode;
    if (ap && (from_addr & inet_addr("255.255.255.0")) == inet_addr("192.168.1.0")) {
        out[0] = 192; out[1] = 168; out[2] = 1; out[3] = 1;
        return true;
    }
    esp_netif_ip_info_t ip = {};
    if (s_sta_netif && esp_netif_get_ip_info(s_sta_netif, &ip) == ESP_OK && ip.ip.addr != 0) {
        memcpy(out, &ip.ip.addr, 4);
        return true;
    }
    if (ap) {
        out[0] = 192; out[1] = 168; out[2] = 1; out[3] = 1;
        return true;
    }
    return false;
}

struct MdnsAnswerPlan {
    bool wantA = false;
    bool wantNsec = false;   // AAAA query: NSEC declares only an A record.
    bool legacy = false;     // Query from a source port other than 5353.
    bool unicast = false;    // Legacy query or QU bit.
    uint16_t id = 0;
    uint16_t firstQtype = 0;
};

static int mdns_append_name(uint8_t* buf, int out, const uint8_t* name, size_t name_len)
{
    memcpy(buf + out, name, name_len);
    out += name_len;
    buf[out++] = 0;
    return out;
}

static int mdns_append_ttl(uint8_t* buf, int out, uint32_t ttl)
{
    buf[out++] = static_cast<uint8_t>(ttl >> 24);
    buf[out++] = static_cast<uint8_t>(ttl >> 16);
    buf[out++] = static_cast<uint8_t>(ttl >> 8);
    buf[out++] = static_cast<uint8_t>(ttl);
    return out;
}

// resp needs 256 bytes: at the hostname limit, header 12 + question 45 + A 55 + NSEC 96 is about 208.
static int mdns_build_response(uint8_t* resp, const MdnsAnswerPlan& plan, const uint8_t ip[4],
                               const uint8_t* name, size_t name_len)
{
    uint32_t ttl = plan.legacy ? 10 : 120;             // RFC 6762 section 6.7 limits legacy TTL to 10s.
    uint16_t rrclass = plan.legacy ? 0x0001 : 0x8001;  // Legacy replies omit cache-flush.
    int an = (plan.wantA ? 1 : 0) + (plan.wantNsec ? 1 : 0);
    int out = 0;
    resp[out++] = static_cast<uint8_t>(plan.id >> 8);
    resp[out++] = static_cast<uint8_t>(plan.id);
    resp[out++] = 0x84; resp[out++] = 0x00;            // response + authoritative
    resp[out++] = 0; resp[out++] = plan.legacy ? 1 : 0;
    resp[out++] = 0; resp[out++] = static_cast<uint8_t>(an);
    resp[out++] = 0; resp[out++] = 0;
    resp[out++] = 0; resp[out++] = 0;
    if (plan.legacy) {  // Legacy replies include the question.
        out = mdns_append_name(resp, out, name, name_len);
        resp[out++] = static_cast<uint8_t>(plan.firstQtype >> 8);
        resp[out++] = static_cast<uint8_t>(plan.firstQtype);
        resp[out++] = 0; resp[out++] = 1;
    }
    if (plan.wantA) {
        out = mdns_append_name(resp, out, name, name_len);
        resp[out++] = 0; resp[out++] = 1;  // A
        resp[out++] = static_cast<uint8_t>(rrclass >> 8);
        resp[out++] = static_cast<uint8_t>(rrclass);
        out = mdns_append_ttl(resp, out, ttl);
        resp[out++] = 0; resp[out++] = 4;
        memcpy(resp + out, ip, 4); out += 4;
    }
    if (plan.wantNsec) {
        out = mdns_append_name(resp, out, name, name_len);
        resp[out++] = 0; resp[out++] = 0x2F;  // NSEC
        resp[out++] = static_cast<uint8_t>(rrclass >> 8);
        resp[out++] = static_cast<uint8_t>(rrclass);
        out = mdns_append_ttl(resp, out, ttl);
        uint16_t rdlen = static_cast<uint16_t>(name_len + 1 + 3);  // Next domain plus three-byte bitmap.
        resp[out++] = static_cast<uint8_t>(rdlen >> 8);
        resp[out++] = static_cast<uint8_t>(rdlen);
        out = mdns_append_name(resp, out, name, name_len);  // Next domain is this host.
        resp[out++] = 0; resp[out++] = 1; resp[out++] = 0x40;  // Window 0, length 1, type 1 (A) only.
    }
    return out;
}

static void mdns_sms_task(void*)
{
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    if (sock < 0) {
        s_mdns_task_started.store(false, std::memory_order_relaxed);
        idf_log_line("Could not create mDNS socket");
        vTaskDelete(nullptr);
        return;
    }

    int yes = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));
    timeval timeout = {};
    timeout.tv_sec = 1;
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(5353);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) {
        idf_log_line("Could not bind mDNS to port 5353");
        close(sock);
        s_mdns_task_started.store(false, std::memory_order_relaxed);
        vTaskDelete(nullptr);
        return;
    }

    uint8_t ttl = 255;  // RFC 6762 requires multicast TTL=255.
    setsockopt(sock, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, sizeof(ttl));

    // Cache the configurable encoded hostname (issue #9) and compare it with configuration every second.
    char host[33] = {};
    uint8_t name[MDNS_NAME_CAP];
    size_t name_len = 0;
    idf_config_copy_mdns_host(host, sizeof(host));
    name_len = mdns_encode_name(host, name);

    auto sta_addr = []() -> uint32_t {
        esp_netif_ip_info_t ip = {};
        if (s_sta_netif && esp_netif_get_ip_info(s_sta_netif, &ip) == ESP_OK && ip.ip.addr != 0) {
            return ip.ip.addr;  // Network byte order.
        }
        return 0;
    };
    auto ap_addr = []() -> uint32_t {
        ApState ap;
        return ap_state_snapshot(ap, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)) && ap.mode
                   ? inet_addr("192.168.1.1")
                   : 0;
    };
    // Leave then rejoin for interface/IP changes and periodic IGMP reports; repeated ADD only increments references.
    auto refresh_membership = [&](uint32_t& tracked, uint32_t cur, bool force) -> bool {
        if (cur == tracked && !force) return false;
        bool changed = (cur != tracked);
        if (tracked != 0) {
            ip_mreq d = {};
            d.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
            d.imr_interface.s_addr = tracked;
            setsockopt(sock, IPPROTO_IP, IP_DROP_MEMBERSHIP, &d, sizeof(d));
            tracked = 0;
        }
        if (cur != 0) {
            ip_mreq a = {};
            a.imr_multiaddr.s_addr = inet_addr("224.0.0.251");
            a.imr_interface.s_addr = cur;
            if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &a, sizeof(a)) == 0) {
                tracked = cur;
                if (changed) {
                    idf_logf("mDNS joined multicast: http://%s.local", host);
                    return true;
                }
            }
        }
        return false;
    };

    uint32_t joined_sta = 0;
    uint32_t joined_ap = 0;
    int64_t last_refresh_us = esp_timer_get_time();
    int announce_left = 0;
    uint8_t req[512];
    uint8_t resp[256];

    while (true) {
        sockaddr_in from = {};
        socklen_t from_len = sizeof(from);
        int len = recvfrom(sock, req, sizeof(req), 0, reinterpret_cast<sockaddr*>(&from), &from_len);
        // Yield after immediate errors to avoid a high-priority busy loop during lwIP memory pressure.
        if (len < 0 && errno != EWOULDBLOCK && errno != EAGAIN) vTaskDelay(pdMS_TO_TICKS(200));

        // Hot-update within one second and immediately announce the new hostname.
        {
            char cur_host[33] = {};
            idf_config_copy_mdns_host(cur_host, sizeof(cur_host));
            if (strcmp(cur_host, host) != 0) {
                strcpy(host, cur_host);
                name_len = mdns_encode_name(host, name);
                announce_left = 2;
                idf_logf("mDNS hostname changed: http://%s.local", host);
            }
        }

        // The one-second timeout follows interface changes; force refresh every 60s against snooping expiry.
        int64_t now_us = esp_timer_get_time();
        bool force = (now_us - last_refresh_us) >= 60000000LL;
        if (force) last_refresh_us = now_us;
        bool newly_joined = refresh_membership(joined_sta, sta_addr(), force);
        newly_joined = refresh_membership(joined_ap, ap_addr(), force) || newly_joined;
        if (newly_joined) announce_left = 2;
        if (announce_left > 0) {
            // Announcements are naturally at least one second apart.
            uint8_t ip[4] = {};
            if (mdns_pick_ip(0, ip)) {
                MdnsAnswerPlan ann;
                ann.wantA = true;
                int n = mdns_build_response(resp, ann, ip, name, name_len);
                sockaddr_in dst = {};
                dst.sin_family = AF_INET;
                dst.sin_port = htons(5353);
                dst.sin_addr.s_addr = inet_addr("224.0.0.251");
                sendto(sock, resp, n, 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
            }
            --announce_left;
        }

        if (len < 12) continue;
        if (req[2] & 0xF8) continue;  // Ignore responses (QR=1) and nonstandard opcodes.

        uint16_t qd = (static_cast<uint16_t>(req[4]) << 8) | req[5];
        int pos = 12;
        MdnsAnswerPlan plan;
        plan.legacy = (from.sin_port != htons(5353));
        if (plan.legacy) plan.id = (static_cast<uint16_t>(req[0]) << 8) | req[1];
        for (uint16_t q = 0; q < qd && pos < len; ++q) {
            bool matched = mdns_query_matches_host(req, len, pos, name, name_len);
            // A compression pointer beginning with 0xC0 is a two-byte terminator, not a length prefix.
            while (pos < len) {
                uint8_t b = req[pos];
                if (b == 0) { pos += 1; break; }
                if (b >= 0xC0) { pos += 2; break; }
                pos += b + 1;
            }
            if (pos + 4 > len) break;
            uint16_t qtype = (static_cast<uint16_t>(req[pos]) << 8) | req[pos + 1];
            uint16_t qclass = (static_cast<uint16_t>(req[pos + 2]) << 8) | req[pos + 3];
            pos += 4;
            if (!matched) continue;
            if (qtype == 1 || qtype == 255) plan.wantA = true;
            else if (qtype == 28) plan.wantNsec = true;
            else continue;
            if (plan.firstQtype == 0) plan.firstQtype = qtype;
            if (qclass & 0x8000) plan.unicast = true;  // QU requests unicast.
        }
        if (!plan.wantA && !plan.wantNsec) continue;
        if (plan.legacy) plan.unicast = true;

        uint8_t ip[4] = {};
        if (!mdns_pick_ip(from.sin_addr.s_addr, ip)) continue;
        int n = mdns_build_response(resp, plan, ip, name, name_len);
        sockaddr_in dst = {};
        if (plan.unicast) {
            dst = from;
        } else {
            dst.sin_family = AF_INET;
            dst.sin_port = htons(5353);
            dst.sin_addr.s_addr = inet_addr("224.0.0.251");
        }
        sendto(sock, resp, n, 0, reinterpret_cast<sockaddr*>(&dst), sizeof(dst));
    }
}

static void start_mdns_task_once()
{
    bool expected = false;
    if (!s_mdns_task_started.compare_exchange_strong(expected, true, std::memory_order_relaxed)) return;
    // 3456 covers the 256-byte response required by configurable hostnames plus hostname cache.
    BaseType_t ok = xTaskCreate(mdns_sms_task, "idf_mdns", 3456, nullptr, 2, nullptr);
    if (ok != pdPASS) {
        s_mdns_task_started.store(false, std::memory_order_relaxed);
        idf_log_line("mDNS responder failed to start");
    }
}

static esp_err_t configure_ap_netif(void)
{
    esp_netif_ip_info_t ip_info = {};
    esp_netif_set_ip4_addr(&ip_info.ip, 192, 168, 1, 1);
    esp_netif_set_ip4_addr(&ip_info.gw, 192, 168, 1, 1);
    esp_netif_set_ip4_addr(&ip_info.netmask, 255, 255, 255, 0);

    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_stop(s_ap_netif));
    esp_err_t err = esp_netif_set_ip_info(s_ap_netif, &ip_info);
    if (err != ESP_OK) return err;

    const char* captive_uri = "http://192.168.1.1/";
    ESP_ERROR_CHECK_WITHOUT_ABORT(esp_netif_dhcps_option(
        s_ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_CAPTIVEPORTAL_URI,
        const_cast<char*>(captive_uri), strlen(captive_uri)));
    err = esp_netif_dhcps_start(s_ap_netif);
    return err == ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED ? ESP_OK : err;
}

static esp_err_t start_provisioning_ap_locked(bool manual, TickType_t state_timeout)
{
    ApState ap;
    if (!ap_state_snapshot(ap, state_timeout)) return ESP_ERR_TIMEOUT;
    if (ap.mode) {
        if (manual && !ap.manual) {
            set_ap_state(true, true, ap.ssid);
            idf_log_line("BOOT long press: keeping current AP and switching to manual provisioning mode");
        }
        start_dns_task_once();
        idf_logf("Provisioning AP started; visit http://192.168.1.1/");
        return ESP_OK;
    }

    uint8_t mac[6] = {};
    esp_err_t err = esp_read_mac(mac, ESP_MAC_WIFI_SOFTAP);
    if (err != ESP_OK) {
        idf_logf("Provisioning AP failed: could not read MAC: %s", esp_err_to_name(err));
        return err;
    }
    char ssid[33];
    snprintf(ssid, sizeof(ssid), "%s%02X%02X%02X", AP_SSID_PREFIX, mac[3], mac[4], mac[5]);
    err = configure_ap_netif();
    if (err != ESP_OK) {
        idf_logf("Provisioning AP failed: could not configure AP IP: %s", esp_err_to_name(err));
        return err;
    }

    wifi_config_t ap_config = {};
    strlcpy(reinterpret_cast<char*>(ap_config.ap.ssid), ssid, sizeof(ap_config.ap.ssid));
    strlcpy(reinterpret_cast<char*>(ap_config.ap.password), AP_PASSWORD, sizeof(ap_config.ap.password));
    ap_config.ap.ssid_len = strlen(ssid);
    ap_config.ap.channel = 1;
    ap_config.ap.max_connection = 4;
    ap_config.ap.authmode = WIFI_AUTH_WPA2_PSK;
    ap_config.ap.pmf_cfg.capable = true;
    ap_config.ap.pmf_cfg.required = false;

    err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (err != ESP_OK) {
        idf_logf("Provisioning AP failed: could not set APSTA mode: %s", esp_err_to_name(err));
        return err;
    }
    err = esp_wifi_set_config(WIFI_IF_AP, &ap_config);
    if (err != ESP_OK) {
        idf_logf("Provisioning AP failed: could not set AP parameters: %s", esp_err_to_name(err));
        return err;
    }
    if (sta_can_connect()) ESP_ERROR_CHECK_WITHOUT_ABORT(wifi_connect_locked());
    set_ap_state(true, manual, ssid);
    start_dns_task_once();
    ESP_LOGW(TAG, "%s: %s, http://192.168.1.1/",
             manual ? "BOOT long press started provisioning AP" : "Provisioning AP started", ssid);
    idf_logf("%s: %s, http://192.168.1.1/",
             manual ? "BOOT long press started provisioning AP" : "Provisioning AP started", ssid);
    return ESP_OK;
}

static esp_err_t start_provisioning_ap(bool manual)
{
    const TickType_t driver_timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
    WifiDriverOperation operation(driver_timeout);
    if (!operation) return ESP_ERR_TIMEOUT;
    return start_provisioning_ap_locked(manual, driver_timeout);
}

static void provision_button_task(void*)
{
    gpio_config_t io = {};
    io.pin_bit_mask = 1ULL << PROVISION_BUTTON_PIN;
    io.mode = GPIO_MODE_INPUT;
    io.pull_up_en = GPIO_PULLUP_ENABLE;
    io.pull_down_en = GPIO_PULLDOWN_DISABLE;
    io.intr_type = GPIO_INTR_DISABLE;
    gpio_config(&io);

    int64_t down_since = 0;
    bool triggered = false;
    while (true) {
        bool pressed = gpio_get_level(PROVISION_BUTTON_PIN) == 0;
        int64_t now_ms = esp_timer_get_time() / 1000LL;
        if (!pressed) {
            down_since = 0;
            triggered = false;
        } else {
            if (down_since == 0) down_since = now_ms;
            if (!triggered && now_ms - down_since >= PROVISION_BUTTON_HOLD_MS) {
                triggered = true;
                start_provisioning_ap(true);
            }
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }
}

static bool wifi_profile_password_valid(const std::string& pass)
{
    if (pass.empty()) return true;
    if (pass.size() < 8 || pass.size() > 63) return false;
    return std::all_of(pass.begin(), pass.end(), [](unsigned char ch) {
        return ch >= 0x20 && ch <= 0x7E;
    });
}

// Apply credentials and start STA without waiting. Open networks bind the scanned open BSSID; the driver
// rejects same-name open APs for secured networks to prevent evil-twin downgrade.
static esp_err_t wifi_apply_and_connect_locked(const std::string& ssid, const std::string& pass,
                                               const wifi_ap_record_t* ap,
                                               TickType_t state_timeout)
{
    if (ssid.empty() || ssid.size() > MAX_WIFI_SSID_BYTES || !wifi_profile_password_valid(pass)) {
        return ESP_ERR_INVALID_ARG;
    }
    if (pass.empty() && !ap) return ESP_ERR_NOT_FOUND;
    if (ap && !idf_wifi_profile_matches_auth(pass.empty(), ap->authmode)) return ESP_ERR_INVALID_ARG;

    wifi_config_t sta_config = {};
    strlcpy(reinterpret_cast<char*>(sta_config.sta.ssid), ssid.c_str(), sizeof(sta_config.sta.ssid));
    strlcpy(reinterpret_cast<char*>(sta_config.sta.password), pass.c_str(), sizeof(sta_config.sta.password));
    sta_config.sta.scan_method = WIFI_FAST_SCAN;
    sta_config.sta.sort_method = WIFI_CONNECT_AP_BY_SIGNAL;
    sta_config.sta.threshold.authmode = pass.empty() ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK;
    if (ap) {
        sta_config.sta.bssid_set = true;
        memcpy(sta_config.sta.bssid, ap->bssid, sizeof(sta_config.sta.bssid));
        sta_config.sta.channel = ap->primary;
    }

    ApState ap_state;
    if (!ap_state_snapshot(ap_state, state_timeout)) return ESP_ERR_TIMEOUT;
    esp_err_t err = esp_wifi_set_mode(ap_state.mode ? WIFI_MODE_APSTA : WIFI_MODE_STA);
    if (err != ESP_OK) return err;
    err = esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    if (err != ESP_OK) return err;
    s_current_profile_open.store(pass.empty(), std::memory_order_relaxed);
    s_sta_configured.store(true, std::memory_order_relaxed);
    return wifi_connect_locked();
}

static esp_err_t wifi_apply_and_connect(const std::string& ssid, const std::string& pass,
                                        const wifi_ap_record_t* ap = nullptr)
{
    const TickType_t driver_timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
    WifiDriverOperation operation(driver_timeout);
    if (!operation) return ESP_ERR_TIMEOUT;
    return wifi_apply_and_connect_locked(
        ssid, pass, ap, driver_timeout);
}

static esp_err_t wifi_apply_and_connect_if_current(const std::string& ssid, const std::string& pass,
                                                   const wifi_ap_record_t* ap,
                                                   uint32_t captured_generation)
{
    const TickType_t driver_timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
    WifiDriverOperation operation(driver_timeout);
    if (!operation) return ESP_ERR_TIMEOUT;
    if (!idf_wifi_selector_can_apply(
            captured_generation, s_provisioning_generation.load(std::memory_order_acquire),
            s_provisioning.load(std::memory_order_acquire))) {
        return ESP_ERR_INVALID_STATE;
    }
    return wifi_apply_and_connect_locked(
        ssid, pass, ap, driver_timeout);
}

static esp_err_t wifi_disconnect_driver_locked()
{
    if (s_wifi_event_group) {
        xEventGroupClearBits(s_wifi_event_group, WIFI_CONNECTED_BIT | WIFI_DISCONNECTED_BIT);
    }
    esp_err_t err = esp_wifi_disconnect();
    if (err != ESP_OK) {
        // Offline state has no event to await; if connected state still fails, preserve old configuration for caller recovery.
        return s_sta_connected.load(std::memory_order_relaxed) ? err : ESP_OK;
    }
    if (!s_wifi_event_group) return ESP_ERR_INVALID_STATE;
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group, WIFI_DISCONNECTED_BIT, pdTRUE, pdFALSE, pdMS_TO_TICKS(1500));
    return (bits & WIFI_DISCONNECTED_BIT) ? ESP_OK : ESP_ERR_TIMEOUT;
}

static esp_err_t wifi_disconnect_quietly()
{
    const TickType_t driver_timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
    WifiDriverOperation operation(driver_timeout);
    if (!operation) return ESP_ERR_TIMEOUT;
    if (!reset_recovery_state(
            true, true, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))) {
        ESP_LOGW(TAG, "WiFi recovery AP transition did not settle; skipping concurrent disconnect");
        return ESP_ERR_TIMEOUT;
    }
    s_sta_configured.store(false, std::memory_order_relaxed);
    return wifi_disconnect_driver_locked();
}

static esp_err_t wifi_scan_candidates(
    const std::vector<IdfWifiNetwork>& nets,
    std::vector<IdfWifiCandidate>& candidates,
    std::array<wifi_ap_record_t, IDF_MAX_WIFI_NETWORKS>& best_by_profile)
{
    std::array<bool, IDF_MAX_WIFI_NETWORKS> matched = {};
    WifiScanLease lease;
    if (!lease) return ESP_ERR_INVALID_STATE;
    {
        WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS), true);
        if (!operation) return ESP_ERR_TIMEOUT;
        wifi_scan_config_t scan_cfg = {};
        esp_err_t err = esp_wifi_scan_start(&scan_cfg, true);
        if (err != ESP_OK) return public_scan_error(err);

        uint16_t total = 0;
        err = esp_wifi_scan_get_ap_num(&total);
        if (err != ESP_OK) {
            esp_wifi_clear_ap_list();
            return err;
        }
        wifi_ap_record_t rec = {};
        for (uint16_t r = 0; r < total; ++r) {
            err = esp_wifi_scan_get_ap_record(&rec);
            if (err != ESP_OK) {
                esp_wifi_clear_ap_list();
                return err;
            }
            const char* seen = reinterpret_cast<const char*>(rec.ssid);
            for (size_t i = 0; i < nets.size(); ++i) {
                if (nets[i].ssid == seen && wifi_profile_password_valid(nets[i].pass) &&
                    idf_wifi_profile_matches_auth(nets[i].pass.empty(), rec.authmode) &&
                    (!matched[i] || rec.rssi > best_by_profile[i].rssi)) {
                    matched[i] = true;
                    best_by_profile[i] = rec;
                }
            }
        }
        esp_wifi_clear_ap_list();
    }
    lease.release();

    candidates.clear();
    candidates.reserve(nets.size());
    for (size_t i = 0; i < nets.size(); ++i) {
        if (matched[i]) {
            candidates.push_back({i, best_by_profile[i].rssi, true});
        } else if (!nets[i].pass.empty() && wifi_profile_password_valid(nets[i].pass)) {
            // Hidden secured networks can use the WPA2+ threshold; open networks require a scanned and bound BSSID.
            candidates.push_back({i, -128, false});
        }
    }
    idf_wifi_order_candidates(candidates);
    return ESP_OK;
}

// Scan saved WiFi networks instead of blind fixed-order attempts (issue #9). Pick the strongest present match;
// if none are visible, rotate through hidden or absent networks without serial 20s scan waits.
static void wifi_select_task(void*)
{
    do {
        uint32_t generation = s_provisioning_generation.load(std::memory_order_acquire);
        if (!idf_wifi_selector_can_apply(
                generation, s_provisioning_generation.load(std::memory_order_acquire),
                s_provisioning.load(std::memory_order_acquire))) {
            break;
        }
        std::vector<IdfWifiNetwork> nets = idf_config_get_wifi_networks();
        if (nets.empty()) break;
        std::vector<IdfWifiCandidate> candidates;
        std::array<wifi_ap_record_t, IDF_MAX_WIFI_NETWORKS> best_by_profile = {};
        esp_err_t scan_err = wifi_scan_candidates(nets, candidates, best_by_profile);
        if (scan_err != ESP_OK) {
            ESP_LOGW(TAG, "Network-selection scan failed: %s", esp_err_to_name(scan_err));
            break;
        }
        if (candidates.empty()) {
            idf_log_line("No saved WiFi with matching security found; skipping connection");
            break;
        }
        uint32_t attempt = s_candidate_attempt.fetch_add(1, std::memory_order_relaxed);
        const IdfWifiCandidate& candidate =
            candidates[idf_wifi_candidate_position(candidates.size(), attempt)];
        const IdfWifiNetwork& net = nets[candidate.profileIndex];
        if (candidate.scanned) {
            idf_logf("Saved WiFi found: %s (RSSI %d); connecting", net.ssid.c_str(), candidate.rssi);
        } else {
            idf_logf("Secured WiFi not visible; trying as hidden network: %s", net.ssid.c_str());
        }
        if (!idf_wifi_selector_can_apply(
                generation, s_provisioning_generation.load(std::memory_order_acquire),
                s_provisioning.load(std::memory_order_acquire))) {
            break;
        }
        esp_err_t err = wifi_apply_and_connect_if_current(
            net.ssid, net.pass,
            candidate.scanned ? &best_by_profile[candidate.profileIndex] : nullptr,
            generation);
        if (err != ESP_OK && err != ESP_ERR_WIFI_CONN) {
            ESP_LOGW(TAG, "Connection failed to start after network selection: %s", esp_err_to_name(err));
        }
    } while (false);
    s_select_running.store(false, std::memory_order_relaxed);
    vTaskDelete(nullptr);
}

static void start_wifi_select_once(void)
{
    bool expected = false;
    if (s_recovery_mutex && xSemaphoreTake(
            s_recovery_mutex, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)) == pdTRUE) {
        if (s_recovery_ap_inflight ||
            !s_select_running.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
            xSemaphoreGive(s_recovery_mutex);
            return;
        }
        xSemaphoreGive(s_recovery_mutex);
    } else if (!s_select_running.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
        return;
    }
    // 4096: scan records are on the heap, but esp_wifi scan APIs and log formatting still need stack headroom.
    if (xTaskCreate(wifi_select_task, "idf_wifi_sel", 4096, nullptr, 2, nullptr) != pdPASS) {
        s_select_running.store(false, std::memory_order_relaxed);
        idf_log_line("WiFi selection task failed to start; connecting with current configuration");
        if (sta_can_connect()) wifi_connect_now();
    }
}

// Start STA without waiting; sta_connect_watch_task decides the result so startup continues in parallel.
// Connect one secured network directly for hidden-SSID support; scan for multiple or open networks.
static esp_err_t connect_sta_begin(const IdfConfig& config)
{
    int count = 0;
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        if (!config.wifiNetworks[i].ssid.empty()) ++count;
    }
    if (count > 1 || config.wifiNetworks[0].pass.empty()) {
        idf_logf("%d WiFi networks saved; scanning for the strongest available", count);
        start_wifi_select_once();
        return ESP_OK;
    }
    const IdfWifiNetwork& net = config.wifiNetworks[0];
    esp_err_t err = wifi_apply_and_connect(net.ssid, net.pass);
    if (err != ESP_OK) return err;
    ESP_LOGI(TAG, "Connecting WiFi: %s%s", net.ssid.c_str(), config.wifiFromFallback ? " (fallback)" : "");
    idf_logf("Connecting WiFi: %s%s", net.ssid.c_str(), config.wifiFromFallback ? " (fallback)" : "");
    return ESP_OK;
}

// Wait for first connection: success clears AP state; a 20s timeout falls back to provisioning AP.
static void sta_wait_first_connect(void)
{
    EventBits_t bits = xEventGroupWaitBits(
        s_wifi_event_group, WIFI_CONNECTED_BIT, pdFALSE, pdFALSE,
        pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS));
    if (bits & WIFI_CONNECTED_BIT) {
        set_ap_state(false, false, std::string());
    } else {
        ESP_LOGW(TAG, "Initial WiFi connection timed out; entering APSTA provisioning mode");
        idf_log_line("Initial WiFi connection timed out; entering APSTA provisioning mode");
        ESP_ERROR_CHECK_WITHOUT_ABORT(start_provisioning_ap(false));
    }
}

static void sta_connect_watch_task(void*)
{
    sta_wait_first_connect();
    vTaskDelete(nullptr);
}

esp_err_t idf_wifi_start(const IdfConfig& config)
{
    if (s_started.load(std::memory_order_relaxed)) return ESP_OK;

    s_state_mutex = xSemaphoreCreateMutex();
    if (!s_state_mutex) return ESP_ERR_NO_MEM;
    s_recovery_mutex = xSemaphoreCreateMutex();
    if (!s_recovery_mutex) {
        cleanup_wifi_start_resources(false, false, false);
        return ESP_ERR_NO_MEM;
    }
    s_wifi_driver_mutex = xSemaphoreCreateMutex();
    if (!s_wifi_driver_mutex) {
        cleanup_wifi_start_resources(false, false, false);
        return ESP_ERR_NO_MEM;
    }

    s_wifi_event_group = xEventGroupCreate();
    if (!s_wifi_event_group) {
        cleanup_wifi_start_resources(false, false, false);
        return ESP_ERR_NO_MEM;
    }
    s_has_sta_credentials.store(!config.wifiNetworks[0].ssid.empty(), std::memory_order_relaxed);

    s_sta_netif = esp_netif_create_default_wifi_sta();
    s_ap_netif = esp_netif_create_default_wifi_ap();
    if (!s_sta_netif || !s_ap_netif) {
        cleanup_wifi_start_resources(false, false, false);
        return ESP_ERR_NO_MEM;
    }

    // Configuration validates hostname; only legacy callers can pass empty, so retain the sms fallback.
    const std::string hostname = config.hostname.empty() ? std::string("sms") : config.hostname;
    esp_err_t hostname_err = esp_netif_set_hostname(s_sta_netif, hostname.c_str());
    if (hostname_err != ESP_OK) idf_logf("Failed to set DHCP hostname: %s", esp_err_to_name(hostname_err));

    wifi_init_config_t init_cfg = WIFI_INIT_CONFIG_DEFAULT();
    bool wifi_inited = false;
    bool wifi_event_registered = false;
    bool ip_event_registered = false;
    esp_err_t err = esp_wifi_init(&init_cfg);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_init failed: %s", esp_err_to_name(err));
        idf_logf("WiFi initialization failed: %s", esp_err_to_name(err));
        cleanup_wifi_start_resources(false, false, false);
        return err;
    }
    wifi_inited = true;
    err = esp_wifi_set_storage(WIFI_STORAGE_RAM);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_set_storage failed: %s", esp_err_to_name(err));
        idf_logf("WiFi storage-mode configuration failed: %s", esp_err_to_name(err));
        cleanup_wifi_start_resources(wifi_inited, wifi_event_registered, ip_event_registered);
        return err;
    }
    err = esp_wifi_set_ps(WIFI_PS_NONE);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_set_ps failed: %s", esp_err_to_name(err));
        idf_logf("WiFi power-save configuration failed: %s", esp_err_to_name(err));
        cleanup_wifi_start_resources(wifi_inited, wifi_event_registered, ip_event_registered);
        return err;
    }
    err = esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, nullptr);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "WIFI_EVENT handler register failed: %s", esp_err_to_name(err));
        idf_logf("WiFi event-handler registration failed: %s", esp_err_to_name(err));
        cleanup_wifi_start_resources(wifi_inited, false, false);
        return err;
    }
    wifi_event_registered = true;
    err = esp_event_handler_register(IP_EVENT, IP_EVENT_STA_GOT_IP, &wifi_event_handler, nullptr);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "IP_EVENT handler register failed: %s", esp_err_to_name(err));
        idf_logf("IP event-handler registration failed: %s", esp_err_to_name(err));
        cleanup_wifi_start_resources(wifi_inited, wifi_event_registered, false);
        return err;
    }
    ip_event_registered = true;
    err = esp_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "esp_wifi_start failed: %s", esp_err_to_name(err));
        idf_logf("WiFi startup failed: %s", esp_err_to_name(err));
        cleanup_wifi_start_resources(wifi_inited, wifi_event_registered, ip_event_registered);
        return err;
    }
    s_started.store(true, std::memory_order_relaxed);
    // The SuperMini antenna is most stable at 8.5dBm; better RF hardware can select a higher Web setting.
    err = idf_wifi_set_tx_power(config.wifiTxPowerQuarterDbm);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_set_max_tx_power failed: %s", esp_err_to_name(err));
        idf_logf("Failed to set WiFi transmit power: %s", esp_err_to_name(err));
    }
    start_mdns_task_once();
    // 3072 covers wifi_config_t (~132B) plus log formatting in start_provisioning_ap.
    {
        bool expected = false;
        if (s_button_task_started.compare_exchange_strong(expected, true, std::memory_order_relaxed)) {
            BaseType_t ok = xTaskCreate(provision_button_task, "idf_boot_ap", 3072, nullptr, 2, nullptr);
            if (ok != pdPASS) {
                s_button_task_started.store(false, std::memory_order_relaxed);
                idf_log_line("BOOT provisioning-button task failed to start");
            }
        }
    }

    if (!s_reconnect_timer) {
        const esp_timer_create_args_t targs = {
            .callback = &reconnect_watchdog_cb,
            .arg = nullptr,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "wifi_watchdog",
            .skip_unhandled_events = true,
        };
        if (esp_timer_create(&targs, &s_reconnect_timer) == ESP_OK) {
            if (esp_timer_start_periodic(s_reconnect_timer, 15ULL * 1000 * 1000) != ESP_OK) {
                esp_timer_delete(s_reconnect_timer);
                s_reconnect_timer = nullptr;
                idf_log_line("Could not start WiFi reconnect watchdog");
            }
        } else {
            idf_log_line("Could not create WiFi reconnect watchdog");
        }
    }

    if (!s_scan_cleanup_timer) {
        const esp_timer_create_args_t targs = {
            .callback = &scan_cleanup_timer_cb,
            .arg = nullptr,
            .dispatch_method = ESP_TIMER_TASK,
            .name = "wifi_scan_cleanup",
            .skip_unhandled_events = true,
        };
        if (esp_timer_create(&targs, &s_scan_cleanup_timer) != ESP_OK) {
            idf_log_line("Could not create WiFi scan cleanup timer");
        }
    }

    if (config.wifiNetworks[0].ssid.empty()) {
        ESP_LOGW(TAG, "WiFi is not configured; entering provisioning AP");
        idf_log_line("WiFi is not configured; entering provisioning AP");
        return start_provisioning_ap(false);
    }

    err = connect_sta_begin(config);
    if (err != ESP_OK) {
        // On immediate set_mode/set_config/connect failure, log the real error and fall back to provisioning.
        ESP_LOGW(TAG, "WiFi connection failed to start (%s); entering APSTA provisioning mode", esp_err_to_name(err));
        idf_logf("WiFi connection failed to start (%s); entering APSTA provisioning mode", esp_err_to_name(err));
        ESP_ERROR_CHECK_WITHOUT_ABORT(start_provisioning_ap(false));
        return ESP_OK;
    }
    // 3072 covers wifi_config_t plus log formatting in start_provisioning_ap.
    if (xTaskCreate(sta_connect_watch_task, "idf_sta_watch", 3072, nullptr, 2, nullptr) != pdPASS) {
        sta_wait_first_connect();  // Fall back to synchronous wait so provisioning fallback is preserved.
    }
    return ESP_OK;
}

esp_err_t idf_wifi_resync_ntp(void)
{
    if (!s_started.load(std::memory_order_relaxed)) return ESP_ERR_INVALID_STATE;
    if (!s_sta_connected.load(std::memory_order_relaxed)) return ESP_ERR_INVALID_STATE;  // Cannot sync while offline.
    s_ntp_manual_us.store(esp_timer_get_time(), std::memory_order_relaxed);  // Log manual-sync results.
    if (!s_sntp_started.load(std::memory_order_relaxed)) {
        start_sntp_once();  // Start SNTP and issue the first request immediately.
        idf_logf("Web UI requested NTP sync; SNTP started");
    } else {
        esp_sntp_restart();  // Force immediate resynchronization.
        idf_logf("Web UI requested immediate NTP sync");
    }
    return ESP_OK;
}

esp_err_t idf_wifi_reconnect(void)
{
    if (!s_started.load(std::memory_order_relaxed)) return ESP_ERR_INVALID_STATE;
    if (!sta_can_connect()) return ESP_ERR_INVALID_STATE;
    esp_err_t err = wifi_disconnect_quietly();
    if (err != ESP_OK) {
        s_sta_configured.store(false, std::memory_order_relaxed);
        return err;
    }
    s_sta_configured.store(true, std::memory_order_relaxed);
    s_disconnect_streak.store(0, std::memory_order_relaxed);
    if (s_current_profile_open.load(std::memory_order_relaxed)) {
        start_wifi_select_once();
        return ESP_OK;
    }
    return wifi_connect_now();
}

esp_err_t idf_wifi_set_tx_power(uint8_t quarter_dbm)
{
    if (!s_started.load(std::memory_order_relaxed)) return ESP_ERR_INVALID_STATE;
    if (quarter_dbm < 8 || quarter_dbm > 84) return ESP_ERR_INVALID_ARG;
    WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS));
    if (!operation) return ESP_ERR_TIMEOUT;
    return esp_wifi_set_max_tx_power(static_cast<int8_t>(quarter_dbm));
}

esp_err_t idf_wifi_provision_connect(const std::string& ssid, const std::string& pass)
{
    if (!s_started.load(std::memory_order_relaxed)) return ESP_ERR_INVALID_STATE;
    if (ssid.empty() || ssid.size() > MAX_WIFI_SSID_BYTES || !wifi_profile_password_valid(pass)) {
        return ESP_ERR_INVALID_ARG;
    }
    wifi_ap_record_t ap = {};
    const wifi_ap_record_t* selected = nullptr;
    if (pass.empty()) {
        std::vector<wifi_ap_record_t> cached_records;
        bool cache_ready = false;
        const TickType_t state_timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
        if (!s_state_mutex || xSemaphoreTake(s_state_mutex, state_timeout) != pdTRUE) {
            return ESP_ERR_TIMEOUT;
        }
        cached_records.assign(s_scan_cache_records.begin(),
                              s_scan_cache_records.begin() + s_scan_cache_count);
        cache_ready = s_scan_cache_ready;
        xSemaphoreGive(s_state_mutex);
        std::vector<IdfWifiScannedAp> scanned;
        scanned.reserve(cached_records.size());
        for (const wifi_ap_record_t& record : cached_records) {
            IdfWifiScannedAp item;
            item.ssid = reinterpret_cast<const char*>(record.ssid);
            item.rssi = record.rssi;
            item.authmode = record.authmode;
            memcpy(item.bssid.data(), record.bssid, item.bssid.size());
            scanned.push_back(std::move(item));
        }
        std::array<uint8_t, 6> selected_bssid = {};
        if (!cache_ready || !idf_wifi_find_cached_open_ap(scanned, ssid, selected_bssid)) {
            return cache_ready ? ESP_ERR_NOT_FOUND : ESP_ERR_INVALID_STATE;
        }
        const auto record = std::find_if(cached_records.begin(), cached_records.end(),
                                         [&](const wifi_ap_record_t& candidate) {
                                             return memcmp(candidate.bssid, selected_bssid.data(),
                                                           selected_bssid.size()) == 0;
                                         });
        if (record != cached_records.end()) {
            ap = *record;
            selected = &ap;
        }
        if (!selected) return ESP_ERR_NOT_FOUND;
    }

    const TickType_t driver_timeout = pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS);
    WifiDriverOperation operation(driver_timeout);
    if (!operation) return ESP_ERR_TIMEOUT;

    bool previous_has_credentials = s_has_sta_credentials.load(std::memory_order_relaxed);
    bool previous_configured = s_sta_configured.load(std::memory_order_relaxed);
    bool previous_open = s_current_profile_open.load(std::memory_order_relaxed);
    ProvisioningTarget previous_target;
    if (!provisioning_target_snapshot(previous_target, driver_timeout)) {
        return ESP_ERR_TIMEOUT;
    }
    wifi_config_t previous_config = {};
    bool previous_config_valid =
        esp_wifi_get_config(WIFI_IF_STA, &previous_config) == ESP_OK && previous_config.sta.ssid[0];
    esp_err_t err = ESP_OK;

    if (!reset_recovery_state(true, true, driver_timeout)) {
        return ESP_ERR_TIMEOUT;
    }
    // Invalidate the old provisioning generation before disconnecting so a queued old GOT_IP cannot close the current AP.
    s_sta_configured.store(false, std::memory_order_relaxed);
    if (replace_provisioning_target(ProvisioningTarget(), driver_timeout) == 0) {
        return ESP_ERR_TIMEOUT;
    }

    auto restore_previous = [&]() {
        if (previous_config_valid) esp_wifi_set_config(WIFI_IF_STA, &previous_config);
        s_has_sta_credentials.store(previous_has_credentials, std::memory_order_relaxed);
        s_sta_configured.store(previous_configured, std::memory_order_relaxed);
        s_current_profile_open.store(previous_open, std::memory_order_relaxed);
        replace_provisioning_target(previous_target, driver_timeout);
        if (previous_has_credentials && previous_configured) wifi_connect_locked();
    };

    err = wifi_disconnect_driver_locked();
    if (err != ESP_OK) {
        restore_previous();
        return err;
    }
    // Keep APSTA so the page remains connected; the IP event schedules delayed AP shutdown.
    err = esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (err != ESP_OK) {
        restore_previous();
        return err;
    }

    ProvisioningTarget target;
    target.active = true;
    target.ssid = ssid;
    uint32_t generation = replace_provisioning_target(target, driver_timeout);
    if (generation == 0) {
        restore_previous();
        return ESP_ERR_TIMEOUT;
    }

    if (pass.empty()) {
        if (!bind_provisioning_bssid(generation, ap.bssid, driver_timeout)) {
            restore_previous();
            return ESP_ERR_INVALID_STATE;
        }
        selected = &ap;  // Open networks require a scanned and bound BSSID.
    }

    s_has_sta_credentials.store(true, std::memory_order_relaxed);
    s_disconnect_streak.store(0, std::memory_order_relaxed);
    s_candidate_attempt.store(0, std::memory_order_relaxed);
    err = wifi_apply_and_connect_locked(ssid, pass, selected, driver_timeout);
    if (err != ESP_OK) {
        restore_previous();
        return err;
    }
    ESP_LOGI(TAG, "Provisioning: saving and connecting %s", ssid.c_str());
    idf_logf("Saved WiFi in provisioning AP and connecting: %s", ssid.c_str());
    return err;
}

esp_err_t idf_wifi_provision_connect(const char* ssid, size_t ssid_length,
                                     const char* pass, size_t pass_length) try
{
    if (!ssid || !pass || ssid_length == 0 || ssid_length > MAX_WIFI_SSID_BYTES ||
        (pass_length != 0 && (pass_length < 8 || pass_length > MAX_WIFI_PASSWORD_BYTES))) {
        return ESP_ERR_INVALID_ARG;
    }
    return idf_wifi_provision_connect(std::string(ssid, ssid_length), std::string(pass, pass_length));
}
catch (const std::bad_alloc&) { return ESP_ERR_NO_MEM; }

static std::string wifi_scan_records_json(const wifi_ap_record_t* records, size_t count)
{
    std::string json;
    json.reserve(1024);
    json += "[";
    bool first = true;
    for (size_t i = 0; i < count; ++i) {
        const char* ssid = reinterpret_cast<const char*>(records[i].ssid);
        if (!ssid[0]) continue;
        bool duplicate = false;
        for (size_t k = 0; k < count; ++k) {
            if (k == i) continue;
            const char* other = reinterpret_cast<const char*>(records[k].ssid);
            if (strcmp(ssid, other) != 0) continue;
            if (records[k].rssi > records[i].rssi ||
                (k < i && records[k].rssi == records[i].rssi)) {
                duplicate = true;
                break;
            }
        }
        if (duplicate) continue;
        if (!first) json += ",";
        first = false;
        json += "{\"ssid\":\"";
        idf_util_json_escape_append(json, ssid);
        char tail[96];
        snprintf(tail, sizeof(tail), "\",\"rssi\":%d,\"enc\":%d}",
                 records[i].rssi,
                 records[i].authmode == WIFI_AUTH_OPEN ? 0 : 1);
        json += tail;
    }
    json += "]";
    return json;
}

static void wifi_scan_collect_task(void*)
{
    wifi_scan_collect_once();
    vTaskDelete(nullptr);
}

esp_err_t idf_wifi_scan_request(void)
{
    if (!s_started.load(std::memory_order_relaxed)) return ESP_ERR_INVALID_STATE;
    if (s_scan_refresh_pending.load(std::memory_order_acquire)) return ESP_OK;

    // Async scans need both the cleanup timer and watchdog fallback before claiming global scan ownership.
    if (!s_scan_cleanup_timer || !s_reconnect_timer) return ESP_ERR_NO_MEM;
    WifiScanLease lease;
    if (!lease) return ESP_ERR_INVALID_STATE;
    WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS), true);
    if (!operation) return ESP_ERR_TIMEOUT;
    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_err_t err = esp_wifi_get_mode(&mode);
    if (err != ESP_OK) return err;
    if (mode == WIFI_MODE_AP) {
        err = esp_wifi_set_mode(WIFI_MODE_APSTA);
        if (err != ESP_OK) return err;
    }

    s_scan_refresh_pending.store(true, std::memory_order_release);
    wifi_scan_config_t scan_cfg = {};
    err = esp_wifi_scan_start(&scan_cfg, false);
    if (err != ESP_OK) {
        s_scan_refresh_pending.store(false, std::memory_order_release);
        if (s_state_mutex && xSemaphoreTake(
                s_state_mutex, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)) == pdTRUE) {
            s_scan_cache_error = public_scan_error(err);
            xSemaphoreGive(s_state_mutex);
        }
        return public_scan_error(err);
    }
    lease.detach();  // SCAN_DONE collector releases scan/connection ownership held across tasks.
    return ESP_OK;
}

IdfWifiScanSnapshot idf_wifi_scan_get_snapshot(void)
{
    IdfWifiScanSnapshot snapshot;
    snapshot.busy = s_scan_refresh_pending.load(std::memory_order_acquire);
    if (s_state_mutex && xSemaphoreTake(
            s_state_mutex, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)) == pdTRUE) {
        snapshot.json = s_scan_cache_json;
        snapshot.ready = s_scan_cache_ready;
        snapshot.error = s_scan_cache_error;
        xSemaphoreGive(s_state_mutex);
    }
    return snapshot;
}

esp_err_t idf_wifi_scan_json(std::string& out_json)
{
    esp_err_t request_err = idf_wifi_scan_request();
    IdfWifiScanSnapshot snapshot = idf_wifi_scan_get_snapshot();
    out_json = std::move(snapshot.json);
    if (request_err != ESP_OK && !snapshot.ready && !snapshot.busy) return request_err;
    return ESP_OK;
}

bool idf_wifi_is_ap_mode(void)
{
    ApState ap;
    return ap_state_snapshot(ap, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)) && ap.mode;
}

IdfWifiStatus idf_wifi_get_status(void)
{
    IdfWifiStatus s;
    ApState ap_state;
    if (ap_state_snapshot(ap_state, pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))) {
        s.apMode = ap_state.mode;
        s.apSsid = ap_state.ssid;
        if (ap_state.mode) s.apIp = "192.168.1.1";
    }

    uint8_t mac[6] = {};
    if (esp_read_mac(mac, ESP_MAC_WIFI_STA) == ESP_OK) s.mac = mac_to_string(mac);

    wifi_ap_record_t ap = {};
    WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS));
    if (operation) {
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            s.staConnected = true;
            s.ssid = reinterpret_cast<const char*>(ap.ssid);
            s.rssi = ap.rssi;
            s.channel = ap.primary;
            s.bssid = mac_to_string(ap.bssid);
        }
    } else {
        s.staConnected = s_sta_connected.load(std::memory_order_relaxed);
    }

    esp_netif_ip_info_t ip = {};
    if (s_sta_netif && esp_netif_get_ip_info(s_sta_netif, &ip) == ESP_OK && ip.ip.addr != 0) {
        s.ip = ip4_to_string(ip.ip);
        s.gw = ip4_to_string(ip.gw);
        s.mask = ip4_to_string(ip.netmask);
    }

    esp_netif_dns_info_t dns = {};
    if (s_sta_netif && esp_netif_get_dns_info(s_sta_netif, ESP_NETIF_DNS_MAIN, &dns) == ESP_OK &&
        dns.ip.u_addr.ip4.addr != 0) {
        s.dns = ip4_to_string(dns.ip.u_addr.ip4);
    }

    return s;
}
