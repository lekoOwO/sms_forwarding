#include "idf_wifi_core.h"

#include <algorithm>

#include "esp_idf_version.h"

bool idf_wifi_profile_matches_auth(bool open_profile, wifi_auth_mode_t authmode)
{
    if (open_profile) return authmode == WIFI_AUTH_OPEN;
    switch (authmode) {
        case WIFI_AUTH_WPA2_PSK:
        case WIFI_AUTH_WPA_WPA2_PSK:
        case WIFI_AUTH_WPA3_PSK:
        case WIFI_AUTH_WPA2_WPA3_PSK:
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
        case WIFI_AUTH_WPA3_EXT_PSK:
        case WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE:
#endif
            return true;
        default:
            return false;
    }
}

void idf_wifi_order_candidates(std::vector<IdfWifiCandidate>& candidates)
{
    std::stable_sort(candidates.begin(), candidates.end(), [](const auto& a, const auto& b) {
        if (a.scanned != b.scanned) return a.scanned;
        return a.scanned && a.rssi > b.rssi;
    });
}

size_t idf_wifi_candidate_position(size_t candidate_count, uint32_t attempt)
{
    return candidate_count == 0 ? 0 : attempt % candidate_count;
}

bool idf_wifi_provision_target_matches(
    const std::string& expected_ssid, bool expected_bssid_set,
    const std::array<uint8_t, 6>& expected_bssid,
    const std::string& actual_ssid, const std::array<uint8_t, 6>& actual_bssid)
{
    return expected_ssid == actual_ssid &&
           (!expected_bssid_set || expected_bssid == actual_bssid);
}

bool idf_wifi_selector_can_apply(uint32_t captured_generation,
                                 uint32_t current_generation,
                                 bool provisioning_active)
{
    return !provisioning_active && captured_generation == current_generation;
}

bool idf_wifi_find_cached_open_ap(const std::vector<IdfWifiScannedAp>& records,
                                  const std::string& ssid,
                                  std::array<uint8_t, 6>& bssid_out)
{
    const IdfWifiScannedAp* best = nullptr;
    for (const IdfWifiScannedAp& record : records) {
        if (record.ssid == ssid && record.authmode == WIFI_AUTH_OPEN &&
            (!best || record.rssi > best->rssi)) {
            best = &record;
        }
    }
    if (!best) return false;
    bssid_out = best->bssid;
    return true;
}

bool idf_wifi_recovery_ap_due(const IdfWifiRecoveryPolicy& policy)
{
    if (policy.apStarted || policy.staConnected || !policy.staConfigured ||
        policy.apMode || policy.provisioning || policy.selectorActive) {
        return false;
    }
    if (policy.outageSinceUs < 0 || policy.outageGeneration != policy.currentGeneration ||
        policy.nowUs < policy.outageSinceUs ||
        policy.nowUs - policy.outageSinceUs < IDF_WIFI_RECOVERY_AP_AFTER_US) {
        return false;
    }
    return policy.lastApAttemptUs < 0 ||
           (policy.nowUs >= policy.lastApAttemptUs &&
            policy.nowUs - policy.lastApAttemptUs >= IDF_WIFI_RECOVERY_AP_AFTER_US);
}
