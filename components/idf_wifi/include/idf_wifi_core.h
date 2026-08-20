#pragma once

#include <stddef.h>
#include <stdint.h>

#include <array>
#include <string>
#include <vector>

#include "esp_wifi_types.h"

struct IdfWifiCandidate {
    size_t profileIndex = 0;
    int rssi = -128;
    bool scanned = false;
};

struct IdfWifiScannedAp {
    std::string ssid;
    int rssi = -128;
    wifi_auth_mode_t authmode = WIFI_AUTH_OPEN;
    std::array<uint8_t, 6> bssid = {};
};

static constexpr int64_t IDF_WIFI_RECOVERY_AP_AFTER_US = 60LL * 1000000LL;

struct IdfWifiRecoveryPolicy {
    int64_t nowUs = 0;
    int64_t outageSinceUs = -1;
    uint32_t outageGeneration = 0;
    uint32_t currentGeneration = 0;
    int64_t lastApAttemptUs = -1;
    bool apStarted = false;
    bool staConnected = false;
    bool staConfigured = false;
    bool apMode = false;
    bool provisioning = false;
    bool selectorActive = false;
};

bool idf_wifi_profile_matches_auth(bool open_profile, wifi_auth_mode_t authmode);
void idf_wifi_order_candidates(std::vector<IdfWifiCandidate>& candidates);
size_t idf_wifi_candidate_position(size_t candidate_count, uint32_t attempt);
bool idf_wifi_provision_target_matches(
    const std::string& expected_ssid, bool expected_bssid_set,
    const std::array<uint8_t, 6>& expected_bssid,
    const std::string& actual_ssid, const std::array<uint8_t, 6>& actual_bssid);
bool idf_wifi_selector_can_apply(uint32_t captured_generation,
                                 uint32_t current_generation,
                                 bool provisioning_active);
bool idf_wifi_find_cached_open_ap(const std::vector<IdfWifiScannedAp>& records,
                                  const std::string& ssid,
                                  std::array<uint8_t, 6>& bssid_out);
bool idf_wifi_recovery_ap_due(const IdfWifiRecoveryPolicy& policy);
