#!/usr/bin/env python3

import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WIFI = ROOT / "components/idf_wifi"

WIFI_TYPES = r'''#pragma once
typedef enum {
    WIFI_AUTH_OPEN = 0,
    WIFI_AUTH_WEP,
    WIFI_AUTH_WPA_PSK,
    WIFI_AUTH_WPA2_PSK,
    WIFI_AUTH_WPA_WPA2_PSK,
    WIFI_AUTH_ENTERPRISE,
    WIFI_AUTH_WPA2_ENTERPRISE = WIFI_AUTH_ENTERPRISE,
    WIFI_AUTH_WPA3_PSK,
    WIFI_AUTH_WPA2_WPA3_PSK,
    WIFI_AUTH_WAPI_PSK,
    WIFI_AUTH_OWE,
    WIFI_AUTH_WPA3_ENT_192,
    WIFI_AUTH_WPA3_EXT_PSK,
    WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE,
    WIFI_AUTH_DPP,
    WIFI_AUTH_WPA3_ENTERPRISE,
    WIFI_AUTH_WPA2_WPA3_ENTERPRISE,
    WIFI_AUTH_WPA_ENTERPRISE,
    WIFI_AUTH_MAX
} wifi_auth_mode_t;
'''

HARNESS = r'''
#include <array>
#include <cassert>
#include <string>
#include <vector>

#include "idf_wifi_core.h"

int main() {
    assert(idf_wifi_profile_matches_auth(true, WIFI_AUTH_OPEN));
    assert(!idf_wifi_profile_matches_auth(true, WIFI_AUTH_WPA2_PSK));

    assert(!idf_wifi_profile_matches_auth(false, WIFI_AUTH_OPEN));
    assert(!idf_wifi_profile_matches_auth(false, WIFI_AUTH_WPA_PSK));
    assert(idf_wifi_profile_matches_auth(false, WIFI_AUTH_WPA2_PSK));
    assert(idf_wifi_profile_matches_auth(false, WIFI_AUTH_WPA_WPA2_PSK));
    assert(idf_wifi_profile_matches_auth(false, WIFI_AUTH_WPA3_PSK));
    assert(idf_wifi_profile_matches_auth(false, WIFI_AUTH_WPA2_WPA3_PSK));
    assert(idf_wifi_profile_matches_auth(false, WIFI_AUTH_WPA3_EXT_PSK));
    assert(idf_wifi_profile_matches_auth(false, WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE));
    assert(!idf_wifi_profile_matches_auth(false, WIFI_AUTH_ENTERPRISE));
    assert(!idf_wifi_profile_matches_auth(false, WIFI_AUTH_WAPI_PSK));
    assert(!idf_wifi_profile_matches_auth(false, WIFI_AUTH_OWE));
    assert(!idf_wifi_profile_matches_auth(false, WIFI_AUTH_DPP));

    std::vector<IdfWifiCandidate> candidates = {
        {0, -61, true},
        {1, -34, true},
        {2, -128, false},
    };
    idf_wifi_order_candidates(candidates);
    assert(candidates[0].profileIndex == 1);
    assert(candidates[1].profileIndex == 0);
    assert(candidates[2].profileIndex == 2);
    assert(idf_wifi_candidate_position(candidates.size(), 0) == 0);
    assert(idf_wifi_candidate_position(candidates.size(), 1) == 1);
    assert(idf_wifi_candidate_position(candidates.size(), 2) == 2);
    assert(idf_wifi_candidate_position(candidates.size(), 3) == 0);
    assert(idf_wifi_candidate_position(0, 10) == 0);

    const std::array<uint8_t, 6> office_bssid = {0x02, 0, 0, 0, 0, 1};
    const std::array<uint8_t, 6> other_bssid = {0x02, 0, 0, 0, 0, 2};
    assert(idf_wifi_provision_target_matches(
        "Office", false, office_bssid, "Office", other_bssid));
    assert(!idf_wifi_provision_target_matches(
        "Office", false, office_bssid, "Guest", office_bssid));
    assert(idf_wifi_provision_target_matches(
        "Guest", true, office_bssid, "Guest", office_bssid));
    assert(!idf_wifi_provision_target_matches(
        "Guest", true, office_bssid, "Guest", other_bssid));

    assert(idf_wifi_selector_can_apply(7, 7, false));
    assert(!idf_wifi_selector_can_apply(7, 8, false));
    assert(!idf_wifi_selector_can_apply(7, 7, true));

    const std::vector<IdfWifiScannedAp> scan_cache = {
        {"Guest", -20, WIFI_AUTH_WPA2_PSK, other_bssid},
        {"Guest", -55, WIFI_AUTH_OPEN, office_bssid},
        {"Guest", -70, WIFI_AUTH_OPEN, other_bssid},
    };
    std::array<uint8_t, 6> selected_bssid = {};
    assert(idf_wifi_find_cached_open_ap(scan_cache, "Guest", selected_bssid));
    assert(selected_bssid == office_bssid);
    assert(!idf_wifi_find_cached_open_ap(scan_cache, "Missing", selected_bssid));
}
'''


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="idf-wifi-security-") as temp_dir:
        temp = Path(temp_dir)
        (temp / "esp_wifi_types.h").write_text(WIFI_TYPES, encoding="utf-8")
        harness = temp / "wifi_security_test.cpp"
        binary = temp / "wifi_security_test"
        harness.write_text(HARNESS, encoding="utf-8")
        subprocess.run(
            [
                "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                f"-I{temp}", f"-I{WIFI / 'include'}",
                str(WIFI / "idf_wifi_core.cpp"), str(harness), "-o", str(binary),
            ],
            check=True,
        )
        subprocess.run([str(binary)], check=True)

    source = (WIFI / "idf_wifi.cpp").read_text(encoding="utf-8")
    assert '"%s%02X%02X%02X", AP_SSID_PREFIX, mac[3], mac[4], mac[5]' in source
    assert "pass.empty() ? WIFI_AUTH_OPEN : WIFI_AUTH_WPA2_PSK" in source

    provision = source.split("esp_err_t idf_wifi_provision_connect", 1)[1].split(
        "esp_err_t idf_wifi_scan_json", 1
    )[0]
    assert "previous_config" in provision
    assert "s_sta_configured.store(previous_configured" in provision
    assert "s_current_profile_open.store(previous_open" in provision


if __name__ == "__main__":
    main()
