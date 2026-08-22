#!/usr/bin/env python3

import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WIFI = ROOT / "components/idf_wifi"
SOURCE = (ROOT / "components/idf_wifi/idf_wifi.cpp").read_text(encoding="utf-8")
CORE_HEADER = (ROOT / "components/idf_wifi/include/idf_wifi_core.h").read_text(encoding="utf-8")


class WifiRecoverySourceTest(unittest.TestCase):
    WIFI_TYPES = r'''#pragma once
typedef enum {
    WIFI_AUTH_OPEN = 0,
    WIFI_AUTH_WPA2_PSK,
    WIFI_AUTH_WPA_WPA2_PSK,
    WIFI_AUTH_WPA3_PSK,
    WIFI_AUTH_WPA2_WPA3_PSK,
    WIFI_AUTH_WPA3_EXT_PSK,
    WIFI_AUTH_WPA3_EXT_PSK_MIXED_MODE,
} wifi_auth_mode_t;
'''

    POLICY_HARNESS = r'''
#include <cassert>

#include "idf_wifi_core.h"

int main() {
    IdfWifiRecoveryPolicy policy;
    policy.nowUs = 60LL * 1000000LL;
    policy.outageSinceUs = 0;
    policy.outageGeneration = 7;
    policy.currentGeneration = 7;
    policy.staConfigured = true;
    policy.selectorActive = true;
    assert(!idf_wifi_recovery_ap_due(policy));
    policy.selectorActive = false;
    assert(idf_wifi_recovery_ap_due(policy));

    int ap_requests = 0;
    auto request_ap = [&]() {
        if (!idf_wifi_recovery_ap_due(policy)) return false;
        ++ap_requests;
        policy.lastApAttemptUs = policy.nowUs;
        return true;
    };
    assert(request_ap());
    assert(ap_requests == 1);
    assert(!request_ap());

    policy.nowUs += 15LL * 1000000LL;
    assert(!idf_wifi_recovery_ap_due(policy));
    assert(ap_requests == 1);
    policy.nowUs += 45LL * 1000000LL;
    assert(request_ap());
    assert(ap_requests == 2);

    policy.apStarted = true;
    assert(!idf_wifi_recovery_ap_due(policy));
    policy.apStarted = false;
    policy.staConnected = true;
    assert(!idf_wifi_recovery_ap_due(policy));
    policy.staConnected = false;
    policy.apMode = true;
    assert(!idf_wifi_recovery_ap_due(policy));
    policy.apMode = false;
    policy.provisioning = true;
    assert(!idf_wifi_recovery_ap_due(policy));
    policy.provisioning = false;
    policy.currentGeneration = 8;
    assert(!idf_wifi_recovery_ap_due(policy));
    policy.currentGeneration = 7;
    policy.outageSinceUs = -1;
    assert(!idf_wifi_recovery_ap_due(policy));
    policy.outageSinceUs = 0;
    policy.staConfigured = false;
    assert(!idf_wifi_recovery_ap_due(policy));
    policy.staConfigured = true;
    policy.nowUs = 1;
    policy.lastApAttemptUs = -1;
    assert(!idf_wifi_recovery_ap_due(policy));
}
'''

    def test_recovery_policy_is_executable(self):
        with tempfile.TemporaryDirectory(prefix="idf-wifi-recovery-") as temp_dir:
            temp = Path(temp_dir)
            (temp / "esp_wifi_types.h").write_text(self.WIFI_TYPES, encoding="utf-8")
            harness = temp / "wifi_recovery_test.cpp"
            binary = temp / "wifi_recovery_test"
            harness.write_text(self.POLICY_HARNESS, encoding="utf-8")
            subprocess.run(
                [
                    "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    f"-I{temp}", f"-I{WIFI / 'include'}",
                    str(WIFI / "idf_wifi_core.cpp"), str(harness), "-o", str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    INTEGRATION_HARNESS = r'''
#include <algorithm>
#include <cassert>
#include <string>
#include <vector>

#include "idf_wifi_core.h"

struct WatchdogModel {
    IdfWifiRecoveryPolicy policy;
    bool selectorRunning = false;
    bool recoveryClaimed = false;
    uint32_t claimGeneration = 0;
    bool recoveryStarted = false;
    bool resetDuringApStart = false;
    bool apStartSucceeds = true;
    int apRequests = 0;
    std::vector<std::string> events;

    void reset() {
        events.push_back("reset");
        policy.outageSinceUs = -1;
        ++policy.outageGeneration;
        policy.currentGeneration = policy.outageGeneration;
        policy.lastApAttemptUs = -1;
        policy.apStarted = false;
        recoveryStarted = false;
    }

    void request_selector() {
        if (recoveryClaimed) {
            events.push_back("selector_deferred");
        } else if (!selectorRunning) {
            events.push_back("selector");
        }
    }

    void watchdog() {
        policy.selectorActive = selectorRunning;
        if (!recoveryClaimed && idf_wifi_recovery_ap_due(policy)) {
            recoveryClaimed = true;
            claimGeneration = policy.currentGeneration;
            policy.lastApAttemptUs = policy.nowUs;
            events.push_back("claim");
            events.push_back("ap_begin");
            ++apRequests;
            if (resetDuringApStart) {
                reset();
                request_selector();
            }
            if (apStartSucceeds && recoveryClaimed &&
                claimGeneration == policy.currentGeneration &&
                policy.outageGeneration == policy.currentGeneration) {
                policy.apStarted = true;
                recoveryStarted = true;
            } else if (apStartSucceeds) {
                events.push_back("close_stale_ap");
            }
            recoveryClaimed = false;
            claimGeneration = 0;
        }
        request_selector();
    }
};

struct DriverRaceModel {
    bool apStartInFlight = true;
    bool resetRequested = false;
    bool staleApOpen = true;
    std::vector<std::string> events;

    bool disconnect(bool apStartCompletes) {
        if (apStartInFlight) {
            resetRequested = true;
            events.push_back("reset");
            if (!apStartCompletes) return false;
            apStartInFlight = false;
            staleApOpen = false;
            events.push_back("ap_exit");
        }
        events.push_back("driver_disconnect");
        return true;
    }
};

static WatchdogModel outage_model() {
    WatchdogModel model;
    model.policy.nowUs = 60LL * 1000000LL;
    model.policy.outageSinceUs = 0;
    model.policy.outageGeneration = 4;
    model.policy.currentGeneration = 4;
    model.policy.staConfigured = true;
    return model;
}

int main() {
    WatchdogModel selector = outage_model();
    selector.selectorRunning = true;
    selector.watchdog();
    assert(selector.apRequests == 0);
    assert(std::find(selector.events.begin(), selector.events.end(), "ap_begin") == selector.events.end());

    WatchdogModel due = outage_model();
    due.watchdog();
    assert(due.apRequests == 1);
    assert(due.events.size() == 3);
    assert(due.events[0] == "claim");
    assert(due.events[1] == "ap_begin");
    assert(due.events[2] == "selector");

    WatchdogModel reset = outage_model();
    reset.resetDuringApStart = true;
    reset.watchdog();
    assert(!reset.recoveryStarted);
    assert(reset.events.size() == 6);
    assert(reset.events[0] == "claim");
    assert(reset.events[1] == "ap_begin");
    assert(reset.events[2] == "reset");
    assert(reset.events[3] == "selector_deferred");
    assert(reset.events[4] == "close_stale_ap");
    assert(reset.events[5] == "selector");

    WatchdogModel retry = outage_model();
    retry.apStartSucceeds = false;
    retry.watchdog();
    assert(retry.apRequests == 1);
    retry.policy.nowUs += 15LL * 1000000LL;
    retry.watchdog();
    assert(retry.apRequests == 1);
    retry.policy.nowUs += 45LL * 1000000LL;
    retry.apStartSucceeds = true;
    retry.watchdog();
    assert(retry.apRequests == 2);
    assert(retry.recoveryStarted);

    DriverRaceModel serialized;
    assert(serialized.disconnect(true));
    assert(serialized.events.size() == 3);
    assert(serialized.events[0] == "reset");
    assert(serialized.events[1] == "ap_exit");
    assert(serialized.events[2] == "driver_disconnect");
    assert(!serialized.staleApOpen);

    DriverRaceModel timed_out;
    assert(!timed_out.disconnect(false));
    assert(timed_out.events.size() == 1);
    assert(timed_out.events[0] == "reset");
    assert(timed_out.apStartInFlight);
}
'''

    def test_watchdog_integration_order_and_reset_are_executable(self):
        with tempfile.TemporaryDirectory(prefix="idf-wifi-recovery-integration-") as temp_dir:
            temp = Path(temp_dir)
            (temp / "esp_wifi_types.h").write_text(self.WIFI_TYPES, encoding="utf-8")
            harness = temp / "wifi_recovery_integration_test.cpp"
            binary = temp / "wifi_recovery_integration_test"
            harness.write_text(self.INTEGRATION_HARNESS, encoding="utf-8")
            subprocess.run(
                [
                    "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    f"-I{temp}", f"-I{WIFI / 'include'}",
                    str(WIFI / "idf_wifi_core.cpp"), str(harness), "-o", str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    def test_watchdog_opens_one_recovery_ap_after_bounded_outage(self):
        watchdog = SOURCE.split("static void reconnect_watchdog_cb", 1)[1].split(
            "static void dns_captive_task", 1
        )[0]

        self.assertIn(
            "IDF_WIFI_RECOVERY_AP_AFTER_US = 60LL * 1000000LL", CORE_HEADER
        )
        self.assertIn("esp_timer_get_time()", watchdog)
        self.assertIn("s_sta_outage_since_us", watchdog)
        self.assertIn("s_sta_outage_generation", watchdog)
        self.assertIn("s_recovery_ap_last_attempt_us", SOURCE)
        self.assertIn("idf_wifi_recovery_ap_due", SOURCE)
        self.assertIn("claim_recovery_ap_if_due", watchdog)
        self.assertIn("finish_recovery_ap_claim", watchdog)
        self.assertIn("start_provisioning_ap_locked(false, driver_timeout)", watchdog)
        self.assertIn("ap.mode", watchdog)
        self.assertIn("s_provisioning.load", watchdog)
        self.assertIn("s_has_sta_credentials.load(std::memory_order_relaxed)", watchdog)

        ap_start = watchdog.index("start_provisioning_ap_locked(false, driver_timeout)")
        self.assertLess(watchdog.index("claim_recovery_ap_if_due"), ap_start)
        self.assertLess(ap_start, watchdog.index("start_wifi_select_once();"))
        self.assertLess(ap_start, watchdog.index("wifi_connect_now();", ap_start))

        policy = (WIFI / "idf_wifi_core.cpp").read_text(encoding="utf-8")
        self.assertIn("policy.selectorActive", policy)
        self.assertNotIn("(void)policy.selectorActive", policy)

        selector = SOURCE.split("static void start_wifi_select_once(void)", 1)[1].split(
            "// Start STA without waiting", 1
        )[0]
        self.assertIn("s_recovery_ap_inflight", selector)

        disconnected = SOURCE.split(
            "if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)", 1
        )[1].split("if (event_base == IP_EVENT", 1)[0]
        self.assertIn("s_sta_outage_since_us.compare_exchange_strong", disconnected)

    def test_got_ip_resets_recovery_latch_and_uses_existing_ap_close_path(self):
        got_ip = SOURCE.split(
            "if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)", 1
        )[1].split("// After STA gets an IP", 1)[0]

        self.assertIn("reset_recovery_state(false, false", got_ip)
        self.assertIn("schedule_ap_close(1)", got_ip)
        self.assertIn("WifiDriverOperation operation(0)", got_ip)

        disconnect = SOURCE.split("static esp_err_t wifi_disconnect_quietly", 1)[1].split(
            "static esp_err_t wifi_scan_candidates", 1
        )[0]
        self.assertIn("reset_recovery_state(", disconnect)
        self.assertIn("true, true", disconnect)
        self.assertIn("s_wifi_driver_mutex", SOURCE)
        self.assertIn("WifiDriverOperation operation(driver_timeout)", disconnect)
        self.assertIn("WIFI_RECOVERY_SYNC_TIMEOUT_MS", SOURCE)
        finish = SOURCE.split("static bool finish_recovery_ap_claim", 1)[1].split(
            "static std::atomic<bool> s_ntp_first_logged", 1
        )[0]
        self.assertLess(finish.index("close_recovery_ap_if_active_locked"), finish.index("s_recovery_ap_inflight = false"))

        reconnect = SOURCE.split("esp_err_t idf_wifi_reconnect", 1)[1].split(
            "esp_err_t idf_wifi_set_tx_power", 1
        )[0]
        self.assertLess(
            reconnect.index("if (err != ESP_OK)"),
            reconnect.index("s_sta_configured.store(true"),
        )

        provision_timeout = SOURCE.split("esp_err_t idf_wifi_provision_connect", 1)[1].split(
            "static std::string wifi_scan_records_json", 1
        )[0]
        self.assertIn("return ESP_ERR_TIMEOUT", provision_timeout)

    def test_disconnect_fast_path_requires_no_link_or_pending_attempt(self):
        disconnect = SOURCE.split("static esp_err_t wifi_disconnect_driver_locked", 1)[1].split(
            "static esp_err_t wifi_disconnect_quietly", 1
        )[0]
        self.assertNotIn("if (!s_sta_connected.load(std::memory_order_relaxed)) return ESP_OK;", disconnect)
        self.assertIn("s_sta_link_connected.load(std::memory_order_relaxed)", disconnect)
        self.assertIn("s_sta_connecting.load(std::memory_order_relaxed)", disconnect)

        connected = SOURCE.split(
            "if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_CONNECTED)", 1
        )[1].split("if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)", 1)[0]
        disconnected = SOURCE.split(
            "if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED)", 1
        )[1].split("if (event_base == IP_EVENT", 1)[0]
        self.assertIn("s_sta_link_connected.store(true", connected)
        self.assertIn("s_sta_connecting.store(false", connected)
        self.assertIn("s_sta_link_connected.store(false", disconnected)
        self.assertIn("s_sta_connecting.store(false", disconnected)

    BOOT_PROFILE_HARNESS = r'''
#include <array>
#include <cassert>

struct BootModel {
    bool ap = false;
    bool selector = false;
    bool sta_configured = false;

    void start(const std::array<bool, 3>& saved) {
        int count = 0;
        for (bool present : saved) count += present ? 1 : 0;
        if (count == 0) {
            ap = true;
            return;
        }
        if (count > 1 || !saved[0]) {
            selector = true;
            return;
        }
        sta_configured = true;
    }

    void selector_apply(const std::array<bool, 3>& saved) {
        if (!selector) return;
        for (bool present : saved) {
            if (present) {
                sta_configured = true;
                return;
            }
        }
    }
};

int main() {
    BootModel persisted_profile;
    persisted_profile.start({false, true, false});
    assert(persisted_profile.selector);
    assert(!persisted_profile.ap);
    persisted_profile.selector_apply({false, true, false});
    assert(persisted_profile.sta_configured);

    BootModel unconfigured;
    unconfigured.start({false, false, false});
    assert(unconfigured.ap);
    assert(!unconfigured.selector);
    assert(!unconfigured.sta_configured);
}
'''

    def test_boot_selects_a_persisted_profile_from_any_saved_slot(self):
        startup = SOURCE.split("esp_err_t idf_wifi_start", 1)[1].split(
            "esp_err_t idf_wifi_resync_ntp", 1
        )[0]
        self.assertIn("int saved_networks = 0", startup)
        self.assertIn("s_has_sta_credentials.store(saved_networks > 0", startup)
        self.assertIn("if (saved_networks == 0)", startup)
        self.assertNotIn("if (config.wifiNetworks[0].ssid.empty())", startup)
        with tempfile.TemporaryDirectory(prefix="idf-wifi-boot-profile-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_boot_profile_test.cpp"
            binary = temp / "wifi_boot_profile_test"
            harness.write_text(self.BOOT_PROFILE_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    SELECTOR_RETRY_HARNESS = r'''
#include <cassert>

struct SelectorRetryModel {
    bool saved_profiles = false;
    bool provisioning = false;
    bool connected = false;
    int selector_runs = 0;

    void watchdog_tick() {
        if (!saved_profiles || provisioning || connected) return;
        ++selector_runs;
    }
};

int main() {
    SelectorRetryModel failed_scan;
    failed_scan.saved_profiles = true;
    failed_scan.watchdog_tick();
    failed_scan.watchdog_tick();
    assert(failed_scan.selector_runs == 2);

    SelectorRetryModel provisioning;
    provisioning.saved_profiles = true;
    provisioning.provisioning = true;
    provisioning.watchdog_tick();
    assert(provisioning.selector_runs == 0);

    SelectorRetryModel empty;
    empty.watchdog_tick();
    assert(empty.selector_runs == 0);
}
'''

    def test_selector_retry_uses_saved_profiles_and_starts_after_sta_mode(self):
        watchdog = SOURCE.split("static void reconnect_watchdog_cb", 1)[1].split(
            "static void dns_captive_task", 1
        )[0]
        self.assertIn("s_has_sta_credentials.load(std::memory_order_relaxed)", watchdog)
        self.assertNotIn("if (!sta_can_connect()) return;", watchdog)
        self.assertIn("!s_sta_configured.load(std::memory_order_relaxed)", watchdog)
        startup = SOURCE.split("esp_err_t idf_wifi_start", 1)[1].split(
            "esp_err_t idf_wifi_resync_ntp", 1
        )[0]
        self.assertLess(
            startup.index("esp_wifi_set_mode(WIFI_MODE_STA)"),
            startup.index("esp_wifi_start()"),
        )
        self.assertLess(
            startup.index("esp_wifi_start()"),
            startup.index("connect_sta_begin(config)"),
        )
        with tempfile.TemporaryDirectory(prefix="idf-wifi-selector-retry-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_selector_retry_test.cpp"
            binary = temp / "wifi_selector_retry_test"
            harness.write_text(self.SELECTOR_RETRY_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    PROVISION_CLOSE_HARNESS = r'''
#include <cassert>

struct ProvisioningCloseModel {
    bool provisioning = true;
    bool target_active = true;
    bool validation_pending = true;
    bool ap_mode = true;

    void got_ip(bool target_matches) {
        if (!provisioning) return;
        if (!target_matches) {
            validation_pending = false;
            return;
        }
        provisioning = false;
        target_active = false;
        validation_pending = false;
    }

    bool close_timer() {
        if (validation_pending) return false;
        if (!provisioning && ap_mode) {
            ap_mode = false;
            return true;
        }
        return false;
    }
};

int main() {
    ProvisioningCloseModel matched;
    matched.got_ip(true);
    assert(!matched.provisioning);
    assert(!matched.target_active);
    assert(!matched.validation_pending);
    assert(matched.close_timer());
    assert(!matched.ap_mode);

    ProvisioningCloseModel fallback;
    fallback.got_ip(false);
    assert(fallback.provisioning);
    assert(fallback.target_active);
    assert(!fallback.close_timer());
    assert(fallback.ap_mode);
}
'''

    def test_matched_provisioning_clears_validation_marker_before_ap_close(self):
        got_ip = SOURCE.split(
            "if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)", 1
        )[1].split("// After STA gets an IP", 1)[0]
        got_ip_matched = got_ip.split(
            "if (result == ProvisioningValidationResult::Matched)", 1
        )[1].split("} else if", 1)[0]
        close_timer = SOURCE.split("static void ap_close_timer_cb(void*)", 1)[1].split(
            "static void schedule_ap_close", 1
        )[0]
        close_timer_matched = close_timer.split(
            "} else if (result == ProvisioningValidationResult::Matched)", 1
        )[1].split("} else", 1)[0]
        for section in (got_ip_matched, close_timer_matched):
            self.assertIn("s_provisioning_validation_generation.store(0", section)
        with tempfile.TemporaryDirectory(prefix="idf-wifi-provision-close-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_provision_close_test.cpp"
            binary = temp / "wifi_provision_close_test"
            harness.write_text(self.PROVISION_CLOSE_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness), "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    DRIVER_OPERATION_HARNESS = r'''
#include <cassert>
#include <future>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

enum class Caller {
    StartupNoConfig,
    StartupConnectFailure,
    FirstConnectTimeout,
    RecoveryWatchdog,
    ManualButton,
};

struct DriverModel {
    std::mutex operation;
    bool ap = false;
    bool manual = false;
    std::vector<std::string> events;

    void start_ap(Caller caller, std::promise<void>* entered = nullptr,
                  std::shared_future<void> release = {}) {
        std::unique_lock<std::mutex> guard(operation);
        events.push_back("ap_enter");
        if (entered) {
            entered->set_value();
            release.wait();
        }
        if (caller == Caller::ManualButton && ap) manual = true;
        ap = true;
        events.push_back(caller == Caller::ManualButton ? "manual_ap" : "recovery_or_startup_ap");
        events.push_back("ap_exit");
    }

    void disconnect() {
        std::lock_guard<std::mutex> guard(operation);
        events.push_back("disconnect_enter");
        ap = false;
        manual = false;
        events.push_back("disconnect_driver");
        events.push_back("disconnect_exit");
    }
};

int main() {
    DriverModel model;
    const Caller start_callers[] = {
        Caller::StartupNoConfig, Caller::StartupConnectFailure, Caller::FirstConnectTimeout,
        Caller::RecoveryWatchdog, Caller::ManualButton,
    };
    for (Caller caller : start_callers) model.start_ap(caller);
    assert(model.ap);
    assert(model.manual);

    model.disconnect();
    assert(!model.ap);
    assert(model.events.back() == "disconnect_exit");

    DriverModel recovery_then_disconnect;
    std::promise<void> recovery_entered;
    std::shared_future<void> recovery_entered_future = recovery_entered.get_future().share();
    std::promise<void> release_recovery;
    std::shared_future<void> release_recovery_future = release_recovery.get_future().share();
    std::thread recovery([&]() {
        recovery_then_disconnect.start_ap(
            Caller::RecoveryWatchdog, &recovery_entered, release_recovery_future);
    });
    recovery_entered_future.wait();
    std::thread disconnect([&]() { recovery_then_disconnect.disconnect(); });
    release_recovery.set_value();
    recovery.join();
    disconnect.join();
    assert(recovery_then_disconnect.events[0] == "ap_enter");
    assert(recovery_then_disconnect.events[2] == "ap_exit");
    assert(recovery_then_disconnect.events[3] == "disconnect_enter");
    assert(recovery_then_disconnect.events[4] == "disconnect_driver");

    DriverModel recovery_then_manual;
    std::promise<void> manual_recovery_entered;
    std::shared_future<void> manual_recovery_entered_future = manual_recovery_entered.get_future().share();
    std::promise<void> release_manual_recovery;
    std::shared_future<void> release_manual_recovery_future = release_manual_recovery.get_future().share();
    std::thread manual_recovery([&]() {
        recovery_then_manual.start_ap(
            Caller::RecoveryWatchdog, &manual_recovery_entered, release_manual_recovery_future);
    });
    manual_recovery_entered_future.wait();
    std::thread manual([&]() { recovery_then_manual.start_ap(Caller::ManualButton); });
    release_manual_recovery.set_value();
    manual_recovery.join();
    manual.join();
    assert(recovery_then_manual.manual);
    assert(recovery_then_manual.events[0] == "ap_enter");
    assert(recovery_then_manual.events[2] == "ap_exit");
    assert(recovery_then_manual.events[3] == "ap_enter");
    assert(recovery_then_manual.events[4] == "manual_ap");
    assert(recovery_then_manual.events[5] == "ap_exit");
}
'''

    def test_shared_driver_operation_lock_covers_all_ap_callers_and_disconnect(self):
        start = SOURCE.split("static esp_err_t start_provisioning_ap_locked(bool manual, TickType_t state_timeout)\n{", 1)[1].split(
            "static void provision_button_task", 1
        )[0]
        disconnect = SOURCE.split("static esp_err_t wifi_disconnect_quietly", 1)[1].split(
            "static esp_err_t wifi_scan_candidates", 1
        )[0]
        apply = SOURCE.split("static esp_err_t wifi_apply_and_connect", 1)[1].split(
            "static esp_err_t wifi_disconnect_quietly", 1
        )[0]
        for section in (start, disconnect, apply):
            self.assertIn("WifiDriverOperation", section)
        self.assertIn("s_wifi_driver_mutex", SOURCE)

        caller_bounds = (
            ("provision_button_task", "static bool wifi_profile_password_valid"),
            ("sta_wait_first_connect", "static void sta_connect_watch_task"),
            ("reconnect_watchdog_cb", "static void dns_captive_task"),
        )
        for caller, end in caller_bounds:
            caller_source = SOURCE.split(f"static void {caller}", 1)[1].split(end, 1)[0]
            self.assertIn("start_provisioning_ap", caller_source)
        startup = SOURCE.split("esp_err_t idf_wifi_start", 1)[1].split(
            "esp_err_t idf_wifi_resync_ntp", 1
        )[0]
        self.assertGreaterEqual(startup.count("start_provisioning_ap(false)"), 2)

        def assert_driver_lock(section):
            self.assertIn("WifiDriverOperation", section)

        assert_driver_lock(start)
        assert_driver_lock(disconnect)
        assert_driver_lock(apply)

        with tempfile.TemporaryDirectory(prefix="idf-wifi-driver-order-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_driver_operation_test.cpp"
            binary = temp / "wifi_driver_operation_test"
            harness.write_text(self.DRIVER_OPERATION_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness),
                 "-pthread", "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

        mutated_start = start.replace("WifiDriverOperation", "RemovedDriverOperation", 1)
        with self.assertRaises(AssertionError):
            assert_driver_lock(mutated_start)

    DRIVER_BOUNDARY_HARNESS = r'''
#include <cassert>
#include <mutex>
#include <string>
#include <vector>

struct BoundaryModel {
    std::mutex operation;
    std::vector<std::string> events;
    bool manual_ap = false;
    bool close_retry_scheduled = false;
    bool closed = false;

    void collect_scan(bool allocation_ok) {
        std::lock_guard<std::mutex> guard(operation);
        events.push_back("scan_enter");
        if (!allocation_ok) events.push_back("scan_clear");
        else events.push_back("scan_records_clear");
        events.push_back("scan_exit");
    }

    bool set_tx_power(bool can_lock) {
        if (!can_lock) return false;
        std::lock_guard<std::mutex> guard(operation);
        events.push_back("tx_power_driver");
        return true;
    }

    void got_ip_timer(bool can_lock) {
        if (manual_ap) return;
        if (!can_lock) {
            close_retry_scheduled = true;
            return;
        }
        std::lock_guard<std::mutex> guard(operation);
        if (!manual_ap) closed = true;
    }
};

int main() {
    BoundaryModel model;
    model.collect_scan(true);
    model.collect_scan(false);
    assert(model.events.size() == 6);
    assert(model.events[0] == "scan_enter");
    assert(model.events[2] == "scan_exit");
    assert(model.events[3] == "scan_enter");
    assert(model.events[4] == "scan_clear");
    assert(model.events[5] == "scan_exit");

    assert(!model.set_tx_power(false));
    assert(model.events.size() == 6);
    assert(model.set_tx_power(true));
    assert(model.events.back() == "tx_power_driver");

    model.got_ip_timer(false);
    assert(model.close_retry_scheduled);
    assert(!model.closed);
    model.got_ip_timer(true);
    assert(model.closed);

    BoundaryModel manual;
    manual.manual_ap = true;
    manual.got_ip_timer(false);
    assert(!manual.close_retry_scheduled);
    assert(!manual.closed);
}
'''

    def test_scan_tx_power_and_got_ip_close_share_boundary(self):
        collect = SOURCE.split("static void wifi_scan_collect_once()\n{", 1)[1].split(
            "static void scan_cleanup_timer_cb", 1
        )[0]
        scan_done = SOURCE.split("if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE &&", 1)[1].split(
            "if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)", 1
        )[0]
        tx_power = SOURCE.split("esp_err_t idf_wifi_set_tx_power", 1)[1].split(
            "esp_err_t idf_wifi_provision_connect", 1
        )[0]
        got_ip = SOURCE.split(
            "if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)", 1
        )[1].split("// After STA gets an IP", 1)[0]
        close_timer = SOURCE.split("static void ap_close_timer_cb(void*)", 1)[1].split(
            "static void schedule_ap_close", 1
        )[0]
        close_helper = SOURCE.split("static bool close_recovery_ap_if_active(TickType_t timeout", 1)[1].split(
            "// Invalidate recovery", 1
        )[0]

        for section in (collect, tx_power, close_helper):
            self.assertIn("WifiDriverOperation", section)
        self.assertIn("esp_wifi_scan_get_ap_num", collect)
        self.assertIn("esp_wifi_scan_get_ap_records", collect)
        self.assertIn("esp_wifi_clear_ap_list", collect)
        self.assertIn("schedule_scan_cleanup", scan_done)
        self.assertIn("pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)", tx_power)
        self.assertIn("return ESP_ERR_TIMEOUT", tx_power)
        self.assertIn("schedule_ap_close", got_ip)
        self.assertIn("WifiDriverOperation operation(0)", got_ip)
        self.assertIn("ap.manual", close_timer)
        self.assertIn("schedule_ap_close(1000)", close_timer)

        def assert_scan_lock(section):
            self.assertIn("WifiDriverOperation", section)

        def assert_tx_power_lock(section):
            self.assertIn("WifiDriverOperation", section)
            self.assertIn("pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)", section)
            self.assertIn("return ESP_ERR_TIMEOUT", section)

        def assert_got_ip_read_bounded(section):
            self.assertIn("schedule_ap_close(1)", section)
            self.assertIn("WifiDriverOperation operation(0)", section)

        def assert_bounded_close(section):
            self.assertIn("pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)", section)

        def assert_timer_rechecks_manual(section):
            self.assertIn("ap.manual", section)
            self.assertIn("schedule_ap_close(1000)", section)

        with self.assertRaises(AssertionError):
            assert_scan_lock(collect.replace("WifiDriverOperation", "RemovedDriverOperation", 1))
        def assert_scan_done_deferred(section):
            self.assertIn("schedule_scan_cleanup", section)
            self.assertNotIn("WifiDriverOperation operation", section)

        assert_scan_done_deferred(scan_done)
        with self.assertRaises(AssertionError):
            assert_scan_done_deferred(scan_done.replace("schedule_scan_cleanup", "esp_wifi_clear_ap_list", 1))
        with self.assertRaises(AssertionError):
            assert_tx_power_lock(tx_power.replace("WifiDriverOperation", "RemovedDriverOperation", 1))
        with self.assertRaises(AssertionError):
            assert_got_ip_read_bounded(got_ip.replace("WifiDriverOperation operation(0)", "esp_wifi_sta_get_ap_info", 1))
        with self.assertRaises(AssertionError):
            assert_bounded_close(close_helper.replace(
                "pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)", "portMAX_DELAY", 1
            ))
        with self.assertRaises(AssertionError):
            assert_timer_rechecks_manual(close_timer.replace("ap.manual", "removed_manual", 1))

        def assert_driver_lock(section):
            self.assertIn("WifiDriverOperation", section)

        with self.assertRaises(AssertionError):
            assert_driver_lock(collect.replace("WifiDriverOperation", "RemovedDriverOperation", 1))

        with tempfile.TemporaryDirectory(prefix="idf-wifi-boundary-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_driver_boundary_test.cpp"
            binary = temp / "wifi_driver_boundary_test"
            harness.write_text(self.DRIVER_BOUNDARY_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness),
                 "-pthread", "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    SCAN_LIFECYCLE_HARNESS = r'''
#include <cassert>
#include <string>
#include <vector>

struct ScanLifecycleModel {
    bool scan_active = false;
    bool cleanup_deferred = false;
    bool retry_scheduled = false;
    bool driver_called = false;
    bool manual_ap = false;

    bool begin_scan() {
        if (scan_active) return false;
        scan_active = true;
        return true;
    }

    bool mutating_driver_call() {
        if (scan_active) return false;
        driver_called = true;
        return true;
    }

    void scan_done_task_creation_failed() { cleanup_deferred = true; }

    bool cleanup_task(bool can_lock) {
        if (!cleanup_deferred) return false;
        if (!can_lock) {
            retry_scheduled = true;
            return false;
        }
        driver_called = true;
        scan_active = false;
        cleanup_deferred = false;
        return true;
    }

    bool close_ap_timer(bool can_lock) {
        if (manual_ap) return false;
        if (!can_lock) {
            retry_scheduled = true;
            return false;
        }
        driver_called = true;
        return true;
    }

    bool bounded_read(bool can_lock) {
        if (!can_lock) return false;
        driver_called = true;
        return true;
    }
};

int main() {
    ScanLifecycleModel model;
    assert(model.begin_scan());
    assert(!model.mutating_driver_call());
    model.scan_done_task_creation_failed();
    assert(!model.cleanup_task(false));
    assert(model.retry_scheduled);
    assert(model.cleanup_task(true));
    assert(!model.scan_active);
    assert(model.driver_called);
    assert(model.mutating_driver_call());

    ScanLifecycleModel timer;
    assert(!timer.close_ap_timer(false));
    assert(timer.retry_scheduled);
    assert(timer.close_ap_timer(true));
    timer.manual_ap = true;
    assert(!timer.close_ap_timer(true));

    ScanLifecycleModel reads;
    assert(!reads.bounded_read(false));
    assert(!reads.driver_called);
    assert(reads.bounded_read(true));
}
'''

    FINAL_AUDIT_HARNESS = r'''
#include <cassert>
#include <cstdint>
#include <string>
#include <vector>

struct AdmissionModel {
    bool configured = true;
    bool target_active = true;
    bool scan_active = false;
    bool driver_admitted = false;

    bool provision() {
        if (scan_active) return false;
        driver_admitted = true;
        configured = false;
        target_active = false;
        return true;
    }
};

struct SelectorModel {
    uint32_t generation = 4;
    bool provisioning = false;
    bool scan_active = true;
    std::vector<std::string> events;

    bool apply(uint32_t captured_generation) {
        if (scan_active) return false;
        if (captured_generation != generation || provisioning) return false;
        events.push_back("apply");
        return true;
    }
};

struct GotIpModel {
    uint32_t target_generation = 7;
    bool manual_ap = false;
    bool retry = false;
    bool closed = false;

    void validate(bool read_ok, uint32_t observed_generation) {
        if (manual_ap || observed_generation != target_generation) return;
        if (!read_ok) {
            retry = true;
            return;
        }
        closed = true;
        retry = false;
    }
};

struct ScanModel {
    bool active = true;
    bool list_cleared = false;

    void collect(bool allocation_ok) {
        if (!allocation_ok) {
            list_cleared = true;
            active = false;
            return;
        }
        list_cleared = true;
        active = false;
    }
};

struct TimerModel {
    bool handle = false;
    bool retry = false;
    int attempts = 0;

    void schedule(bool create_ok, bool start_ok) {
        ++attempts;
        if (!handle && !create_ok) {
            retry = true;
            return;
        }
        handle = true;
        if (!start_ok) {
            retry = true;
            return;
        }
        retry = false;
    }
};

int main() {
    AdmissionModel admission;
    admission.scan_active = true;
    assert(!admission.provision());
    assert(admission.configured);
    assert(admission.target_active);
    admission.scan_active = false;
    assert(admission.provision());
    assert(!admission.configured);
    assert(!admission.target_active);

    SelectorModel selector;
    assert(!selector.apply(selector.generation));
    selector.scan_active = false;
    ++selector.generation;
    assert(!selector.apply(4));
    selector.provisioning = true;
    assert(!selector.apply(selector.generation));
    selector.provisioning = false;
    assert(selector.apply(selector.generation));

    GotIpModel got_ip;
    got_ip.validate(false, got_ip.target_generation);
    assert(got_ip.retry);
    got_ip.validate(true, got_ip.target_generation);
    assert(got_ip.closed);
    got_ip.manual_ap = true;
    got_ip.closed = false;
    got_ip.validate(true, got_ip.target_generation);
    assert(!got_ip.closed);

    ScanModel scan;
    scan.collect(false);
    assert(!scan.active);
    assert(scan.list_cleared);
    scan.active = true;
    scan.collect(true);
    assert(!scan.active);
    assert(scan.list_cleared);

    TimerModel timer;
    timer.schedule(false, false);
    assert(timer.retry);
    timer.schedule(true, false);
    assert(timer.retry);
    timer.schedule(true, true);
    assert(!timer.retry);
    assert(timer.attempts == 3);
}
'''

    def test_final_audit_admission_generation_cleanup_and_timer_failures(self):
        provision = SOURCE.split("esp_err_t idf_wifi_provision_connect", 1)[1].split(
            "static std::string wifi_scan_records_json", 1
        )[0]
        selector = SOURCE.split("static void wifi_select_task(void*)", 1)[1].split(
            "static void start_wifi_select_once", 1
        )[0]
        apply_current = SOURCE.split("static esp_err_t wifi_apply_and_connect_if_current", 1)[1].split(
            "static esp_err_t wifi_disconnect_driver_locked", 1
        )[0]
        got_ip = SOURCE.split(
            "if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)", 1
        )[1].split("// After STA gets an IP", 1)[0]
        collect = SOURCE.split("static void wifi_scan_collect_once()\n{", 1)[1].split(
            "static void scan_cleanup_timer_cb", 1
        )[0]
        remember = SOURCE.split("static void wifi_remember_task(void*)", 1)[1].split(
            "// A 15s reconnect watchdog", 1
        )[0]
        close_schedule = SOURCE.split("static void schedule_ap_close(uint32_t delay_ms)\n{", 1)[1].split(
            "static void schedule_scan_cleanup", 1
        )[0]
        close_timer = SOURCE.split("static void ap_close_timer_cb", 1)[1].split(
            "static void schedule_ap_close", 1
        )[0]
        watchdog = SOURCE.split("static void reconnect_watchdog_cb", 1)[1].split(
            "static void dns_captive_task", 1
        )[0]

        admission = provision.index("WifiDriverOperation operation(driver_timeout)")
        self.assertLess(admission, provision.index("s_sta_configured.store(false"))
        self.assertLess(admission, provision.index("replace_provisioning_target(ProvisioningTarget(), driver_timeout)"))
        self.assertNotIn("if (s_ap_close_timer) esp_timer_stop", provision)
        self.assertIn("wifi_apply_and_connect_if_current", selector)
        self.assertIn("WifiDriverOperation operation(driver_timeout)", apply_current)
        self.assertIn("s_provisioning_generation.load", apply_current)
        self.assertIn("wifi_apply_and_connect_locked", apply_current)
        self.assertIn("s_provisioning_validation_generation", got_ip)
        self.assertIn("schedule_ap_close(1000)", got_ip)
        self.assertNotIn("ScanRefreshScope", collect)
        self.assertIn("s_scan_collect_records", collect)
        self.assertIn("s_scan_collect_records", SOURCE)
        self.assertNotIn("std::vector<wifi_ap_record_t>", collect)
        self.assertNotIn("std::string json", collect)
        self.assertIn("s_scan_running.store(false", collect)
        self.assertNotIn("WifiDriverOperation operation(portMAX_DELAY", collect)
        self.assertIn("WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS), true)", collect)
        self.assertIn("wifi_remember_once", remember)
        self.assertIn("esp_timer_start_once", close_schedule)
        self.assertIn("!= ESP_OK", close_schedule)
        self.assertIn("s_ap_close_pending", close_schedule)
        self.assertIn("ap_close_timer_cb(nullptr)", watchdog)
        self.assertIn("schedule_ap_close(1000)", close_timer)
        self.assertIn("TickType_t timeout", SOURCE)

        for owner in ("wifi_scan_candidates", "wifi_scan_collect_once", "idf_wifi_scan_request"):
            section = SOURCE.split(f"{owner}", 1)[1].split("\n}", 1)[0]
            self.assertIn("pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)", section)

        with tempfile.TemporaryDirectory(prefix="idf-wifi-final-audit-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_final_audit_test.cpp"
            binary = temp / "wifi_final_audit_test"
            harness.write_text(self.FINAL_AUDIT_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness),
                 "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    CALLBACK_FAILURE_HARNESS = r'''
#include <cassert>
#include <cstdint>

struct ProvisioningCompletionModel {
    bool retry = false;
    bool completed = false;

    bool complete(bool state_lock_available) {
        if (!state_lock_available) {
            retry = true;
            return false;
        }
        completed = true;
        retry = false;
        return true;
    }
};

struct WatchdogSnapshotModel {
    bool ap_started = false;

    bool try_start(bool state_available) {
        if (!state_available) return false;
        ap_started = true;
        return true;
    }
};

struct GotIpRetryModel {
    uint32_t pending_generation = 0;
    uint32_t current_generation = 9;
    bool manual_ap = false;
    bool closed = false;

    void got_ip(bool reset_available, bool ap_snapshot_available) {
        if (pending_generation == 0) pending_generation = current_generation;
        if (!reset_available || !ap_snapshot_available) return;
        if (manual_ap || pending_generation != current_generation) return;
        closed = true;
        pending_generation = 0;
    }
};

struct ScanSchedulerModel {
    bool scan_active = false;

    bool begin(bool cleanup_timer, bool watchdog_timer) {
        if (!cleanup_timer || !watchdog_timer) return false;
        scan_active = true;
        return true;
    }
};

int main() {
    ProvisioningCompletionModel completion;
    assert(!completion.complete(false));
    assert(completion.retry);
    assert(completion.complete(true));
    assert(completion.completed);

    WatchdogSnapshotModel watchdog;
    assert(!watchdog.try_start(false));
    assert(!watchdog.ap_started);
    assert(watchdog.try_start(true));

    GotIpRetryModel got_ip;
    got_ip.got_ip(false, true);
    assert(got_ip.pending_generation == 9);
    got_ip.got_ip(true, false);
    assert(got_ip.pending_generation == 9);
    got_ip.got_ip(true, true);
    assert(got_ip.closed);
    got_ip.closed = false;
    got_ip.pending_generation = 9;
    ++got_ip.current_generation;
    got_ip.got_ip(true, true);
    assert(!got_ip.closed);
    got_ip.current_generation = 10;
    got_ip.pending_generation = 10;
    got_ip.manual_ap = true;
    got_ip.got_ip(true, true);
    assert(!got_ip.closed);

    ScanSchedulerModel scan;
    assert(!scan.begin(false, false));
    assert(!scan.scan_active);
    assert(!scan.begin(true, false));
    assert(!scan.scan_active);
    assert(scan.begin(true, true));
    assert(scan.scan_active);
}
'''

    def test_callbacks_fail_closed_with_injected_scheduler_failures(self):
        complete = SOURCE.split("static bool complete_provisioning_target", 1)[1].split(
            "static bool bind_provisioning_bssid", 1
        )[0]
        validate = SOURCE.split("static ProvisioningValidationResult validate_provisioning_target_locked", 1)[1].split(
            "// Delay AP shutdown", 1
        )[0]
        watchdog = SOURCE.split("static void reconnect_watchdog_cb", 1)[1].split(
            "static void dns_captive_task", 1
        )[0]
        start_locked = SOURCE.split("static esp_err_t start_provisioning_ap_locked", 1)[1].split(
            "static esp_err_t start_provisioning_ap(bool", 1
        )[0]
        got_ip = SOURCE.split(
            "if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)", 1
        )[1].split("// After STA gets an IP", 1)[0]
        scan_request = SOURCE.split("esp_err_t idf_wifi_scan_request(void)", 1)[1].split(
            "IdfWifiScanSnapshot idf_wifi_scan_get_snapshot", 1
        )[0]
        startup = SOURCE.split("if (!s_reconnect_timer)", 1)[1].split(
            "if (!s_scan_cleanup_timer)", 1
        )[0]

        self.assertNotIn("TickType_t timeout = portMAX_DELAY", complete)
        self.assertIn("complete_provisioning_target(generation, timeout)", validate)
        self.assertIn("start_provisioning_ap_locked(false, driver_timeout)", watchdog)
        self.assertIn("TickType_t state_timeout", start_locked)
        self.assertIn("ap_state_snapshot(ap, state_timeout)", start_locked)
        pending_store = got_ip.index("s_provisioning_validation_generation.store")
        reset_call = got_ip.index("if (!reset_recovery_state")
        ap_snapshot = got_ip.index("if (!ap_state_snapshot")
        self.assertLess(pending_store, reset_call)
        self.assertLess(pending_store, ap_snapshot)
        self.assertIn("s_provisioning_generation.load", got_ip)
        self.assertIn("if (!s_scan_cleanup_timer || !s_reconnect_timer)", scan_request)
        self.assertIn("esp_timer_start_periodic(s_reconnect_timer", startup)
        self.assertIn(") != ESP_OK", startup)

        with tempfile.TemporaryDirectory(prefix="idf-wifi-callback-failures-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_callback_failure_test.cpp"
            binary = temp / "wifi_callback_failure_test"
            harness.write_text(self.CALLBACK_FAILURE_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness),
                 "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    def test_scan_lifecycle_callbacks_reads_and_ap_start_are_bounded(self):
        scan_done = SOURCE.split(
            "if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_SCAN_DONE &&", 1
        )[1].split(
            "if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START)", 1
        )[0]
        scan_cleanup = ""
        if "static void scan_cleanup_timer_cb(void*)" in SOURCE:
            scan_cleanup = SOURCE.split("static void scan_cleanup_timer_cb(void*)", 1)[1].split(
                "static void wifi_event_handler", 1
            )[0]
        close_timer = SOURCE.split("static void ap_close_timer_cb(void*)", 1)[1].split(
            "static void schedule_ap_close", 1
        )[0]
        scan_request = SOURCE.split("esp_err_t idf_wifi_scan_request(void)", 1)[1].split(
            "IdfWifiScanSnapshot idf_wifi_scan_get_snapshot", 1
        )[0]
        scan_collect = SOURCE.split("static void wifi_scan_collect_once()\n{", 1)[1].split(
            "static void scan_cleanup_timer_cb", 1
        )[0]
        got_ip = SOURCE.split(
            "if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP)", 1
        )[1].split("// After STA gets an IP", 1)[0]
        remember = SOURCE.split("static void wifi_remember_once()\n{", 1)[1].split(
            "static void wifi_remember_task", 1
        )[0]
        status = SOURCE.split("IdfWifiStatus idf_wifi_get_status(void)", 1)[1]
        start_wrapper = SOURCE.split("static esp_err_t start_provisioning_ap(bool manual)", 1)[1].split(
            "static void provision_button_task", 1
        )[0]
        operation = SOURCE.split("class WifiDriverOperation", 1)[1].split(
            "static esp_err_t wifi_connect_locked", 1
        )[0]

        self.assertIn("schedule_scan_cleanup", scan_done)
        self.assertNotIn("WifiDriverOperation operation", scan_done)
        self.assertIn("WifiDriverOperation operation(0, true)", scan_cleanup)
        self.assertIn("schedule_scan_cleanup", scan_cleanup)
        self.assertIn("WifiDriverOperation operation(0)", close_timer)
        self.assertIn("schedule_ap_close(1000)", close_timer)
        self.assertIn("WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS), true)", scan_request)
        self.assertIn("WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS), true)", scan_collect)
        self.assertIn("if (!scan_owner", operation)
        self.assertIn("s_scan_running.load", operation)
        self.assertIn("if (!scan_owner && s_scan_running.load", operation)
        self.assertIn("WifiDriverOperation operation(0)", got_ip)
        self.assertIn("WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))", remember)
        self.assertIn("WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))", status)
        self.assertIn("WifiDriverOperation operation(driver_timeout)", start_wrapper)

        def assert_deferred(section):
            self.assertIn("schedule_scan_cleanup", section)
            self.assertNotIn("WifiDriverOperation operation", section)

        def assert_timer_bounded(section):
            self.assertIn("WifiDriverOperation operation(0)", section)
            self.assertNotIn("WifiDriverOperation operation;", section)

        def assert_scan_owner(section):
            self.assertIn("WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS), true)", section)

        def assert_read_bounded(section):
            self.assertIn("WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))", section)

        def assert_ap_start_bounded(section):
            self.assertIn("pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)", section)

        with self.assertRaises(AssertionError):
            assert_deferred(scan_done.replace("schedule_scan_cleanup", "esp_wifi_clear_ap_list", 1))
        with self.assertRaises(AssertionError):
            assert_timer_bounded(close_timer.replace("WifiDriverOperation operation(0)", "WifiDriverOperation operation", 1))
        with self.assertRaises(AssertionError):
            assert_scan_owner(scan_request.replace(
                "WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS), true)",
                "WifiDriverOperation operation", 1))
        with self.assertRaises(AssertionError):
            assert_read_bounded(remember.replace("pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)", "portMAX_DELAY", 1))
        with self.assertRaises(AssertionError):
            assert_read_bounded(status.replace(
                "WifiDriverOperation operation(pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS))",
                "WifiDriverOperation operation", 1))
        with self.assertRaises(AssertionError):
            assert_ap_start_bounded(start_wrapper.replace(
                "pdMS_TO_TICKS(WIFI_RECOVERY_SYNC_TIMEOUT_MS)", "portMAX_DELAY", 2))

        with tempfile.TemporaryDirectory(prefix="idf-wifi-scan-lifecycle-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_scan_lifecycle_test.cpp"
            binary = temp / "wifi_scan_lifecycle_test"
            harness.write_text(self.SCAN_LIFECYCLE_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness),
                 "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    CLAIM_BOUNDARY_HARNESS = r'''
#include <cassert>

struct RecoveryCompletionModel {
    bool inflight = true;
    bool completion_retry = false;
    bool close_retry = false;

    void finish(bool ap_state_known, bool completion_lock_available) {
        if (!ap_state_known) close_retry = true;
        if (!completion_lock_available) {
            completion_retry = true;
            return;
        }
        inflight = false;
        completion_retry = false;
    }

    void retry_completion(bool lock_available) {
        if (completion_retry && lock_available) {
            inflight = false;
            completion_retry = false;
        }
    }
};

struct ScanCollectionModel {
    bool running = true;
    bool error_recorded = false;

    void collect(bool bounded_storage_available) {
        if (!bounded_storage_available) error_recorded = true;
        running = false;
    }
};

int main() {
    RecoveryCompletionModel unknown;
    unknown.finish(false, true);
    assert(unknown.close_retry);
    assert(!unknown.inflight);

    RecoveryCompletionModel blocked;
    blocked.finish(true, false);
    assert(blocked.inflight);
    assert(blocked.completion_retry);
    blocked.retry_completion(true);
    assert(!blocked.inflight);
    assert(!blocked.completion_retry);

    ScanCollectionModel allocation_failure;
    allocation_failure.collect(false);
    assert(allocation_failure.error_recorded);
    assert(!allocation_failure.running);
}
'''

    def test_driver_state_and_claim_failures_are_bounded(self):
        apply_locked = SOURCE.split(
            "static esp_err_t wifi_apply_and_connect_locked", 1
        )[1].split("static esp_err_t wifi_apply_and_connect(", 1)[0]
        replace = SOURCE.split("static uint32_t replace_provisioning_target", 1)[1].split(
            "static bool complete_provisioning_target", 1
        )[0]
        bind = SOURCE.split("static bool bind_provisioning_bssid", 1)[1].split(
            "enum class ProvisioningValidationResult", 1
        )[0]
        collect = SOURCE.split("static void wifi_scan_collect_once()\n{", 1)[1].split(
            "static void scan_cleanup_timer_cb", 1
        )[0]
        finish = SOURCE.split("static bool finish_recovery_ap_claim", 1)[1].split(
            "static std::atomic<bool> s_ntp_first_logged", 1
        )[0]

        self.assertIn("TickType_t state_timeout", apply_locked)
        self.assertIn("ap_state_snapshot(ap_state, state_timeout)", apply_locked)
        self.assertNotIn("ap_state_snapshot().mode", apply_locked)
        self.assertIn("TickType_t timeout", replace)
        self.assertNotIn("xSemaphoreTake(s_state_mutex, portMAX_DELAY)", replace)
        self.assertIn("TickType_t timeout", bind)
        self.assertNotIn("xSemaphoreTake(s_state_mutex, portMAX_DELAY)", bind)
        self.assertIn("s_scan_collect_records", collect)
        self.assertNotIn("std::vector<wifi_ap_record_t>", collect)
        self.assertNotIn("std::string json", collect)
        self.assertIn("s_scan_running.store(false", collect)
        self.assertIn("state_known", finish)
        self.assertIn("schedule_ap_close(1000)", finish)
        self.assertIn("s_recovery_completion_retry_pending", SOURCE)
        self.assertNotIn("portMAX_DELAY", SOURCE)
        self.assertNotIn("static ApState ap_state_snapshot()", SOURCE)

        scan_candidates = SOURCE.split("static esp_err_t wifi_scan_candidates", 1)[1].split(
            "// Scan saved WiFi networks", 1
        )[0]
        self.assertIn("    {\n        WifiDriverOperation operation", scan_candidates)
        self.assertIn("    }\n    lease.release();\n\n    candidates.clear();", scan_candidates)
        self.assertIn("WifiScanLease lease", scan_candidates)
        self.assertIn("lease.release();\n\n    candidates.clear();", scan_candidates)
        selector_source = SOURCE.split("static void wifi_select_task(void*)", 1)[1].split(
            "static void start_wifi_select_once", 1
        )[0]
        self.assertNotIn("WifiScanLease lease", selector_source)

        watchdog = SOURCE.split("static void reconnect_watchdog_cb", 1)[1].split(
            "static void dns_captive_task", 1
        )[0]
        self.assertLess(
            watchdog.index("retry_recovery_claim_completion"),
            watchdog.index("if (!s_has_sta_credentials.load(std::memory_order_relaxed)) return;"),
        )

        with tempfile.TemporaryDirectory(prefix="idf-wifi-claim-boundary-") as temp_dir:
            temp = Path(temp_dir)
            harness = temp / "wifi_claim_boundary_test.cpp"
            binary = temp / "wifi_claim_boundary_test"
            harness.write_text(self.CLAIM_BOUNDARY_HARNESS, encoding="utf-8")
            subprocess.run(
                ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(harness),
                 "-o", str(binary)],
                check=True,
            )
            subprocess.run([str(binary)], check=True)


if __name__ == "__main__":
    unittest.main()
