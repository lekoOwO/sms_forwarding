import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MISSING = object()


def _overlay_legacy_wifi(current, ssid=MISSING, password=MISSING):
    if not isinstance(ssid, str) or not isinstance(password, str):
        return current
    try:
        ssid_bytes = ssid.encode("utf-8")
        password_bytes = password.encode("ascii")
    except UnicodeEncodeError:
        return current
    if len(ssid_bytes) > 31 or (password and not 8 <= len(password_bytes) <= 63):
        return current
    if any(byte < 0x20 or byte > 0x7E for byte in password_bytes):
        return current
    if not ssid and password:
        return current
    return (ssid, password)

class WifiHeartbeatConfigTest(unittest.TestCase):
    def test_legacy_loader_maps_only_confirmed_wifi_network_and_heartbeat_keys(self):
        source = (ROOT / "code/config.cpp").read_text()
        overlay = source[source.index("bool legacyWifiProfileValid") :
                         source.index("LegacyStatus loadLegacyConfig")]
        legacy = source[source.index("LegacyStatus loadLegacyConfig") :
                        source.index("bool openConfigStorage")]

        for key in ("wifiSSID", "wifiPass", "wifiSSID2", "wifiPass2"):
            self.assertIn(f'"{key}"', overlay)
        self.assertIn("preferences.getString(ssidKey", overlay)
        self.assertIn("preferences.getString(passwordKey", overlay)
        self.assertIn('preferences.getInt("networkMode"', overlay)
        self.assertIn('preferences.getType("networkMode") == PT_I32', overlay)
        self.assertIn("mode >= NETWORK_MODE_WIFI_ONLY && mode <= NETWORK_MODE_MIX", overlay)
        self.assertIn('preferences.getType("heartbeatEnable") == PT_U8', overlay)
        self.assertIn('preferences.getUChar("heartbeatEnable"', overlay)
        self.assertIn("enabled <= 1", overlay)
        self.assertIn("legacyWifiProfileValid", overlay)
        self.assertNotIn('preferences.getString("remark"', overlay)
        self.assertNotIn("heartbeatInterval", overlay)
        self.assertIn("overlayLegacyConnectivity(value)", legacy)
        self.assertIn('preferences.getString("remark"', legacy)
        self.assertIn("boundedUtf8(remark, MAX_DEVICE_NAME_BYTES)", legacy)
        self.assertIn("hasNoAsciiControls(remark)", legacy)
        self.assertNotIn('preferences.getInt("heartbeatInterval"', legacy)
        self.assertIn("storageSemanticsValid(value)", legacy)

    def test_malformed_or_partial_legacy_wifi_does_not_replace_valid_slot_values(self):
        current = ("slot-network", "slot-password")
        for candidate in (
            {"password": "legacy-pass"},
            {"ssid": "x" * 32, "password": "legacy-pass"},
            {"ssid": "legacy", "password": "short"},
            {"ssid": "legacy", "password": "密碼password"},
            {"ssid": "legacy"},
        ):
            self.assertEqual(current, _overlay_legacy_wifi(current, **candidate))
        self.assertEqual(("legacy", "legacy-pass"),
                         _overlay_legacy_wifi(current, "legacy", "legacy-pass"))
        self.assertEqual(("guest", ""), _overlay_legacy_wifi(current, "guest", ""))

    def test_old_slots_overlay_legacy_connectivity_then_atomically_upgrade_to_v4(self):
        source = (ROOT / "code/config.cpp").read_text()
        slot = source[source.index("struct SlotState") : source.index("void setDefaults")]
        read_slot = source[source.index("bool readSlot") : source.index("bool generationNewer")]
        load = source[source.index("ConfigLoadStatus loadConfig") :
                      source.index("bool isPushChannelValid")]

        self.assertIn("uint16_t schema", slot)
        self.assertIn("&state.schema", read_slot)
        upgrade = load[load.index("if (hasValidSlot)") : load.index("bool hasSlotData")]
        self.assertIn("slots[selected].schema < CONFIG_SCHEMA_VERSION", upgrade)
        self.assertIn("overlayLegacyConnectivity", upgrade)
        self.assertIn("storageSemanticsValid", upgrade)
        self.assertIn("saveConfig(selectedConfig)", upgrade)
        self.assertLess(upgrade.index("storageSemanticsValid"),
                        upgrade.index("saveConfig(selectedConfig)"))
        self.assertLess(upgrade.index("saveConfig(selectedConfig)"),
                        upgrade.index("config = std::move(selectedConfig)"))

    def test_push_snapshot_redacts_secrets_and_save_retains_or_resets_safely(self):
        source = (ROOT / "code/web_handlers.cpp").read_text()
        snapshot = source[source.index("void handleConfig()") :
                          source.index("// Handle flight mode")]
        save = source[source.index("// Push channel configuration") :
                      source.index("if (!isConfigSemanticallyValid(next))")]

        for field in ("url", "key1", "key2", "customBody"):
            self.assertIn(f'channelJson["{field}"] = ""', snapshot)
            self.assertIn(f'channelJson["{field}Set"] = channel.{field}.length() > 0', snapshot)
        self.assertIn("bool typeChanged", save)
        for field in ("url", "key1", "key2", "customBody"):
            self.assertIn(f"channel.{field} = \"\"", save)
        for key in ("urlKey", "k1Key", "k2Key", "bodyKey"):
            self.assertIn(f"requestHasArg({key}) && requestArg({key}).length() > 0", save)
        whole_handler = source[source.index("void handleSave()") : source.index("// Handle log queries")]
        self.assertLess(whole_handler.index("isConfigSemanticallyValid(next)"),
                        whole_handler.index("saveConfig(next)"))
        self.assertLess(whole_handler.index("saveConfig(next)"),
                        whole_handler.index("config = next"))

    def test_v4_appends_portable_wifi_and_legacy_network_timers(self):
        schema_dir = ROOT / "dev_doc/config-schema"
        manifest = json.loads((schema_dir / "manifest.json").read_text())
        self.assertEqual(4, manifest["currentVersion"])
        schema = json.loads((schema_dir / manifest["versions"]["4"]).read_text())
        config = schema["properties"]["config"]["properties"]

        wifi = config["wifiProfiles"]
        self.assertEqual(5, wifi["x-itemCount"])
        self.assertTrue(wifi["x-portableRestore"])
        self.assertEqual(31, wifi["items"]["properties"]["ssid"]["x-maxUtf8Bytes"])
        password = wifi["items"]["properties"]["password"]
        self.assertEqual(63, password["x-maxUtf8Bytes"])
        self.assertEqual("^(?:|[ -~]{8,63})$", password["pattern"])

        expected = {
            "networkMode": (0, 0, 2),
            "heartbeatEnable": (True, None, None),
            "heartbeatInterval": (6, 1, 240),
        }
        for name, (default, minimum, maximum) in expected.items():
            field = config[name]
            self.assertEqual(default, field["default"])
            if minimum is not None:
                self.assertEqual(minimum, field["minimum"])
                self.assertEqual(maximum, field["maximum"])

    def test_sta_failure_starts_basic_auth_provisioning_ap_instead_of_rebooting(self):
        globals_source = (ROOT / "code/globals.cpp").read_text()
        sketch = (ROOT / "code/code.ino").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()

        self.assertIn('WiFi.softAP(apSsid.c_str(), "sms-forwarder-setup")', globals_source)
        self.assertIn("WIFI_AP_STA", globals_source)
        self.assertIn("startProvisioningAp()", sketch)
        self.assertIn("networkTick();", sketch)
        self.assertIn("apActive && WiFi.status() == WL_CONNECTED", globals_source)
        self.assertNotIn("WiFiMulti", globals_source)
        self.assertIn("WIFI_AUTH_WPA2_PSK", globals_source)
        self.assertIn("WIFI_AUTH_OPEN", globals_source)
        self.assertIn('profile["open"]', handlers)
        self.assertIn("next.wifiProfiles[i].password.length() == 0", handlers)
        self.assertNotIn("ESP.restart();", sketch)
        self.assertIn('status["apMode"]', handlers)

    def test_cellular_transport_fails_closed_without_touching_paid_data(self):
        modem = (ROOT / "code/modem.cpp").read_text()
        push = (ROOT / "code/push.cpp").read_text()
        transport = modem[modem.index("bool modemHttpPost(") :
                          modem.index("// Power-cycle the modem")]
        self.assertIn("statusCode = -1", transport)
        self.assertIn("Cellular delivery is disabled until a CA is provisioned", transport)
        self.assertIn("return false", transport)
        self.assertIn("Cellular transport does not support GET", push)
        for forbidden in (
            "AT+CEREG?",
            "AT+CGACT=1,1",
            "AT+MHTTP",
            "runTransaction(",
            "Serial1.write",
            "Serial1.print",
        ):
            self.assertNotIn(forbidden, transport)

    def test_heartbeat_uses_monotonic_hours_after_ntp_and_push_only(self):
        sketch = (ROOT / "code/code.ino").read_text()
        self.assertIn("sendSystemPushNotification", sketch)
        self.assertIn("3600000UL", sketch)
        self.assertIn("time(nullptr) >= 1700000000", sketch)
        heartbeat_block = sketch[sketch.index("void heartbeatTick()") : sketch.index("void setup()")]
        self.assertNotIn("sendEmailNotification", heartbeat_block)


if __name__ == "__main__":
    unittest.main()
