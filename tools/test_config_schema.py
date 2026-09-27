#!/usr/bin/env python3
"""Focused tests for the versioned configuration schema contract."""

from __future__ import annotations

import hashlib
import json
import re
import subprocess
import sys
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SCHEMA_DIR = ROOT / "dev_doc/config-schema"

# Published schema files are immutable wire-format compatibility fixtures.
IMMUTABLE_SCHEMA_SHA256 = {
    1: "80b341a31713f61f14f8373bf7ecfdfc06b755efd7d701688f9967d25d08f448",
    2: "acfbfae7c5e6691e8c445d4d5d13125ee70b0eb1b6775e00e146ca3f7f3d6a18",
    3: "f83c9413623b8d0a99665a078993ed98aff6b0c1d40cc97e2597b751a8f96aa6",
    4: "51ebce31de035cc853d5b9e55a7c46233724121369c543839bed258c8a1d4984",
    5: "01318a093657a2e166b65dd6cd31650a5dcb79a70860fb068a6b9cc392b9de58",
    6: "ae57a2b7f9bd53250c07f145f79c3e5a6c3af5435955f2f8b2f3fc22bd331dbb",
}


class ConfigSchemaTest(unittest.TestCase):
    def test_legacy_schema_fixtures_and_manifest_envelope_are_unchanged(self) -> None:
        manifest = json.loads((SCHEMA_DIR / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["format"], "sms-forwarding-config")
        self.assertEqual(manifest["backupEnvelope"]["magic"], "SMSCFG01")
        self.assertEqual(manifest["backupEnvelope"]["byteOrder"], "little-endian")
        self.assertEqual(manifest["backupEnvelope"]["headerBytes"], 44)
        self.assertEqual(manifest["backupEnvelope"]["aadBytes"], 44)
        self.assertEqual(manifest["backupEnvelope"]["maxEncryptedBytes"], 32828)
        for version, digest in IMMUTABLE_SCHEMA_SHA256.items():
            path = SCHEMA_DIR / manifest["versions"][str(version)]
            self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)

    def test_v7_adds_bounded_sensitive_cellular_channel_settings(self) -> None:
        manifest = json.loads((SCHEMA_DIR / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["currentVersion"], 7)
        schema = json.loads((SCHEMA_DIR / manifest["versions"]["7"]).read_text(encoding="utf-8"))
        config = schema["properties"]["config"]["properties"]
        channel = config["pushChannels"]["items"]
        self.assertIn("cellularEnabled", channel["required"])
        self.assertIn("cellularUrl", channel["required"])
        self.assertEqual(channel["properties"]["cellularEnabled"]["default"], True)
        self.assertEqual(channel["properties"]["cellularEnabled"]["x-codecOrder"], 9)
        self.assertEqual(channel["properties"]["cellularUrl"]["default"], "")
        self.assertEqual(channel["properties"]["cellularUrl"]["maxLength"], 512)
        self.assertEqual(channel["properties"]["cellularUrl"]["x-maxUtf8Bytes"], 512)
        self.assertEqual(channel["properties"]["cellularUrl"]["x-codecOrder"], 10)
        self.assertTrue(channel["properties"]["cellularUrl"]["x-sensitive"])
        self.assertNotIn("wifiFromFallback", config)
        for field in (
            "deviceName", "notificationLocale", "wifiProfiles", "networkMode", "heartbeatEnable",
            "heartbeatInterval", "wifiTxPowerQuarterDbm", "webAccounts",
            "emailEnabled", "pushEnabled", "forwardRules", "kaEnabled", "kaIntervalDays", "kaTrafficKB",
            "kaAction", "kaTarget", "kaUrl", "kaProfile", "kaLastTime", "tzOffsetMin",
            "ntpServer", "rebootEnabled", "rebootHour",
            "smsHealthEnabled", "smsHealthHour", "smsHealthNotify", "netLedEnabled",
            "callNotifyEnabled", "dataEnabled", "roamingEnabled", "apn", "operatorPlmn",
            "phoneNumber", "simCredentials", "pushChannels", "schedTasks",
        ):
            self.assertIn(field, config)
        self.assertNotIn("webUser", config)
        self.assertNotIn("webPass", config)
        self.assertNotIn("mdnsHost", config)
        self.assertNotIn("hbEnabled", config)
        self.assertNotIn("hbHour", config)
        self.assertEqual(
            schema["x-legacyMigration"]["keepalive"],
            {
                "enabled": {"from": "kaEnable", "target": "kaEnabled"},
                "intervalDays": {"from": "kaIntervalDays", "target": "kaIntervalDays"},
                "trafficKB": {"from": "kaTraffic", "target": "kaTrafficKB"},
                "baseDate": {"from": "kaBaseDate", "target": "kaLastTime"},
            },
        )
        self.assertEqual(config["kaTrafficKB"]["minimum"], 1)
        self.assertEqual(config["kaTrafficKB"]["maximum"], 10000)
        self.assertEqual(config["kaTrafficKB"]["default"], 1)
        self.assertEqual(config["kaTrafficKB"]["x-runtimeMax"], 512)
        self.assertIn("512", config["kaTrafficKB"]["description"])
        self.assertNotIn("MHTTP", config["kaTrafficKB"]["description"])
        self.assertIn("action 1", config["kaAction"]["description"].lower())
        self.assertIn("verified cellular HTTPS GET", config["kaAction"]["description"])
        task_action = config["schedTasks"]["items"]["properties"]["action"]
        self.assertIn("action 1", task_action["description"].lower())
        self.assertIn("unsupported", task_action["description"].lower())
        self.assertEqual(
            schema["x-legacyMigration"],
            {
                "mdnsHost": {
                    "target": "hostname",
                    "policy": "copy-if-target-default",
                },
                "hbEnabled": {
                    "target": "heartbeatEnable",
                    "policy": "copy-if-target-default",
                },
                "hbHour": {
                    "target": "heartbeatInterval",
                    "policy": "ignore-use-default",
                    "default": 6,
                    "reason": "daily clock hour has no interval equivalent",
                },
                "keepalive": {
                    "enabled": {"from": "kaEnable", "target": "kaEnabled"},
                    "intervalDays": {"from": "kaIntervalDays", "target": "kaIntervalDays"},
                    "trafficKB": {"from": "kaTraffic", "target": "kaTrafficKB"},
                    "baseDate": {"from": "kaBaseDate", "target": "kaLastTime"},
                },
            },
        )
        self.assertEqual(
            config["webAccounts"]["x-legacyMigration"],
            {"from": ["webUser", "webPass"], "target": "webAccounts[0]"},
        )
        self.assertEqual(config["wifiProfiles"]["x-itemCount"], 5)
        self.assertEqual(config["webAccounts"]["x-itemCount"], 10)
        self.assertEqual(config["pushChannels"]["items"]["properties"]["type"]["minimum"], 1)
        self.assertEqual(config["pushChannels"]["items"]["properties"]["type"]["maximum"], 12)
        self.assertEqual(config["simCredentials"]["x-itemCount"], 5)
        self.assertEqual(config["pushChannels"]["items"]["properties"]["titleTemplate"]["x-maxUtf8Bytes"], 256)
        self.assertEqual(config["pushChannels"]["items"]["properties"]["bodyTemplate"]["x-maxUtf8Bytes"], 2048)
        for field in (
            "deviceName", "hostname", "webAccounts",
            "phoneNumber",
            "simCredentials", "kaProfile", "kaLastTime",
        ):
            self.assertFalse(config[field]["x-portableRestore"])
        for field in ("wifiProfiles", "networkMode", "heartbeatEnable", "heartbeatInterval"):
            self.assertTrue(config[field]["x-portableRestore"])
        wifi = config["wifiProfiles"]["items"]["properties"]
        self.assertTrue(wifi["ssid"].get("x-portableRestore", True))
        self.assertTrue(wifi["password"].get("x-portableRestore", True))
        sim = config["simCredentials"]["items"]["properties"]
        for field in ("iccid", "pin", "puk", "pinMaxAttempts", "pukMaxAttempts", "pinFailedAttempts", "pukFailedAttempts"):
            self.assertFalse(sim[field]["x-portableRestore"])
        task = config["schedTasks"]["items"]["properties"]
        self.assertFalse(task["profile"]["x-portableRestore"])
        self.assertFalse(task["lastRun"]["x-portableRestore"])
        wifi = config["wifiProfiles"]["items"]["properties"]
        self.assertEqual(wifi["ssid"]["maxLength"], 31)
        self.assertEqual(wifi["ssid"]["x-maxUtf8Bytes"], 31)
        self.assertEqual(wifi["password"]["maxLength"], 63)
        self.assertEqual(wifi["password"]["x-maxUtf8Bytes"], 63)
        self.assertEqual(wifi["password"]["pattern"], r"^(?:|[ -~]{8,63})$")
        password_pattern = re.compile(wifi["password"]["pattern"])
        self.assertIsNotNone(password_pattern.fullmatch(""))
        self.assertIsNotNone(password_pattern.fullmatch("12345678"))
        self.assertIsNotNone(password_pattern.fullmatch("x" * 63))
        self.assertIsNone(password_pattern.fullmatch("1234567"))
        self.assertIsNone(password_pattern.fullmatch("x" * 64))
        self.assertIsNone(password_pattern.fullmatch("password\n"))
        self.assertEqual(config["phoneNumber"]["maxLength"], 32)
        self.assertEqual(config["phoneNumber"]["x-maxUtf8Bytes"], 32)
        self.assertFalse(config["roamingEnabled"]["default"])
        self.assertFalse(config["roamingEnabled"]["x-portableRestore"])
        self.assertEqual(config["smtpServer"]["maxLength"], 253)
        self.assertEqual(config["smtpUser"]["maxLength"], 254)
        self.assertEqual(
            config["wifiTxPowerQuarterDbm"]["enum"],
            [8, 20, 28, 34, 44, 52, 56, 60, 66, 72, 80],
        )
        self.assertEqual(
            config["pushChannels"]["items"]["properties"]["key2"]["x-maxUtf8Bytes"], 256
        )

    def test_worst_case_wire_size_is_bounded(self) -> None:
        manifest = json.loads((SCHEMA_DIR / "manifest.json").read_text(encoding="utf-8"))
        schema = json.loads((SCHEMA_DIR / manifest["versions"]["7"]).read_text(encoding="utf-8"))
        wire = schema["x-wireCodec"]
        self.assertEqual(wire["headerBytes"], 20)
        self.assertEqual(wire["stringLengthPrefixBytes"], 2)
        self.assertEqual(wire["arrayCountBytes"], 1)
        self.assertEqual(wire["scalarBytes"], {"boolean": 1, "integer": 4})
        self.assertEqual(schema["x-wireWorstCase"]["binaryBytes"], 29331)
        self.assertEqual(schema["x-wireWorstCase"]["payloadBytes"], 29311)
        self.assertEqual(
            schema["x-wireWorstCase"]["headroomBytes"],
            manifest["maxBinaryBytes"] - schema["x-wireWorstCase"]["binaryBytes"],
        )
        self.assertGreaterEqual(schema["x-wireWorstCase"]["headroomBytes"], 0)

    def test_generated_idf_header_has_no_drift(self) -> None:
        subprocess.run(
            [sys.executable, "tools/generate-config-schema.py", "--check"],
            cwd=ROOT,
            check=True,
        )
        header = (ROOT / "components/idf_config/include/config_schema_generated.h").read_text(
            encoding="utf-8"
        )
        self.assertIn("CONFIG_SCHEMA_VERSION = 7", header)
        self.assertIn("MAX_SIM_CREDENTIALS 5", header)
        self.assertIn("PUSH_TYPE_NTFY = 12", header)
        self.assertNotIn("MAX_WEB_USER_BYTES", header)
        self.assertNotIn("MAX_WEB_PASS_BYTES", header)
        self.assertIn("MAX_PUSH_CELLULAR_URL_BYTES = 512", header)
        self.assertIn("CONFIG_WORST_CASE_BINARY_BYTES = 29331", header)
        self.assertIn("CONFIG_BINARY_HEADROOM_BYTES = 3437", header)
        self.assertNotIn("MAX_MDNS_HOST_BYTES", header)

    def test_generated_web_schema_has_no_drift(self) -> None:
        manifest = json.loads((SCHEMA_DIR / "manifest.json").read_text(encoding="utf-8"))
        schema = json.loads((SCHEMA_DIR / manifest["versions"][str(manifest["currentVersion"])]).read_text(encoding="utf-8"))
        config = schema["properties"]["config"]["properties"]
        generated = (ROOT / "web/src/lib/config-schema.generated.ts").read_text(encoding="utf-8")

        self.assertIn(
            f"CONFIG_SCHEMA_VERSION = {schema['properties']['schemaVersion']['const']} as const",
            generated,
        )
        self.assertIn(f'"smtpSendTo": {config["smtpSendTo"]["x-maxUtf8Bytes"]}', generated)
        self.assertIn(f'"adminPhone": {config["adminPhone"]["x-maxUtf8Bytes"]}', generated)
        self.assertIn(
            f"networkMode: {{ min: {config['networkMode']['minimum']}, max: {config['networkMode']['maximum']}, default: {config['networkMode']['default']} }}",
            generated,
        )
        self.assertIn(
            f"heartbeatInterval: {{ min: {config['heartbeatInterval']['minimum']}, max: {config['heartbeatInterval']['maximum']}, default: {config['heartbeatInterval']['default']} }}",
            generated,
        )


if __name__ == "__main__":
    unittest.main()
