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

# The v1-v4 files are immutable wire-format compatibility fixtures.
IMMUTABLE_SCHEMA_SHA256 = {
    1: "80b341a31713f61f14f8373bf7ecfdfc06b755efd7d701688f9967d25d08f448",
    2: "acfbfae7c5e6691e8c445d4d5d13125ee70b0eb1b6775e00e146ca3f7f3d6a18",
    3: "f83c9413623b8d0a99665a078993ed98aff6b0c1d40cc97e2597b751a8f96aa6",
    4: "51ebce31de035cc853d5b9e55a7c46233724121369c543839bed258c8a1d4984",
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

    def test_v5_covers_durable_idf_fields_and_portable_boundaries(self) -> None:
        manifest = json.loads((SCHEMA_DIR / "manifest.json").read_text(encoding="utf-8"))
        self.assertEqual(manifest["currentVersion"], 5)
        schema = json.loads((SCHEMA_DIR / manifest["versions"]["5"]).read_text(encoding="utf-8"))
        config = schema["properties"]["config"]["properties"]
        self.assertNotIn("wifiFromFallback", config)
        for field in (
            "deviceName", "notificationLocale", "wifiProfiles", "networkMode", "heartbeatEnable",
            "heartbeatInterval", "wifiTxPowerQuarterDbm", "webAccounts",
            "emailEnabled", "pushEnabled", "forwardRules", "kaEnabled", "kaIntervalDays",
            "kaAction", "kaTarget", "kaUrl", "kaProfile", "kaLastTime", "tzOffsetMin",
            "ntpServer", "mdnsHost", "rebootEnabled", "rebootHour", "hbEnabled", "hbHour",
            "smsHealthEnabled", "smsHealthHour", "smsHealthNotify", "netLedEnabled",
            "callNotifyEnabled", "dataEnabled", "roamingEnabled", "apn", "operatorPlmn",
            "phoneNumber", "simCredentials", "pushChannels", "schedTasks",
        ):
            self.assertIn(field, config)
        self.assertNotIn("webUser", config)
        self.assertNotIn("webPass", config)
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
            "deviceName", "hostname", "webAccounts", "wifiProfiles", "networkMode",
            "heartbeatEnable", "heartbeatInterval", "phoneNumber",
            "simCredentials", "kaProfile", "kaLastTime",
        ):
            self.assertFalse(config[field]["x-portableRestore"])
        wifi = config["wifiProfiles"]["items"]["properties"]
        self.assertFalse(wifi["ssid"]["x-portableRestore"])
        self.assertFalse(wifi["password"]["x-portableRestore"])
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
        self.assertEqual(
            config["pushChannels"]["items"]["properties"]["key2"]["x-maxUtf8Bytes"], 256
        )

    def test_worst_case_wire_size_is_bounded(self) -> None:
        manifest = json.loads((SCHEMA_DIR / "manifest.json").read_text(encoding="utf-8"))
        schema = json.loads((SCHEMA_DIR / manifest["versions"]["5"]).read_text(encoding="utf-8"))
        wire = schema["x-wireCodec"]
        self.assertEqual(wire["headerBytes"], 20)
        self.assertEqual(wire["stringLengthPrefixBytes"], 2)
        self.assertEqual(wire["arrayCountBytes"], 1)
        self.assertEqual(wire["scalarBytes"], {"boolean": 1, "integer": 4})
        self.assertEqual(schema["x-wireWorstCase"]["binaryBytes"], 26540)
        self.assertEqual(schema["x-wireWorstCase"]["payloadBytes"], 26520)
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
        self.assertIn("CONFIG_SCHEMA_VERSION = 5", header)
        self.assertIn("MAX_SIM_CREDENTIALS 5", header)
        self.assertIn("PUSH_TYPE_NTFY = 12", header)
        self.assertNotIn("MAX_WEB_USER_BYTES", header)
        self.assertNotIn("MAX_WEB_PASS_BYTES", header)
        self.assertIn("CONFIG_WORST_CASE_BINARY_BYTES = 26540", header)
        self.assertIn("CONFIG_BINARY_HEADROOM_BYTES = 6228", header)


if __name__ == "__main__":
    unittest.main()
