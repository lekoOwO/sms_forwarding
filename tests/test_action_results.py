import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ActionResultsTest(unittest.TestCase):
    def test_action_result_contract_and_codes_match_every_runtime(self):
        spec = json.loads((ROOT / "dev_doc/openapi.json").read_text())
        schema = spec["components"]["schemas"]["ActionResult"]
        self.assertEqual(schema["required"], ["success", "code", "data", "detail"])
        self.assertNotIn("message", schema["properties"])
        self.assertEqual(schema["properties"]["data"], {"$ref": "#/components/schemas/ActionData"})
        documented = set(schema["properties"]["code"]["enum"])

        pattern = r'"(ACTION_[A-Z0-9_]+)"'
        # Every ActionResult producer participates in the public contract.
        runtime_sources = "\n".join(
            (ROOT / path).read_text()
            for path in (
                "code/web_handlers.cpp",
                "code/config_backup.cpp",
                "code/ota_update.cpp",
            )
        )
        firmware = set(re.findall(pattern, runtime_sources))
        mock = set(re.findall(pattern, (ROOT / "mock_server/server.mjs").read_text()))
        self.assertEqual(firmware, documented)
        self.assertEqual(mock, documented)

        for locale in ("en", "zh-TW", "zh-CN"):
            messages = json.loads((ROOT / f"web/src/lib/locales/{locale}.json").read_text())
            self.assertTrue(documented <= messages.keys(), locale)

    def test_structured_action_fields_match_firmware_mock_and_frontend(self):
        spec = json.loads((ROOT / "dev_doc/openapi.json").read_text())
        fields = set(spec["components"]["schemas"]["ActionData"]["properties"])
        self.assertEqual(fields, {
            "manufacturer", "model", "revision", "rsrpDbm", "rsrqDb", "cesq",
            "imsi", "iccid", "msisdn", "registration", "operator", "pdpActive",
            "apn", "wifiStatus", "ssid", "rssiDbm", "ip", "gateway", "netmask",
            "dns", "mac", "bssid", "channel", "mode", "raw", "latencyMs", "ttl",
            "signalDbm", "rssi", "ber", "imei", "jobId", "uploadId", "exportId",
            "chunkSize", "nextOffset",
        })

        firmware = "\n".join(
            (ROOT / path).read_text()
            for path in ("code/web_handlers.cpp", "code/config_backup.cpp", "code/ota_update.cpp")
        )
        self.assertIn('setStringOrNull(dataObject, "manufacturer", manufacturer)', firmware)
        mock = (ROOT / "mock_server/server.mjs").read_text()
        for field in fields:
            self.assertIn(f'"{field}"', firmware, field)
            self.assertRegex(mock, rf"\b{field}\b", field)

        component = (ROOT / "web/src/lib/components/ActionResult.svelte").read_text()
        self.assertIn("Object.entries(result.data)", component)
        self.assertNotIn("readableDeviceMessage", component)

    def test_each_device_tool_owns_its_result_and_statuses_are_separated(self):
        page = (ROOT / "web/src/routes/+page.svelte").read_text()
        self.assertNotIn("deviceResult", page)
        for name in ("overviewResult", "diagnosticsResult", "networkResult", "controlResult", "terminalResult", "logsResult"):
            self.assertIn(name, page)
            self.assertIn(f"result={{{name}}}", page)
        self.assertGreaterEqual(page.count('orientation="vertical"'), 2)


if __name__ == "__main__":
    unittest.main()
