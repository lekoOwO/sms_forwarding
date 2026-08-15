import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class HttpLimitsTest(unittest.TestCase):
    def test_pinned_webserver_patch_is_hash_guarded(self):
        patch = (ROOT / "scripts/patches/esp32-webserver-3.3.10-request-limits.patch").read_text()
        apply = (ROOT / "scripts/apply-esp32-webserver-3.3.10-patch.sh").read_text()
        check = (ROOT / "scripts/check-esp32-webserver-3.3.10-patch.sh").read_text()
        dev = (ROOT / "scripts/dev.sh").read_text()
        self.assertIn("original=522a46a1b8bed19b5482b65eb96bb87fe068c937c4516d17111179b2e8b88adc", apply)
        self.assertIn("HTTP_REQUEST_LINE_LIMIT = 2048", patch)
        self.assertIn("HTTP_HEADER_LIMIT = 8192", patch)
        self.assertIn("HTTP_BODY_LIMIT = 16384", patch)
        self.assertIn("hasContentLength || !parseContentLength", patch)
        self.assertIn('413, "Payload Too Large"', patch)
        expected = "2dfea7725ea715a9e94bc256ba7ada831bebbca5a3bfeee417e4000c86034610"
        self.assertIn(f"patched={expected}", apply)
        self.assertIn(f"expected={expected}", check)
        self.assertIn("apply-esp32-webserver-3.3.10-patch.sh", dev)

    def test_openapi_and_frontend_publish_utf8_byte_limits(self):
        spec = json.loads((ROOT / "dev_doc/openapi.json").read_text())
        self.assertEqual(spec["x-requestLimits"]["requestLineBytes"], 2048)
        self.assertEqual(spec["x-requestLimits"]["totalHeaderBytes"], 8192)
        self.assertEqual(spec["x-requestLimits"]["bodyBytes"], 16384)
        update = spec["components"]["schemas"]["ConfigUpdate"]
        self.assertEqual(update["properties"]["smtpServer"]["x-maxUtf8Bytes"], 253)
        self.assertEqual(update["patternProperties"]["^push[0-4]body$"]["x-maxUtf8Bytes"], 2048)
        page = (ROOT / "web/src/routes/+page.svelte").read_text()
        self.assertIn("new TextEncoder()", page)
        self.assertIn("const index = Number(pushTab)", page)


if __name__ == "__main__":
    unittest.main()
