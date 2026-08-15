import json
import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ApiContractTest(unittest.TestCase):
    def test_openapi_matches_firmware_routes(self):
        spec = json.loads((ROOT / "dev_doc/openapi.json").read_text())
        sketch = (ROOT / "code/code.ino").read_text()
        registrations = re.findall(
            r'server\.on\("([^\"]+)"(?:,\s*(HTTP_[A-Z]+))?,', sketch
        )
        firmware = {
            (path, "post" if method == "HTTP_POST" else "get")
            for path, method in registrations
        }
        documented = {
            (path, method)
            for path, operations in spec["paths"].items()
            for method in operations
            if method in {"get", "post"}
        }
        self.assertEqual(firmware, documented)
        self.assertEqual(spec["openapi"], "3.1.0")
        self.assertEqual(
            spec["components"]["securitySchemes"]["basicAuth"],
            {"type": "http", "scheme": "basic"},
        )
        for operations in spec["paths"].values():
            for method, operation in operations.items():
                if method in {"get", "post"}:
                    self.assertTrue(
                        {"200", "201", "202"} & operation["responses"].keys()
                    )
                    self.assertIn("401", operation["responses"])

    def test_mock_and_development_entrypoint_exist(self):
        compose = (ROOT / "compose.yaml").read_text()
        dockerfile = (ROOT / "mock_server/Dockerfile").read_text()
        script = (ROOT / "scripts/dev.sh").read_text()
        self.assertIn("mock-server:", compose)
        self.assertIn("4174:3000", compose)
        self.assertIn("./web:/web:ro", compose)
        self.assertIn("WEB_ROOT: /web/build", compose)
        self.assertIn("FROM node:22-alpine", dockerfile)
        for command in (
            "start mock-server",
            "stop mock-server",
            "restart mock-server",
            "build frontend",
            "build firmware",
        ):
            self.assertIn(command, script)

    def test_frontend_routes_are_documented(self):
        spec = json.loads((ROOT / "dev_doc/openapi.json").read_text())
        page = (ROOT / "web/src/routes/+page.svelte").read_text()
        api = (ROOT / "web/src/lib/api.ts").read_text()
        frontend = {
            "/api/config",
            "/save",
            "/sendsms",
            "/ping",
            "/query",
            "/flight",
            "/at",
            "/log",
            "/modem",
            "/wifi",
            "/api/config/export",
            "/api/config/restore/start",
            "/api/config/restore/chunk",
            "/api/config/restore/finish",
            "/api/jobs",
            "/api/ota/start",
            "/api/ota/chunk",
            "/api/ota/finish",
        }
        for path in frontend:
            self.assertIn(path, spec["paths"])
            self.assertIn(path, page + api)


if __name__ == "__main__":
    unittest.main()
