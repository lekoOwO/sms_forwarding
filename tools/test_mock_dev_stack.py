import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class MockDevStackTests(unittest.TestCase):
    def test_compose_has_only_the_bounded_mock_service(self):
        self.assertTrue((ROOT / "compose.yaml").is_file(), "compose.yaml must define the mock runtime")
        self.assertTrue((ROOT / "mock_server" / "Dockerfile").is_file(), "mock image definition must exist")
        services = subprocess.run(
            ["docker", "compose", "-f", "compose.yaml", "config", "--services"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout.splitlines()
        self.assertEqual(services, ["mock-server"])

        config = json.loads(subprocess.run(
            ["docker", "compose", "-f", "compose.yaml", "config", "--format", "json"],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout)
        self.assertEqual(set(config["services"]), {"mock-server"})
        service = config["services"]["mock-server"]
        self.assertEqual(service["ports"], [{
            "mode": "ingress", "target": 3000, "published": "4174", "protocol": "tcp",
        }])
        self.assertEqual(service["volumes"], [
            {
                "type": "bind", "source": str(ROOT / "web" / "build"),
                "target": "/web/build", "read_only": True,
            },
            {
                "type": "bind", "source": str(ROOT / "dev_doc" / "openapi.json"),
                "target": "/spec/openapi.json", "read_only": True,
            },
        ])
        self.assertIs(service["read_only"], True)
        self.assertFalse(service.get("privileged", False))
        self.assertNotEqual(service.get("network_mode"), "host")
        self.assertNotIn("secrets", service)

        dockerfile = (ROOT / "mock_server" / "Dockerfile").read_text(encoding="utf-8")
        self.assertEqual(
            dockerfile.splitlines()[0],
            "FROM node:24.14.0-alpine@sha256:7fddd9ddeae8196abf4a3ef2de34e11f7b1a722119f91f28ddf1e99dcafdf114",
        )
        self.assertIn("npm ci --omit=dev", dockerfile)
        self.assertNotIn("chromium", dockerfile.lower())

    def test_dev_wrapper_dispatches_documented_commands_without_translation(self):
        self.assertTrue((ROOT / "scripts" / "dev.sh").is_file(), "development command wrapper must exist")
        with tempfile.TemporaryDirectory() as directory:
            fake_bin = Path(directory)
            log = fake_bin / "calls.log"
            fake = "#!/bin/sh\nprintf '%s %s\\n' \"$(basename \"$0\")\" \"$*\" >> \"$CALL_LOG\"\n"
            for name in ("docker", "npm", "python3"):
                executable = fake_bin / name
                executable.write_text(fake, encoding="utf-8")
                executable.chmod(executable.stat().st_mode | stat.S_IXUSR)
            env = {**os.environ, "PATH": f"{fake_bin}:{os.environ['PATH']}", "CALL_LOG": str(log)}
            for command in (
                "web-install", "web-check", "web-build", "firmware-build", "lint",
                "mock-start", "mock-stop", "mock-logs", "mock-test",
            ):
                subprocess.run([str(ROOT / "scripts" / "dev.sh"), command], cwd=ROOT, env=env, check=True)
            self.assertEqual(
                log.read_text(encoding="utf-8").splitlines(),
                [
                    "npm ci --prefix web",
                    "npm --prefix web run check",
                    "npm --prefix web run build",
                    "python3 tools/device.py build",
                    "python3 tools/run_lint.py",
                    "docker compose up -d --build mock-server",
                    "docker compose stop mock-server",
                    "docker compose logs --follow mock-server",
                    "npm --prefix mock_server test",
                ],
            )


if __name__ == "__main__":
    unittest.main()
