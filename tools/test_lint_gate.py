import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
RUNNER = ROOT / "tools" / "run_lint.py"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"


def load_runner():
    spec = importlib.util.spec_from_file_location("run_lint", RUNNER)
    if spec is None or spec.loader is None:
        raise AssertionError("tools/run_lint.py is not importable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class LintGateTests(unittest.TestCase):
    def test_discovery_reads_only_tracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracked = {
                "web/src/page.svelte": "",
                "tools/check.py": "",
                "tools/check.sh": "",
                "main/app_main.cpp": "",
                "components/modem/include/modem.h": "",
            }
            for name, content in tracked.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            (root / ".gitignore").write_text(".secrets/\n", encoding="utf-8")
            subprocess.run(["git", "init", "--quiet"], cwd=root, check=True)
            subprocess.run(
                ["git", "add", ".gitignore", *tracked], cwd=root, check=True
            )

            (root / ".secrets/bad.py").parent.mkdir(parents=True, exist_ok=True)
            (root / ".secrets/bad.py").write_text("print(missing)\n", encoding="utf-8")
            untracked = root / "components/modem/untracked_bad.cpp"
            untracked.write_text("void f() { int *p = nullptr; *p = 1; }\n", encoding="utf-8")
            (root / "components/idf_web/OTA_RUNTIME_READY").parent.mkdir(
                parents=True, exist_ok=True
            )
            (root / "components/idf_web/OTA_RUNTIME_READY").write_text(
                "sentinel\n", encoding="utf-8"
            )

            discovered = load_runner().discover_sources(root)

        self.assertEqual(["web/src/page.svelte"], discovered["web"])
        self.assertEqual(["tools/check.py"], discovered["python"])
        self.assertEqual(["tools/check.sh"], discovered["shell"])
        self.assertEqual(
            ["components/modem/include/modem.h", "main/app_main.cpp"],
            discovered["cpp"],
        )

    def test_discovers_owned_sources_and_excludes_generated_vendor_and_build_outputs(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            fixtures = {
                "web/src/page.svelte": "",
                "web/src/config.generated.ts": "",
                "web/scripts/package.mjs": "",
                "web/vite.config.ts": "",
                "tools/check.py": "",
                "components/modem/test/check.py": "",
                ".secrets/bad.py": "print(missing)\n",
                "tools/check.sh": "",
                "main/app_main.cpp": "",
                "components/modem/modem.cpp": "",
                "components/modem/include/modem.h": "",
                "components/config/include/config_schema_generated.h": "",
                "components/config/include/firmware_version_generated.h": "",
                "components/idf_pdu/pdulib.cpp": "",
                "code/web_assets.cpp": "",
                "build/generated.cpp": "",
                "web/node_modules/dependency.js": "",
            }
            for name, content in fixtures.items():
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text(content, encoding="utf-8")

            discovered = load_runner().discover_sources(root)

        self.assertEqual(
            ["web/scripts/package.mjs", "web/src/page.svelte", "web/vite.config.ts"],
            discovered["web"],
        )
        self.assertEqual(
            ["components/modem/test/check.py", "tools/check.py"], discovered["python"]
        )
        self.assertEqual(["tools/check.sh"], discovered["shell"])
        self.assertEqual(
            [
                "components/modem/include/modem.h",
                "components/modem/modem.cpp",
                "main/app_main.cpp",
            ],
            discovered["cpp"],
        )

    def test_ci_enforces_lint_before_build_and_runs_current_host_contracts(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertIn("\n  lint:\n", workflow)
        self.assertIn("\n    needs: lint\n", workflow)
        self.assertIn("python3 tests/lint_gate_smoke.py", workflow)
        self.assertIn("python3 tools/run_lint.py", workflow)
        for command in (
            "python3 components/idf_web/test/test_ota_runtime.py",
            "python3 components/idf_web/test/test_web_security.py",
            "python3 components/idf_web/test/test_openapi_conformance.py",
            "python3 tools/test_idf_config_codec.py",
            "python3 tools/test_idf_config_persistence.py",
            "python3 tools/test_idf_config_updates.py",
            "python3 components/idf_modem/test/test_uart_owner.py",
            "python3 components/idf_push/test/test_push_runtime.py",
            "python3 components/idf_sms/test/test_sms_retention_policy.py",
            "python3 components/idf_wifi/test/test_wifi_security.py",
        ):
            self.assertIn(command, workflow)

    def test_web_lint_entry_uses_only_present_repository_paths(self):
        package = json.loads((ROOT / "web/package.json").read_text(encoding="utf-8"))
        command = package["scripts"]["lint"]
        self.assertNotIn("mock_server", command)
        self.assertTrue((ROOT / "eslint.config.js").is_file())
        self.assertTrue((ROOT / "eslint-suppressions.json").is_file())

        dockerfile = (ROOT / "tools/lint/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM alpine@sha256:", dockerfile)
        self.assertIn("CPPCHECK_VERSION=2.14.2-r1", dockerfile)
        self.assertIn("RUFF_VERSION=0.16.0", dockerfile)
        self.assertIn("SHELLCHECK_VERSION=0.10.0-r2", dockerfile)


if __name__ == "__main__":
    unittest.main()
