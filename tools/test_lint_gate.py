import importlib.util
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from test_firmware_release import yaml_node


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


def scalar_mapping(text: str, indent: int) -> dict[str, str]:
    mapping = {}
    for line in text.splitlines():
        if not line.strip() or len(line) - len(line.lstrip(" ")) != indent:
            continue
        key, separator, _ = line.strip().partition(":")
        if separator:
            mapping[key] = yaml_node(text, indent, key)[0]
    return mapping


def parse_workflow_job(workflow: str, name: str) -> dict[str, object]:
    _, block = yaml_node(workflow, 2, name)
    job: dict[str, object] = scalar_mapping(block, 4)
    _, permissions = yaml_node(block, 4, "permissions")
    job["permissions"] = scalar_mapping(permissions, 6)

    lines = block.splitlines()
    starts = [
        index for index, line in enumerate(lines)
        if line == "      -" or line.startswith("      - ")
    ]
    steps = []
    for position, start in enumerate(starts):
        end = starts[position + 1] if position + 1 < len(starts) else len(lines)
        step_text = "\n".join([
            f"        {lines[start].strip()[2:]}",
            *lines[start + 1:end],
        ])
        step: dict[str, object] = scalar_mapping(step_text, 8)
        try:
            _, with_block = yaml_node(step_text, 8, "with")
            step["with"] = scalar_mapping(with_block, 10)
        except AssertionError:
            pass
        steps.append(step)
    job["steps"] = steps
    return job


class LintGateTests(unittest.TestCase):
    def assert_host_contracts(self, workflow):
        build = parse_workflow_job(workflow, "build")
        host_index = next(
            index for index, step in enumerate(build["steps"])
            if step.get("name") == "Run host contract tests"
        )
        build_index = next(
            index for index, step in enumerate(build["steps"])
            if step.get("name") == "Build firmware"
        )
        host_contracts = build["steps"][host_index]
        self.assertLess(host_index, build_index)
        self.assertEqual("bash", host_contracts.get("shell"))
        self.assertNotIn("if", host_contracts)
        self.assertNotIn("continue-on-error", host_contracts)
        self.assertEqual([
            "python3 tools/test_config_schema.py",
            "python3 tools/test_idf_config_codec.py",
            "python3 tools/test_idf_config_persistence.py",
            "python3 tools/test_idf_config_updates.py",
            "python3 components/idf_modem/test/test_uart_owner.py",
            "python3 components/idf_push/test/test_push_runtime.py",
            "python3 components/idf_sms/test/test_sms_retention_policy.py",
            "python3 components/idf_wifi/test/test_wifi_security.py",
            "python3 tools/test_idf_baseline.py",
            "python3 tools/test_device.py",
            "node --test tools/config_backup_verify.test.mjs",
            "python3 tools/test_ota_test_profile.py",
            "python3 tools/test_ota_observability.py",
            "python3 tools/test_usb_recovery.py",
            "python3 components/idf_web/test/test_web_security.py",
            "python3 components/idf_web/test/test_openapi_conformance.py",
            "python3 components/idf_web/test/test_ota_runtime.py",
        ], host_contracts["run"].splitlines())
        return build

    def test_discovery_reads_only_tracked_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tracked = {
                "mock_server/server.mjs": "",
                "mock_server/test/api.test.mjs": "",
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

        self.assertEqual(
            [
                "mock_server/server.mjs",
                "mock_server/test/api.test.mjs",
                "web/src/page.svelte",
            ],
            discovered["web"],
        )
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
                "mock_server/server.mjs": "",
                "mock_server/test/api.test.mjs": "",
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
            [
                "mock_server/server.mjs",
                "mock_server/test/api.test.mjs",
                "web/scripts/package.mjs",
                "web/src/page.svelte",
                "web/vite.config.ts",
            ],
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
        build = self.assert_host_contracts(workflow)
        self.assertEqual(build["needs"], "[lint, mock]")
        self.assertIn("python3 tests/lint_gate_smoke.py", workflow)
        self.assertIn("python3 tools/run_lint.py", workflow)

    def test_ci_host_contracts_reject_bypass_mutations(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        command = "node --test tools/config_backup_verify.test.mjs"
        step = "      - name: Run host contract tests\n        shell: bash\n        run: |"
        before_host = "      - name: Build and verify Web UI assets"
        build_firmware = "      - name: Build firmware"
        wrong_order = (
            workflow.replace(before_host, "      - name: ORDER_PLACEHOLDER", 1)
            .replace(build_firmware, before_host, 1)
            .replace("      - name: ORDER_PLACEHOLDER", build_firmware, 1)
        )
        mutations = {
            "ignored failure": workflow.replace(command, f"{command} || true", 1),
            "duplicate": workflow.replace(command, f"{command}\n          {command}", 1),
            "commented": workflow.replace(command, f"# {command}", 1),
            "conditional": workflow.replace(step, step.replace("run:", "if: always()\n        run:"), 1),
            "continue on error": workflow.replace(step, step.replace("run:", "continue-on-error: true\n        run:"), 1),
            "unsafe shell": workflow.replace(step, step.replace("shell: bash", "shell: bash {0}"), 1),
            "wrong order": wrong_order,
        }
        for name, mutated in mutations.items():
            with self.subTest(name=name), self.assertRaises(AssertionError):
                self.assert_host_contracts(mutated)

    def test_ci_runs_mock_gate_on_pinned_ubuntu(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        expected = {
            "runs-on": "ubuntu-24.04",
            "permissions": {"contents": "read"},
            "steps": [
                {
                    "name": "Checkout repository",
                    "uses": "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
                    "with": {"persist-credentials": "false"},
                },
                {
                    "name": "Set up Node.js",
                    "uses": "actions/setup-node@48b55a011bda9f5d6aeb4c2d9c7362e8dae4041e",
                    "with": {
                        "node-version": "24.14.0",
                        "cache": "npm",
                        "cache-dependency-path": (
                            "mock_server/package-lock.json\n"
                            "web/package-lock.json\n"
                        ),
                    },
                },
                {
                    "name": "Install Web UI dependencies",
                    "run": "npm ci --prefix web",
                },
                {
                    "name": "Build Web UI for mock tests",
                    "working-directory": "web",
                    "run": "npm exec -- vite build",
                },
                {
                    "name": "Install mock server dependencies",
                    "run": "npm ci --prefix mock_server",
                },
                {
                    "name": "Test mock API",
                    "run": "npm --prefix mock_server test",
                },
                {
                    "name": "Test mock development stack",
                    "run": (
                        "python3 tools/test_mock_dev_stack.py\n"
                        "bash -n scripts/dev.sh\n"
                        "docker compose -f compose.yaml config --quiet\n"
                    ),
                },
            ],
        }
        _, mock_block = yaml_node(workflow, 2, "mock")
        mutated_blocks = [
            mock_block.replace(
                "persist-credentials: false", "persist-credentials: true", 1
            ),
            mock_block.replace(
                "    runs-on: ubuntu-24.04",
                "    runs-on: ubuntu-24.04\n    if: false",
                1,
            ),
            mock_block.replace(
                "        run: npm --prefix mock_server test",
                "        run: npm --prefix mock_server test\n"
                "        continue-on-error: true",
                1,
            ),
            mock_block.replace(
                "    steps:\n      - name:",
                "    steps:\n      - run: echo bypass\n      - name:",
                1,
            ),
            mock_block.replace(
                "    steps:\n      - name:",
                "    steps:\n      -\n        run: echo bypass\n      - name:",
                1,
            ),
        ]
        for mutated_block in mutated_blocks:
            self.assertNotEqual(mutated_block, mock_block)
            mutated = workflow.replace(mock_block, mutated_block, 1)
            with self.assertRaises(AssertionError):
                self.assertEqual(parse_workflow_job(mutated, "mock"), expected)
        self.assertEqual(parse_workflow_job(workflow, "mock"), expected)

    def test_web_lint_entry_uses_only_present_repository_paths(self):
        package = json.loads((ROOT / "web/package.json").read_text(encoding="utf-8"))
        command = package["scripts"]["lint"]
        self.assertIn("mock_server", command)
        self.assertTrue((ROOT / "eslint.config.js").is_file())
        self.assertTrue((ROOT / "eslint-suppressions.json").is_file())

        dockerfile = (ROOT / "tools/lint/Dockerfile").read_text(encoding="utf-8")
        self.assertIn("FROM alpine@sha256:", dockerfile)
        self.assertIn("CPPCHECK_VERSION=2.14.2-r1", dockerfile)
        self.assertIn("RUFF_VERSION=0.16.0", dockerfile)
        self.assertIn("SHELLCHECK_VERSION=0.10.0-r2", dockerfile)


if __name__ == "__main__":
    unittest.main()
