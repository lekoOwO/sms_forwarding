import json
from pathlib import Path
import re
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "components/idf_web"


def definition(source, name):
    start = re.search(rf"^static [^\n]*\b{re.escape(name)}\(", source, re.M).start()
    brace = source.index("\n{", start) + 1
    depth = 1
    for end in range(brace + 1, len(source)):
        depth += (source[end] == "{") - (source[end] == "}")
        if depth == 0:
            return source[start:end + 1] + "\n"
    raise AssertionError(name)


def build_harness(source):
    fixture = (WEB / "test/esim_install_fixture.cpp").read_text()
    structs = ""
    for name in ("WebAsyncJob", "EsimWebCache", "EsimTaskArg"):
        start = source.index(f"struct {name} {{")
        structs += source[start:source.index("\n};", start) + 3] + "\n"
    names = (
        "json_prop", "action_result", "clear_form_fields", "esim_action_label",
        "copy_esim_cache", "new_esim_handle", "modern_esim_state", "modern_esim_class",
        "wait_esim_modem_ready_and_idle", "esim_transition_can_succeed", "resolve_esim_handle",
        "append_modern_esim_profile_json", "esim_install_progress", "esim_install_confirmation",
        "submit_esim_confirmation", "esim_task", "start_esim_job", "modern_esim_job_code",
        "send_modern_esim_error", "handle_api_esim",
    )
    return fixture.replace("// STRUCTS", structs).replace("// FUNCTIONS", "\n".join(definition(source, name) for name in names))


class EsimInstallTests(unittest.TestCase):
    def run_fixture(self, source):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            (path / "esp_err.h").write_text("#pragma once\nusing esp_err_t = int;\nconstexpr int ESP_OK=0, ESP_FAIL=-1, ESP_ERR_INVALID_ARG=1, ESP_ERR_INVALID_STATE=2, ESP_ERR_TIMEOUT=3, ESP_ERR_NOT_FOUND=4;\n")
            (path / "fixture.cpp").write_text(build_harness(source))
            command = ["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-sign-compare", "-fno-exceptions", f"-I{path}"]
            for component in ("idf_web", "idf_logbuf", "idf_esim", "idf_lpa"):
                command.append(f"-I{ROOT / 'components' / component / 'include'}")
            command += [str(path / "fixture.cpp"), str(WEB / "idf_web_core.cpp"),
                        str(ROOT / "components/idf_logbuf/idf_util.cpp"),
                        str(ROOT / "components/idf_lpa/idf_lpa_activation_code.cpp"), "-o", str(path / "fixture")]
            compiled = subprocess.run(command, capture_output=True, text=True)
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            return subprocess.run([str(path / "fixture")], capture_output=True, text=True)

    def test_real_handler_task_and_confirmation_handoff(self):
        source = (WEB / "idf_web.cpp").read_text()
        result = self.run_fixture(source)
        self.assertEqual(result.returncode, 0, result.stderr)
        status = json.loads(result.stdout)
        self.assertEqual(status["job"]["state"], "succeeded")
        self.assertEqual(status["job"]["code"], "ACTION_ESIM_NOTIFICATION_PENDING")
        self.assertTrue(status["job"]["notificationPending"])
        self.assertEqual(status["profiles"][0]["state"], "disabled")
        self.assertNotIn("secret", result.stdout)
        self.assertNotIn("INSTALL-SECRET", result.stdout)

    def test_handoff_rejects_cross_job_mutation(self):
        source = (WEB / "idf_web.cpp").read_text()
        old = "const bool pending = s_esim_job.id == job_id && s_esim_job.running &&"
        self.assertIn(old, source)
        result = self.run_fixture(source.replace(old, "const bool pending = job_id != 0 && s_esim_job.running &&", 1))
        self.assertNotEqual(result.returncode, 0)

    def test_acceptance_does_not_depend_on_a_later_status_snapshot(self):
        source = (WEB / "idf_web.cpp").read_text()
        old = "std::to_string(accepted_id)"
        self.assertIn(old, source)
        snapshot = "std::to_string([] { WebAsyncJob view; if (cell_job_lock()) { view = s_esim_job; cell_job_unlock(); } return view.id; }())"
        result = self.run_fixture(source.replace(old, snapshot, 1))
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
