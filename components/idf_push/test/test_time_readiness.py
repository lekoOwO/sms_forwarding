import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from components.idf_sms.test.test_sms_retention_policy import function_body


ROOT = Path(__file__).resolve().parents[3]
PUSH = ROOT / "components/idf_push"


class TimeReadinessTest(unittest.TestCase):
    def test_real_workers_preserve_attempts_and_expire_pending_tests(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler)
        source = (PUSH / "idf_push.cpp").read_text()

        def definition(name):
            match = re.search(
                rf"(?m)^(?:static )?[^\n;{{}}]*\b{name}\s*\([^;]*?\)\s*\{{", source
            )
            self.assertIsNotNone(match, name)
            return match.group() + function_body(source[match.start():], name) + "}\n"

        names = (
            "ensure_init", "note_channel_result", "channel_cooling",
            "register_forward_completion_locked", "note_forward_target_success",
            "cancel_forward_completion_locked", "cancel_forward_completion",
            "channel_valid", "backoff_seconds", "transport_path_for_network",
            "enqueue_push_job_locked", "enqueue_email_job_locked", "channel_waits_for_time",
            "fail_push_job_without_retry", "purge_push_jobs_disabled", "process_push_one",
            "process_email_one", "fail_pending_tests", "expire_test_jobs_locked", "process_test_one",
        )
        state = source[source.index("static constexpr size_t PUSH_QUEUE_MAX"):
                       source.index("static bool ensure_init()")]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            (temporary / "esp_err.h").write_text(
                "#pragma once\nusing esp_err_t = int;\nconstexpr int ESP_OK = 0;\n"
            )
            (temporary / "time_runtime.inc").write_text(
                state + "\n" + "\n".join(map(definition, names))
            )
            binary = temporary / "time_readiness_fixture"
            compiled = subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                 "-Wno-unused-function", "-Wno-unused-variable", "-fno-exceptions", "-fno-rtti",
                 "-I", directory,
                 *[f"-I{ROOT / 'components' / component / 'include'}" for component in
                   ("idf_push", "idf_config", "idf_modem", "idf_wifi", "idf_logbuf")],
                 str(PUSH / "idf_push_cellular.cpp"), str(PUSH / "idf_push_core.cpp"),
                 str(ROOT / "components/idf_logbuf/idf_util.cpp"),
                 str(PUSH / "test/time_readiness_fixture.cpp"), "-o", str(binary)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
