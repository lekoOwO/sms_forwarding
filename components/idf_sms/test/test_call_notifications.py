import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from components.idf_sms.test.test_sms_retention_policy import function_body


SOURCE = Path(__file__).resolve().parents[1] / "idf_sms.cpp"


class CallNotificationTest(unittest.TestCase):
    def test_production_call_recovery(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler)
        source = SOURCE.read_text()

        def definition(name):
            match = re.search(
                rf"(?m)^(?:static )?[^\n;{{}}]*\b{name}\s*\([^;]*?\)\s*\{{", source
            )
            self.assertIsNotNone(match, name)
            return match.group() + function_body(source, name) + "}\n"

        helpers = ("starts_with", "is_hex_string", "canonical_phone", "masked_phone", "number_blacklisted",
                   "is_valid_phone_number", "parse_sms_index_token", "parse_cmti_index")
        call_block = source[source.index("// ===== Call notifications ====="):
                            source.index("static bool extract_first_stored_pdu")]
        state = source[source.index("static std::string s_urc_carry"):
                       source.index("static void cleanup_start_resources")]
        with tempfile.TemporaryDirectory() as directory:
            temporary = Path(directory)
            (temporary / "call_runtime.inc").write_text(
                state + "\n" + "\n".join(map(definition, helpers)) + call_block
            )
            binary = temporary / "call_notification_fixture"
            compiled = subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-Wno-unused-function",
                 "-fno-exceptions", "-fno-rtti", "-I", directory,
                 "-I", str(SOURCE.parents[1] / "idf_modem/include"),
                 str(SOURCE.parent / "test" / "call_notification_fixture.cpp"), "-o", str(binary)],
                capture_output=True, text=True,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            executed = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(executed.returncode, 0, executed.stderr)


if __name__ == "__main__":
    unittest.main()
