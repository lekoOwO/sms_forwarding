import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


COMPONENT = Path(__file__).resolve().parents[1]


class InstallContractTest(unittest.TestCase):
    def test_install_composes_real_protocol_with_bounded_hardware_boundaries(self):
        compiler = shutil.which("g++")
        if compiler is None:
            self.skipTest("g++ is required for the host fixture")
        with tempfile.TemporaryDirectory(prefix="lpa-install-") as directory:
            temp = Path(directory)
            (temp / "esp_err.h").write_text(
                "#pragma once\nusing esp_err_t = int;\n"
                "constexpr int ESP_OK=0, ESP_FAIL=-1, ESP_ERR_INVALID_ARG=-2, "
                "ESP_ERR_INVALID_STATE=-3, ESP_ERR_NO_MEM=-4, "
                "ESP_ERR_INVALID_SIZE=-5, ESP_ERR_INVALID_RESPONSE=-6, "
                "ESP_ERR_TIMEOUT=-7, ESP_ERR_NOT_SUPPORTED=-8;\n"
            )
            (temp / "idf_modem.h").write_text(
                '#pragma once\n#include <string>\n#include <cstdint>\n#include "esp_err.h"\n'
                "esp_err_t idf_modem_get_imei(std::string&, uint32_t);\n"
            )
            (temp / "esp_timer.h").write_text(
                "#pragma once\n#include <cstdint>\nint64_t esp_timer_get_time();\n"
            )
            fixture = temp / "fixture"
            subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pedantic",
                 "-fno-exceptions", "-fno-rtti", "-I", str(temp),
                 "-I", str(COMPONENT / "include"),
                 "-I", str(COMPONENT.parent / "idf_esim" / "include"),
                 str(COMPONENT / "test" / "install_fixture.cpp"),
                 str(COMPONENT / "idf_lpa_install.cpp"),
                 str(COMPONENT / "idf_lpa_activation_code.cpp"),
                 str(COMPONENT / "idf_lpa_rsp.cpp"),
                 str(COMPONENT.parent / "idf_esim" / "idf_esim_codec.cpp"),
                 "-lcrypto", "-o", str(fixture)],
                check=True, capture_output=True, text=True,
            )
            checked = subprocess.run([str(fixture)], capture_output=True, text=True)
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)


if __name__ == "__main__":
    unittest.main()
