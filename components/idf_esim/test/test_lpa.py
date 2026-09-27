import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


COMPONENT = Path(__file__).resolve().parents[1]
FIXTURE = COMPONENT / "test" / "esim_lpa_fixture.cpp"


ESP_ERR_H = r'''
#pragma once
using esp_err_t = int;
inline constexpr esp_err_t ESP_OK = 0;
inline constexpr esp_err_t ESP_FAIL = -1;
inline constexpr esp_err_t ESP_ERR_INVALID_ARG = -2;
inline constexpr esp_err_t ESP_ERR_INVALID_STATE = -3;
inline constexpr esp_err_t ESP_ERR_NO_MEM = -4;
inline constexpr esp_err_t ESP_ERR_INVALID_SIZE = -5;
inline constexpr esp_err_t ESP_ERR_INVALID_RESPONSE = -6;
inline constexpr esp_err_t ESP_ERR_NOT_FOUND = -7;
inline constexpr esp_err_t ESP_ERR_NOT_SUPPORTED = -8;
inline const char* esp_err_to_name(esp_err_t) { return "error"; }
'''

MODEM_H = r'''
#pragma once
#include <cstdint>
#include <string>
#include "esp_err.h"
struct IdfModemStatus {
    bool atReady = true;
    std::string phase = "ready";
};
esp_err_t idf_modem_send_at(const std::string&, uint32_t, std::string&);
void idf_modem_begin_esim_operation();
void idf_modem_end_esim_operation();
void idf_modem_set_sim_identity_hook(void (*)());
esp_err_t idf_modem_request_reset(bool);
IdfModemStatus idf_modem_get_status();
'''

LOG_H = r'''
#pragma once
void idf_log_line(const char*);
void idf_logf(const char*, ...);
'''

UTIL_H = r'''
#pragma once
#include <cctype>
#include <string>
inline std::string idf_util_trim_copy(const std::string& value) {
    size_t begin = 0;
    while (begin < value.size() && std::isspace(static_cast<unsigned char>(value[begin]))) ++begin;
    size_t end = value.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(value[end - 1]))) --end;
    return value.substr(begin, end - begin);
}
'''


class EsimLpaHostTest(unittest.TestCase):
    def test_real_codec_and_card_session_fixture(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "g++ is required for the eSIM host check")
        self.assertTrue(FIXTURE.exists(), "missing eSIM fake transport fixture")
        self.assertTrue((COMPONENT / "idf_esim_codec.cpp").exists(), "missing TLV codec")
        self.assertTrue((COMPONENT / "include/idf_esim_lpa.h").exists(), "missing LPA API header")

        with tempfile.TemporaryDirectory(prefix="idf-esim-lpa-") as directory:
            root = Path(directory)
            stubs = root / "stubs"
            (stubs / "freertos").mkdir(parents=True)
            (stubs / "esp_err.h").write_text(ESP_ERR_H, encoding="utf-8")
            (stubs / "idf_modem.h").write_text(MODEM_H, encoding="utf-8")
            (stubs / "idf_log.h").write_text(LOG_H, encoding="utf-8")
            (stubs / "idf_util.h").write_text(UTIL_H, encoding="utf-8")
            (stubs / "freertos/FreeRTOS.h").write_text(
                "#pragma once\n#define pdMS_TO_TICKS(value) (value)\n", encoding="utf-8"
            )
            (stubs / "freertos/task.h").write_text(
                "#pragma once\n#include <cstdint>\ninline void vTaskDelay(uint32_t) {}\n",
                encoding="utf-8",
            )
            binary = root / "esim_lpa_fixture"
            result = subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    "-fno-exceptions",
                    "-fno-rtti",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-Wl,--gc-sections",
                    "-I",
                    str(stubs),
                    "-I",
                    str(COMPONENT / "include"),
                    str(COMPONENT / "idf_esim_codec.cpp"),
                    str(COMPONENT / "idf_esim.cpp"),
                    str(FIXTURE),
                    "-o",
                    str(binary),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
