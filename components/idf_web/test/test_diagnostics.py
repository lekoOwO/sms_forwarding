import subprocess
import tempfile
import unittest
from pathlib import Path

from .test_web_security import function_body


class DiagnosticsTest(unittest.TestCase):
    def test_rule_preview_uses_runtime_matcher_and_never_saves(self):
        from tools.test_idf_config_updates import HOST_CPP, ESP_ERR_H, ESP_LOG_H, FREERTOS_H, SEMPHR_H, IDF_LOG_H
        root = Path(__file__).resolve().parents[3]
        source = (root / "components/idf_web/idf_web.cpp").read_text()
        fixture = HOST_CPP + r'''
#include "idf_web_core.h"
static bool preview_success;
static std::string preview_code, preview_data, preview_detail;
static std::string action_result(bool success, const char* code, const std::string& data = {}, const std::string& detail = {}) {
    preview_success = success; preview_code = code; preview_data = data; preview_detail = detail;
    return {};
}
'''
        fixture += 'static std::string run_rules_preview_job(const std::string& payload) {' + function_body(source, "run_rules_preview_job") + '}\n'
        fixture += r'''
#undef require
#define require(condition) do { if (!(condition)) { std::fprintf(stderr, "preview assertion line %d\n", __LINE__); std::abort(); } } while (0)
int main() {
    reset();
    run_rules_preview_job("rules=%23!forward-rules-csv-v1%0Afrom%2C%5E09%5Cd%2B%2Cemail&sender=09123&text=sample");
    require(preview_success && preview_code == "ACTION_QUERY_OK");
    require(preview_data == "\"matched\":true,\"line\":1,\"drop\":false,\"email\":true,\"channelMask\":0");
    run_rules_preview_job("rules=%23!forward-rules-csv-v1%0Are%2C%5B%2Cemail&text=sample");
    require(!preview_success && preview_detail == "1:regex");
    run_rules_preview_job("rules=kw%09X%09drop&sender=" + std::string(33, 'a'));
    require(!preview_success && preview_code == "ACTION_INPUT_TOO_LONG");
    run_rules_preview_job("rules=kw%09X%09drop&text=" + std::string(2049, 'a'));
    require(!preview_success && preview_code == "ACTION_INPUT_TOO_LONG");
    run_rules_preview_job("rules=kw%09X%09drop&text=X%00Y");
    require(!preview_success);
    run_rules_preview_job("rules=&rules=kw%09X%09drop");
    require(!preview_success);
    run_rules_preview_job("rules=&unexpected=value");
    require(!preview_success);
    require(save_count == 0 && s_config.forwardRules.empty());
}
'''
        with tempfile.TemporaryDirectory() as directory:
            temp = Path(directory)
            (temp / "freertos").mkdir()
            for name, content in {"esp_err.h": ESP_ERR_H, "esp_log.h": ESP_LOG_H,
                                  "freertos/FreeRTOS.h": FREERTOS_H, "freertos/semphr.h": SEMPHR_H,
                                  "idf_log.h": IDF_LOG_H}.items():
                (temp / name).write_text(content)
            cpp, binary = temp / "preview.cpp", temp / "preview"
            cpp.write_text(fixture)
            subprocess.run(["g++", "-std=c++17", "-ffunction-sections", "-fdata-sections", "-Wl,--gc-sections",
                            "-I", str(temp), "-I", str(root / "components/idf_config"),
                            "-I", str(root / "components/idf_config/include"),
                            "-I", str(root / "components/idf_web/include"), str(cpp),
                            str(root / "components/idf_web/idf_web_core.cpp"), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_operator_query_returns_name_or_empty_without_format_write(self):
        source = (Path(__file__).resolve().parents[1] / "idf_web.cpp").read_text()
        fixture = r'''
#include <cassert>
#include <cctype>
#include <cstdio>
#include <string>
#include <vector>
using esp_err_t = int;
constexpr int ESP_OK = 0;
static std::string reply, operator_value;
static std::vector<std::string> commands;
static int idf_modem_send_at(const char* command, int, std::string& response)
{ commands.emplace_back(command); response = reply; return ESP_OK; }
static int idf_modem_request_reset(bool) { assert(false); return -1; }
static int idf_modem_get_imei(std::string&, int) { assert(false); return -1; }
static bool parse_csq_line(const std::string&, int&, int&) { assert(false); return false; }
static void json_prop(std::string&, const char* key, const std::string& value)
{ assert(std::string(key) == "operator"); operator_value = value; }
static std::string action_result(bool success, const char* code, const std::string& = {}, const std::string& = {})
{ assert(success); return code; }
'''
        fixture += "static std::string first_line_containing(const std::string& resp, const char* needle) {" + function_body(source, "first_line_containing") + "}\n"
        fixture += "static std::string run_modem_job(const std::string& action) {" + function_body(source, "run_modem_job") + "}\n"
        fixture += r'''
int main() {
    const char* responses[] = {
        "+COPS: 0,0,\"\",7\r\nOK\r\n",
        "+COPS: 0,0,\"Test Mobile\",7\r\nOK\r\n",
        "+COPS: 0,2,\"00101\",7\r\nOK\r\n",
        "+COPS: 0\r\nOK\r\n"
    };
    const char* expected[] = {"", "Test Mobile", "00101", ""};
    for (unsigned i = 0; i < 4; ++i) {
        reply = responses[i]; commands.clear();
        assert(run_modem_job("operator") == "ACTION_MODEM_OK");
        assert(operator_value == expected[i]);
        assert(commands == std::vector<std::string>{"AT+COPS?"});
    }
}
'''
        with tempfile.TemporaryDirectory() as directory:
            cpp = Path(directory, "diagnostics.cpp")
            binary = Path(directory, "diagnostics")
            cpp.write_text(fixture)
            subprocess.run(["g++", "-std=c++17", str(cpp), "-o", str(binary)], check=True)
            result = subprocess.run([str(binary)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
