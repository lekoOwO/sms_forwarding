import subprocess
import tempfile
import unittest
from pathlib import Path

from .test_web_security import function_body


class DiagnosticsTest(unittest.TestCase):
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
