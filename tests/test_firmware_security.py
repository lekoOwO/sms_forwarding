import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FirmwareSecurityTest(unittest.TestCase):
    def test_utf8_validator_rejects_malformed_sequences(self):
        source = r'''
#include "utf8_validation.h"

int main() {
  const char ascii[] = {'A', 0};
  const char euro[] = {char(0xe2), char(0x82), char(0xac), 0};
  const char maxCodePoint[] = {char(0xf4), char(0x8f), char(0xbf), char(0xbf), 0};
  const char stray[] = {char(0xff), 0};
  const char overlong[] = {char(0xc0), char(0x80), 0};
  const char surrogate[] = {char(0xed), char(0xa0), char(0x80), 0};
  const char tooHigh[] = {char(0xf4), char(0x90), char(0x80), char(0x80), 0};
  const char truncated[] = {char(0xe2), char(0x82), 0};
  return validUtf8CharLength(ascii) == 1 &&
         validUtf8CharLength(euro) == 3 &&
         validUtf8CharLength(maxCodePoint) == 4 &&
         validUtf8CharLength(stray) == 0 &&
         validUtf8CharLength(overlong) == 0 &&
         validUtf8CharLength(surrogate) == 0 &&
         validUtf8CharLength(tooHigh) == 0 &&
         validUtf8CharLength(truncated) == 0 ? 0 : 1;
}
'''
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            test_cpp = work / "utf8_test.cpp"
            binary = work / "utf8_test"
            test_cpp.write_text(source)
            subprocess.run(
                [
                    "g++",
                    "-std=c++11",
                    "-I",
                    str(ROOT / "code"),
                    str(test_cpp),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run([str(binary)], check=True)

    def test_sms_parser_enforces_fixed_buffer_invariants(self):
        sms = (ROOT / "code/sms_process.cpp").read_text()
        header = (ROOT / "code/sms_process.h").read_text()
        self.assertIn("isValidConcatMetadata(partNumber, totalParts)", sms)
        self.assertIn("concatBuffer[i].totalParts != totalParts", sms)
        self.assertIn("return -1;", sms)
        self.assertIn("str.length() > MAX_PDU_LENGTH", sms)
        self.assertIn("str.length() % 2 != 0", sms)
        self.assertIn("bool allowAdminCommands", header)
        self.assertIn("timestamp.c_str(), false", sms)
        reset = sms.index("concatInfo[0] = concatInfo[1] = concatInfo[2] = 0;")
        self.assertLess(reset, sms.index("pdu.decodePDU"))

    def test_push_output_is_bounded_and_context_escaped(self):
        push = (ROOT / "code/push.cpp").read_text()
        self.assertIn('snprintf(escaped, sizeof(escaped), "\\\\u%04X"', push)
        self.assertNotIn("http.getString()", push)
        self.assertIn("https://www.pushplus.plus/send", push)
        self.assertIn("String safeSubject = String(subject);", push)
        self.assertIn("jsonEscape(text)", push)
        for sensitive_log in (
            'logCaptureLn(String("GET URL: "',
            'logCaptureLn(String("PushPlus: "',
            'logCaptureLn(String("Telegram: "',
        ):
            self.assertNotIn(sensitive_log, push)

    def test_sms_bodies_are_not_copied_to_device_logs(self):
        sms = (ROOT / "code/sms_process.cpp").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertNotIn('logCaptureLn(String("收到PDU数据: "', sms)
        self.assertNotIn('logCaptureLn(String("内容: " + String(text)))', sms)
        self.assertNotIn('logCaptureLn(String("短信内容: " + content))', handlers)

    def test_management_responses_apply_small_security_headers(self):
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertIn('server.sendHeader("Content-Security-Policy", "frame-ancestors \'none\'")', handlers)
        self.assertGreaterEqual(handlers.count('server.sendHeader("Cache-Control", "no-store")'), 4)
        hard_reset = handlers[handlers.index('else if (action == "hardreset")'):]
        self.assertLess(hard_reset.index("busy = false;"), hard_reset.index("return;"))

    def test_modem_and_log_buffers_are_bounded(self):
        globals_header = (ROOT / "code/globals.h").read_text()
        modem = (ROOT / "code/modem.cpp").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertIn("#define MODEM_RESPONSE_MAX_LENGTH", globals_header)
        self.assertIn("#define LOG_LINE_MAX_LENGTH", globals_header)
        self.assertGreaterEqual(
            modem.count("resp.length() < MODEM_RESPONSE_MAX_LENGTH"), 5
        )
        self.assertIn("_logAppendFragment(msg);", handlers)
        self.assertNotIn("_logLine += msg;", handlers)

    def test_hmac_failures_abort_signed_pushes(self):
        push = (ROOT / "code/push.cpp").read_text()
        self.assertIn("static bool hmacSha256", push)
        self.assertGreaterEqual(push.count("if (!hmacSha256("), 2)
        self.assertIn("if (sign.length() == 0)", push)
        self.assertNotIn("uint8_t hmacResult[32];", push)


if __name__ == "__main__":
    unittest.main()
