import re
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class FirmwareSecurityTest(unittest.TestCase):
    def test_firmware_sources_use_english_text(self):
        for suffix in ("*.ino", "*.cpp", "*.h"):
            for path in (ROOT / "code").rglob(suffix):
                if path.name == "notification_locale.cpp":
                    continue
                text = path.read_text()
                self.assertNotRegex(text, r"[\u3400-\u9fff]", str(path))

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
  const char control[] = {char(0x01), 0};
  const char multiline[] = {'a', '\n', '\t', 'b', 0};
  char exactDiscordLimit[2001];
  char overDiscordLimit[2002];
  for (int i = 0; i < 2000; ++i) exactDiscordLimit[i] = overDiscordLimit[i] = 'a';
  exactDiscordLimit[2000] = 0;
  overDiscordLimit[2000] = 'a';
  overDiscordLimit[2001] = 0;
  return validUtf8CharLength(ascii) == 1 &&
         validUtf8CharLength(euro) == 3 &&
         validUtf8CharLength(maxCodePoint) == 4 &&
         validUtf8CharLength(stray) == 0 &&
         validUtf8CharLength(overlong) == 0 &&
         validUtf8CharLength(surrogate) == 0 &&
         validUtf8CharLength(tooHigh) == 0 &&
         validUtf8CharLength(truncated) == 0 &&
         isValidUtf8(ascii) && isValidUtf8(euro) && isValidUtf8(maxCodePoint) &&
         !isValidUtf8(stray) && !isValidUtf8(overlong) &&
         !isValidUtf8(surrogate) && !isValidUtf8(tooHigh) &&
         !isValidUtf8(truncated) && isValidUtf8(control) &&
         utf8CodePointCount(exactDiscordLimit, 2000) == 2000 &&
         utf8CodePointCount(overDiscordLimit, 2000) == 2001 &&
         utf8CodePointCount(euro, 2000) == 1 &&
         utf8CodePointCount(stray, 2000) == 2001 &&
         !isValidUtf8Text(control) && isValidUtf8Text(multiline) &&
         !hasValidJsonEncoding(control) && hasValidJsonEncoding(ascii) &&
         hasValidJsonEncoding(euro) ? 0 : 1;
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
        globals_header = (ROOT / "code/globals.h").read_text()
        serial_buffer_size = int(re.search(r"#define SERIAL_BUFFER_SIZE (\d+)", globals_header).group(1))
        max_pdu_length = int(re.search(r"#define MAX_PDU_LENGTH (\d+)", globals_header).group(1))
        self.assertIn("isValidConcatMetadata(partNumber, totalParts)", sms)
        self.assertIn("concatBuffer[i].totalParts != totalParts", sms)
        self.assertIn("return -1;", sms)
        self.assertIn("str.length() > MAX_PDU_LENGTH", sms)
        self.assertIn("str.length() % 2 != 0", sms)
        self.assertNotIn("allowAdminCommands", header)
        self.assertNotIn('startsWith("SMS:")', sms)
        self.assertNotIn('equals("RESET")', sms)
        self.assertIn("Incomplete administrator multipart SMS discarded", sms)
        self.assertGreaterEqual(max_pdu_length, 350)
        self.assertEqual(max_pdu_length % 2, 0)
        self.assertLess(max_pdu_length, serial_buffer_size)
        reset = sms.index("concatInfo[0] = concatInfo[1] = concatInfo[2] = 0;")
        self.assertLess(reset, sms.index("pdu.decodePDU"))

    def test_push_output_is_bounded_and_context_escaped(self):
        push = (ROOT / "code/push.cpp").read_text()
        self.assertIn("serializeJson", push)
        self.assertNotIn("jsonEscape", push)
        self.assertNotIn("jsonData +=", push)
        self.assertNotIn("http.getString()", push)
        self.assertIn("https://www.pushplus.plus/send", push)
        self.assertIn("String safeSubject = String(subject);", push)
        for sensitive_log in (
            'logCaptureLn(String("GET URL: "',
            'logCaptureLn(String("PushPlus: "',
            'logCaptureLn(String("Telegram: "',
        ):
            self.assertNotIn(sensitive_log, push)

    def test_arduinojson_is_pinned_and_owns_firmware_json(self):
        dockerfile = (ROOT / "Dockerfile").read_text()
        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        push = (ROOT / "code/push.cpp").read_text()
        self.assertIn("ARG ARDUINOJSON_VERSION=7.4.3", dockerfile)
        self.assertIn('ArduinoJson@${ARDUINOJSON_VERSION}', dockerfile)
        self.assertIn('ArduinoJson@7.4.3', workflow)
        for source in (handlers, push):
            self.assertIn("#include <ArduinoJson.h>", source)
            self.assertIn("serializeJson", source)
            self.assertIn("hasValidJsonEncoding", source)
            self.assertNotIn("jsonEscape", source)
        self.assertNotIn('data = "{\\"', handlers)

    def test_sms_bodies_are_not_copied_to_device_logs(self):
        sms = (ROOT / "code/sms_process.cpp").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertNotIn('logCaptureLn(String("Received PDU data: "', sms)
        self.assertNotIn('logCaptureLn(String("Message: " + String(text)))', sms)
        self.assertNotIn('logCaptureLn(String("SMS content: " + content))', handlers)

    def test_management_responses_apply_small_security_headers(self):
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertIn('server.sendHeader("Content-Security-Policy", "frame-ancestors \'none\'")', handlers)
        self.assertIn('server.sendHeader("Content-Encoding", "gzip")', handlers)
        self.assertGreaterEqual(handlers.count('server.sendHeader("Cache-Control", "no-store")'), 3)
        self.assertIn("static void sendJson(", handlers)
        self.assertIn("static void sendJsonFailure()", handlers)
        self.assertIn("if (rejectModemBusy()) return;", handlers)
        self.assertEqual(1, handlers.count("server.handleClient()"))
        self.assertIn("static void httpTask", handlers)

    def test_wifi_restart_allows_response_to_leave_before_disconnect(self):
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        start = handlers.index("void handleWifi()")
        wifi_handler = handlers[start:]
        response = wifi_handler.index('sendActionResult(200, true, "ACTION_WIFI_RESTARTING")')
        grace_period = wifi_handler.index("delay(500);", response)
        disconnect = wifi_handler.index("WiFi.disconnect(true);", response)
        self.assertLess(response, grace_period)
        self.assertLess(grace_period, disconnect)

    def test_account_updates_cannot_restore_default_credentials(self):
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertIn("Config next = config;", handlers)
        self.assertIn("if (!saveConfig(next))", handlers)
        self.assertIn("config = next;", handlers)
        self.assertIn("ACTION_INPUT_INVALID", handlers)
        self.assertIn("ACTION_CONFIG_ACCOUNT_REQUIRED", handlers)
        self.assertNotIn(
            "config.webAccounts[0].username = DEFAULT_WEB_USER", handlers
        )

    def test_modem_and_log_buffers_are_bounded(self):
        globals_header = (ROOT / "code/globals.h").read_text()
        modem = (ROOT / "code/modem.cpp").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertIn("#define MODEM_RESPONSE_MAX_LENGTH", globals_header)
        self.assertIn("#define LOG_LINE_MAX_LENGTH", globals_header)
        self.assertIn("transactionResponse.length() < MODEM_RESPONSE_MAX_LENGTH", modem)
        self.assertIn("MODEM_RESPONSE_MAX_LENGTH - transactionResponse.length()", modem)
        self.assertIn("_logAppendFragment(msg);", handlers)
        self.assertNotIn("_logLine += msg;", handlers)

    def test_usb_logging_does_not_block_the_main_loop(self):
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertIn("Serial.availableForWrite()", handlers)
        self.assertNotIn("Serial.print(msg);", handlers)
        self.assertNotIn("Serial.println(msg);", handlers)

    def test_hmac_failures_abort_signed_pushes(self):
        push = (ROOT / "code/push.cpp").read_text()
        self.assertIn("static bool hmacSha256", push)
        self.assertGreaterEqual(push.count("if (!hmacSha256("), 2)
        self.assertIn("if (sign.length() == 0)", push)
        self.assertNotIn("uint8_t hmacResult[32];", push)


if __name__ == "__main__":
    unittest.main()
