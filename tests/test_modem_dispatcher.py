import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ModemDispatcherTest(unittest.TestCase):
    def test_modem_dispatcher_is_the_only_uart_reader(self):
        readers = set()
        for path in (ROOT / "code").glob("*"):
            if path.suffix in {".cpp", ".ino"} and "Serial1.read()" in path.read_text():
                readers.add(path.name)
        self.assertEqual(readers, {"modem.cpp"})
        modem = (ROOT / "code/modem.cpp").read_text()
        self.assertNotIn("server.handleClient()", modem)
        self.assertIn("processModemLine(line)", modem)

    def test_management_sms_and_raw_bridge_are_disabled(self):
        sms = (ROOT / "code/sms_process.cpp").read_text()
        globals_header = (ROOT / "code/globals.h").read_text()
        self.assertNotIn('startsWith("SMS:")', sms)
        self.assertNotIn('equals("RESET")', sms)
        self.assertIn("#define ENABLE_MODEM_USB_RAW_BRIDGE 0", globals_header)

    def test_modem_init_retries_are_finite(self):
        modem = (ROOT / "code/modem.cpp").read_text()
        self.assertIn("retry < INIT_RETRIES", modem)
        self.assertNotIn('while (!sendATandWaitOK("AT"', modem)
        self.assertNotIn('while (!sendATandWaitOK("AT+CNMI', modem)
        self.assertNotIn('while (!sendATandWaitOK("AT+CMGF', modem)


if __name__ == "__main__":
    unittest.main()
