import re
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "idf_modem.cpp"


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if not match:
        raise AssertionError(f"missing function: {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated function: {name}")


class UartOwnerContractTest(unittest.TestCase):
    def test_only_owner_checked_wrappers_read_or_write_uart(self):
        source = SOURCE.read_text()

        # All byte I/O must stay visible behind the two owner-checked choke points.
        self.assertNotRegex(source, r"\buart_(?:write_chars|read_pattern)\s*\(")
        self.assertEqual(source.count("uart_read_bytes("), 1)
        self.assertEqual(source.count("uart_write_bytes("), 1)
        self.assertEqual(source.count("uart_flush_input("), 1)
        self.assertEqual(source.count("uart_get_buffered_data_len("), 1)

        read = function_body(source, "owner_uart_read")
        write = function_body(source, "owner_uart_write")
        flush = function_body(source, "owner_uart_flush")
        buffered = function_body(source, "capture_pending_uart_locked")
        for body in (read, write, flush, buffered):
            self.assertIn("assert_owner_task();", body)

        self.assertIn("uart_read_bytes(", read)
        self.assertIn("uart_write_bytes(", write)

        for api in (
            "idf_modem_send_at",
            "idf_modem_send_at_until",
            "idf_modem_send_pdu",
            "idf_modem_cellular_http_get",
        ):
            body = function_body(source, api)
            self.assertNotIn("owner_uart_read(", body)
            self.assertNotIn("owner_uart_write(", body)
            self.assertIn("submit_owner_command", body)

        send_at = function_body(source, "owner_send_at")
        send_until = function_body(source, "owner_send_at_until")
        send_pdu = function_body(source, "owner_send_pdu")
        self.assertIn("MAX_RESPONSE = 8192", send_at)
        self.assertIn("MAX_RESPONSE = 4096", send_until)
        self.assertIn("MAX_RESPONSE = 4096", send_pdu)

        public_send_at = function_body(source, "idf_modem_send_at")
        self.assertIn('cmd.rfind("AT+CNMA", 0)', public_send_at)
        self.assertIn("if (!priority) owner_drain_priority_commands();", public_send_at)
        submit = function_body(source, "submit_owner_command")
        self.assertIn("!priority && !s_runtime_queue_ready.load", submit)
        owner_loop = function_body(source, "modem_task")
        self.assertIn("s_runtime_queue_ready.store(true", owner_loop)
        self.assertLess(
            owner_loop.index("owner_process_one_command(true)"),
            owner_loop.index("owner_process_one_command(false)"),
        )

        http_bound = re.search(
            r"CELLULAR_HTTP_CALL_TIMEOUT_MS\s*=\s*(\d+)UL", source
        )
        self.assertIsNotNone(http_bound)
        self.assertGreaterEqual(int(http_bound.group(1)), 360_000)


if __name__ == "__main__":
    unittest.main()
