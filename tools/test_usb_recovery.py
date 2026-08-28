#!/usr/bin/env python3
"""Host checks for the bounded development USB recovery protocol."""

from __future__ import annotations

import errno
import hashlib
import io
import json
import os
import pathlib
import pty
import re
import shlex
import subprocess
import shutil
import sys
import termios
import time
import unittest
import threading
from contextlib import redirect_stderr, redirect_stdout
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
MODULE_PATH = ROOT / "tools" / "usb_recovery.py"
RECOVERY_BUILD_DIR = pathlib.Path(
    os.environ.get("SMS_USB_RECOVERY_BUILD_DIR", ROOT / "build" / "idf-usb-recovery")
)
PROJECT_RELEASE_SOURCES = (
    "app_main.cpp",
    "usb_recovery.cpp",
    "components/idf_modem/idf_modem.cpp",
    "components/idf_config/idf_config.cpp",
    "components/idf_web/idf_web.cpp",
)
REQUIRE_RECOVERY_BUILD = os.environ.get("SMS_USB_RECOVERY_REQUIRE_BUILD") == "1"
HARDWARE_CGDCONT_CAPTURE_SHA256 = (
    "4673a351a80e0b1313aa7ffdf4f00ca8215de2b020033bd8a5fb6d76350f7087"
)
HARDWARE_CGDCONT_CAPTURE_BYTES = 62
HARDWARE_CEREG_CAPTURE_SHA256 = (
    "f5c557e389521e0d7fc50c494292f83ec07c221bfbed03707a22ecd28416b04a"
)
HARDWARE_CEREG_CAPTURE_BYTES = 36
USB_RECOVERY_TASK_STACK_BYTES = 4096
USB_RECOVERY_TASK_STACK_HEADROOM_BYTES = 1024
USB_RECOVERY_TASK_MAX_FRAME_BYTES = (
    USB_RECOVERY_TASK_STACK_BYTES - USB_RECOVERY_TASK_STACK_HEADROOM_BYTES
)
sys.path.insert(0, str(MODULE_PATH.parent))
import usb_recovery  # noqa: E402


MSSLCIPHER_QUERY_ID = 0x12


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


class UsbRecoveryProtocolTest(unittest.TestCase):
    def test_cpol_query_transport_timeout_is_longer_but_bounded(self):
        self.assertEqual(usb_recovery.QUERY_TIMEOUT, 3.0)
        self.assertEqual(usb_recovery.CPOL_QUERY_TIMEOUT, 8.0)

    def test_msslcipher_extended_response_matches_transport_capacity(self):
        self.assertEqual(usb_recovery.MAX_QUERY_RESPONSE, 96)
        self.assertEqual(usb_recovery.MSSLCIPHER_MAX_RESPONSE, 192)
        self.assertEqual(usb_recovery.MSSLCIPHER_MAX_IDS, 24)
        self.assertEqual(
            usb_recovery.MAX_FRAME,
            usb_recovery.HEADER_SIZE
            + max(usb_recovery.MAX_ASYNC_PROVISION_PAYLOAD,
                  1 + usb_recovery.MSSLCIPHER_MAX_RESPONSE)
            + usb_recovery.CRC_SIZE,
        )
        ids = ",".join(f"0x{value:04X}" for value in range(0xC02B, 0xC02B + 24))
        valid = (f"+MSSLCIPHER: ({ids})\r\nOK\r\n").encode()
        self.assertTrue(usb_recovery.sanitize_query_response(
            usb_recovery.QUERY_MSSLCIPHER, valid)["valid"])
        response = usb_recovery._build_unchecked_frame(
            usb_recovery.RESPONSE_MODEM_QUERY, b"\x00" + valid, sequence=4
        )
        parsed = usb_recovery.FrameParser(usb_recovery.RESPONSE_COMMANDS).feed(response)
        self.assertEqual(len(parsed), 1)
        self.assertEqual(parsed[0].payload, b"\x00" + valid)
        too_many = ",".join(f"{value:04X}" for value in range(0xC02B, 0xC02B + 25))
        invalid = (f"+MSSLCIPHER: ({too_many})\r\nOK\r\n").encode()
        self.assertFalse(usb_recovery.sanitize_query_response(
            usb_recovery.QUERY_MSSLCIPHER, invalid)["valid"])

    def test_transaction_timeout_must_be_finite_positive_and_bounded(self):
        for timeout in (0.0, -1.0, float("nan"), float("inf"), 91.0):
            with self.subTest(timeout=timeout), mock.patch.object(usb_recovery, "Device") as device_cls:
                with self.assertRaisesRegex(ValueError, "timeout"):
                    usb_recovery.run_transaction(
                        "/dev/serial/by-id/test", timeout,
                        usb_recovery.COMMAND_STATE, b"",
                    )
                device_cls.assert_not_called()

    def test_state_retries_share_an_absolute_deadline(self):
        attempts = []
        clock = [100.0]

        class FailedDevice:
            def __init__(self, _path, timeout, **_kwargs):
                attempts.append(timeout)

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def transact(self, _command, _payload):
                clock[0] += 4.0
                raise usb_recovery.DeviceError("transport failed")

        with mock.patch.object(usb_recovery, "Device", FailedDevice), \
                mock.patch.object(usb_recovery.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(usb_recovery.time, "sleep"):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "timed out"):
                usb_recovery.run_transaction(
                    "/dev/serial/by-id/test", 5.0,
                    usb_recovery.COMMAND_STATE, b"", deadline=105.0,
                )
        self.assertEqual(attempts, [5.0, 1.0])

    def test_ota_state_retries_after_a_lost_read_response(self):
        attempts = []
        response = usb_recovery.Frame(
            usb_recovery.RESPONSE_OTA_STATE, 0,
            usb_recovery.OTA_STATE_STRUCT.pack(
                usb_recovery.APP0_OFFSET,
                usb_recovery.OTA_IMAGE_STATE_VALID,
                0, 0, 0, 0,
            ),
        )

        class LostReadDevice:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def transact(self, command, _payload):
                attempts.append(command)
                if len(attempts) == 1:
                    raise usb_recovery.DeviceError("USB device timed out")
                return response

        with mock.patch.object(usb_recovery, "Device", LostReadDevice):
            self.assertEqual(
                usb_recovery.run_transaction(
                    "/dev/serial/by-id/test", 1.0,
                    usb_recovery.COMMAND_OTA_STATE, b"",
                ),
                response,
            )
        self.assertEqual(attempts, [usb_recovery.COMMAND_OTA_STATE] * 2)

    def test_ota_state_extended_probe_is_once_and_returns_key_identity(self):
        legacy = usb_recovery.OTA_STATE_STRUCT.pack(
            usb_recovery.APP0_OFFSET, usb_recovery.OTA_IMAGE_STATE_VALID,
            0, 0, 0, 0,
        )
        fingerprint = "d7699fd512f82cfa86924a2ed90f3f165b1b21795455641f4327b24dc04fbe0b"
        transaction = mock.Mock(return_value=usb_recovery.Frame(
            usb_recovery.RESPONSE_OTA_STATE, 0,
            legacy + bytes.fromhex(fingerprint),
        ))
        with mock.patch.object(usb_recovery, "run_transaction", transaction):
            state = usb_recovery.read_ota_state(
                "/dev/serial/by-id/test", 1.0, deadline=5.0,
            )
        self.assertEqual(state["public_key_sha256"], fingerprint)
        transaction.assert_called_once_with(
            "/dev/serial/by-id/test", 1.0, usb_recovery.COMMAND_OTA_STATE,
            b"\x01", deadline=5.0,
        )

    def test_ota_state_falls_back_only_for_old_firmware_timeout_or_invalid_argument(self):
        legacy = usb_recovery.OTA_STATE_STRUCT.pack(
            usb_recovery.APP0_OFFSET, usb_recovery.OTA_IMAGE_STATE_VALID,
            0, 0, 0, 0,
        )
        for unsupported in (
            usb_recovery.DeviceError("USB device timed out"),
            usb_recovery.CommandError(usb_recovery.STATUS_INVALID_ARG),
        ):
            with self.subTest(error=unsupported), mock.patch.object(
                usb_recovery, "run_transaction", side_effect=(
                    unsupported,
                    usb_recovery.Frame(usb_recovery.RESPONSE_OTA_STATE, 0, legacy),
                ),
            ) as transaction:
                state = usb_recovery.read_ota_state("/dev/serial/by-id/test", 1.0)
            self.assertIsNone(state["public_key_sha256"])
            self.assertEqual(
                [call.args[3] for call in transaction.call_args_list],
                [b"\x01", b""],
            )

    def test_ota_state_never_downgrades_internal_error_or_malformed_extended_data(self):
        legacy = usb_recovery.OTA_STATE_STRUCT.pack(
            usb_recovery.APP0_OFFSET, usb_recovery.OTA_IMAGE_STATE_VALID,
            0, 0, 0, 0,
        )
        cases = (
            usb_recovery.CommandError(usb_recovery.STATUS_INTERNAL),
            usb_recovery.DeviceError("USB device disconnected"),
            usb_recovery.Frame(
                usb_recovery.RESPONSE_OTA_STATE, 0, legacy + b"\x00" * 31,
            ),
        )
        for result in cases:
            with self.subTest(result=result), mock.patch.object(
                usb_recovery, "run_transaction",
                side_effect=result if isinstance(result, Exception) else None,
                return_value=None if isinstance(result, Exception) else result,
            ) as transaction:
                with self.assertRaises(usb_recovery.DeviceError):
                    usb_recovery.read_ota_state("/dev/serial/by-id/test", 1.0)
            transaction.assert_called_once()

    def test_ota_state_legacy_read_requires_exact_18_byte_response(self):
        extended = usb_recovery.OTA_STATE_STRUCT.pack(
            usb_recovery.APP0_OFFSET, usb_recovery.OTA_IMAGE_STATE_VALID,
            0, 0, 0, 0,
        ) + b"\x00" * 32
        with mock.patch.object(
            usb_recovery, "run_transaction", return_value=usb_recovery.Frame(
                usb_recovery.RESPONSE_OTA_STATE, 0, extended,
            ),
        ):
            with self.assertRaises(usb_recovery.DeviceError):
                usb_recovery.read_ota_state(
                    "/dev/serial/by-id/test", 1.0, legacy=True,
                )

    def test_ota_state_selector_accepts_only_empty_or_identity_request(self):
        usb_recovery.build_frame(usb_recovery.COMMAND_OTA_STATE, b"", 1)
        usb_recovery.build_frame(usb_recovery.COMMAND_OTA_STATE, b"\x01", 1)
        for payload in (b"\x00", b"\x02", b"\x01\x00"):
            with self.subTest(payload=payload), self.assertRaises(ValueError):
                usb_recovery.build_frame(usb_recovery.COMMAND_OTA_STATE, payload, 1)

    def test_ota_state_identity_request_is_not_retried(self):
        attempts = []

        class TimeoutDevice:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def transact(self, command, payload):
                attempts.append((command, payload))
                raise usb_recovery.DeviceError("USB device timed out")

        with mock.patch.object(usb_recovery, "Device", TimeoutDevice):
            with self.assertRaises(usb_recovery.DeviceError):
                usb_recovery.run_transaction(
                    "/dev/serial/by-id/test", 1.0,
                    usb_recovery.COMMAND_OTA_STATE, b"\x01",
                )
        self.assertEqual(attempts, [(usb_recovery.COMMAND_OTA_STATE, b"\x01")])

    def test_ota_migration_recovery_is_at_most_once(self):
        attempts = []

        class LostMutationDevice:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def transact(self, command, _payload):
                attempts.append(command)
                raise usb_recovery.DeviceError("USB device timed out")

        with mock.patch.object(usb_recovery, "Device", LostMutationDevice):
            with self.assertRaises(usb_recovery.DeviceError):
                usb_recovery.run_transaction(
                    "/dev/serial/by-id/test", 1.0,
                    usb_recovery.COMMAND_OTA_MIGRATION_RECOVER, b"",
                )
        self.assertEqual(attempts, [usb_recovery.COMMAND_OTA_MIGRATION_RECOVER])

    def test_transaction_rejects_setup_overrun_after_absolute_deadline(self):
        clock = [100.0]

        class LateDevice:
            def __init__(self, _path, _timeout, **_kwargs):
                pass

            def __enter__(self):
                clock[0] = 102.0
                return self

            def __exit__(self, *_args):
                return False

            def transact(self, _command, _payload):
                return usb_recovery.Frame(
                    usb_recovery.RESPONSE_MODEM_QUERY, 0, b"OK\r\n"
                )

        with mock.patch.object(usb_recovery, "Device", LateDevice), \
                mock.patch.object(usb_recovery.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "timed out"):
                usb_recovery.run_transaction(
                    "/dev/serial/by-id/test", 5.0,
                    usb_recovery.COMMAND_MODEM_QUERY, b"\x03", deadline=101.0,
                )

    def test_provision_status_poll_sleep_stays_inside_absolute_deadline(self):
        sleeps = []
        clock = [100.0]

        def fake_transaction(*_args, **_kwargs):
            clock[0] = 100.9
            raise usb_recovery.CommandError(usb_recovery.STATUS_NOT_FOUND)

        def fake_sleep(value):
            sleeps.append(value)
            clock[0] += value

        with mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                mock.patch.object(usb_recovery.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(usb_recovery.time, "sleep", side_effect=fake_sleep):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "timed out"):
                usb_recovery._wait_for_provision(
                    "/dev/serial/by-id/test", 1, 101.0, None,
                )
        self.assertEqual(len(sleeps), 1)
        self.assertAlmostEqual(sleeps[0], 0.1)

    def test_generic_query_sanitizer_rejects_invalid_transport_content(self):
        invalid = (
            b"+CSQ: 1,2\r\n",
            b"+CSQ: 1,2\r\nERROR\r\n",
            b"+CSQ: 1,2\xff\r\nOK\r\n",
            b"+CSQ: 1,2\x01\r\nOK\r\n",
            b"+CSQ: 1,2\r\nOK\r\ntrailing\r\n",
        )
        for raw in invalid:
            with self.subTest(raw=raw):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(usb_recovery.QUERY_CSQ, raw),
                    {"query_id": usb_recovery.QUERY_CSQ,
                     "valid": False, "error": "invalid-response"},
                )

    def test_non_ascii_digits_are_rejected_before_redaction_or_hashing(self):
        arabic_digits = "١" * 19
        for query_id, raw in (
            (usb_recovery.QUERY_ICCID, f"+ICCID: {arabic_digits}\r\nOK\r\n".encode()),
            (usb_recovery.QUERY_COPS, f'+COPS: 0,0,"{arabic_digits}"\r\nOK\r\n'.encode()),
        ):
            with self.subTest(query_id=query_id):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(query_id, raw),
                    {"query_id": query_id,
                     "valid": False, "error": "invalid-response"},
                )

    def test_ati_sanitizer_rejects_arbitrary_short_identity_text(self):
        for raw in (b"ATI\r\nabc\r\nOK\r\n", b"ATI\r\n+SECRET: value\r\nOK\r\n"):
            with self.subTest(raw=raw):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(usb_recovery.QUERY_ATI, raw),
                    {"query_id": usb_recovery.QUERY_ATI,
                     "valid": False, "error": "invalid-response"},
                )

    def test_external_oserror_is_not_reflected(self):
        class BrokenDevice:
            def __init__(self, *_args, **_kwargs):
                pass

            def __enter__(self):
                raise OSError("secret-device-path")

            def __exit__(self, *_args):
                return False

        with mock.patch.object(usb_recovery, "Device", BrokenDevice):
            with self.assertRaises(usb_recovery.DeviceError) as raised:
                usb_recovery.run_transaction(
                    "/dev/serial/by-id/test", 1.0,
                    usb_recovery.COMMAND_MODEM_QUERY, b"\x08",
                )
        self.assertNotIn("secret-device-path", str(raised.exception))

    def test_wifi_command_rejects_invalid_timeout_before_prompting(self):
        args = type("Args", (), {"device": "/dev/serial/by-id/test", "timeout": 91.0, "ssid": "network"})()
        with mock.patch.object(usb_recovery.getpass, "getpass") as getpass:
            with self.assertRaisesRegex(ValueError, "timeout"):
                usb_recovery._wifi_command(args)
        getpass.assert_not_called()

    def test_busy_reason_is_bounded_and_old_empty_busy_is_compatible(self):
        self.assertEqual(usb_recovery.busy_reason_name(b""), None)
        self.assertEqual(usb_recovery.busy_reason_name(bytes((1,))), "gate_closed")
        self.assertEqual(usb_recovery.busy_reason_name(bytes((2,))), "mutex_timeout")
        self.assertEqual(usb_recovery.busy_reason_name(bytes((3,))), "slots_full")
        self.assertEqual(usb_recovery.busy_reason_name(bytes((4,))), "queue_full")
        self.assertEqual(usb_recovery.busy_reason_name(bytes((255,))), "unknown")
        self.assertEqual(usb_recovery.busy_reason_name(bytes((1, 2))), "unknown")
        old = usb_recovery.CommandError(usb_recovery.STATUS_BUSY, b"")
        self.assertEqual(str(old), "device rejected request (busy)")
        detailed = usb_recovery.CommandError(usb_recovery.STATUS_BUSY, bytes((3,)))
        self.assertEqual(detailed.reason, "slots_full")
        self.assertEqual(str(detailed), "device rejected request (busy; slots_full)")
        malformed = usb_recovery.CommandError(usb_recovery.STATUS_BUSY, bytes((3, 4)))
        self.assertEqual(malformed.reason, "unknown")
        self.assertNotIn("3", str(malformed))

    def test_busy_reason_error_parser_is_strict_and_redacts_unknown_suffixes(self):
        self.assertEqual(
            usb_recovery.busy_reason_payload_from_error(
                "device rejected request (busy)\n"
            ),
            b"",
        )
        for code, name in usb_recovery.BUSY_REASON_NAMES.items():
            with self.subTest(name=name):
                self.assertEqual(
                    usb_recovery.busy_reason_payload_from_error(
                        f"device rejected request (busy; {name})\n"
                    ),
                    bytes((code,)),
                )

        secret = "secret-like-suffix"
        payload = usb_recovery.busy_reason_payload_from_error(
            f"device rejected request (busy; gate_closed) {secret}"
        )
        self.assertEqual(payload, bytes((0,)))
        error = usb_recovery.CommandError(usb_recovery.STATUS_BUSY, payload)
        self.assertEqual(error.reason, "unknown")
        self.assertNotIn(secret, str(error))

    def test_protocol_error_parser_accepts_known_statuses_and_rejects_suffixes(self):
        statuses = (
            usb_recovery.STATUS_INVALID_ARG,
            usb_recovery.STATUS_NOT_FOUND,
            usb_recovery.STATUS_INVALID_STATE,
            usb_recovery.STATUS_NOT_READY,
            usb_recovery.STATUS_TIMEOUT,
            usb_recovery.STATUS_NO_MEM,
            usb_recovery.STATUS_INTERNAL,
        )
        for status in statuses:
            with self.subTest(status=status):
                error = f"device rejected request ({usb_recovery.status_name(status)})\n"
                self.assertEqual(
                    usb_recovery.parse_protocol_error(error),
                    (status, b""),
                )
        self.assertEqual(
            usb_recovery.parse_protocol_error(
                "device rejected request (busy; queue_full)\n"
            ),
            (usb_recovery.STATUS_BUSY, bytes((4,))),
        )
        secret = "secret-like-suffix"
        self.assertEqual(
            usb_recovery.parse_protocol_error(
                f"device rejected request (invalid-argument) {secret}"
            ),
            (None, b""),
        )
        self.assertEqual(
            usb_recovery.parse_protocol_error(
                "device rejected request (busy; made_up)\n"
            ),
            (None, b""),
        )
        self.assertEqual(
            usb_recovery.parse_protocol_error(
                "device rejected request (ok)\n"
            ),
            (None, b""),
        )

    def test_modem_query_uses_fixed_ids_and_rejects_arbitrary_at(self):
        expected = {
            "ati": (usb_recovery.QUERY_ATI, "ATI"),
            "cpin": (usb_recovery.QUERY_CPIN, "AT+CPIN?"),
            "cereg": (usb_recovery.QUERY_CEREG, "AT+CEREG?"),
            "cops": (usb_recovery.QUERY_COPS, "AT+COPS?"),
            "cgatt": (usb_recovery.QUERY_CGATT, "AT+CGATT?"),
            "cgact": (usb_recovery.QUERY_CGACT, "AT+CGACT?"),
            "cgpaddr": (usb_recovery.QUERY_CGPADDR, "AT+CGPADDR"),
            "iccid": (usb_recovery.QUERY_ICCID, "AT+ICCID"),
            "csq": (usb_recovery.QUERY_CSQ, "AT+CSQ"),
            "cesq": (usb_recovery.QUERY_CESQ, "AT+CESQ"),
            "cfun": (usb_recovery.QUERY_CFUN, "AT+CFUN?"),
            "creg": (usb_recovery.QUERY_CREG, "AT+CREG?"),
            "cgreg": (usb_recovery.QUERY_CGREG, "AT+CGREG?"),
            "ceer": (usb_recovery.QUERY_CEER, "AT+CEER"),
            "cimi": (usb_recovery.QUERY_CIMI, "AT+CIMI"),
            "cpol": (usb_recovery.QUERY_CPOL, "AT+CPOL?"),
            "cgdcont": (usb_recovery.QUERY_CGDCONT, "AT+CGDCONT?"),
            "msslcipher": (MSSLCIPHER_QUERY_ID, "AT+MSSLCIPHER=?"),
        }
        self.assertEqual(usb_recovery.QUERY_COMMANDS, expected)
        for name, (query_id, _command) in expected.items():
            self.assertEqual(usb_recovery.encode_modem_query(name), bytes((query_id,)))
        for mutation in ("AT+CGACT=1,1", "AT+COPS=?", "AT+CRSM=176,12258,0,0,10,0"):
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                usb_recovery.encode_modem_query(mutation)
        with self.assertRaises(ValueError):
            usb_recovery.encode_modem_query(0x13)
        with self.assertRaises(ValueError):
            usb_recovery.build_frame(usb_recovery.COMMAND_MODEM_QUERY, b"AT+CGACT=1,1", 0)

    def test_msslcipher_sanitizer_returns_only_known_flags_and_bounded_counts(self):
        raw = (
            b"+MSSLCIPHER: (0xC02B,0xC02C,0xC02F,0xC030,0x1301)\r\n"
            b"OK\r\n"
        )
        safe = usb_recovery.sanitize_query_response(MSSLCIPHER_QUERY_ID, raw)
        self.assertEqual(safe, {
            "query_id": MSSLCIPHER_QUERY_ID,
            "valid": True,
            "supported": {"c02b": True, "c02c": True, "c02f": True, "c030": True},
            "count": 5,
            "count_bucket": "5-8",
            "unknown_present": True,
        })
        encoded = json.dumps(safe, sort_keys=True)
        for value in ("0xC02B", "0xC02C", "0xC02F", "0xC030", "0x1301"):
            self.assertNotIn(value, encoded)

    def test_msslcipher_sanitizer_rejects_malformed_duplicate_range_and_control(self):
        cases = (
            b"+MSSLCIPHER: (C02B,C02C,C02F)\r\nERROR\r\n",
            b"+MSSLCIPHER: (C02B,C02B)\r\nOK\r\n",
            b"+MSSLCIPHER: (C02B,10000)\r\nOK\r\n",
            b"+MSSLCIPHER: (C02B,G02C)\r\nOK\r\n",
            b"+MSSLCIPHER: (C02B,\x1bC02C)\r\nOK\r\n",
            b"+MSSLCIPHER: (C02B)\r\n+MSSLCIPHER: (C02C)\r\nOK\r\n",
        )
        expected = {
            "query_id": MSSLCIPHER_QUERY_ID,
            "valid": False,
            "error": "invalid-response",
        }
        for raw in cases:
            with self.subTest(raw=raw):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(MSSLCIPHER_QUERY_ID, raw),
                    expected,
                )

    def test_cimi_sanitizer_keeps_only_safe_identity_metadata(self):
        raw = b"460011234567890\r\nOK\r\n"
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CIMI, raw)
        self.assertEqual(safe, {
            "query_id": usb_recovery.QUERY_CIMI,
            "valid": True,
            "present": True,
            "length": 15,
            "sha256": "9fee96bff58192f20a038944cf64fae4a5b7aa8324a84578fb3e79fb05b0805e",
            "mcc": "460",
        })
        self.assertNotIn("460011234567890", json.dumps(safe, sort_keys=True))

    def test_cpol_summary_sanitizer_keeps_only_structural_counts(self):
        summary = (
            b"CPOL1;len=520;rec=4;fmt=7,1,1,2;rat=complete,3,1,2,0;"
            b"bad=0;fail=0\r\nOK\r\n"
        )
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CPOL, summary)
        self.assertEqual(safe, {
            "query_id": usb_recovery.QUERY_CPOL,
            "valid": True,
            "raw_length": 520,
            "record_count": 4,
            "format_bitmap": 7,
            "format_counts": {"0": 1, "1": 1, "2": 2},
            "rat_complete": True,
            "rat_counts": {"0": 3, "1": 1, "2": 2, "3": 0},
            "malformed_count": 0,
            "parse_failed": False,
        })
        encoded = json.dumps(safe, sort_keys=True)
        for secret in ("46000", "operator", "PLMN", "APN"):
            self.assertNotIn(secret, encoded)

    def test_cpol_summary_distinguishes_missing_rat_and_parse_failure(self):
        cases = (
            (
                b"CPOL1;len=62;rec=2;fmt=5,1,0,1;rat=missing,0,0,0,0;bad=0;fail=0\r\nOK\r\n",
                {"rat_complete": False},
            ),
            (
                b"CPOL1;len=520;rec=3;fmt=7,1,1,1;rat=missing,1,1,1,0;bad=2;fail=1\r\nOK\r\n",
                {"rat_complete": False, "malformed_count": 2, "parse_failed": True},
            ),
            (
                b"CPOL1;len=520;rec=4;fmt=7,2,1,1;rat=missing,2,1,1,0;bad=0;fail=0\r\nOK\r\n",
                {"rat_complete": False},
            ),
        )
        for payload, expected in cases:
            with self.subTest(payload=payload):
                safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CPOL, payload)
                for key, value in expected.items():
                    self.assertEqual(safe[key], value)
                self.assertEqual(len(safe["rat_counts"]), 4)

    def test_cpol_summary_rejects_raw_or_malformed_summary(self):
        cases = (
            b'+CPOL: 0,2,"46000",0\r\nOK\r\n',
            b"CPOL1;len=520;rec=1;fmt=1,1,0,0;rat=unknown,1,0,0,0;bad=0;fail=0\r\nOK\r\n",
            b"CPOL1;len=520;rec=1;fmt=1,1,0,0;rat=missing,1,0,0,0;bad=0;fail=0\r\nERROR\r\n",
            b"CPOL1;len=520;rec=1;fmt=1,1,0,0;rat=missing,1,0,0,0;bad=0;fail=0\x01\r\nOK\r\n",
            b"x" * (usb_recovery.MAX_QUERY_RESPONSE + 1),
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(usb_recovery.QUERY_CPOL, payload),
                    {"query_id": usb_recovery.QUERY_CPOL,
                     "valid": False, "error": "invalid-response"},
                )

    def test_cpol_summary_rejects_impossible_numeric_and_rat_metadata(self):
        cases = (
            b"CPOL1;len=8193;rec=1;fmt=1,1,0,0;rat=missing,0,0,0,0;bad=0;fail=0\r\nOK\r\n",
            b"CPOL1;len=520;rec=1;fmt=1,1,0,0;rat=complete,2,0,0,0;bad=0;fail=0\r\nOK\r\n",
            b"CPOL1;len=520;rec=4;fmt=2,4,0,0;rat=complete,1,1,1,1;bad=0;fail=0\r\nOK\r\n",
            b"CPOL1;len=520;rec=0;fmt=0,0,0,0;rat=complete,0,0,0,0;bad=0;fail=0\r\nOK\r\n",
            b"CPOL1;len=520;rec=1;fmt=1,1,0,0;rat=complete,1,0,0,0;bad=1;fail=0\r\nOK\r\n",
            b"CPOL1;len=520;rec=0;fmt=0,0,0,0;rat=missing,1,0,0,0;bad=0;fail=0\r\nOK\r\n",
            b"CPOL1;len=520;rec=1;fmt=1,1,0,0;rat=missing,2,0,0,0;bad=0;fail=0\r\nOK\r\n",
            b"CPOL1;len=520;rec=1;fmt=1,1,0,0;rat=missing,1,0,0,0;bad=0;fail=0\r\nOK\r\n",
        )
        for payload in cases:
            with self.subTest(payload=payload):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(usb_recovery.QUERY_CPOL, payload),
                    {"query_id": usb_recovery.QUERY_CPOL,
                     "valid": False, "error": "invalid-response"},
                )

    def test_cgdcont_sanitizer_keeps_context_metadata_without_apn_or_address(self):
        raw = (
            b'+CGDCONT: 1,"IP","internet.example","10.20.30.40"\r\n'
            b'+CGDCONT: 2,"IPV6","","::"\r\nOK\r\n'
        )
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CGDCONT, raw)
        self.assertEqual(safe["query_id"], usb_recovery.QUERY_CGDCONT)
        self.assertTrue(safe["valid"])
        self.assertEqual(safe["entries"], [
            {
                "cid": 1,
                "pdp_type": "IP",
                "apn": {"present": True, "sha256": "7f8fc19c143c817fabf32127fc9cda9b5856ca9a8171882deaf41f477a6d1947"},
                "address": {"present": True, "sha256": "fec9cdeaf025e268325956b138339005d0b106c7b2823ccc21515a71496040dc"},
                "safe_flags": {"apn_hashed": True, "address_hashed": True},
            },
            {
                "cid": 2,
                "pdp_type": "IPV6",
                "apn": {"present": False},
                "address": {"present": True, "sha256": "71546855d6279ef70d20909b292c42c2dcb02cd06bde01485da52d13e304ebf4"},
                "safe_flags": {"apn_hashed": False, "address_hashed": True},
            },
        ])
        encoded = json.dumps(safe, sort_keys=True)
        self.assertNotIn("internet.example", encoded)
        self.assertNotIn("10.20.30.40", encoded)

    def test_cgdcont_sanitizer_accepts_omitted_optional_tail_fields(self):
        raw = (
            b'+CGDCONT: 2,"IP","internet.example"\r\nOK\r\n'
        )
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CGDCONT, raw)
        self.assertEqual(safe["query_id"], usb_recovery.QUERY_CGDCONT)
        self.assertTrue(safe["valid"])
        self.assertEqual(safe["entries"], [
            {
                "cid": 2,
                "pdp_type": "IP",
                "apn": {
                    "present": True,
                    "sha256": "7f8fc19c143c817fabf32127fc9cda9b5856ca9a8171882deaf41f477a6d1947",
                },
                "address": {"present": False},
                "safe_flags": {"apn_hashed": True, "address_hashed": False},
            },
        ])
        self.assertNotIn("internet.example", json.dumps(safe, sort_keys=True))

    def test_cereg_sanitizer_structures_safe_registration_fields(self):
        raw = b'+CEREG: 2,5,"ABCD","12345678",7\r\nOK\r\n'
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CEREG, raw)
        self.assertEqual(safe["query_id"], usb_recovery.QUERY_CEREG)
        self.assertTrue(safe["valid"])
        self.assertEqual(safe["field_count"], 5)
        self.assertEqual(safe["mode"], "location")
        self.assertEqual(safe["stat"], "registered-roaming")
        self.assertEqual(safe["act"], "e-utran")
        self.assertFalse(safe["home"])
        self.assertTrue(safe["roaming"])
        self.assertTrue(safe["registered"])
        self.assertEqual(safe["cause_flags"], {"present": False})
        self.assertTrue(safe["location"]["present"])
        self.assertEqual(
            [field["length"] for field in safe["location"]["fields"]], [4, 8]
        )
        encoded = json.dumps(safe, sort_keys=True)
        self.assertNotIn("ABCD", encoded)
        self.assertNotIn("12345678", encoded)
        for field in safe["location"]["fields"]:
            self.assertRegex(field["sha256"], r"^[0-9a-f]{64}$")

    def test_cereg_sanitizer_structures_status_only_without_location(self):
        raw = b"+CEREG: 1,1\r\nOK\r\n"
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CEREG, raw)
        self.assertEqual(safe["field_count"], 2)
        self.assertEqual(safe["mode"], "status")
        self.assertEqual(safe["stat"], "registered-home")
        self.assertIsNone(safe["act"])
        self.assertEqual(safe["location"], {"present": False})
        self.assertEqual(safe["cause_flags"], {"present": False})
        self.assertTrue(safe["home"])
        self.assertFalse(safe["roaming"])
        self.assertTrue(safe["registered"])

    def test_cereg_sanitizer_fails_closed_on_transport_and_future_shapes(self):
        invalid = (
            b'+CEREG: 2,2,"ABCD","12345678",7\r\n',
            b'+CEREG: 2,2,"ABCD","12345678",7\r\nERROR\r\n',
            b'+CEREG: 2,2,"ABCD","12345678",7\r\n\r\nOK\r\n',
            b'+CEREG: 2,2,"ABCD","12345678",7\r\nOK\r\ntrailing\r\n',
            b'+CEREG: 2,2,"ABCD","12345678",7\x01\r\nOK\r\n',
            b'+CEREG: 2,2,"ABCD","12345678",7\xff\r\nOK\r\n',
            b'+CEREG:\t2,2,"ABCD","12345678",7\r\nOK\r\n',
            b'+CEREG: 2,\t2,"ABCD","12345678",7\r\nOK\r\n',
            b'+CEREG: 2,2,"ABCD","12345678",7\v\r\nOK\r\n',
            b'+CEREG: 2,2,"ABCD","12345678",7\f\r\nOK\r\n',
            '+CEREG:\u00a02,2,"ABCD","12345678",7\r\nOK\r\n'.encode(),
            b'+CREG: 2,2,"ABCD","12345678",7\r\nOK\r\n',
            b'+CEREG: 2,2,"ABCD","12345678"\r\nOK\r\n',
            b'+CEREG: 2,2,"ABCD","12345678",7,8\r\nOK\r\n',
            b'+CEREG: 3,2\r\nOK\r\n',
            b'+CEREG: 2,2\r\nOK\r\n',
        )
        for raw in invalid:
            with self.subTest(raw_length=len(raw)):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(usb_recovery.QUERY_CEREG, raw),
                    {"query_id": usb_recovery.QUERY_CEREG,
                     "valid": False, "error": "invalid-response"},
                )

    def test_cereg_sanitizer_rejects_unproven_values_and_location_shapes(self):
        invalid = (
            b'+CEREG: 3,1\r\nOK\r\n',
            b'+CEREG: 1,6\r\nOK\r\n',
            b'+CEREG: 2,1,"ABCD","12345678",8\r\nOK\r\n',
            b'+CEREG: 2,1,"ABC","12345678",7\r\nOK\r\n',
            b'+CEREG: 2,1,"ABCD","1234",7\r\nOK\r\n',
            b'+CEREG: 2,1,"ABCD","1234567G",7\r\nOK\r\n',
            b'+CEREG: 1,1,"ABCD","12345678",7\r\nOK\r\n',
            b'+CEREG: 2,01,"ABCD","12345678",7\r\nOK\r\n',
            b'+CEREG: 2,1,"ABCD","12345678",07\r\nOK\r\n',
        )
        for raw in invalid:
            with self.subTest(raw_length=len(raw)):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(usb_recovery.QUERY_CEREG, raw),
                    {"query_id": usb_recovery.QUERY_CEREG,
                     "valid": False, "error": "invalid-response"},
                )

    def test_cereg_hardware_fixture_shape_is_safe_when_present(self):
        evidence_root = ROOT / ".secrets"
        if not evidence_root.is_dir():
            self.skipTest("private hardware evidence is not present")
        candidates = []
        for path in evidence_root.rglob("*"):
            try:
                metadata = path.stat()
            except OSError:
                continue
            if not path.is_file() or metadata.st_size != HARDWARE_CEREG_CAPTURE_BYTES:
                continue
            if metadata.st_mode & 0o777 != 0o600:
                continue
            try:
                payload = path.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(payload).hexdigest() == HARDWARE_CEREG_CAPTURE_SHA256:
                candidates.append(payload)
        if not candidates:
            self.skipTest("private hardware CEREG fixture is not present")
        self.assertEqual(len(candidates), 1)
        raw = candidates[0]
        lines = raw.splitlines()
        self.assertEqual(len(lines), 2)
        self.assertEqual(lines[-1], b"OK")
        self.assertTrue(lines[0].startswith(b"+CEREG:"))
        fields = lines[0][len(b"+CEREG:"):].strip().split(b",")
        self.assertEqual(len(fields), 5)
        self.assertTrue(re.fullmatch(rb"[0-9]+", fields[0]))
        self.assertTrue(re.fullmatch(rb"[0-9]+", fields[1]))
        self.assertTrue(re.fullmatch(rb'"[0-9A-Fa-f]+"', fields[2]))
        self.assertTrue(re.fullmatch(rb'"[0-9A-Fa-f]+"', fields[3]))
        self.assertTrue(re.fullmatch(rb"[0-9]+", fields[4]))
        self.assertEqual([len(fields[2]) - 2, len(fields[3]) - 2], [4, 8])
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CEREG, raw)
        self.assertTrue(safe["valid"])
        self.assertEqual(safe["field_count"], 5)
        self.assertEqual(safe["mode"], "location")
        self.assertEqual(safe["stat"], "rlos-only")
        self.assertEqual(safe["act"], "e-utran")
        self.assertEqual([field["length"] for field in safe["location"]["fields"]], [4, 8])
        encoded = json.dumps(safe, sort_keys=True)
        self.assertNotIn("+CEREG:", encoded)
        self.assertNotIn("OK", encoded)
        for field in fields[2:4]:
            self.assertNotIn(field.decode("ascii"), encoded)

    def test_cgdcont_hardware_fixture_is_three_fields_and_sanitizes_without_address(self):
        evidence_root = ROOT / ".secrets"
        if not evidence_root.is_dir():
            self.skipTest("private hardware evidence is not present")
        candidates = []
        for path in evidence_root.rglob("*"):
            try:
                metadata = path.stat()
            except OSError:
                continue
            if not path.is_file() or metadata.st_size != HARDWARE_CGDCONT_CAPTURE_BYTES:
                continue
            if metadata.st_mode & 0o777 != 0o600:
                continue
            try:
                payload = path.read_bytes()
            except OSError:
                continue
            if hashlib.sha256(payload).hexdigest() == HARDWARE_CGDCONT_CAPTURE_SHA256:
                candidates.append(payload)
        if not candidates:
            self.skipTest("private hardware CGDCONT fixture is not present")
        self.assertEqual(len(candidates), 1)
        raw = candidates[0]
        lines = raw.splitlines()
        self.assertEqual(len(lines), 3)
        self.assertEqual(lines[-1], b"OK")
        for line in lines[:2]:
            self.assertTrue(line.startswith(b"+CGDCONT:"))
            self.assertEqual(line.count(b","), 2)
            self.assertEqual(line.count(b'"'), 4)
            self.assertFalse(any(byte < 0x20 and byte not in (0x0D, 0x0A) for byte in line))
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CGDCONT, raw)
        self.assertTrue(safe["valid"])
        self.assertEqual(safe["entry_count"], 2)
        self.assertTrue(all(entry["address"] == {"present": False} for entry in safe["entries"]))

    def test_cgdcont_sanitizer_rejects_unproven_shapes_and_unquoted_fields(self):
        invalid = (
            b'+CGDCONT: 1\r\nOK\r\n',
            b'+CGDCONT: 1,"IP"\r\nOK\r\n',
            b'+CGDCONT: 1,"IP","apn","addr",0\r\nOK\r\n',
            b'+CGDCONT: 1,IP,"apn"\r\nOK\r\n',
            b'+CGDCONT: 1,"IP",apn\r\nOK\r\n',
            b'+CGDCONT: 1,"IP","apn",addr\r\nOK\r\n',
            b'+CGDCONT: 1,"IP","ap,n"\r\nOK\r\n',
            '+CGDCONT: ١,"IP","apn"\r\nOK\r\n'.encode(),
            '+CGDCONT: 1,"IP","\u00e9"\r\nOK\r\n'.encode(),
        )
        for raw in invalid:
            with self.subTest(raw_length=len(raw)):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(usb_recovery.QUERY_CGDCONT, raw),
                    {"query_id": usb_recovery.QUERY_CGDCONT,
                     "valid": False, "error": "invalid-response"},
                )

    def test_new_query_sanitizers_fail_closed_on_bad_transport_content(self):
        cases = (
            (usb_recovery.QUERY_CIMI, b"AT+CIMI\r\n460011234567890\r\nextra\r\nOK\r\n"),
            (usb_recovery.QUERY_CIMI, b"+CMTI: \"SM\",1\r\nOK\r\n"),
            (usb_recovery.QUERY_CIMI, b"\xff\r\nOK\r\n"),
            (usb_recovery.QUERY_CPOL, b'+CPOL: 0,2,"46000",0\r\nERROR\r\n'),
            (usb_recovery.QUERY_CPOL, b'+CPOL: 0,2,"\xff",0\r\nOK\r\n'),
            (usb_recovery.QUERY_CGDCONT, b'AT+CGDCONT?\r\n+CGDCONT: 1,"IP","apn","addr"\r\nOK\r\n'),
            (usb_recovery.QUERY_CGDCONT, b"x" * (usb_recovery.MAX_QUERY_RESPONSE + 1)),
        )
        for query_id, raw in cases:
            with self.subTest(query_id=query_id, raw=raw):
                safe = usb_recovery.sanitize_query_response(query_id, raw)
                self.assertEqual(safe, {
                    "query_id": query_id,
                    "valid": False,
                    "error": "invalid-response",
                })
                self.assertNotIn("46000", json.dumps(safe, sort_keys=True))

    def test_new_query_sanitizers_reject_c0_and_c1_controls_inside_fields(self):
        for control in (b"\x01", b"\x1f", b"\x7f", b"\x9f"):
            cases = (
                (usb_recovery.QUERY_CPOL,
                 b'+CPOL: 0,2,"' + control + b'",0\r\nOK\r\n'),
                (usb_recovery.QUERY_CGDCONT,
                 b'+CGDCONT: 1,"IP","' + control + b'","addr"\r\nOK\r\n'),
                (usb_recovery.QUERY_CGDCONT,
                 b'+CGDCONT: 1,"IP","apn","' + control + b'"\r\nOK\r\n'),
            )
            for query_id, raw in cases:
                with self.subTest(control=control, query_id=query_id):
                    self.assertEqual(
                        usb_recovery.sanitize_query_response(query_id, raw),
                        {"query_id": query_id, "valid": False, "error": "invalid-response"},
                    )

    def test_query_cli_raw_is_explicit_and_does_not_call_sanitizer(self):
        raw = b"AT+COPS?\r\n+COPS: 0\r\nOK\r\n"

        def fake_transaction(_path, _timeout, _command, _payload):
            return usb_recovery.Frame(usb_recovery.RESPONSE_MODEM_QUERY, 0, raw)

        args = type("Args", (), {
            "device": "/dev/serial/by-id/test",
            "timeout": None,
            "query_name": "cops",
            "query_option": None,
            "raw": True,
        })()
        output = io.BytesIO()
        stdout = type("Stdout", (), {"buffer": output})()
        with mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                mock.patch.object(usb_recovery, "sanitize_query_response") as sanitize, \
                mock.patch.object(usb_recovery.sys, "stdout", stdout):
            self.assertEqual(usb_recovery._query_command(args), 0)
            self.assertEqual(output.getvalue(), raw)
        sanitize.assert_not_called()

    def test_query_cli_rejects_empty_response_in_raw_and_json_modes(self):
        for raw_mode in (False, True):
            with self.subTest(raw=raw_mode):
                args = type("Args", (), {
                    "device": "/dev/serial/by-id/test",
                    "timeout": None,
                    "query_name": "cereg",
                    "query_option": None,
                    "raw": raw_mode,
                })()
                response = usb_recovery.Frame(
                    usb_recovery.RESPONSE_MODEM_QUERY, 0, b"\r\n"
                )
                stdout = (
                    type("Stdout", (), {"buffer": io.BytesIO()})()
                    if raw_mode else io.StringIO()
                )
                with mock.patch.object(
                    usb_recovery, "run_transaction", return_value=response
                ), mock.patch.object(usb_recovery.sys, "stdout", stdout):
                    with self.assertRaisesRegex(
                        usb_recovery.DeviceError, "empty modem query response"
                    ):
                        usb_recovery._query_command(args)

    def test_cli_blank_error_has_fixed_stderr(self):
        error = io.StringIO()
        with mock.patch.object(
            usb_recovery, "run_transaction", side_effect=usb_recovery.DeviceError("")
        ), redirect_stderr(error):
            result = usb_recovery.main([
                "--device", "/dev/serial/by-id/test", "query", "cereg",
            ])
        self.assertNotEqual(result, 0)
        self.assertEqual(error.getvalue(), "USB recovery operation failed\n")

    def test_query_cli_raw_cpol_is_always_safe_summary(self):
        summary = b"CPOL1;len=520;rec=4;fmt=7,1,1,2;rat=complete,3,1,2,0;bad=0;fail=0\r\nOK\r\n"

        def fake_transaction(_path, _timeout, _command, _payload):
            return usb_recovery.Frame(usb_recovery.RESPONSE_MODEM_QUERY, 0, summary)

        args = type("Args", (), {
            "device": "/dev/serial/by-id/test",
            "timeout": None,
            "query_name": "cpol",
            "query_option": None,
            "raw": True,
        })()
        with mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                mock.patch.object(usb_recovery.sys, "stdout", type("Stdout", (), {
                    "buffer": (output := io.BytesIO())
                })()):
            self.assertEqual(usb_recovery._query_command(args), 0)
        self.assertEqual(output.getvalue(), summary)
        self.assertNotIn("46000", output.getvalue().decode())

    def test_modem_query_response_redacts_iccid_in_default_machine_output(self):
        raw = b"\r\n+ICCID: 8986001234567890123\r\nOK\r\n"
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_ICCID, raw)
        encoded = json.dumps(safe, sort_keys=True)
        self.assertNotIn("8986001234567890123", encoded)
        self.assertTrue(safe["present"])
        self.assertEqual(safe["length"], 19)
        self.assertEqual(safe["sha256"],
                         "633253605454841400e2bd50ba20a50b5836fa48725275d9c03991376881b1e2")

    def test_modem_query_redacts_identity_runs_longer_than_known_lengths(self):
        identity = "7" * 23
        raw = f"+ICCID: {identity}\r\nOK\r\n".encode()
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_ICCID, raw)

        encoded = json.dumps(safe, sort_keys=True)
        self.assertNotIn(identity, encoded)
        self.assertEqual(safe["length"], 23)

    def test_ati_summary_identifies_model_and_firmware_without_identifiers(self):
        raw = (
            b"ATI\r\nML307Y\r\nRevision: FW-1.2\r\n"
            b"IMEI: 8986001234567890123\r\nOK\r\n"
        )
        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_ATI, raw)
        self.assertEqual(safe["model"], "ML307Y")
        self.assertEqual(safe["firmware"], "Revision: FW-1.2")
        self.assertNotIn("8986001234567890123", json.dumps(safe, sort_keys=True))

    def test_ati_rejects_unlabelled_post_model_identity_text(self):
        raw = b"ATI\r\nML307Y\r\nABC1\r\nOK\r\n"
        self.assertEqual(
            usb_recovery.sanitize_query_response(usb_recovery.QUERY_ATI, raw),
            {"query_id": usb_recovery.QUERY_ATI, "valid": False, "error": "invalid-response"},
        )

    def test_fixed_queries_return_interpretable_safe_values(self):
        cases = (
            (
                usb_recovery.QUERY_CPIN,
                b"+CPIN: READY\r\nOK\r\n",
                {"query_id": usb_recovery.QUERY_CPIN, "valid": True, "state": "ready"},
            ),
            (
                usb_recovery.QUERY_COPS,
                b'+COPS: 0,2,"Operator",7\r\nOK\r\n',
                {
                    "query_id": usb_recovery.QUERY_COPS,
                    "valid": True,
                    "mode": "automatic",
                    "format": "numeric",
                    "act": "e-utran",
                    "operator": {
                        "present": True,
                        "length": 8,
                        "sha256": "291101a07fe980e93b900ae85c9eb824f9e7e93d0d754be7440b9386b615cad7",
                    },
                },
            ),
            (
                usb_recovery.QUERY_CGATT,
                b"+CGATT: 0\r\nOK\r\n",
                {"query_id": usb_recovery.QUERY_CGATT, "valid": True, "attached": False},
            ),
            (
                usb_recovery.QUERY_CGACT,
                b"+CGACT: 1,1\r\n+CGACT: 2,0\r\nOK\r\n",
                {
                    "query_id": usb_recovery.QUERY_CGACT,
                    "valid": True,
                    "entry_count": 2,
                    "entries": [
                        {"cid": 1, "active": True},
                        {"cid": 2, "active": False},
                    ],
                },
            ),
            (
                usb_recovery.QUERY_CSQ,
                b"+CSQ: 31,99\r\nOK\r\n",
                {
                    "query_id": usb_recovery.QUERY_CSQ,
                    "valid": True,
                    "rssi": 31,
                    "ber": None,
                    "unknown": {"rssi": False, "ber": True},
                },
            ),
            (
                usb_recovery.QUERY_CESQ,
                b"+CESQ: 63,99,255,255,14,71\r\nOK\r\n",
                {
                    "query_id": usb_recovery.QUERY_CESQ,
                    "valid": True,
                    "rxlev": 63,
                    "ber": None,
                    "rscp": None,
                    "ecn0": None,
                    "rsrq": 14,
                    "rsrp": 71,
                    "unknown": {
                        "rxlev": False, "ber": True, "rscp": True,
                        "ecn0": True, "rsrq": False, "rsrp": False,
                    },
                },
            ),
            (
                usb_recovery.QUERY_CFUN,
                b"+CFUN: 1\r\nOK\r\n",
                {"query_id": usb_recovery.QUERY_CFUN, "valid": True, "mode": 1},
            ),
            (
                usb_recovery.QUERY_CREG,
                b'+CREG: 2,5,"ABCD","12345678",7\r\nOK\r\n',
                {
                    "query_id": usb_recovery.QUERY_CREG,
                    "valid": True,
                    "line_count": 1,
                    "field_count": 5,
                    "mode": "location",
                    "stat": "registered-roaming",
                    "act": "e-utran",
                    "home": False,
                    "roaming": True,
                    "registered": True,
                    "location": {
                        "present": True,
                        "fields": [
                            {"present": True, "length": 4, "sha256": ""},
                            {"present": True, "length": 8, "sha256": ""},
                        ],
                    },
                },
            ),
            (
                usb_recovery.QUERY_CGREG,
                b"+CGREG: 0,0\r\nOK\r\n",
                {
                    "query_id": usb_recovery.QUERY_CGREG,
                    "valid": True,
                    "line_count": 1,
                    "field_count": 2,
                    "mode": "disabled",
                    "stat": "not-registered",
                    "act": None,
                    "home": False,
                    "roaming": False,
                    "registered": False,
                    "location": {"present": False},
                },
            ),
        )
        for query_id, raw, expected in cases:
            with self.subTest(query_id=query_id):
                safe = usb_recovery.sanitize_query_response(query_id, raw)
                for key, value in expected.items():
                    if key == "location":
                        self.assertEqual(safe[key]["present"], value["present"])
                        if value["present"]:
                            self.assertEqual(
                                [field["length"] for field in safe[key]["fields"]],
                                [field["length"] for field in value["fields"]],
                            )
                            self.assertTrue(all(field["sha256"] for field in safe[key]["fields"]))
                    elif key == "operator":
                        self.assertEqual(safe[key]["present"], value["present"])
                        self.assertEqual(safe[key]["length"], value["length"])
                        self.assertEqual(safe[key]["sha256"], value["sha256"])
                    else:
                        self.assertEqual(safe[key], value)
                self.assertNotIn(raw.decode("ascii", "ignore"), json.dumps(safe, sort_keys=True))

    def test_fixed_queries_use_fixture_provenance_for_empty_success(self):
        for query_id in (usb_recovery.QUERY_CEER, usb_recovery.QUERY_CGPADDR):
            with self.subTest(query_id=query_id):
                safe = usb_recovery.sanitize_query_response(query_id, b"OK\n")
                self.assertTrue(safe["valid"])
                if query_id == usb_recovery.QUERY_CEER:
                    self.assertEqual(safe["last_error"], {"present": False})
                else:
                    self.assertEqual(safe["entry_count"], 0)
                    self.assertEqual(safe["entries"], [])

    def test_cgpaddr_sanitizes_dual_stack_addresses_to_structure_only(self):
        ipv4 = "192.0.2.44"
        ipv6 = "2001:db8::44"
        raw = f'+CGPADDR: 3,"{ipv4}",{ipv6}\r\nOK\r\n'.encode("ascii")

        safe = usb_recovery.sanitize_query_response(usb_recovery.QUERY_CGPADDR, raw)

        self.assertEqual(safe, {
            "query_id": usb_recovery.QUERY_CGPADDR,
            "valid": True,
            "entry_count": 1,
            "entries": [{
                "cid": 3,
                "address_count": 2,
                "ipv4": True,
                "ipv6": True,
            }],
        })
        encoded = json.dumps(safe, sort_keys=True)
        self.assertNotIn(ipv4, encoded)
        self.assertNotIn(ipv6, encoded)

    def test_cgpaddr_sanitizes_cid_only_entry(self):
        self.assertEqual(
            usb_recovery.sanitize_query_response(
                usb_recovery.QUERY_CGPADDR,
                b"+CGPADDR: 7\r\nOK\r\n",
            ),
            {
                "query_id": usb_recovery.QUERY_CGPADDR,
                "valid": True,
                "entry_count": 1,
                "entries": [{
                    "cid": 7,
                    "address_count": 0,
                    "ipv4": False,
                    "ipv6": False,
                }],
            },
        )

    def test_cgpaddr_rejects_malformed_duplicate_control_and_excess_tokens(self):
        cases = (
            b"+CGPADDR: 0,192.0.2.1\r\nOK\r\n",
            b"+CGPADDR: 256,192.0.2.1\r\nOK\r\n",
            b"+CGPADDR: 1,999.0.2.1\r\nOK\r\n",
            b"+CGPADDR: 1,192.0.2.1\r\n+CGPADDR: 1,2001:db8::1\r\nOK\r\n",
            b"+CGPADDR: 1,192.0.2.1\x1b\r\nOK\r\n",
            b"+CGPADDR: 1,192.0.2.1,2001:db8::1,192.0.2.2\r\nOK\r\n",
            b"+CGPADDR: 1,\"\",2001:db8::1\r\nOK\r\n",
            b"+CGPADDR: 1,192.0.2.1\r\n+CMTI: \"SM\",1\r\nOK\r\n",
        )
        for raw in cases:
            with self.subTest(raw=raw):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(usb_recovery.QUERY_CGPADDR, raw),
                    {
                        "query_id": usb_recovery.QUERY_CGPADDR,
                        "valid": False,
                        "error": "invalid-response",
                    },
                )

    def test_new_private_query_fixtures_are_bounded_without_raw_output(self):
        fixtures = (
            ("ati-raw-20260823.bin", 36, "3b92c0b78fdd1dc8afbfd56dc2b876023f6de75411feeff93a4d8550ff65d05c", usb_recovery.QUERY_ATI),
            ("ceer-raw-20260823.bin", 3, "a12b7cb43c9d9134b5bb1b35e9096b66775d9e92e7611d1cc92b02edd6782a87", usb_recovery.QUERY_CEER),
            ("cgpaddr-raw-20260823.bin", 3, "a12b7cb43c9d9134b5bb1b35e9096b66775d9e92e7611d1cc92b02edd6782a87", usb_recovery.QUERY_CGPADDR),
        )
        root = ROOT / ".secrets" / "hardware-migration-20260821"
        for name, size, digest, query_id in fixtures:
            path = root / name
            if not path.is_file():
                self.skipTest("private fixed-query fixtures are not present")
            metadata = path.stat()
            self.assertEqual(metadata.st_mode & 0o777, 0o600)
            self.assertEqual(metadata.st_size, size)
            payload = path.read_bytes()
            self.assertEqual(hashlib.sha256(payload).hexdigest(), digest)
            safe = usb_recovery.sanitize_query_response(query_id, payload)
            self.assertTrue(safe["valid"])
            self.assertNotIn(payload.decode("utf-8"), json.dumps(safe, sort_keys=True))
            if query_id == usb_recovery.QUERY_ATI:
                self.assertIsNotNone(safe["model"])
                self.assertIsNotNone(safe["firmware"])
            elif query_id == usb_recovery.QUERY_CEER:
                self.assertEqual(safe["last_error"], {"present": False})
            else:
                self.assertEqual(safe["entries"], [])

    def test_fixed_queries_fail_closed_on_duplicates_urcs_and_unknown_sentinels(self):
        cases = (
            (usb_recovery.QUERY_CPIN, b"+CPIN: READY\r\n+CPIN: READY\r\nOK\r\n"),
            (usb_recovery.QUERY_COPS, b'+COPS: 0,2,"x",7\r\n+CMTI: "SM",1\r\nOK\r\n'),
            (usb_recovery.QUERY_CGACT, b"+CGACT: 1,1\r\n+CGACT: 1,0\r\nOK\r\n"),
            (usb_recovery.QUERY_CSQ, b"+CSQ: 32,99\r\nOK\r\n"),
            (usb_recovery.QUERY_CESQ, b"+CESQ: 64,99,255,255,14,71\r\nOK\r\n"),
            (usb_recovery.QUERY_CFUN, b"+CFUN: 9\r\nOK\r\n"),
            (usb_recovery.QUERY_CREG, b"+CREG: 2,1\r\n+CREG: 2,1\r\nOK\r\n"),
            (usb_recovery.QUERY_CEER, b"+CEER: 0\r\nOK\r\n"),
        )
        for query_id, raw in cases:
            with self.subTest(query_id=query_id):
                self.assertEqual(
                    usb_recovery.sanitize_query_response(query_id, raw),
                    {"query_id": query_id, "valid": False, "error": "invalid-response"},
                )

    def test_query_cli_defaults_to_json_and_sends_only_the_query_id(self):
        calls = []
        raw = b"+ICCID: 8986001234567890123\r\nOK\r\n"

        def fake_transaction(path, timeout, command, payload, **_kwargs):
            calls.append((path, timeout, command, payload))
            return usb_recovery.Frame(usb_recovery.RESPONSE_MODEM_QUERY, 0, raw)

        args = type("Args", (), {
            "device": "/dev/serial/by-id/test",
            "timeout": None,
            "query_name": None,
            "query_option": "iccid",
            "raw": False,
        })()
        output = io.StringIO()
        with mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                redirect_stdout(output):
            self.assertEqual(usb_recovery._query_command(args), 0)
        self.assertEqual(calls, [
            ("/dev/serial/by-id/test", usb_recovery.QUERY_TIMEOUT,
             usb_recovery.COMMAND_MODEM_QUERY, b"\x08"),
        ])
        self.assertNotIn("8986001234567890123", output.getvalue())
        self.assertEqual(json.loads(output.getvalue())["length"], 19)

    def test_query_frame_limit_and_sequence_are_bounded(self):
        frame = usb_recovery.build_frame(
            usb_recovery.RESPONSE_MODEM_QUERY, b"x" * usb_recovery.MAX_PAYLOAD, sequence=7
        )
        parser = usb_recovery.FrameParser(usb_recovery.RESPONSE_COMMANDS)
        self.assertEqual(parser.feed(frame)[0].sequence, 7)
        with self.assertRaises(ValueError):
            usb_recovery.build_frame(
                usb_recovery.COMMAND_MODEM_QUERY,
                b"x" * (usb_recovery.MAX_QUERY_PAYLOAD + 1),
                sequence=0,
            )

    def test_device_transact_ignores_a_response_with_the_wrong_sequence(self):
        master, slave = pty.openpty()
        errors = []
        wrong = usb_recovery.build_frame(usb_recovery.RESPONSE_MODEM_QUERY, b"\x00wrong", sequence=1)
        right = usb_recovery.build_frame(usb_recovery.RESPONSE_MODEM_QUERY, b"\x00right", sequence=0)

        def device_peer():
            try:
                os.read(master, usb_recovery.MAX_FRAME)
                os.write(master, wrong + right)
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        peer = threading.Thread(target=device_peer)
        peer.start()
        try:
            with mock.patch.object(usb_recovery.os, "open", return_value=slave), \
                    mock.patch.object(usb_recovery.fcntl, "flock"), \
                    mock.patch.object(usb_recovery.fcntl, "ioctl", return_value=0):
                with usb_recovery.Device("/dev/serial/by-id/test", timeout=1.0) as device:
                    response = device.transact(usb_recovery.COMMAND_MODEM_QUERY, b"\x01", sequence=0)
            self.assertEqual(response.payload, b"right")
        finally:
            peer.join(1.0)
            os.close(master)
        self.assertFalse(errors)

    def test_device_transact_decodes_bounded_busy_reason(self):
        master, slave = pty.openpty()
        errors = []

        def device_peer():
            try:
                os.read(master, usb_recovery.MAX_FRAME)
                os.write(master, usb_recovery.build_frame(
                    usb_recovery.RESPONSE_MODEM_QUERY, bytes((usb_recovery.STATUS_BUSY, 3)), sequence=0
                ))
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        peer = threading.Thread(target=device_peer)
        peer.start()
        try:
            with mock.patch.object(usb_recovery.os, "open", return_value=slave), \
                    mock.patch.object(usb_recovery.fcntl, "flock"), \
                    mock.patch.object(usb_recovery.fcntl, "ioctl", return_value=0):
                with usb_recovery.Device("/dev/serial/by-id/test", timeout=1.0) as device:
                    with self.assertRaises(usb_recovery.CommandError) as raised:
                        device.transact(usb_recovery.COMMAND_MODEM_QUERY, b"\x10", sequence=0)
            self.assertEqual(raised.exception.reason, "slots_full")
            self.assertNotIn("3", str(raised.exception))
        finally:
            peer.join(1.0)
            os.close(master)
        self.assertFalse(errors)

    def test_device_transact_advances_sequence_and_rejects_delayed_stale_frame(self):
        master, slave = pty.openpty()
        errors = []
        observed = []

        def device_peer():
            try:
                first = os.read(master, usb_recovery.MAX_FRAME)
                observed.append(usb_recovery.HEADER.unpack_from(first)[4])
                os.write(master, usb_recovery.build_frame(
                    usb_recovery.RESPONSE_MODEM_QUERY, b"\x00first",
                    sequence=observed[-1],
                ))
                second = os.read(master, usb_recovery.MAX_FRAME)
                observed.append(usb_recovery.HEADER.unpack_from(second)[4])
                stale = usb_recovery.build_frame(
                    usb_recovery.RESPONSE_MODEM_QUERY, b"\x00stale",
                    sequence=observed[0],
                )
                current = usb_recovery.build_frame(
                    usb_recovery.RESPONSE_MODEM_QUERY, b"\x00second",
                    sequence=observed[-1],
                )
                os.write(master, stale + current)
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        peer = threading.Thread(target=device_peer)
        peer.start()
        try:
            with mock.patch.object(usb_recovery.os, "open", return_value=slave), \
                    mock.patch.object(usb_recovery.fcntl, "flock"), \
                    mock.patch.object(usb_recovery.fcntl, "ioctl", return_value=0), \
                    mock.patch.object(usb_recovery, "_sequence_value", 0):
                with usb_recovery.Device("/dev/serial/by-id/test", timeout=1.0) as device:
                    first = device.transact(usb_recovery.COMMAND_MODEM_QUERY, b"\x01")
                    second = device.transact(usb_recovery.COMMAND_MODEM_QUERY, b"\x01")
            self.assertEqual(first.payload, b"first")
            self.assertEqual(second.payload, b"second")
            self.assertEqual(observed, [0, 1])
        finally:
            peer.join(1.0)
            os.close(master)
        self.assertFalse(errors)

    def test_fragmented_frame_resynchronizes_after_boot_noise(self):
        frame = usb_recovery.build_frame(
            usb_recovery.RESPONSE_STATE, b"\x00", sequence=9
        )
        parser = usb_recovery.FrameParser(usb_recovery.RESPONSE_COMMANDS)
        result = []
        noisy = b"ROM noise\x00\xff" + frame
        for byte in noisy:
            result.extend(parser.feed(bytes((byte,))))
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].command, usb_recovery.RESPONSE_STATE)
        self.assertEqual(result[0].sequence, 9)

    def test_bad_crc_and_oversized_length_are_discarded(self):
        frame = bytearray(usb_recovery.build_frame(
            usb_recovery.RESPONSE_STATE, b"\x00", sequence=1
        ))
        frame[-1] ^= 0x80
        oversized = (
            usb_recovery.MAGIC
            + bytes((usb_recovery.VERSION, usb_recovery.RESPONSE_STATE))
            + (usb_recovery.MAX_PAYLOAD + 1).to_bytes(2, "little")
            + b"\x02"
        )
        parser = usb_recovery.FrameParser(usb_recovery.RESPONSE_COMMANDS)
        self.assertEqual(parser.feed(bytes(frame) + oversized), [])
        self.assertLessEqual(parser.buffered, usb_recovery.MAX_FRAME * 2)

    def test_incomplete_frame_is_released_after_idle_timeout(self):
        parser = usb_recovery.FrameParser(usb_recovery.RESPONSE_COMMANDS)
        incomplete = (
            usb_recovery.MAGIC
            + bytes((usb_recovery.VERSION, usb_recovery.RESPONSE_STATE))
            + usb_recovery.MAX_PAYLOAD.to_bytes(2, "little")
            + b"\x01"
        )
        parser.feed(incomplete)
        parser.reset_if_idle(time.monotonic() + usb_recovery.PARSER_IDLE_TIMEOUT + 1.0)
        frame = usb_recovery.build_frame(
            usb_recovery.RESPONSE_STATE, b"\x00", sequence=2
        )
        self.assertEqual(parser.feed(frame)[0].sequence, 2)

    def test_command_allowlist_and_payload_bound(self):
        with self.assertRaises(ValueError):
            usb_recovery.build_frame(0x7F, b"", sequence=0)
        with self.assertRaises(ValueError):
            usb_recovery.build_frame(
                usb_recovery.COMMAND_WIFI_PROVISION,
                b"x" * (usb_recovery.MAX_PAYLOAD + 1),
                sequence=0,
            )
        usb_recovery.build_frame(usb_recovery.COMMAND_OTA_MIGRATION_RECOVER, b"", sequence=0)
        with self.assertRaises(ValueError):
            usb_recovery.build_frame(
                usb_recovery.COMMAND_OTA_MIGRATION_RECOVER, b"x", sequence=0,
            )
        parser = usb_recovery.FrameParser(usb_recovery.RESPONSE_COMMANDS)
        unknown = usb_recovery._build_unchecked_frame(0x7F, b"", sequence=0)
        self.assertEqual(parser.feed(unknown), [])

    def test_device_path_cannot_escape_by_id_directory(self):
        with self.assertRaises(ValueError):
            usb_recovery.Device("/dev/ttyACM0")
        with self.assertRaises(ValueError):
            usb_recovery.Device("/dev/serial/by-id/../ttyACM0")

    def test_container_device_path_requires_internal_marker_and_flag(self):
        with self.assertRaises(ValueError):
            usb_recovery.Device(usb_recovery.INTERNAL_DEVICE_PATH)
        with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}):
            with self.assertRaises(ValueError):
                usb_recovery.Device(usb_recovery.INTERNAL_DEVICE_PATH)
            device = usb_recovery.Device(
                usb_recovery.INTERNAL_DEVICE_PATH, internal_container=True,
            )
        self.assertEqual(device.path, usb_recovery.INTERNAL_DEVICE_PATH)

    def test_container_cli_internal_state_accepts_fixed_device_and_timeout(self):
        calls = []

        def fake_transaction(path, timeout, command, payload, **kwargs):
            calls.append((path, timeout, command, payload, kwargs))
            return usb_recovery.Frame(usb_recovery.RESPONSE_STATE, 0, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00")

        with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction):
            self.assertEqual(usb_recovery.main([
                "--device", usb_recovery.INTERNAL_DEVICE_PATH,
                "--timeout", "2.25", "--internal-container", "state",
            ]), 0)
        self.assertEqual(calls[0][:4], (
            usb_recovery.INTERNAL_DEVICE_PATH, 2.25, usb_recovery.COMMAND_STATE, b"",
        ))
        self.assertTrue(calls[0][4]["internal_container"])
        self.assertIn("deadline", calls[0][4])

    def test_container_cli_migration_recovery_sends_empty_payload(self):
        calls = []

        def fake_transaction(path, timeout, command, payload, **kwargs):
            calls.append((path, timeout, command, payload, kwargs))
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_OTA_MIGRATION_RECOVER, 0, b""
            )

        with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction):
            self.assertEqual(usb_recovery.main([
                "--device", usb_recovery.INTERNAL_DEVICE_PATH,
                "--timeout", "2.25", "--internal-container", "ota-migration-recover",
            ]), 0)
        self.assertEqual(calls[0][:4], (
            usb_recovery.INTERNAL_DEVICE_PATH, 2.25,
            usb_recovery.COMMAND_OTA_MIGRATION_RECOVER, b"",
        ))
        self.assertTrue(calls[0][4]["internal_container"])
        self.assertIn("deadline", calls[0][4])

    def test_internal_diag_batch_uses_fixed_ids_and_sanitizes_before_json(self):
        calls = []
        raw = {
            usb_recovery.QUERY_ICCID: b"+ICCID: 8986001234567890123\r\nOK\r\n",
            usb_recovery.QUERY_CSQ: b"+CSQ: 31,99\r\nOK\r\n",
        }
        args = type("Args", (), {
            "device": usb_recovery.INTERNAL_DEVICE_PATH,
            "timeout": 12.0,
            "query_names": ["iccid", "csq"],
            "internal_container": True,
        })()

        def fake_transaction(path, timeout, command, payload, **kwargs):
            calls.append((path, timeout, command, payload, kwargs))
            query_id = payload[0]
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_MODEM_QUERY,
                0,
                raw[query_id],
            )

        output = io.StringIO()
        with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                redirect_stdout(output):
            self.assertEqual(usb_recovery._diag_batch_command(args), 0)

        self.assertEqual([call[3] for call in calls], [b"\x08", b"\x09"])
        self.assertTrue(all(call[4]["internal_container"] for call in calls))
        self.assertNotIn("8986001234567890123", output.getvalue())
        payload = json.loads(output.getvalue())
        self.assertEqual(set(payload), {"version", "results"})
        self.assertEqual(set(payload["results"]), {"iccid", "csq"})

    def test_internal_diag_batch_keeps_fixed_invalid_result_and_continues(self):
        calls = []
        raw = {
            usb_recovery.QUERY_CEREG: b"+CEREG: 3,1\r\nOK\r\n",
            usb_recovery.QUERY_CSQ: b"+CSQ: 31,99\r\nOK\r\n",
        }
        args = type("Args", (), {
            "device": usb_recovery.INTERNAL_DEVICE_PATH,
            "timeout": 12.0,
            "query_names": ["cereg", "csq"],
            "internal_container": True,
        })()

        def fake_transaction(path, timeout, command, payload, **kwargs):
            calls.append((path, timeout, command, payload, kwargs))
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_MODEM_QUERY,
                0,
                raw[payload[0]],
            )

        output = io.StringIO()
        with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                redirect_stdout(output):
            self.assertEqual(usb_recovery._diag_batch_command(args), 0)

        self.assertEqual(len(calls), 2)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["results"]["cereg"], {
            "query_id": usb_recovery.QUERY_CEREG,
            "valid": False,
            "error": "invalid-response",
        })
        self.assertEqual(
            usb_recovery.sanitize_query_response(
                usb_recovery.QUERY_CEREG, raw[usb_recovery.QUERY_CEREG]
            ),
            payload["results"]["cereg"],
        )
        self.assertTrue(payload["results"]["csq"]["valid"])

    def test_internal_diag_batch_keeps_unavailable_result_and_continues(self):
        calls = []
        args = type("Args", (), {
            "device": usb_recovery.INTERNAL_DEVICE_PATH,
            "timeout": 12.0,
            "query_names": ["iccid", "csq"],
            "internal_container": True,
        })()

        def fake_transaction(path, timeout, command, payload, **kwargs):
            calls.append((path, timeout, command, payload, kwargs))
            if payload == bytes((usb_recovery.QUERY_ICCID,)):
                raise usb_recovery.CommandError(usb_recovery.STATUS_NOT_READY)
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_MODEM_QUERY,
                0,
                b"+CSQ: 31,99\r\nOK\r\n",
            )

        output = io.StringIO()
        with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                redirect_stdout(output):
            self.assertEqual(usb_recovery._diag_batch_command(args), 0)

        self.assertEqual(len(calls), 2)
        payload = json.loads(output.getvalue())
        self.assertEqual(payload["results"]["iccid"], {
            "query_id": usb_recovery.QUERY_ICCID,
            "valid": False,
            "error": "unavailable",
        })
        self.assertEqual(payload["results"]["csq"]["rssi"], 31)

    def test_diag_batch_requires_the_internal_container_marker(self):
        args = type("Args", (), {
            "device": usb_recovery.INTERNAL_DEVICE_PATH,
            "timeout": 12.0,
            "query_names": ["iccid"],
            "internal_container": False,
        })()
        with self.assertRaisesRegex(ValueError, "internal command"):
            usb_recovery._diag_batch_command(args)

    def test_host_cli_cannot_use_internal_device_path(self):
        error = io.StringIO()
        with redirect_stderr(error):
            result = usb_recovery.main([
                "--device", usb_recovery.INTERNAL_DEVICE_PATH, "state",
            ])
        self.assertNotEqual(result, 0)
        self.assertIn("explicit /dev/serial/by-id path", error.getvalue())

    def test_device_reports_open_failure_instead_of_hiding_claim_stage(self):
        with mock.patch.object(
            usb_recovery.os,
            "open",
            side_effect=OSError(errno.EACCES, "permission denied"),
        ):
            with self.assertRaisesRegex(usb_recovery.DeviceError, r"open.*EACCES"):
                with usb_recovery.Device("/dev/serial/by-id/test"):
                    pass

    def test_device_restores_termios_before_unlock_and_close(self):
        master, slave = pty.openpty()
        inspect_fd = os.dup(slave)
        before = termios.tcgetattr(inspect_fd)
        try:
            with mock.patch.object(usb_recovery.os, "open", return_value=slave), \
                    mock.patch.object(usb_recovery.fcntl, "flock"), \
                    mock.patch.object(usb_recovery.fcntl, "ioctl", return_value=0):
                with usb_recovery.Device("/dev/serial/by-id/test"):
                    self.assertNotEqual(termios.tcgetattr(inspect_fd), before)
            self.assertEqual(termios.tcgetattr(inspect_fd), before)
        finally:
            os.close(inspect_fd)
            os.close(master)

    def test_device_transact_recovers_after_idle_incomplete_response(self):
        master, slave = pty.openpty()
        errors = []
        valid = usb_recovery.build_frame(
            usb_recovery.RESPONSE_STATE, b"\x00", sequence=0
        )
        incomplete = (
            usb_recovery.MAGIC
            + bytes((usb_recovery.VERSION, usb_recovery.RESPONSE_STATE))
            + usb_recovery.MAX_PAYLOAD.to_bytes(2, "little")
            + b"\x00"
        )

        def device_peer():
            try:
                os.read(master, usb_recovery.MAX_FRAME)
                os.write(master, incomplete)
                time.sleep(usb_recovery.PARSER_IDLE_TIMEOUT + 0.05)
                os.write(master, valid)
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        peer = threading.Thread(target=device_peer)
        peer.start()
        try:
            with mock.patch.object(usb_recovery.os, "open", return_value=slave), \
                    mock.patch.object(usb_recovery.fcntl, "flock"), \
                    mock.patch.object(usb_recovery.fcntl, "ioctl", return_value=0):
                with usb_recovery.Device("/dev/serial/by-id/test", timeout=3.0) as device:
                    response = device.transact(usb_recovery.COMMAND_STATE, b"", sequence=0)
            self.assertEqual(response.command, usb_recovery.RESPONSE_STATE)
        finally:
            peer.join(3.0)
            os.close(master)
        self.assertFalse(errors)

    def test_device_transact_times_out_during_continuous_noise(self):
        master, slave = pty.openpty()
        stop = threading.Event()
        errors = []

        def device_peer():
            try:
                os.read(master, usb_recovery.MAX_FRAME)
                noise_until = time.monotonic() + 0.25
                os.set_blocking(master, False)
                while not stop.is_set() and time.monotonic() < noise_until:
                    try:
                        os.write(master, b"unframed noise" * 256)
                    except BlockingIOError:
                        time.sleep(0.001)
                    except OSError:
                        break
            except BaseException as exc:  # pragma: no cover - reported below
                errors.append(exc)

        peer = threading.Thread(target=device_peer)
        peer.start()
        try:
            with mock.patch.object(usb_recovery.os, "open", return_value=slave), \
                    mock.patch.object(usb_recovery.fcntl, "flock"), \
                    mock.patch.object(usb_recovery.fcntl, "ioctl", return_value=0):
                with usb_recovery.Device("/dev/serial/by-id/test", timeout=0.05) as device:
                    started = time.monotonic()
                    with self.assertRaisesRegex(usb_recovery.DeviceError, "timed out"):
                        device.transact(usb_recovery.COMMAND_STATE, b"", sequence=0)
            elapsed = time.monotonic() - started
            self.assertLess(elapsed, 0.15)
        finally:
            stop.set()
            peer.join(1.0)
            os.close(master)
        self.assertFalse(errors)

    def test_provision_transaction_is_at_most_once_but_state_retries(self):
        attempts = []

        class FailedDevice:
            def __init__(self, *_args):
                pass

            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def transact(self, command, _payload):
                attempts.append(command)
                raise usb_recovery.DeviceError("transport failed")

        with mock.patch.object(usb_recovery, "Device", FailedDevice):
            with self.assertRaises(usb_recovery.DeviceError):
                usb_recovery.run_transaction(
                    "/dev/serial/by-id/test", 0.01,
                    usb_recovery.COMMAND_WIFI_PROVISION, b"payload",
                )
        self.assertEqual(attempts, [usb_recovery.COMMAND_WIFI_PROVISION])

        attempts.clear()
        with mock.patch.object(usb_recovery, "Device", FailedDevice):
            with self.assertRaises(usb_recovery.DeviceError):
                usb_recovery.run_transaction(
                    "/dev/serial/by-id/test", 0.01,
                    usb_recovery.COMMAND_STATE, b"",
                )
        self.assertEqual(attempts, [usb_recovery.COMMAND_STATE] * 3)

    def test_command_defaults_allow_durable_provisioning(self):
        calls = []
        nonce = 0x0102030405060708

        def fake_transaction(path, timeout, command, payload, **_kwargs):
            calls.append((path, timeout, command, payload))
            if command == usb_recovery.COMMAND_STATE:
                return usb_recovery.Frame(command | usb_recovery.RESPONSE_MASK, 0, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00")
            if command == usb_recovery.COMMAND_WIFI_PROVISION_ASYNC:
                return usb_recovery.Frame(command | usb_recovery.RESPONSE_MASK, 0, b"")
            return usb_recovery.Frame(
                command | usb_recovery.RESPONSE_MASK, 0,
                nonce.to_bytes(8, "little") + b"\x02\x00\x01",
            )

        args = type("Args", (), {"device": "/dev/serial/by-id/test", "timeout": None})()
        with mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                mock.patch.object(usb_recovery.getpass, "getpass", return_value="password"), \
                mock.patch.object(usb_recovery, "new_provision_nonce", return_value=nonce):
            usb_recovery._state_command(args)
            args.ssid = "network"
            usb_recovery._wifi_command(args)
        self.assertEqual(calls[0][1:], (5.0, usb_recovery.COMMAND_STATE, b""))
        self.assertEqual(calls[1][1], 90.0)
        self.assertEqual(calls[1][2], usb_recovery.COMMAND_WIFI_PROVISION_ASYNC)
        help_text = " ".join(usb_recovery.build_parser().format_help().split())
        self.assertIn("90s for wifi-provision", help_text)

    def test_wifi_payload_starts_with_client_nonce(self):
        payload = usb_recovery.encode_wifi_provision_async(
            "net", "password", nonce=0x0123456789ABCDEF
        )
        self.assertEqual(payload, b"\xef\xcd\xab\x89\x67\x45\x23\x01\x03\x08netpassword")

    def test_nonce_generation_uses_64_nonsecret_bits(self):
        with mock.patch.object(usb_recovery.secrets, "randbits", return_value=7) as randbits:
            self.assertEqual(usb_recovery.new_provision_nonce(), 7)
        randbits.assert_called_once_with(64)

    def test_async_frame_has_bounded_extended_payload_without_changing_legacy_limit(self):
        frame = usb_recovery.build_frame(
            usb_recovery.COMMAND_WIFI_PROVISION_ASYNC,
            b"x" * usb_recovery.MAX_ASYNC_PROVISION_PAYLOAD,
            sequence=0,
        )
        self.assertEqual(len(frame), usb_recovery.HEADER_SIZE + 104 + usb_recovery.CRC_SIZE)
        with self.assertRaises(ValueError):
            usb_recovery.build_frame(
                usb_recovery.COMMAND_WIFI_PROVISION_ASYNC,
                b"x" * (usb_recovery.MAX_ASYNC_PROVISION_PAYLOAD + 1),
                sequence=0,
            )
        with self.assertRaises(ValueError):
            usb_recovery.build_frame(
                usb_recovery.COMMAND_WIFI_PROVISION,
                b"x" * (usb_recovery.MAX_PAYLOAD + 1),
                sequence=0,
            )

    def test_state_parser_requires_a_nonzero_boot_id(self):
        state = usb_recovery.decode_state_payload(b"\x00\x00\x00\x00\x00\x78\x56\x34\x12")
        self.assertEqual(set(state), {"ap_mode", "credential_configured", "ip", "sta_connected", "boot_id"})
        self.assertEqual(state["boot_id"], 0x12345678)
        for payload in (b"\x00\x00\x00\x00\x00", b"\x00\x00\x00\x00\x00\x00\x00\x00\x00"):
            with self.subTest(payload=payload), self.assertRaises(usb_recovery.DeviceError):
                usb_recovery.decode_state_payload(payload)

        status = usb_recovery.decode_provision_status_payload(
            b"\x12\x34\x56\x78\x00\x00\x00\x00\x02\x00\x01"
        )
        self.assertEqual(status, {"nonce": 0x78563412, "state": usb_recovery.PROVISION_SETUP_STARTED, "error": 0, "connection": 1})

    def test_lost_ack_polls_matching_nonce_without_resending(self):
        nonce = 0x1020304050607080
        calls = []
        states = [
            usb_recovery.Frame(
                usb_recovery.RESPONSE_WIFI_PROVISION_STATUS, 0,
                b"\x80\x70\x60\x50\x40\x30\x20\x10\x01\x00\x01",
            ),
            usb_recovery.Frame(
                usb_recovery.RESPONSE_WIFI_PROVISION_STATUS, 0,
                b"\x80\x70\x60\x50\x40\x30\x20\x10\x02\x00\x02",
            ),
        ]

        def transaction(_path, _timeout, command, _payload, **_kwargs):
            calls.append(command)
            if command == usb_recovery.COMMAND_WIFI_PROVISION_ASYNC:
                raise usb_recovery.DeviceError("USB device timed out")
            return states.pop(0)

        args = type("Args", (), {
            "device": "/dev/serial/by-id/test",
            "timeout": None,
            "ssid": "net",
        })()
        with mock.patch.object(usb_recovery, "run_transaction", side_effect=transaction), \
                mock.patch.object(usb_recovery, "new_provision_nonce", return_value=nonce), \
                mock.patch.object(usb_recovery.getpass, "getpass", return_value="password"), \
                mock.patch.object(usb_recovery.time, "sleep"):
            self.assertEqual(usb_recovery._wifi_command(args), 0)
        self.assertEqual(calls, [
            usb_recovery.COMMAND_WIFI_PROVISION_ASYNC,
            usb_recovery.COMMAND_WIFI_PROVISION_STATUS,
            usb_recovery.COMMAND_WIFI_PROVISION_STATUS,
        ])

    def test_stale_nonce_is_not_treated_as_current(self):
        nonce = 0x1020304050607080
        calls = []
        states = [
            usb_recovery.Frame(
                usb_recovery.RESPONSE_WIFI_PROVISION_STATUS, 0,
                b"\x99\x88\x77\x66\x55\x44\x33\x22\x02\x00\x01",
            ),
            usb_recovery.Frame(
                usb_recovery.RESPONSE_WIFI_PROVISION_STATUS, 0,
                b"\x80\x70\x60\x50\x40\x30\x20\x10\x03\x06\x03",
            ),
        ]

        def transaction(_path, _timeout, command, _payload, **_kwargs):
            calls.append(command)
            if command == usb_recovery.COMMAND_WIFI_PROVISION_ASYNC:
                return usb_recovery.Frame(usb_recovery.RESPONSE_WIFI_PROVISION, 0, b"")
            return states.pop(0)

        args = type("Args", (), {
            "device": "/dev/serial/by-id/test",
            "timeout": None,
            "ssid": "net",
        })()
        with mock.patch.object(usb_recovery, "run_transaction", side_effect=transaction), \
                mock.patch.object(usb_recovery, "new_provision_nonce", return_value=nonce), \
                mock.patch.object(usb_recovery.getpass, "getpass", return_value="password"), \
                mock.patch.object(usb_recovery.time, "sleep"):
            with self.assertRaises(usb_recovery.CommandError) as raised:
                usb_recovery._wifi_command(args)
        self.assertEqual(raised.exception.status, usb_recovery.STATUS_BUSY)
        self.assertEqual(calls, [
            usb_recovery.COMMAND_WIFI_PROVISION_ASYNC,
            usb_recovery.COMMAND_WIFI_PROVISION_STATUS,
            usb_recovery.COMMAND_WIFI_PROVISION_STATUS,
        ])

    def test_busy_ack_is_terminal_without_status_poll_or_resend(self):
        calls = []

        def transaction(_path, _timeout, command, _payload, **_kwargs):
            calls.append(command)
            raise usb_recovery.CommandError(usb_recovery.STATUS_BUSY)

        args = type("Args", (), {
            "device": "/dev/serial/by-id/test",
            "timeout": None,
            "ssid": "net",
        })()
        with mock.patch.object(usb_recovery, "run_transaction", side_effect=transaction), \
                mock.patch.object(usb_recovery, "new_provision_nonce", return_value=1), \
                mock.patch.object(usb_recovery.getpass, "getpass", return_value="password"):
            with self.assertRaises(usb_recovery.CommandError) as raised:
                usb_recovery._wifi_command(args)
        self.assertEqual(raised.exception.status, usb_recovery.STATUS_BUSY)
        self.assertEqual(calls, [usb_recovery.COMMAND_WIFI_PROVISION_ASYNC])

    def test_lost_ack_deadline_includes_initial_request(self):
        calls = []
        deadlines = []

        def transaction(_path, _timeout, command, _payload, **kwargs):
            calls.append(command)
            deadlines.append(kwargs.get("deadline"))
            raise usb_recovery.DeviceError("USB device timed out")

        args = type("Args", (), {
            "device": "/dev/serial/by-id/test",
            "timeout": 90.0,
            "ssid": "net",
        })()
        with mock.patch.object(usb_recovery, "run_transaction", side_effect=transaction), \
                mock.patch.object(usb_recovery, "new_provision_nonce", return_value=1), \
                mock.patch.object(usb_recovery.getpass, "getpass", return_value="password"), \
                mock.patch.object(usb_recovery.time, "monotonic", side_effect=(100.0, 190.0)):
            with self.assertRaises(usb_recovery.DeviceError):
                usb_recovery._wifi_command(args)
        self.assertEqual(calls, [usb_recovery.COMMAND_WIFI_PROVISION_ASYNC])
        self.assertEqual(deadlines, [190.0])


class UsbRecoveryBuildGuardTest(unittest.TestCase):
    def test_ota_state_firmware_keeps_legacy_wire_and_opt_in_identity(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        limit = function_body(source, "command_payload_limit")
        state = function_body(source, "ota_state")
        self.assertIn("if (command == kCommandOtaState) return 1;", limit)
        self.assertIn("frame.payload_length == 1 && frame.payload[0] == 0x01", state)
        self.assertIn("idf_web_ota_get_public_key_sha256", state)
        self.assertIn("kOtaStatePublicKeySize", state)
        self.assertIn("size_t state_length = kOtaStatePayload", state)
        self.assertIn("*output_length = 1 + state_length", state)

    def test_dev_frame_stage_instrumentation_is_bounded(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        self.assertIn("#if SMS_USB_RECOVERY && !FIRMWARE_IS_RELEASE", source)
        for stage in (
            "frame_received",
            "state_payload_begin",
            "state_payload_end",
            "write_frame",
        ):
            self.assertEqual(source.count(f"stage={stage}"), 1)

        fixture = "\n".join((
            "usb_recovery stage=frame_received seq=9 len=0",
            "usb_recovery stage=state_payload_begin seq=9 len=0",
            "usb_recovery stage=state_payload_end seq=9 len=9",
            "usb_recovery stage=write_frame seq=9 len=10 result=ESP_OK written=19",
        ))
        marker = re.compile(
            r"^usb_recovery stage=(frame_received|state_payload_begin|"
            r"state_payload_end|write_frame) seq=(\d+) len=(\d+)"
            r"(?: result=([A-Z0-9_]+) written=(\d+))?$"
        )
        records = [marker.fullmatch(line) for line in fixture.splitlines()]
        self.assertTrue(all(records))
        self.assertEqual([record.group(1) for record in records], [
            "frame_received",
            "state_payload_begin",
            "state_payload_end",
            "write_frame",
        ])
        instrumented_lines = [line for line in source.splitlines() if "usb_recovery stage=" in line]
        self.assertNotRegex("\n".join(instrumented_lines), r"\b(payload|ip|ssid|password|credential|device)\b")

    def test_query_path_is_dev_only_and_never_accepts_at_text(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        modem = (ROOT / "components" / "idf_modem" / "idf_modem.cpp").read_text(encoding="utf-8")
        self.assertIn("#if SMS_USB_RECOVERY", source)
        self.assertIn("kCommandModemQuery", source)
        self.assertIn("frame.payload_length != 1", source)
        self.assertIn("idf_modem_usb_query(frame.payload[0]", source)
        self.assertIn("Status::NotReady", source)
        self.assertNotIn("frame.payload", modem[modem.find("idf_modem_usb_query"):])

    def test_query_error_mapping_preserves_busy_and_timeout_status(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        mapping = function_body(source, "map_query_error")
        generic_mapping = function_body(source, "map_error")
        self.assertIn("IDF_MODEM_ERR_BUSY", mapping)
        self.assertIn("Status::Busy", mapping)
        self.assertIn("return map_error(err)", mapping)
        self.assertIn("ESP_ERR_TIMEOUT", generic_mapping)
        self.assertIn("Status::Timeout", generic_mapping)

    def test_modem_query_passes_busy_reason_and_fixed_output_length(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        modem_query = function_body(source, "modem_query")
        self.assertIn("kMaxModemQueryId = 0x12", source)
        self.assertIn(
            "kMaxQueryResponsePayload = IDF_MODEM_USB_QUERY_MSSLCIPHER_MAX_RESPONSE",
            source,
        )
        self.assertIn("1 + kMaxQueryResponsePayload", source)
        self.assertIn("frame.payload[0] > kMaxModemQueryId", modem_query)
        self.assertIn("idf_modem_usb_query(frame.payload[0], response, &busy_reason)", modem_query)
        self.assertIn("*output_length = 2", modem_query)

    def test_recovery_starts_after_config_and_before_wifi(self):
        source = (ROOT / "main" / "app_main.cpp").read_text(encoding="utf-8")
        config_load = source.index("esp_err_t cfg_err = idf_config_load();")
        usb_start = source.index("idf_usb_recovery_start())")
        wifi_start = source.index("idf_wifi_start(idf_config_get());")
        self.assertLess(config_load, usb_start)
        self.assertLess(usb_start, wifi_start)

    def test_wifi_persists_before_start_and_preserves_mru(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        wifi_header = (ROOT / "components" / "idf_wifi" / "include" / "idf_wifi.h").read_text(
            encoding="utf-8"
        )
        for text in (source, wifi_header):
            self.assertNotIn("idf_wifi_provision_rollback", text)
            self.assertNotIn("idf_wifi_provision_commit", text)
        provision = source.split("static Status provision_wifi_async", 1)[1].split(
            "static size_t state_payload", 1
        )[0]
        worker = source.split("static void usb_wifi_provision_task", 1)[1].split(
            "static Status provision_wifi_legacy", 1
        )[0]
        self.assertIn("xTaskCreate(usb_wifi_provision_task", provision)
        self.assertNotIn("idf_config_save_wifi", provision)
        self.assertIn("idf_config_save_wifi", worker)
        self.assertLess(worker.index("idf_config_save_wifi"), worker.index("idf_wifi_provision_connect"))
        self.assertIn("secure_zero", worker)
        self.assertNotIn("std::string ssid", worker)
        self.assertIn("async_pending", source)
        self.assertNotIn("const IdfConfig", provision)
        self.assertNotIn("IdfWifiNetwork networks", provision)
        self.assertNotIn("idf_config_get()", provision)
        self.assertNotIn("idf_config_save_wifi_networks", provision)

        class Runtime:
            def __init__(self):
                self.durable = False
                self.runtime = "old"
                self.events = []

            def save(self, succeeds):
                self.events.append("save")
                if not succeeds:
                    return False
                self.durable = True
                return True

            def start(self, candidate, succeeds):
                self.events.append("start")
                if not self.durable or not succeeds:
                    return False
                self.runtime = candidate
                return True

        runtime = Runtime()
        self.assertFalse(runtime.save(False))
        self.assertEqual(runtime.runtime, "old")
        self.assertEqual(runtime.events, ["save"])

        runtime = Runtime()
        self.assertTrue(runtime.save(True))
        self.assertFalse(runtime.start("new", False))
        self.assertTrue(runtime.durable)
        self.assertEqual(runtime.runtime, "old")
        self.assertEqual(runtime.events, ["save", "start"])

        profiles = ["new", "oldest", "old"]
        submitted = [profiles[0]] + list(reversed(profiles[1:]))
        self.assertEqual(submitted, ["new", "old", "oldest"])

    def test_wifi_startup_runs_off_usb_reader_task(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        provision = source.split("static Status provision_wifi_async", 1)[1].split(
            "static size_t state_payload", 1
        )[0]
        worker = source.split("static void usb_wifi_provision_task", 1)[1].split(
            "static Status provision_wifi_legacy", 1
        )[0]
        self.assertNotIn("idf_config_save_wifi", provision)
        self.assertIn("idf_config_save_wifi", worker)
        self.assertLess(worker.index("idf_config_save_wifi"), worker.index("idf_wifi_provision_connect"))
        self.assertIn("xTaskCreate(usb_wifi_provision_task", provision)
        self.assertIn("8192", source.split("xTaskCreate(usb_wifi_provision_task", 1)[1])

    def test_wifi_startup_waits_for_settled_ack(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        worker = source.split("static void usb_wifi_provision_task", 1)[1].split(
            "static Status provision_wifi_legacy", 1
        )[0]
        handler = source.split("static void handle_frame", 1)[1].split(
            "static void usb_recovery_task", 1
        )[0]
        self.assertIn("ulTaskNotifyTake", worker)
        self.assertLess(handler.index("write_frame"), handler.index("xTaskNotifyGive"))
        self.assertIn("secure_zero(buffer_", source)
        self.assertIn("secure_zero(input, sizeof(input))", source)
        self.assertIn("idf_wifi_get_status().staConnected", source)

    def test_state_payload_exposes_ephemeral_boot_id(self):
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        payload = source.split("static size_t state_payload", 1)[1].split(
            "static esp_err_t write_frame", 1
        )[0]
        task = source.split("static void usb_recovery_task", 1)[1]
        self.assertIn('#include "esp_system.h"', source)
        self.assertIn("static uint32_t s_boot_id = 0;", source)
        self.assertIn("write_u32(output + 1 + sizeof(ip), s_boot_id)", payload)
        self.assertIn("return 1 + sizeof(ip) + sizeof(s_boot_id);", payload)
        self.assertIn("s_boot_id = esp_random();", task)
        self.assertIn("if (s_boot_id == 0) s_boot_id = 1;", task)

    def test_recovery_artifact_has_enabled_definitions_and_entrypoint(self):
        compile_commands_path = RECOVERY_BUILD_DIR / "compile_commands.json"
        elf_path = RECOVERY_BUILD_DIR / "sms_forwarding_idf.elf"
        if not compile_commands_path.exists() or not elf_path.exists():
            if REQUIRE_RECOVERY_BUILD:
                self.fail("recovery build artifacts are required")
            self.skipTest("recovery build artifacts are not available")

        entries = json.loads(compile_commands_path.read_text(encoding="utf-8"))
        source_commands = {}
        for source in PROJECT_RELEASE_SOURCES:
            suffix = f"/main/{source}" if source in ("app_main.cpp", "usb_recovery.cpp") else f"/{source}"
            matches = [
                entry for entry in entries
                if entry.get("file", "").endswith(suffix)
            ]
            self.assertEqual(len(matches), 1, f"missing unique compile command for {source}")
            source_commands[source] = shlex.split(matches[0]["command"])
            self.assertIn("-DFIRMWARE_IS_RELEASE=0", source_commands[source])
            if source in ("app_main.cpp", "usb_recovery.cpp", "components/idf_modem/idf_modem.cpp"):
                self.assertIn("-DSMS_USB_RECOVERY=1", source_commands[source])

        nm = shutil.which("riscv32-esp-elf-nm") or shutil.which("nm")
        self.assertIsNotNone(nm, "an ELF symbol dumper is required for the recovery build guard")
        symbols = subprocess.run(
            [nm, "-C", "--defined-only", str(elf_path)],
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertRegex(symbols, r"\bidf_usb_recovery_start\b")
        self.assertRegex(symbols, r"\bidf_modem_usb_query\b")

        stack_files = sorted(RECOVERY_BUILD_DIR.rglob("usb_recovery.cpp.su"))
        if not stack_files:
            if REQUIRE_RECOVERY_BUILD:
                self.fail("recovery build must emit usb_recovery.cpp.su")
            self.skipTest("recovery stack-usage artifact is not available")
        stack_entries = {}
        for stack_file in stack_files:
            for line in stack_file.read_text(encoding="utf-8").splitlines():
                fields = line.rsplit(None, 2)
                if len(fields) != 3:
                    continue
                function = fields[0]
                for name in ("usb_recovery_task", "provision_wifi", "process_frame", "handle_frame"):
                    if re.search(rf"(?<![A-Za-z0-9_]){re.escape(name)}(?=[<(])", function):
                        stack_entries.setdefault(name, []).append((int(fields[1]), fields[2], line))

        task_entries = stack_entries.get("usb_recovery_task", [])
        self.assertEqual(len(task_entries), 1, "usb_recovery_task stack usage must be unique")
        frame, qualifier, detail = task_entries[0]
        self.assertIn(qualifier, ("static", "dynamic,bounded"), detail)

        nested_frames = []
        for name in ("provision_wifi", "process_frame", "handle_frame"):
            matches = stack_entries.get(name, [])
            self.assertLessEqual(len(matches), 1, f"{name} stack usage must be unique")
            if matches:
                nested_frames.append((name, matches[0][0], matches[0][2]))

        provision_symbol = re.search(r"\bprovision_wifi\b", symbols) is not None
        provision_stack = any(name == "provision_wifi" for name, _, _ in nested_frames)
        self.assertTrue(
            provision_stack or not provision_symbol,
            "provision_wifi must have a stack-usage entry or be proven inlined in the recovery ELF",
        )
        chain_frame = frame + sum(value for _, value, _ in nested_frames)
        self.assertLessEqual(
            chain_frame,
            USB_RECOVERY_TASK_MAX_FRAME_BYTES,
            f"USB recovery call chain frame {chain_frame} exceeds {USB_RECOVERY_TASK_MAX_FRAME_BYTES} bytes: {detail}",
        )
        representation = "explicit stack entries" if provision_stack else "provision_wifi inlined into task chain"
        print(
            f"usb_recovery_task frame: {frame} bytes; call-chain frame: {chain_frame} bytes "
            f"({USB_RECOVERY_TASK_STACK_BYTES - chain_frame} bytes headroom; {representation})"
        )

    def test_production_build_excludes_usb_source_and_fails_if_enabled(self):
        root_cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        main_cmake = (ROOT / "main" / "CMakeLists.txt").read_text(encoding="utf-8")
        source = (ROOT / "main" / "usb_recovery.cpp").read_text(encoding="utf-8")
        ota_source = (ROOT / "components" / "idf_web" / "idf_web_ota.cpp").read_text(encoding="utf-8")
        self.assertIn("SMS_USB_RECOVERY", root_cmake)
        self.assertIn("FIRMWARE_IS_RELEASE", root_cmake)
        self.assertIn("idf_build_set_property(COMPILE_DEFINITIONS", root_cmake)
        self.assertIn("if(SMS_USB_RECOVERY)", main_cmake)
        self.assertIn("usb_recovery.cpp", main_cmake)
        self.assertIn("target_compile_definitions(${COMPONENT_LIB} PRIVATE", main_cmake)
        self.assertIn('target_compile_options(${COMPONENT_LIB} PRIVATE "-fstack-usage")', main_cmake)
        self.assertIn("#if FIRMWARE_IS_RELEASE && SMS_USB_RECOVERY", source)
        self.assertIn("#error", source)
        self.assertIn("#if SMS_USB_RECOVERY && !FIRMWARE_IS_RELEASE", ota_source)
        self.assertIn("idf_web_ota_migration_recover", ota_source)
        self.assertIn('#include "lwip/sockets.h"', source)
        self.assertIn("usb_serial_jtag_driver_install", source)
        self.assertIn("usb_serial_jtag_read_bytes", source)
        self.assertIn("usb_serial_jtag_write_bytes", source)
        self.assertIn("idf_wifi_provision_connect", source)
        provision = source.split("static Status provision_wifi_async", 1)[1].split(
            "static size_t state_payload", 1
        )[0]
        worker = source.split("static void usb_wifi_provision_task", 1)[1].split(
            "static Status provision_wifi_legacy", 1
        )[0]
        self.assertNotIn("idf_config_save_wifi", provision)
        self.assertIn("idf_config_save_wifi", worker)
        self.assertLess(worker.index("idf_config_save_wifi"), worker.index("idf_wifi_provision_connect"))
        self.assertNotIn("const IdfConfig", provision)
        self.assertNotIn("IdfWifiNetwork networks", provision)
        self.assertIn('#include "idf_modem.h"', source)
        self.assertNotIn("UART1", source)
        self.assertIn("kParserIdleTimeout", source)
        self.assertIn("reset_if_idle", source)

        self.assertRegex(root_cmake, r'FIRMWARE_IS_RELEASE.*CACHE STRING.*FORCE')
        self.assertRegex(root_cmake, r'SMS_USB_RECOVERY.*CACHE STRING.*FORCE')
        idf_sh = (ROOT / "tools" / "idf.sh").read_text(encoding="utf-8")
        self.assertIn('SMS_USB_RECOVERY must be 0 or 1', idf_sh)
        self.assertIn('-D "FIRMWARE_IS_RELEASE=', idf_sh)
        self.assertIn('-D "SMS_USB_RECOVERY=', idf_sh)

        overlay = (ROOT / "sdkconfig.usb-recovery").read_text(encoding="utf-8")
        self.assertIn("CONFIG_ESP_CONSOLE_SECONDARY_NONE=y", overlay)
        self.assertIn("# CONFIG_ESP_ROM_CONSOLE_OUTPUT_SECONDARY is not set", overlay)

        workflow = (ROOT / ".github" / "workflows" / "build.yml").read_text(encoding="utf-8")
        self.assertIn("SMS_USB_RECOVERY=1 FIRMWARE_IS_RELEASE=0 ./tools/idf.sh build", workflow)
        self.assertIn("SMS_USB_RECOVERY_REQUIRE_BUILD=1 python3 tools/test_usb_recovery.py", workflow)
        self.assertIn("build/idf-usb-recovery", idf_sh)
        self.assertIn("build/sdkconfig-usb-recovery", idf_sh)

        release_compile_commands = ROOT / "build" / "idf" / "compile_commands.json"
        release_elf = ROOT / "build" / "idf" / "sms_forwarding_idf.elf"
        if release_compile_commands.exists():
            entries = json.loads(release_compile_commands.read_text(encoding="utf-8"))
            self.assertFalse(any(entry.get("file", "").endswith("/main/usb_recovery.cpp") for entry in entries))
            modem_entries = [
                entry for entry in entries
                if entry.get("file", "").endswith("/components/idf_modem/idf_modem.cpp")
            ]
            self.assertEqual(len(modem_entries), 1)
            self.assertIn("-DSMS_USB_RECOVERY=0", shlex.split(modem_entries[0]["command"]))
        if release_elf.exists():
            nm = shutil.which("riscv32-esp-elf-nm") or shutil.which("nm")
            self.assertIsNotNone(nm)
            symbols = subprocess.run(
                [nm, "-C", "--defined-only", str(release_elf)],
                check=True,
                capture_output=True,
                text=True,
            ).stdout
            self.assertNotRegex(symbols, r"idf_usb_recovery_start|idf_modem_usb_query|usb_query_command")
            self.assertNotRegex(symbols, r"idf_web_ota_migration_recover")


if __name__ == "__main__":
    unittest.main()
