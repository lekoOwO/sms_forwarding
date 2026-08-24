#!/usr/bin/env python3
"""Focused checks for dev signed OTA flash/state/health boundaries."""

from __future__ import annotations

import contextlib
import io
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import unittest
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import device  # noqa: E402
import usb_recovery  # noqa: E402


class OtaFlashProfileTest(unittest.TestCase):
    def test_ota_test_image_requires_verified_profile_cache(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            profile = root / "build" / "idf-ota-test"
            profile.mkdir(parents=True)
            image = profile / "sms_forwarding_idf.bin"
            image.write_bytes(b"dev-image")
            (profile / "CMakeCache.txt").write_text(
                "FIRMWARE_IS_RELEASE:STRING=0\n"
                "SMS_USB_RECOVERY:STRING=1\n"
                "SMS_OTA_TEST_KEY:STRING=1\n",
                encoding="ascii",
            )
            with mock.patch.object(device, "ROOT", root):
                self.assertEqual(device.validate_app0_image(image), len(b"dev-image"))

    def test_ota_test_image_rejects_stale_profile_flags_and_nonregular_files(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            profile = root / "build" / "idf-ota-test"
            profile.mkdir(parents=True)
            image = profile / "sms_forwarding_idf.bin"
            image.write_bytes(b"dev-image")
            cache = profile / "CMakeCache.txt"
            cache.write_text(
                "FIRMWARE_IS_RELEASE:STRING=0\n"
                "SMS_USB_RECOVERY:STRING=1\n"
                "SMS_OTA_TEST_KEY:STRING=0\n",
                encoding="ascii",
            )
            with mock.patch.object(device, "ROOT", root):
                with self.assertRaises(ValueError):
                    device.validate_app0_image(image)
                cache.unlink()
                image.unlink()
                os.mkfifo(image)
                with self.assertRaises(ValueError):
                    device.validate_app0_image(image)


class OtaStateProtocolTest(unittest.TestCase):
    def test_ota_state_payload_preserves_legacy_and_decodes_exact_extended_identity(self):
        legacy = usb_recovery.OTA_STATE_STRUCT.pack(
            usb_recovery.APP0_OFFSET, usb_recovery.OTA_IMAGE_STATE_PENDING_VERIFY,
            1, 7, 9, 0,
        )
        self.assertEqual(
            len(legacy), 18,
        )
        self.assertEqual(
            usb_recovery.decode_ota_state_payload(legacy),
            {
                "active_offset": usb_recovery.APP0_OFFSET,
                "image_state": "pending-verify",
                "pending_verify": True,
                "accepted": 7,
                "pending": 9,
                "pending_address": 0,
            },
        )
        fingerprint = "d7699fd512f82cfa86924a2ed90f3f165b1b21795455641f4327b24dc04fbe0b"
        extended = legacy + bytes.fromhex(fingerprint)
        self.assertEqual(len(extended), 50)
        self.assertEqual(
            usb_recovery.decode_ota_state_payload(extended),
            {
                "active_offset": usb_recovery.APP0_OFFSET,
                "image_state": "pending-verify",
                "pending_verify": True,
                "accepted": 7,
                "pending": 9,
                "pending_address": 0,
                "public_key_sha256": fingerprint,
            },
        )

    def test_ota_state_payload_rejects_invalid_fields_and_lengths(self):
        legacy = usb_recovery.OTA_STATE_STRUCT.pack(
            usb_recovery.APP0_OFFSET, usb_recovery.OTA_IMAGE_STATE_PENDING_VERIFY,
            1, 7, 9, 0,
        )
        for bad in (
            usb_recovery.OTA_STATE_STRUCT.pack(0, 1, 1, 7, 9, 0),
            usb_recovery.OTA_STATE_STRUCT.pack(
                usb_recovery.APP0_OFFSET, 99, 0, 7, 9, 0,
            ),
            legacy + b"\x00",
            legacy + b"\x00" * 31,
            legacy + b"\x00" * 33,
        ):
            with self.subTest(payload=bad):
                with self.assertRaises(usb_recovery.DeviceError):
                    usb_recovery.decode_ota_state_payload(bad)

    def test_container_ota_state_requires_exact_seven_key_shape(self):
        fingerprint = "d7699fd512f82cfa86924a2ed90f3f165b1b21795455641f4327b24dc04fbe0b"
        state = {
            "active_offset": usb_recovery.APP0_OFFSET,
            "image_state": "valid",
            "pending_verify": False,
            "accepted": 7,
            "pending": 0,
            "pending_address": 0,
            "public_key_sha256": fingerprint,
        }
        self.assertEqual(usb_recovery.validate_ota_state(state), state)
        legacy_fallback = dict(state, public_key_sha256=None)
        self.assertEqual(usb_recovery.validate_ota_state(legacy_fallback), legacy_fallback)
        for bad in (
            {key: value for key, value in state.items() if key != "public_key_sha256"},
            dict(state, public_key_sha256=fingerprint.upper()),
            dict(state, public_key_sha256=fingerprint[:-1]),
            dict(state, public_key_sha256=""),
            dict(state, extra=None),
        ):
            with self.subTest(state=bad):
                with self.assertRaises(usb_recovery.DeviceError):
                    usb_recovery.validate_ota_state(bad)

    def test_device_ota_state_command_emits_strict_json(self):
        active_offset = usb_recovery.APP1_OFFSET
        fingerprint = "d7699fd512f82cfa86924a2ed90f3f165b1b21795455641f4327b24dc04fbe0b"
        wire_payload = (
            bytes((usb_recovery.STATUS_OK,))
            + active_offset.to_bytes(4, "little")
            + bytes((usb_recovery.OTA_IMAGE_STATE_VALID, 0))
            + (11).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + (0).to_bytes(4, "little")
            + bytes.fromhex(fingerprint)
        )
        wire = usb_recovery.build_frame(
            usb_recovery.RESPONSE_OTA_STATE, wire_payload, 0x2A,
        )
        self.assertEqual(
            len(wire), usb_recovery.HEADER_SIZE + 51 + usb_recovery.CRC_SIZE,
        )
        frames = usb_recovery.FrameParser(usb_recovery.RESPONSE_COMMANDS).feed(wire)
        self.assertEqual(len(frames), 1)
        response = usb_recovery.Frame(
            frames[0].command, frames[0].sequence, frames[0].payload[1:],
        )
        output = io.StringIO()
        with mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(
                "/dev/serial/by-id/test", "/dev/ttyACM0")), \
                mock.patch.object(device.usb_recovery, "run_transaction", return_value=response) as transaction, \
                contextlib.redirect_stdout(output):
            self.assertEqual(device.main(["--device", "/dev/serial/by-id/test", "ota-state"]), 0)
        self.assertEqual(transaction.call_args.args[3], b"\x01")
        result = json.loads(output.getvalue())
        self.assertEqual(result, {
            "accepted": 11,
            "active_offset": active_offset,
            "image_state": "valid",
            "pending": 0,
            "pending_address": 0,
            "pending_verify": False,
            "public_key_sha256": fingerprint,
        })
        self.assertFalse(result["pending_verify"])


class OtaFailHealthProfileTest(unittest.TestCase):
    def test_fail_health_package_uses_isolated_artifact_and_strict_signer(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            build = root / "build"
            normal = build / "idf-ota-test"
            fail_health = build / "idf-ota-test-fail-health"
            normal.mkdir(parents=True)
            fail_health.mkdir()
            normal_image = normal / "sms_forwarding_idf.bin"
            fail_image = fail_health / "sms_forwarding_idf.bin"
            normal_image.write_bytes(b"normal-image")
            fail_image.write_bytes(b"fail-health-image")
            normal_cache = normal / "CMakeCache.txt"
            fail_cache = fail_health / "CMakeCache.txt"
            normal_cache.write_text("normal-cache\n", encoding="ascii")
            fail_cache.write_text("fail-cache\n", encoding="ascii")
            private_key = normal / "ota_test_private.pem"
            public_key = normal / "ota_test_public_key.der.b64"
            private_key.write_text("test-private-key", encoding="ascii")
            public_key.write_text("test-public-key", encoding="ascii")
            output = root / "dist" / "health.smsota"
            command = device.build_parser().parse_args([
                "ota-test-package", "--fail-health", "--counter", "37",
                "--version", "1.1.4-health-test", "--output", str(output),
            ])
            self.assertTrue(command.fail_health)
            calls: list[tuple[list[str], dict[str, str] | None]] = []

            def fake_run(command_line, **kwargs):
                command_line = [str(value) for value in command_line]
                calls.append((command_line, kwargs.get("env")))
                if command_line == [str(root / "tools" / "idf.sh"), "build"]:
                    environment = kwargs["env"]
                    self.assertEqual(environment["SMS_OTA_TEST_FAIL_HEALTH"], "1")
                    self.assertEqual(environment["SMS_OTA_TEST_KEY"], "1")
                    self.assertEqual(environment["SMS_USB_RECOVERY"], "1")
                    self.assertEqual(environment["FIRMWARE_IS_RELEASE"], "0")
                    self.assertEqual(environment["SMS_OTA_TEST_PUBLIC_KEY"], str(public_key))
                    return subprocess.CompletedProcess(command_line, 0)
                if command_line[1] == str(root / "scripts" / "sign-ota-release.py"):
                    self.assertEqual(command_line[2], str(fail_image))
                    self.assertEqual(command_line[3], str(output))
                    self.assertEqual(command_line[command_line.index("--private-key") + 1], str(private_key))
                    self.assertEqual(command_line[command_line.index("--counter") + 1], "37")
                    self.assertEqual(command_line[command_line.index("--version") + 1], "1.1.4-health-test")
                    self.assertEqual(command_line[command_line.index("--expected-public-sha256") + 1], "f" * 64)
                    output.parent.mkdir(parents=True, exist_ok=True)
                    output.write_bytes(b"signed-fail-health-package")
                    return subprocess.CompletedProcess(command_line, 0)
                raise AssertionError(f"unexpected subprocess: {command_line}")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "OTA_TEST_PROFILE_DIR", normal), \
                    mock.patch.object(device, "IDF_HELPER", root / "tools" / "idf.sh"), \
                    mock.patch.object(device, "OTA_TEST_SIGNER", root / "scripts" / "sign-ota-release.py"), \
                    mock.patch.object(device, "_ensure_ota_test_keypair", return_value=(
                        private_key, public_key, "f" * 64,
                    )), \
                    mock.patch.object(device.subprocess, "run", side_effect=fake_run):
                self.assertEqual(device._ota_test_package_command(command), 0)

            self.assertEqual(normal_image.read_bytes(), b"normal-image")
            self.assertEqual(normal_cache.read_bytes(), b"normal-cache\n")
            self.assertEqual(fail_cache.read_bytes(), b"fail-cache\n")
            self.assertEqual(output.read_bytes(), b"signed-fail-health-package")
            self.assertEqual(len(calls), 2)
            command_text = " ".join(" ".join(call[0]) for call in calls)
            self.assertNotIn("flash", command_text)
            self.assertNotIn("reboot", command_text)
            self.assertNotIn("upload", command_text)


if __name__ == "__main__":
    unittest.main()
