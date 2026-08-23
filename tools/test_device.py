#!/usr/bin/env python3
"""安全裝置工具的 host focused checks。"""

from __future__ import annotations

import contextlib
import base64
import hashlib
import io
import json
import os
import pathlib
import struct
import sys
import subprocess
import tempfile
import unittest
import urllib.parse
from unittest import mock


ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tools"))
import device  # noqa: E402
import usb_recovery  # noqa: E402


DEVICE = "/dev/serial/by-id/usb-test"
TARGET = "/dev/ttyACM0"


class DevicePathTest(unittest.TestCase):
    def test_device_must_be_explicit_by_id_path_or_environment(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            with self.assertRaisesRegex(ValueError, "SMS_DEVICE"):
                device.resolve_device(None)
        with self.assertRaises(ValueError):
            device.resolve_device("/dev/ttyACM0")
        with mock.patch.dict(os.environ, {"SMS_DEVICE": DEVICE}, clear=True):
            self.assertEqual(device.resolve_device(None), DEVICE)

    def test_by_id_resolves_to_one_character_device(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            by_id = root / "by-id"
            by_id.mkdir()
            target = root / "ttyACM0"
            target.write_bytes(b"")
            link = by_id / "usb-test"
            link.symlink_to(target)
            with mock.patch.object(device, "DEVICE_PREFIX", f"{by_id}/"), \
                    mock.patch.object(device.stat, "S_ISCHR", return_value=True):
                resolved = device.resolve_serial_device(str(link))
            self.assertEqual(resolved.by_id, str(link))
            self.assertEqual(resolved.target, str(target.resolve()))

    def test_by_id_rejects_non_character_target(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            by_id = root / "by-id"
            by_id.mkdir()
            target = root / "regular-file"
            target.write_bytes(b"")
            link = by_id / "usb-test"
            link.symlink_to(target)
            with mock.patch.object(device, "DEVICE_PREFIX", f"{by_id}/"), \
                    mock.patch.object(device.stat, "S_ISCHR", return_value=False):
                with self.assertRaises(ValueError):
                    device.resolve_serial_device(str(link))


class DeviceCommandTest(unittest.TestCase):
    def run_main(self, argv):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            result = device.main(argv)
        return result, output.getvalue()

    def test_doctor_reports_sanitized_read_only_checks(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            by_id = root / "by-id"
            by_id.mkdir()
            target = root / "ttyACM0"
            target.write_bytes(b"")
            target.chmod(0o660)
            link = by_id / "private-device-serial"
            link.symlink_to(target)
            missing = str(by_id / "private-missing-serial")

            cases = (
                {
                    "name": "host-access",
                    "argv": ["--device", str(link), "doctor"],
                    "environment": {},
                    "host_access": True,
                    "image_rc": 1,
                    "device": (True, True, True, True),
                    "permission": ("ok", "none"),
                    "image_present": False,
                    "ready": True,
                },
                {
                    "name": "group-access-missing",
                    "argv": ["--device", str(link), "doctor"],
                    "environment": {},
                    "host_access": False,
                    "image_rc": 0,
                    "device": (True, True, True, False),
                    "permission": (
                        "group-access-missing",
                        "join-device-group-and-start-new-login-session",
                    ),
                    "image_present": True,
                    "ready": True,
                },
                {
                    "name": "unconfigured",
                    "argv": ["doctor"],
                    "environment": {},
                    "host_access": False,
                    "image_rc": 1,
                    "device": (False, False, False, False),
                    "permission": ("device-not-configured", "configure-explicit-by-id"),
                    "image_present": False,
                    "ready": False,
                },
                {
                    "name": "missing-environment-device",
                    "argv": ["doctor"],
                    "environment": {"SMS_DEVICE": missing},
                    "host_access": False,
                    "image_rc": 1,
                    "device": (True, False, False, False),
                    "permission": ("device-not-present", "connect-device"),
                    "image_present": False,
                    "ready": False,
                },
            )
            for case in cases:
                docker = mock.Mock(
                    return_value=mock.Mock(
                        returncode=case["image_rc"], stdout="", stderr="private-docker-detail",
                    )
                )
                output = io.StringIO()
                error = io.StringIO()
                with self.subTest(name=case["name"]), \
                        mock.patch.dict(os.environ, case["environment"], clear=True), \
                        mock.patch.object(device, "DEVICE_PREFIX", f"{by_id}/"), \
                        mock.patch.object(device.stat, "S_ISCHR", return_value=True), \
                        mock.patch.object(
                            device.os, "access", return_value=case["host_access"],
                        ), \
                        mock.patch.object(device.os, "geteuid", return_value=999_999), \
                        mock.patch.object(device.os, "getegid", return_value=999_998), \
                        mock.patch.object(device.os, "getgroups", return_value=[]), \
                        mock.patch.object(device.subprocess, "run", docker), \
                        mock.patch.object(device.usb_recovery, "run_transaction") as transaction, \
                        mock.patch.object(device, "_run_esptool") as esptool, \
                        mock.patch.object(device.http.client, "HTTPConnection") as connection, \
                        contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
                    result = device.main(case["argv"])

                self.assertEqual(result, 0)
                self.assertEqual(error.getvalue(), "")
                configured, present, character_device, host_read_write = case["device"]
                code, action = case["permission"]
                self.assertEqual(
                    json.loads(output.getvalue()),
                    {
                        "device": {
                            "character_device": character_device,
                            "configured": configured,
                            "host_read_write": host_read_write,
                            "present": present,
                        },
                        "fallback": {"image_present": case["image_present"]},
                        "permission": {"code": code, "recommended_action": action},
                        "ready": case["ready"],
                    },
                )
                self.assertNotIn(link.name, output.getvalue())
                self.assertNotIn(str(link), output.getvalue())
                self.assertNotIn("private-missing-serial", output.getvalue())
                self.assertEqual(
                    docker.call_args.args[0],
                    ["docker", "image", "inspect", device.IDF_IMAGE],
                )
                transaction.assert_not_called()
                esptool.assert_not_called()
                connection.assert_not_called()

    def test_build_defaults_to_non_release_production(self):
        calls = []

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return mock.Mock(returncode=0)

        with mock.patch.object(device.subprocess, "run", side_effect=fake_run):
            self.assertEqual(self.run_main(["build"])[0], 0)
        self.assertEqual(calls[0][0], [str(ROOT / "tools" / "idf.sh"), "build"])
        self.assertEqual(calls[0][1]["cwd"], ROOT)
        self.assertEqual(calls[0][1]["env"]["SMS_USB_RECOVERY"], "0")
        self.assertEqual(calls[0][1]["env"]["SMS_OTA_TEST_KEY"], "0")
        self.assertEqual(calls[0][1]["env"]["FIRMWARE_IS_RELEASE"], "0")

    def test_external_process_oserror_is_not_reflected(self):
        secret = "private-process-detail"
        with mock.patch.object(device.subprocess, "run", side_effect=OSError(secret)):
            with self.assertRaises(usb_recovery.DeviceError) as raised:
                device._run_process(["external"], stage="external")
        self.assertEqual(str(raised.exception), "external unavailable")
        self.assertNotIn(secret, str(raised.exception))

    def test_external_process_decode_error_is_fixed(self):
        error = UnicodeDecodeError("utf-8", b"\xff", 0, 1, "invalid byte")
        with mock.patch.object(device.subprocess, "run", side_effect=error):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "external invalid text"):
                device._run_process(["external"], stage="external")

    def test_container_state_decode_failure_is_fixed(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        result = mock.Mock(returncode=0, stdout=b"\xff", stderr=b"")
        with mock.patch.object(device, "_run_process", return_value=result):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "invalid state"):
                device._container_recovery(ref, 1.0)

    def test_docker_create_failure_never_starts_the_container(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        name = "sms-forwarding-device-1-a"
        error = usb_recovery.DeviceError("USB recovery container create unavailable")

        with mock.patch.object(device, "_settled_docker_create", side_effect=error) as create, \
                mock.patch.object(device, "_run_process") as process, \
                mock.patch.object(device, "_cleanup_docker_container") as cleanup:
            with self.assertRaisesRegex(usb_recovery.DeviceError, "unavailable"):
                device._run_docker_container(
                    device._docker_command(["chip_id"], ref, container_name=name),
                    timeout=10.0, text=True, stage="USB recovery",
                )

        self.assertEqual(create.call_args.args[0][:2], ["docker", "create"])
        process.assert_not_called()
        cleanup.assert_called_once_with(name)

    def test_docker_start_failure_always_removes_the_created_id(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        name = "sms-forwarding-device-1-a"
        container_id = "a" * 64

        for error in (usb_recovery.DeviceError("USB recovery timed out"), KeyboardInterrupt()):
            with self.subTest(error=type(error).__name__), \
                    mock.patch.object(
                        device, "_settled_docker_create",
                        return_value=(
                            mock.Mock(returncode=0, stdout=container_id + "\n", stderr=""),
                            None,
                        ),
                    ), \
                    mock.patch.object(device, "_run_process", side_effect=error) as process, \
                    mock.patch.object(device, "_cleanup_docker_container") as cleanup:
                with self.assertRaises(type(error)):
                    device._run_docker_container(
                        device._docker_command(["chip_id"], ref, container_name=name),
                        timeout=10.0, text=True, stage="USB recovery",
                    )
            self.assertEqual(
                process.call_args.args[0],
                ["docker", "start", "--attach", container_id],
            )
            cleanup.assert_called_once_with(container_id)

    def test_docker_container_preserves_child_result_and_removes_it(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        name = "sms-forwarding-device-1-a"
        container_id = "b" * 64

        for text, stdout, stderr in (
            (True, "safe-out", "safe-error"),
            (False, b"safe-out", b"safe-error"),
        ):
            with self.subTest(text=text), \
                    mock.patch.object(
                        device, "_settled_docker_create",
                        return_value=(
                            mock.Mock(returncode=0, stdout=container_id + "\n", stderr=""),
                            None,
                        ),
                    ), \
                    mock.patch.object(
                        device, "_run_process",
                        return_value=mock.Mock(returncode=7, stdout=stdout, stderr=stderr),
                    ), \
                    mock.patch.object(device, "_cleanup_docker_container") as cleanup:
                result = device._run_docker_container(
                    device._docker_command(["chip_id"], ref, container_name=name),
                    timeout=10.0, text=text, stage="USB recovery",
                )
            self.assertEqual((result.returncode, result.stdout, result.stderr), (7, stdout, stderr))
            cleanup.assert_called_once_with(container_id)

    def test_docker_container_rejects_start_result_after_deadline_and_removes_it(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        name = "sms-forwarding-device-1-a"
        container_id = "c" * 64
        clock = [100.0]

        def fake_process(_command, **_kwargs):
            clock[0] = 111.0
            return mock.Mock(returncode=0, stdout="safe-out", stderr="")

        with mock.patch.object(
                device, "_settled_docker_create",
                return_value=(
                    mock.Mock(returncode=0, stdout=container_id + "\n", stderr=""), None,
                ),
        ), mock.patch.object(device, "_run_process", side_effect=fake_process), \
                mock.patch.object(device, "_cleanup_docker_container") as cleanup, \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "timed out"):
                device._run_docker_container(
                    device._docker_command(["chip_id"], ref, container_name=name),
                    timeout=10.0, text=True, stage="USB recovery",
                )

        cleanup.assert_called_once_with(container_id)

    def test_docker_create_can_settle_past_deadline_without_starting_usb(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        name = "sms-forwarding-device-1-a"
        container_id = "d" * 64
        clock = [100.0]

        def fake_create(_command, **_kwargs):
            clock[0] = 111.0
            return mock.Mock(returncode=0, stdout=container_id + "\n", stderr=""), None

        with mock.patch.object(
                device, "_settled_docker_create", side_effect=fake_create,
        ) as create, mock.patch.object(device, "_run_process") as process, \
                mock.patch.object(device, "_cleanup_docker_container") as cleanup, \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "timed out"):
                device._run_docker_container(
                    device._docker_command(["chip_id"], ref, container_name=name),
                    timeout=10.0, text=True, stage="USB recovery",
                )

        create.assert_called_once()
        process.assert_not_called()
        cleanup.assert_called_once_with(container_id)

    def test_interrupted_docker_create_settles_then_removes_id_without_starting(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        name = "sms-forwarding-device-1-a"
        container_id = "e" * 64

        class CreateProcess:
            returncode = 0

            def __init__(self):
                self.communicate_calls = 0

            def communicate(self):
                self.communicate_calls += 1
                if self.communicate_calls == 1:
                    raise KeyboardInterrupt()
                return container_id + "\n", ""

        create_process = CreateProcess()

        def fake_run(command, **_kwargs):
            if command[:2] == ["docker", "create"]:
                raise KeyboardInterrupt()
            if command[:3] == ["docker", "rm", "--force"]:
                return mock.Mock(returncode=0, stdout=command[-1] + "\n", stderr="")
            if command[:3] == ["docker", "container", "inspect"]:
                return mock.Mock(
                    returncode=1,
                    stdout="",
                    stderr=f"No such container: {command[-1]}\n",
                )
            self.fail("interrupted create must never start a container")

        with mock.patch.object(device.subprocess, "Popen", return_value=create_process) as popen, \
                mock.patch.object(device.subprocess, "run", side_effect=fake_run) as run:
            with self.assertRaises(KeyboardInterrupt):
                device._run_docker_container(
                    device._docker_command(["chip_id"], ref, container_name=name),
                    timeout=10.0, text=True, stage="USB recovery",
                )

        self.assertEqual(create_process.communicate_calls, 2)
        popen.assert_called_once()
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        self.assertEqual(
            [call.args[0] for call in run.call_args_list],
            [
                ["docker", "rm", "--force", container_id],
                ["docker", "container", "inspect", container_id],
            ],
        )

    def test_docker_create_rejects_malformed_id_and_removes_published_name(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        name = "sms-forwarding-device-1-a"
        create = mock.Mock(return_value=(
            mock.Mock(returncode=0, stdout="not-an-id\n", stderr=""), None,
        ))

        with mock.patch.object(device, "_new_container_name", return_value=name), \
                mock.patch.object(device, "_settled_docker_create", create), \
                mock.patch.object(device, "_run_process") as process, \
                mock.patch.object(device, "_cleanup_docker_container") as cleanup:
            with self.assertRaisesRegex(usb_recovery.DeviceError, "invalid id"):
                device._run_docker_container(
                    device._docker_command(["chip_id"], ref, container_name=name),
                    timeout=10.0, text=True, stage="USB recovery",
                )

        create.assert_called_once()
        process.assert_not_called()
        cleanup.assert_called_once_with(name)

    def test_docker_cleanup_removes_name_published_after_first_rm(self):
        name = "sms-forwarding-device-1-a"
        results = (
            mock.Mock(
                returncode=1, stdout="", stderr=f"No such container: {name}\n",
            ),
            mock.Mock(returncode=0, stdout="[]\n", stderr=""),
            mock.Mock(returncode=0, stdout=name + "\n", stderr=""),
            mock.Mock(
                returncode=1, stdout="", stderr=f"No such container: {name}\n",
            ),
        )

        with mock.patch.object(device.subprocess, "run", side_effect=results) as run:
            device._cleanup_docker_container(name)

        self.assertEqual(
            [call.args[0][:3] for call in run.call_args_list],
            [
                ["docker", "rm", "--force"],
                ["docker", "container", "inspect"],
                ["docker", "rm", "--force"],
                ["docker", "container", "inspect"],
            ],
        )

    def test_container_query_empty_stdout_is_fixed_error(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        result = mock.Mock(returncode=0, stdout="", stderr="")
        with mock.patch.object(device, "_run_process", return_value=result):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "empty query response"):
                device._container_recovery(ref, 1.0, "cereg")

    def test_container_failure_with_empty_stderr_is_fixed_error(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        result = mock.Mock(returncode=1, stdout="", stderr="")
        with mock.patch.object(device, "_run_process", return_value=result):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "USB recovery failed"):
                device._container_recovery(ref, 1.0, "cereg")

    def test_container_migration_failure_preserves_protocol_status(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        result = mock.Mock(
            returncode=1, stdout="", stderr="device rejected request (invalid-state)\n",
        )
        with mock.patch.object(device, "_run_process", return_value=result):
            with self.assertRaises(usb_recovery.CommandError) as raised:
                device._container_recovery(
                    ref, 1.0, command=usb_recovery.COMMAND_OTA_MIGRATION_RECOVER,
                )
        self.assertEqual(raised.exception.status, usb_recovery.STATUS_INVALID_STATE)

    def test_external_timeout_is_fixed_error(self):
        timeout = subprocess.TimeoutExpired(["external"], 1.0)
        with mock.patch.object(device.subprocess, "run", side_effect=timeout):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "external timed out"):
                device._run_process(["external"], timeout=1.0, stage="external")

    def test_diag_host_empty_payload_is_fixed_error(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        response = usb_recovery.Frame(usb_recovery.RESPONSE_MODEM_QUERY, 0, b"")
        with mock.patch.object(device.usb_recovery, "run_transaction", return_value=response):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "empty modem query response"):
                device._diag_query(ref, "cereg", device.time.monotonic() + 10.0)

    def test_diag_host_passes_absolute_deadline_to_transport(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        calls = []
        deadline = device.time.monotonic() + 10.0

        def fake_transaction(path, timeout, command, payload, **kwargs):
            calls.append((path, timeout, command, payload, kwargs))
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_MODEM_QUERY, 0, b"+CEREG: 0\r\nOK\r\n"
            )

        with mock.patch.object(device.usb_recovery, "run_transaction", side_effect=fake_transaction):
            self.assertEqual(
                device._diag_query(ref, "cereg", deadline), b"+CEREG: 0\r\nOK\r\n"
            )
        self.assertEqual(calls[0][4], {"deadline": deadline})

    def test_main_blank_error_has_fixed_stderr(self):
        error = io.StringIO()
        with mock.patch.object(device, "resolve_serial_device", side_effect=usb_recovery.DeviceError("")), \
                mock.patch("sys.stderr", error):
            result, _ = self.run_main(["--device", DEVICE, "diag", "cereg"])
        self.assertNotEqual(result, 0)
        self.assertEqual(error.getvalue(), "device operation failed\n")

    def test_diag_all_uses_one_explicit_bounded_total_deadline(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        deadlines = []

        def fake_query(_device, _name, deadline):
            deadlines.append(deadline)
            return b"OK\r\n"

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(device, "_diag_query", side_effect=fake_query), \
                mock.patch.object(usb_recovery, "sanitize_query_response", return_value={"valid": True}), \
                mock.patch.object(device.time, "monotonic", return_value=100.0):
            result, _ = self.run_main(["--device", DEVICE, "diag", "all"])
        self.assertEqual(result, 0)
        self.assertEqual(len(deadlines), len(device.QUERY_NAMES))
        self.assertEqual(set(deadlines), {100.0 + device.DIAG_ALL_TIMEOUT})
        self.assertLessEqual(device.DIAG_ALL_TIMEOUT, 90.0)

    def test_diag_all_keeps_unavailable_query_and_continues(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        failed = "iccid"

        def fake_query(_device, name, _deadline):
            if name == failed:
                raise usb_recovery.CommandError(usb_recovery.STATUS_NOT_READY)
            return b"OK\r\n"

        def fake_sanitize(query_id, _payload):
            return {"query_id": query_id, "valid": True, "line_count": 1,
                    "sha256": "0" * 64, "redactions": []}

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(device, "_diag_query", side_effect=fake_query), \
                mock.patch.object(usb_recovery, "sanitize_query_response", side_effect=fake_sanitize):
            result, output = self.run_main(["--device", DEVICE, "diag", "all"])

        self.assertEqual(result, 0)
        payload = json.loads(output)
        self.assertEqual(payload[failed], {
            "query_id": usb_recovery.QUERY_COMMANDS[failed][0],
            "valid": False,
            "error": "unavailable",
        })
        self.assertTrue(payload["csq"]["valid"])

    def test_batch_validator_accepts_unavailable_query_result(self):
        self.assertTrue(device._safe_batch_result(
            "iccid", {
                "query_id": usb_recovery.QUERY_ICCID,
                "valid": False,
                "error": "unavailable",
            }
        ))

    def test_diag_all_permission_fallback_starts_one_batch_container(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        process_calls = []
        safe_results = {}
        for name in device.QUERY_NAMES:
            query_id = usb_recovery.QUERY_COMMANDS[name][0]
            if name == "ati":
                result = {"query_id": query_id, "valid": True, "model": None, "firmware": None}
            elif name == "cimi":
                result = {"query_id": query_id, "valid": True, "present": False, "length": 0}
            elif name == "cereg":
                result = {
                    "query_id": query_id, "valid": True, "line_count": 1,
                    "field_count": 2, "mode": "status", "stat": "not-registered",
                    "act": None, "cause_flags": {"present": False},
                    "home": False, "roaming": False, "registered": False,
                    "location": {"present": False},
                }
            elif name == "cpol":
                result = {
                    "query_id": query_id, "valid": True, "raw_length": 1,
                    "record_count": 1, "format_bitmap": 1,
                    "format_counts": {"0": 1, "1": 0, "2": 0},
                    "rat_complete": True, "rat_counts": {"0": 1, "1": 0, "2": 0, "3": 0},
                    "malformed_count": 0, "parse_failed": False,
                }
            elif name == "cgdcont":
                result = {"query_id": query_id, "valid": True, "entry_count": 0, "entries": []}
            elif name == "cpin":
                result = {"query_id": query_id, "valid": True, "state": "ready"}
            elif name == "cops":
                result = {
                    "query_id": query_id, "valid": True, "mode": "automatic",
                    "format": None, "act": None, "operator": {"present": False},
                }
            elif name == "cgatt":
                result = {"query_id": query_id, "valid": True, "attached": False}
            elif name == "cgact":
                result = {
                    "query_id": query_id, "valid": True, "entry_count": 1,
                    "entries": [{"cid": 1, "active": False}],
                }
            elif name == "cgpaddr":
                result = {"query_id": query_id, "valid": True, "entry_count": 0, "entries": []}
            elif name == "csq":
                result = {
                    "query_id": query_id, "valid": True, "rssi": 31, "ber": None,
                    "unknown": {"rssi": False, "ber": True},
                }
            elif name == "cesq":
                result = {
                    "query_id": query_id, "valid": True,
                    "rxlev": 63, "ber": None, "rscp": None, "ecn0": None,
                    "rsrq": 14, "rsrp": 71,
                    "unknown": {
                        "rxlev": False, "ber": True, "rscp": True,
                        "ecn0": True, "rsrq": False, "rsrp": False,
                    },
                }
            elif name == "cfun":
                result = {"query_id": query_id, "valid": True, "mode": 1}
            elif name in {"creg", "cgreg"}:
                result = {
                    "query_id": query_id, "valid": True, "line_count": 1,
                    "field_count": 2, "mode": "disabled", "stat": "not-registered",
                    "act": None, "cause_flags": {"present": False},
                    "home": False, "roaming": False, "registered": False,
                    "location": {"present": False},
                }
            elif name == "ceer":
                result = {"query_id": query_id, "valid": True, "last_error": {"present": False}}
            elif name == "iccid":
                result = {
                    "query_id": query_id, "valid": True, "present": True, "length": 20,
                    "sha256": "0" * 64,
                }
            else:
                result = {
                    "query_id": query_id, "valid": True, "line_count": 1,
                    "sha256": "0" * 64, "redactions": [],
                }
            safe_results[name] = result
        batch_output = json.dumps({"version": 1, "results": safe_results})

        def fake_process(command, **kwargs):
            process_calls.append((command, kwargs))
            return mock.Mock(returncode=0, stdout=batch_output, stderr="")

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "_run_process", side_effect=fake_process), \
                mock.patch.object(device.time, "monotonic", return_value=100.0):
            result, output = self.run_main(["--device", DEVICE, "diag", "all"])

        self.assertEqual(result, 0)
        self.assertEqual(len(process_calls), 1)
        command, kwargs = process_calls[0]
        self.assertIn("diag-batch", command)
        self.assertIn("--internal-container", command)
        self.assertLessEqual(kwargs["timeout"], device.DIAG_ALL_TIMEOUT)
        self.assertEqual(set(json.loads(output)), set(device.QUERY_NAMES))

    def test_cereg_batch_validator_accepts_structured_location_metadata(self):
        self.assertTrue(device._safe_batch_result(
            "cereg", {"query_id": usb_recovery.QUERY_CEREG,
                       "valid": False, "error": "invalid-response"}
        ))
        self.assertFalse(device._safe_batch_result(
            "cereg", {"query_id": usb_recovery.QUERY_CEREG,
                       "valid": False}
        ))
        result = {
            "query_id": usb_recovery.QUERY_CEREG,
            "valid": True,
            "line_count": 1,
            "field_count": 5,
            "mode": "location",
            "stat": "rlos-only",
            "act": "e-utran",
            "cause_flags": {"present": False},
            "home": False,
            "roaming": False,
            "registered": False,
            "location": {
                "present": True,
                "fields": [
                    {"present": True, "length": 4, "sha256": "0" * 64},
                    {"present": True, "length": 8, "sha256": "1" * 64},
                ],
            },
        }
        self.assertTrue(device._safe_batch_result("cereg", result))
        for key, value in (("mode", []), ("stat", {}), ("field_count", True)):
            malformed = result.copy()
            malformed[key] = value
            self.assertFalse(device._safe_batch_result("cereg", malformed))
        result["location"]["fields"].pop()
        self.assertFalse(device._safe_batch_result("cereg", result))

    def test_structured_fixed_query_results_are_batch_safe_and_match_host_sanitizer(self):
        cases = {
            "cpin": b"+CPIN: READY\r\nOK\r\n",
            "cops": b'+COPS: 0,2,"Operator",7\r\nOK\r\n',
            "cgatt": b"+CGATT: 0\r\nOK\r\n",
            "cgact": b"+CGACT: 1,1\r\n+CGACT: 2,0\r\nOK\r\n",
            "cgpaddr": b"OK\n",
            "iccid": b"+ICCID: 8986001234567890123\r\nOK\r\n",
            "csq": b"+CSQ: 31,99\r\nOK\r\n",
            "cesq": b"+CESQ: 63,99,255,255,14,71\r\nOK\r\n",
            "cfun": b"+CFUN: 1\r\nOK\r\n",
            "creg": b"+CREG: 0,11\r\nOK\r\n",
            "cgreg": b"+CGREG: 0,0\r\nOK\r\n",
            "ceer": b"OK\n",
        }
        for name, raw in cases.items():
            with self.subTest(name=name):
                query_id = usb_recovery.QUERY_COMMANDS[name][0]
                safe = usb_recovery.sanitize_query_response(query_id, raw)
                self.assertTrue(safe["valid"])
                self.assertTrue(device._safe_batch_result(name, safe))
                self.assertNotIn(raw.decode("ascii", "ignore"), json.dumps(safe, sort_keys=True))

    def test_diag_all_batch_uses_a_tracked_create_command(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        name = "sms-forwarding-device-1-a"
        process = mock.Mock(side_effect=usb_recovery.DeviceError("USB recovery timed out"))

        with mock.patch.object(device, "_new_container_name", return_value=name), \
                mock.patch.object(device, "_run_process", process):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "timed out"):
                device._container_recovery_batch(
                    ref, ("iccid",), deadline=device.time.monotonic() + 10.0,
                )

        command = process.call_args.args[0]
        self.assertEqual(command[:2], ["docker", "create"])
        self.assertEqual(command[command.index("--name") + 1], name)
        self.assertNotIn("--rm", command)

    def test_diag_all_batch_failures_are_fixed_and_do_not_reflect_stderr(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        secret = "private-container-detail"
        outputs = (
            "",
            '{"version":1,"results":',
            "not-json",
            "☃",
            b"\xff",
        )
        for output in outputs:
            with self.subTest(output=output):
                error = io.StringIO()
                result = mock.Mock(returncode=0, stdout=output, stderr="")
                with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                        mock.patch.object(
                            device.usb_recovery,
                            "run_transaction",
                            side_effect=usb_recovery.DeviceError(
                                "could not claim USB device (open: EACCES)"
                            ),
                        ), \
                        mock.patch.object(device, "_run_process", return_value=result), \
                        mock.patch("sys.stderr", error):
                    status, _ = self.run_main(["--device", DEVICE, "diag", "all"])
                self.assertNotEqual(status, 0)
                self.assertNotIn(secret, error.getvalue())

        error = io.StringIO()
        result = mock.Mock(returncode=1, stdout="", stderr=secret)
        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError(
                        "could not claim USB device (open: EACCES)"
                    ),
                ), \
                mock.patch.object(device, "_run_process", return_value=result), \
                mock.patch("sys.stderr", error):
            status, _ = self.run_main(["--device", DEVICE, "diag", "all"])
        self.assertNotEqual(status, 0)
        self.assertNotIn(secret, error.getvalue())

    def test_diag_all_batch_rejects_deep_json_without_reflecting_parser_error(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        depth = 1100
        deep_redactions = "[" * depth + "]" * depth
        output = (
            '{"version":1,"results":{"iccid":{"query_id":8,"valid":true,'
            '"line_count":1,"sha256":"' + "0" * 64 + '","redactions":'
            + deep_redactions + "}}}"
        )
        result = mock.Mock(returncode=0, stdout=output, stderr="")
        with mock.patch.object(device, "_run_process", return_value=result):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "invalid batch response"):
                device._container_recovery_batch(ref, ("iccid",), deadline=device.time.monotonic() + 10.0)

    def test_release_usb_build_is_rejected_before_backend(self):
        with mock.patch.object(device.subprocess, "run") as run:
            result, _ = self.run_main(["build", "--usb-dev", "--release"])
        self.assertNotEqual(result, 0)
        run.assert_not_called()

    def test_diag_sanitizes_response_and_uses_fixed_query_timeout(self):
        calls = []

        def fake_transaction(path, timeout, command, payload, **_kwargs):
            calls.append((path, timeout, command, payload))
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_MODEM_QUERY,
                0,
                b"+ICCID: 8986001234567890123\r\nOK\r\n",
            )

        with mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                mock.patch.object(device.usb_recovery, "run_transaction", side_effect=fake_transaction):
            result, output = self.run_main(["--device", DEVICE, "diag", "iccid"])
        self.assertEqual(result, 0)
        self.assertNotIn("8986001234567890123", output)
        self.assertEqual(json.loads(output)["query_id"], usb_recovery.QUERY_ICCID)
        self.assertEqual(calls, [(DEVICE, 3.0, usb_recovery.COMMAND_MODEM_QUERY, b"\x08")])

    def test_diag_cpol_uses_a_bounded_longer_transport_timeout(self):
        calls = []

        def fake_transaction(path, timeout, command, payload, **_kwargs):
            calls.append((path, timeout, command, payload))
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_MODEM_QUERY,
                0,
                b"CPOL1;len=520;rec=4;fmt=7,1,1,2;rat=complete,3,1,2,0;bad=0;fail=0\r\nOK\r\n",
            )

        with mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                mock.patch.object(device.usb_recovery, "run_transaction", side_effect=fake_transaction):
            result, _ = self.run_main(["--device", DEVICE, "diag", "cpol"])
        self.assertEqual(result, 0)
        self.assertEqual(calls, [(DEVICE, 8.0, usb_recovery.COMMAND_MODEM_QUERY, b"\x10")])

    def test_diag_raw_cpol_prints_safe_summary_instead_of_payload(self):
        summary = b"CPOL1;len=520;rec=4;fmt=7,1,1,2;rat=complete,3,1,2,0;bad=0;fail=0\r\nOK\r\n"

        def fake_transaction(path, timeout, command, payload, **_kwargs):
            return usb_recovery.Frame(usb_recovery.RESPONSE_MODEM_QUERY, 0, summary)

        with mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                mock.patch.object(device.usb_recovery, "run_transaction", side_effect=fake_transaction):
            result, output = self.run_main(["--device", DEVICE, "diag", "cpol", "--raw"])
        self.assertEqual(result, 0)
        self.assertEqual(output.encode(), summary)
        self.assertNotIn("46000", output)

    def test_diag_retries_only_busy_twice_with_five_second_delay(self):
        calls = []

        def fake_transaction(path, timeout, command, payload, **_kwargs):
            calls.append((path, timeout, command, payload))
            if len(calls) < 3:
                raise usb_recovery.CommandError(usb_recovery.STATUS_BUSY)
            return usb_recovery.Frame(usb_recovery.RESPONSE_MODEM_QUERY, 0, b"OK\r\n")

        with mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                mock.patch.object(device.usb_recovery, "run_transaction", side_effect=fake_transaction), \
                mock.patch.object(device.time, "sleep") as sleep:
            result, _ = self.run_main(["--device", DEVICE, "diag", "ati"])
        self.assertEqual(result, 0)
        self.assertEqual(len(calls), 3)
        self.assertEqual(sleep.call_count, 2)
        sleep.assert_has_calls([mock.call(5.0), mock.call(5.0)])

    def test_diag_host_busy_does_not_sleep_when_deadline_cannot_fit_retry(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        clock = [100.0]

        def monotonic():
            value = clock[0]
            clock[0] = 129.0
            return value

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.CommandError(usb_recovery.STATUS_BUSY),
                ), \
                mock.patch.object(device.time, "monotonic", side_effect=monotonic), \
                mock.patch.object(device.time, "sleep") as sleep:
            result, _ = self.run_main(["--device", DEVICE, "diag", "iccid"])
        self.assertNotEqual(result, 0)
        sleep.assert_not_called()

    def test_diag_rejects_arbitrary_at_text(self):
        self.assertEqual(len(device.QUERY_NAMES), 17)
        self.assertEqual(set(device.QUERY_NAMES), set(usb_recovery.QUERY_COMMANDS))
        with self.assertRaises(SystemExit):
            device.build_parser().parse_args(["--device", DEVICE, "diag", "AT+CGACT=1,1"])
        with self.assertRaises(SystemExit):
            device.build_parser().parse_args(["--device", DEVICE, "diag", "cops", "test"])
        with self.assertRaises(SystemExit):
            device.build_parser().parse_args(["--device", DEVICE, "diag", "crsm"])

    def test_reset_is_dry_run_by_default(self):
        with mock.patch.object(device.subprocess, "run") as run:
            result, output = self.run_main(["--device", DEVICE, "reset"])
        self.assertEqual(result, 0)
        run.assert_not_called()
        plan = json.loads(output)
        self.assertEqual(plan["mode"], "usb_reset")
        self.assertFalse(plan["live"])
        self.assertEqual(plan["timeout"], 90.0)

    def test_live_reset_requires_exact_basename_and_probes_state(self):
        esptool_calls = []
        initial = device.SerialDevice(DEVICE, TARGET)
        fresh = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        resolve_results = iter((initial, fresh))
        state_devices = []
        states = iter((
            {"sta_connected": True, "boot_id": 0x11111111},
            {"sta_connected": True, "boot_id": 0x22222222},
        ))

        def fake_run(command, **kwargs):
            esptool_calls.append((command, kwargs))
            return mock.Mock(returncode=0, stdout="", stderr="")

        def fake_resolve(_path):
            return next(resolve_results)

        def fake_state(ref, *args, **kwargs):
            state_devices.append(ref)
            return next(states)

        with mock.patch.object(device, "resolve_serial_device", side_effect=fake_resolve) as resolve, \
                mock.patch.object(device, "resolve_esptool", return_value="host"), \
                mock.patch.object(device.subprocess, "run", side_effect=fake_run), \
                mock.patch.object(device, "_state", side_effect=fake_state):
            result, output = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertEqual(result, 0)
        self.assertEqual(len(esptool_calls), 1)
        self.assertEqual(esptool_calls[0][0], [
            device.ESPTOOL,
            "--chip", "esp32c3",
            "--port", DEVICE,
            "--before", "usb_reset",
            "--after", "hard_reset",
            "chip_id",
        ])
        self.assertEqual(resolve.call_args_list, [mock.call(DEVICE)] * 2)
        self.assertEqual(state_devices, [initial, fresh])
        self.assertEqual(json.loads(output)["state"]["sta_connected"], True)

    def test_live_reset_waits_for_a_new_boot_id_within_bounded_budget(self):
        initial = device.SerialDevice(DEVICE, TARGET)
        fresh = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        clock = [100.0]
        states = []

        def resolve(_path):
            return initial if not states else fresh

        def probe(_ref, *_args, **kwargs):
            states.append(clock[0])
            if len(states) == 1:
                return {"sta_connected": True, "boot_id": 0x11111111}
            if len(states) == 2:
                clock[0] += 30.0
                return {"sta_connected": True, "boot_id": 0x11111111}
            self.assertGreaterEqual(kwargs["container_timeout"], 20.0)
            clock[0] += 20.0
            return {"sta_connected": True, "boot_id": 0x22222222}

        with mock.patch.object(device, "resolve_serial_device", side_effect=resolve), \
                mock.patch.object(device, "run_esptool"), \
                mock.patch.object(device, "_state", side_effect=probe), \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(device.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertEqual(result, 0)
        self.assertLessEqual(clock[0] - 100.0, 90.0)

    def test_live_reset_allows_slow_fresh_container_probe_within_bounded_budget(self):
        initial = device.SerialDevice(DEVICE, TARGET)
        fresh = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        clock = [100.0]
        resolve_count = [0]
        probe_calls = []

        def resolve(_path):
            resolve_count[0] += 1
            if resolve_count[0] == 1:
                return initial
            clock[0] = max(clock[0], 130.0)
            return fresh

        def probe(ref, timeout=None, *, container_timeout=0.0, deadline=None):
            probe_calls.append((ref, timeout, container_timeout, deadline))
            if ref is initial:
                return {"sta_connected": True, "boot_id": 0x11111111}
            if container_timeout < 20.0:
                raise usb_recovery.DeviceError("fresh container probe budget is too small")
            clock[0] += 20.0
            return {"sta_connected": True, "boot_id": 0x22222222}

        with mock.patch.object(device, "resolve_serial_device", side_effect=resolve), \
                mock.patch.object(device, "run_esptool"), \
                mock.patch.object(device, "_state", side_effect=probe), \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(device.time, "sleep", side_effect=lambda seconds: clock.__setitem__(0, clock[0] + seconds)), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertEqual(result, 0)
        self.assertEqual(probe_calls, [
            (initial, None, 0.0, 190.0),
            (fresh, 5.0, 30.0, 190.0),
        ])
        self.assertLessEqual(clock[0] - 100.0, 90.0)

    def test_live_reset_fails_when_boot_id_does_not_change(self):
        initial = device.SerialDevice(DEVICE, TARGET)
        clock = [100.0]

        def now():
            return clock[0]

        def advance(seconds):
            clock[0] += seconds

        with mock.patch.object(device, "RESET_TIMEOUT", 0.2), \
                mock.patch.object(device, "resolve_serial_device", return_value=initial), \
                mock.patch.object(device, "run_esptool"), \
                mock.patch.object(device, "_state", return_value={"sta_connected": True, "boot_id": 1}) as state, \
                mock.patch.object(device.time, "monotonic", side_effect=now), \
                mock.patch.object(device.time, "sleep", side_effect=advance), \
                mock.patch("sys.stderr", new_callable=io.StringIO) as error:
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertNotEqual(result, 0)
        self.assertGreaterEqual(state.call_count, 2)
        self.assertIn("boot id", error.getvalue())

    def test_live_reset_fails_when_boot_id_is_missing(self):
        initial = device.SerialDevice(DEVICE, TARGET)
        fresh = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        clock = [100.0]
        results = iter((initial, fresh))

        def resolve(_path):
            return next(results, fresh)

        def advance(seconds):
            clock[0] += seconds

        calls = [0]

        def state_probe(*_args, **_kwargs):
            calls[0] += 1
            return {"sta_connected": True, "boot_id": 1} if calls[0] == 1 else {
                "sta_connected": True
            }

        with mock.patch.object(device, "RESET_TIMEOUT", 0.2), \
                mock.patch.object(device, "resolve_serial_device", side_effect=resolve), \
                mock.patch.object(device, "run_esptool"), \
                mock.patch.object(device, "_state", side_effect=state_probe) as state, \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(device.time, "sleep", side_effect=advance), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertNotEqual(result, 0)
        self.assertGreaterEqual(state.call_count, 2)

    def test_live_reset_fails_when_boot_id_is_zero(self):
        initial = device.SerialDevice(DEVICE, TARGET)
        fresh = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        clock = [100.0]
        results = iter((initial, fresh))

        def resolve(_path):
            return next(results, fresh)

        def advance(seconds):
            clock[0] += seconds

        calls = [0]

        def state_probe(*_args, **_kwargs):
            calls[0] += 1
            return {"sta_connected": True, "boot_id": 1} if calls[0] == 1 else {
                "sta_connected": True, "boot_id": 0
            }

        with mock.patch.object(device, "RESET_TIMEOUT", 0.2), \
                mock.patch.object(device, "resolve_serial_device", side_effect=resolve), \
                mock.patch.object(device, "run_esptool"), \
                mock.patch.object(device, "_state", side_effect=state_probe) as state, \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(device.time, "sleep", side_effect=advance), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertNotEqual(result, 0)
        self.assertGreaterEqual(state.call_count, 2)

    def test_live_reset_ignores_a_different_by_id_endpoint(self):
        initial = device.SerialDevice(DEVICE, TARGET)
        other = device.SerialDevice("/dev/serial/by-id/other", "/dev/ttyACM1")
        clock = [100.0]
        results = iter((initial, other))

        def resolve(_path):
            return next(results, other)

        def advance(seconds):
            clock[0] += seconds

        with mock.patch.object(device, "RESET_TIMEOUT", 0.2), \
                mock.patch.object(device, "resolve_serial_device", side_effect=resolve), \
                mock.patch.object(device, "run_esptool"), \
                mock.patch.object(device, "_state", return_value={"sta_connected": True, "boot_id": 1}) as state, \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(device.time, "sleep", side_effect=advance), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertNotEqual(result, 0)
        state.assert_called_once()

    def test_live_reset_fails_on_ordinary_state_timeout(self):
        initial = device.SerialDevice(DEVICE, TARGET)
        fresh = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        clock = [100.0]
        results = iter((initial, fresh))

        def resolve(_path):
            return next(results, fresh)

        def advance(seconds):
            clock[0] += seconds

        calls = [0]

        def state_probe(ref, *args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                return {"sta_connected": True, "boot_id": 1}
            raise usb_recovery.DeviceError("USB device timed out")

        with mock.patch.object(device, "RESET_TIMEOUT", 0.2), \
                mock.patch.object(device, "resolve_serial_device", side_effect=resolve), \
                mock.patch.object(device, "run_esptool"), \
                mock.patch.object(device, "_state", side_effect=state_probe) as state, \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(device.time, "sleep", side_effect=advance), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertNotEqual(result, 0)
        self.assertGreaterEqual(state.call_count, 2)

    def test_reset_falls_back_to_pinned_container_without_broad_device_access(self):
        calls = []
        initial = device.SerialDevice(DEVICE, TARGET)
        fresh = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        resolve_results = iter((initial, fresh))

        def fake_run(command, **kwargs):
            calls.append((command, kwargs))
            return mock.Mock(returncode=0, stdout="", stderr="")

        with mock.patch.object(device, "resolve_serial_device", side_effect=lambda _path: next(resolve_results)), \
                mock.patch.object(device, "resolve_esptool", return_value="container"), \
                mock.patch.object(device, "_run_process", side_effect=fake_run), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=(
                        usb_recovery.Frame(
                            usb_recovery.RESPONSE_STATE, 0, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00"
                        ),
                        usb_recovery.Frame(
                            usb_recovery.RESPONSE_STATE, 0, b"\x00\x00\x00\x00\x00\x02\x00\x00\x00"
                        ),
                    ),
                ):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertEqual(result, 0)
        command = calls[0][0]
        self.assertEqual(command[:2], ["docker", "create"])
        self.assertNotIn("--rm", command)
        self.assertIn("--pull=never", command)
        self.assertIn("--network=none", command)
        self.assertIn("SMS_DEVICE_IN_CONTAINER=1", command)
        self.assertIn("--tmpfs", command)
        self.assertIn("/tmp:rw,nosuid,nodev,noexec,size=16m", command)
        volume_values = [
            command[index + 1] for index, value in enumerate(command[:-1]) if value == "--volume"
        ]
        self.assertEqual(volume_values, [f"{device.ROOT.resolve()}:/workspace:ro"])
        self.assertFalse(any(value.endswith(":rw") for value in volume_values))
        self.assertIn("--device", command)
        self.assertIn(f"{TARGET}:{device.CONTAINER_DEVICE_PATH}", command)
        self.assertIn(device.CONTAINER_DEVICE_PATH, command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("/dev:/dev", command)
        self.assertIn(device.IDF_IMAGE, command)
        self.assertRegex(device.IDF_IMAGE, r"^espressif/idf@sha256:[0-9a-f]{64}$")

    def test_esptool_failure_reports_bounded_sanitized_diagnostic(self):
        error = io.StringIO()
        with mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                mock.patch.object(device, "resolve_esptool", return_value="host"), \
                mock.patch.object(
                    device, "_state", return_value={"sta_connected": False, "boot_id": 1}
                ), \
                mock.patch.object(
                    device.subprocess,
                    "run",
                    return_value=mock.Mock(
                        returncode=7,
                        stdout="",
                        stderr="fatal /dev/serial/by-id/usb-test IMEI=8986001234567890123",
                    ),
                ), \
                mock.patch("sys.stderr", error):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertNotEqual(result, 0)
        self.assertIn("exit 7", error.getvalue())
        self.assertNotIn("usb-test", error.getvalue())
        self.assertNotIn("8986001234567890123", error.getvalue())

    def test_reset_rejects_removed_noop_hard_flag(self):
        with self.assertRaises(SystemExit):
            device.build_parser().parse_args([
                "--device", DEVICE, "reset", "--live", "--hard",
            ])

    def test_live_reset_rejects_wrong_basename_without_esptool(self):
        with mock.patch.object(device, "run_esptool") as run:
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "wrong",
            ])
        self.assertNotEqual(result, 0)
        run.assert_not_called()

    def test_flash_app0_dry_run_has_fixed_slot_and_rejects_merged_path(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"firmware")
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "resolve_esptool", return_value="host"), \
                    mock.patch.object(
                        device.subprocess,
                        "run",
                        return_value=mock.Mock(returncode=0, stdout="", stderr=""),
                    ) as run:
                result, output = self.run_main(["--device", DEVICE, "flash-app0", str(image)])
            self.assertEqual(result, 0)
            run.assert_not_called()
            plan = json.loads(output)
            self.assertEqual(plan["action"], "flash-app0")
            self.assertEqual(plan["slot"], "app0")
            self.assertEqual(plan["offset"], "0x10000")
            self.assertEqual(plan["max_size"], 0x1E0000)

            renamed = image.with_name("renamed.bin")
            renamed.write_bytes(b"firmware")
            with self.assertRaises(ValueError):
                device.validate_app0_image(renamed)
            merged = root / "dist" / "firmware.bin"
            merged.parent.mkdir()
            merged.write_bytes(b"firmware")
            with self.assertRaises(ValueError):
                device.validate_app0_image(merged)
            symlink = image.with_name("link.bin")
            symlink.symlink_to(image)
            with self.assertRaises(ValueError):
                device.validate_app0_image(symlink)

            usb_image = root / "build" / "idf-usb-recovery" / "sms_forwarding_idf.bin"
            usb_image.parent.mkdir(parents=True)
            usb_image.write_bytes(b"firmware")
            with mock.patch.object(device, "ROOT", root):
                self.assertEqual(device.validate_app0_image(usb_image), len(b"firmware"))

    def test_flash_bootloader_dry_run_uses_fixed_offset_and_rejects_app_image(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            bootloader = root / "build" / "idf-ota-test" / "bootloader" / "bootloader.bin"
            bootloader.parent.mkdir(parents=True)
            bootloader.write_bytes(b"bootloader")
            with mock.patch.object(device, "ROOT", root):
                result, output = self.run_main([
                    "--device", DEVICE, "flash-bootloader", str(bootloader),
                ])
            self.assertEqual(result, 0)
            plan = json.loads(output)
            self.assertEqual(plan["action"], "flash-bootloader")
            self.assertEqual(plan["offset"], "0x0")
            self.assertEqual(plan["size"], len(b"bootloader"))
            app = root / "build" / "idf-ota-test" / "sms_forwarding_idf.bin"
            app.write_bytes(b"app")
            with mock.patch.object(device, "ROOT", root):
                with self.assertRaises(ValueError):
                    device.validate_bootloader_image(app)
            renamed = bootloader.with_name("renamed.bin")
            renamed.write_bytes(b"bootloader")
            with mock.patch.object(device, "ROOT", root):
                with self.assertRaises(ValueError):
                    device.validate_bootloader_image(renamed)
            symlink = bootloader.with_name("link.bin")
            symlink.symlink_to(bootloader)
            with mock.patch.object(device, "ROOT", root):
                with self.assertRaises(ValueError):
                    device.validate_bootloader_image(symlink)

    def test_live_flash_bootloader_writes_only_offset_zero_with_hash_pin(self):
        events = []
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            profile = root / "build" / "idf-ota-test"
            image = profile / "bootloader" / "bootloader.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"bootloader")
            (profile / "CMakeCache.txt").write_text("cache", encoding="ascii")
            digest = device.sha256_file(image)

            def fake_run(command, **kwargs):
                events.append((command, kwargs))
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "resolve_esptool", return_value="host"), \
                    mock.patch.object(device.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(device, "confirm_basename", return_value=None), \
                    mock.patch.object(device, "_run_baseline", return_value=None):
                result, output = self.run_main([
                    "--device", DEVICE, "flash-bootloader", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])

        self.assertEqual(result, 0)
        command = events[-1][0]
        self.assertIn("write_flash", command)
        self.assertEqual(command[command.index("--before") + 1], "usb_reset")
        self.assertEqual(command[command.index("--after") + 1], "hard_reset")
        self.assertEqual(command[-2:], ["0x0", str(image)])
        self.assertNotIn("erase_flash", command)
        self.assertNotIn("partition-table.bin", command)
        self.assertEqual(json.loads(output)["sha256"], digest)

    def test_ota_migration_recovery_dry_run_does_not_touch_usb(self):
        with mock.patch.object(device, "resolve_serial_device") as resolve, \
                mock.patch.object(device, "_ota_migration_recover") as recover:
            result, output = self.run_main([
                "--device", DEVICE, "ota-migration-recover",
            ])
        self.assertEqual(result, 0)
        resolve.assert_not_called()
        recover.assert_not_called()
        plan = json.loads(output)
        self.assertEqual(plan["action"], "ota-migration-recover")
        self.assertFalse(plan["live"])
        self.assertEqual(plan["preserves"], ["nvs", "appcfg", "app0", "app1"])
        self.assertEqual(plan["updates"], ["running image state in otadata"])

    def test_ota_migration_recovery_live_requires_exact_device_and_empty_command(self):
        reference = device.SerialDevice(DEVICE, TARGET)
        with mock.patch.object(device, "resolve_serial_device", return_value=reference), \
                mock.patch.object(device, "confirm_basename") as confirm, \
                mock.patch.object(device.usb_recovery, "run_transaction", return_value=usb_recovery.Frame(
                    usb_recovery.RESPONSE_OTA_MIGRATION_RECOVER, 0, b""
                )) as transaction, \
                mock.patch.object(device.time, "monotonic", return_value=100.0):
            result, output = self.run_main([
                "--device", DEVICE, "ota-migration-recover", "--live", "--confirm", "usb-test",
            ])
        self.assertEqual(result, 0)
        confirm.assert_called_once_with(DEVICE, "usb-test")
        transaction.assert_called_once_with(
            DEVICE, device.STATE_TIMEOUT, device.usb_recovery.COMMAND_OTA_MIGRATION_RECOVER,
            b"", deadline=(
                100.0 + device.CONTAINER_TIMEOUT
                + device.CONTAINER_STARTUP_TIMEOUT * 2 + device.STATE_TIMEOUT
            ),
        )
        self.assertEqual(json.loads(output)["status"], "completed")

    def test_ota_migration_timeout_reads_back_valid_state_without_resending(self):
        reference = device.SerialDevice(DEVICE, TARGET)
        state_payload = usb_recovery.OTA_STATE_STRUCT.pack(
            usb_recovery.APP0_OFFSET,
            usb_recovery.OTA_IMAGE_STATE_VALID,
            0, 0, 0, 0,
        )
        calls = []

        def transaction(_path, _timeout, command, payload, **_kwargs):
            calls.append((command, payload))
            if command == usb_recovery.COMMAND_OTA_MIGRATION_RECOVER:
                raise usb_recovery.DeviceError("USB device timed out")
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_OTA_STATE, 0, state_payload,
            )

        with mock.patch.object(
            device.usb_recovery, "run_transaction", side_effect=transaction,
        ):
            device._ota_migration_recover(reference, timeout=1.0)

        self.assertEqual(calls, [
            (usb_recovery.COMMAND_OTA_MIGRATION_RECOVER, b""),
            (usb_recovery.COMMAND_OTA_STATE, b""),
        ])

    def test_ota_migration_timeout_preserves_error_when_readback_is_not_valid(self):
        reference = device.SerialDevice(DEVICE, TARGET)
        state_payload = usb_recovery.OTA_STATE_STRUCT.pack(
            usb_recovery.APP0_OFFSET,
            usb_recovery.OTA_IMAGE_STATE_PENDING_VERIFY,
            1, 0, 1, usb_recovery.APP0_OFFSET,
        )
        original = usb_recovery.DeviceError("USB device timed out")

        def transaction(_path, _timeout, command, _payload, **_kwargs):
            if command == usb_recovery.COMMAND_OTA_MIGRATION_RECOVER:
                raise original
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_OTA_STATE, 0, state_payload,
            )

        with mock.patch.object(
            device.usb_recovery, "run_transaction", side_effect=transaction,
        ):
            with self.assertRaisesRegex(usb_recovery.DeviceError, "USB device timed out") as raised:
                device._ota_migration_recover(reference, timeout=1.0)
        self.assertIs(raised.exception, original)

    def test_ota_container_fallback_adds_cold_start_budget(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        state = {
            "active_offset": usb_recovery.APP0_OFFSET,
            "image_state": "valid",
            "pending_verify": False,
            "accepted": 0,
            "pending": 0,
            "pending_address": 0,
        }
        process_calls = []

        def fake_process(command, **kwargs):
            process_calls.append((command, kwargs))
            return mock.Mock(returncode=0, stdout=json.dumps(state), stderr=b"")

        with mock.patch.object(device, "_run_process", side_effect=fake_process), \
                mock.patch.object(device.time, "monotonic", return_value=100.0):
            result = device._container_recovery(
                ref, device.STATE_TIMEOUT,
                caller_timeout=(
                    device.CONTAINER_TIMEOUT + device.CONTAINER_STARTUP_TIMEOUT * 2
                ),
                deadline=190.0, command=usb_recovery.COMMAND_OTA_STATE,
            )

        self.assertEqual(result, state)
        command, kwargs = process_calls[0]
        self.assertEqual(
            float(command[command.index("--timeout") + 1]),
            device.CONTAINER_TIMEOUT,
        )
        self.assertEqual(
            kwargs["timeout"],
            device.CONTAINER_TIMEOUT + device.CONTAINER_STARTUP_TIMEOUT * 2,
        )

    def test_flash_app1_dry_run_uses_fixed_slot_and_rejects_arbitrary_offset(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"firmware")
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device.subprocess, "run") as run:
                result, output = self.run_main([
                    "--device", DEVICE, "flash-app", "--slot", "app1", str(image),
                ])
            self.assertEqual(result, 0)
            run.assert_not_called()
            plan = json.loads(output)
            self.assertEqual(plan["action"], "flash-app")
            self.assertEqual(plan["slot"], "app1")
            self.assertEqual(plan["offset"], "0x1F0000")
            self.assertEqual(plan["max_size"], 0x1E0000)

            with self.assertRaises(SystemExit):
                device.build_parser().parse_args([
                    "--device", DEVICE, "flash-app", "--slot", "app2", str(image),
                ])
            with self.assertRaises(SystemExit):
                device.build_parser().parse_args([
                    "--device", DEVICE, "flash-app", "--slot", "app1",
                    "--offset", "0x1234", str(image),
                ])

    def test_live_flash_app1_writes_fixed_slot(self):
        events = []

        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"firmware")
            digest = device.sha256_file(image)

            def fake_run(command, **kwargs):
                events.append((command, kwargs))
                if "read_flash" in command:
                    pathlib.Path(command[-1]).write_bytes(b"old-data")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "resolve_esptool", return_value="host"), \
                    mock.patch.object(device.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app0"]}), \
                    mock.patch.object(device, "confirm_basename", return_value=None):
                result, output = self.run_main([
                    "--device", DEVICE, "flash-app", "--slot", "app1", str(image),
                    "--live", "--confirm", "usb-test", "--sha256", digest,
                ])

        self.assertEqual(result, 0)
        esptool = events[-1][0]
        self.assertIn("0x1F0000", esptool)
        self.assertEqual(json.loads(output)["slot"], "app1")

    def test_live_flash_runs_baseline_before_hash_and_fixed_write(self):
        events = []

        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"firmware")
            expected_sha256 = device.sha256_file(image)

            def fake_run(command, **kwargs):
                events.append(("run", command, kwargs))
                if "read_flash" in command:
                    pathlib.Path(command[-1]).write_bytes(b"old-data")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "resolve_esptool", return_value="host"), \
                    mock.patch.object(device.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app1"]}), \
                    mock.patch.object(device, "confirm_basename", return_value=None):
                result, output = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live", "--confirm", "usb-test",
                    "--sha256", expected_sha256,
                ])
        self.assertEqual(result, 0)
        self.assertIn("tools/check_idf_baseline.py", events[0][1][1])
        esptool = next(command for kind, command, _kwargs in events if "write_flash" in command)
        self.assertIn("write_flash", esptool)
        self.assertEqual(esptool[esptool.index("--before") + 1], "usb_reset")
        self.assertEqual(esptool[esptool.index("--after") + 1], "no_reset")
        self.assertIn("0x10000", esptool)
        self.assertNotIn("--offset", esptool)
        verify = next(command for kind, command, _kwargs in events if "verify_flash" in command)
        self.assertEqual(verify[verify.index("verify_flash") + 1], "0x10000")
        self.assertEqual(json.loads(output)["sha256"], expected_sha256)

    def test_live_flash_checks_baseline_for_selected_usb_recovery_profile(self):
        events = []

        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf-usb-recovery" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"firmware")
            digest = device.sha256_file(image)

            def fake_run(command, **kwargs):
                events.append((command, kwargs))
                if "read_flash" in command:
                    pathlib.Path(command[-1]).write_bytes(b"old-data")
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "resolve_esptool", return_value="host"), \
                    mock.patch.object(device.subprocess, "run", side_effect=fake_run), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app1"]}), \
                    mock.patch.object(device, "confirm_basename", return_value=None):
                result, _ = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])

        self.assertEqual(result, 0)
        baseline = events[0][0]
        self.assertEqual(
            pathlib.Path(baseline[baseline.index("--build-dir") + 1]),
            root / "build" / "idf-usb-recovery",
        )

    def test_live_flash_maps_worktree_and_image_into_pinned_container(self):
        calls = []

        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"firmware")
            digest = device.sha256_file(image)

            def fake_run(command, **kwargs):
                calls.append((command, kwargs))
                return mock.Mock(returncode=0, stdout="", stderr="")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "resolve_esptool", return_value="container"), \
                    mock.patch.object(device, "_run_process", side_effect=fake_run), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app1"]}), \
                    mock.patch.object(device, "_read_app_flash_digest", return_value="0" * 64), \
                    mock.patch.object(device, "confirm_basename", return_value=None):
                result, _ = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])
        self.assertEqual(result, 0)
        command = calls[-1][0]
        self.assertIn(device.IDF_IMAGE, command)
        self.assertIn(f"{root.resolve()}:/workspace:ro", command)
        self.assertNotIn(DEVICE, command)
        self.assertIn(f"{TARGET}:{device.CONTAINER_DEVICE_PATH}", command)
        self.assertIn(device.CONTAINER_DEVICE_PATH, command)
        self.assertIn("verify_flash", command)
        self.assertIn("/workspace/sms-forwarding-image-", command[-1])
        self.assertEqual(calls[-1][1]["timeout"], device.RESET_TIMEOUT)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("/dev:/dev", command)

    def test_esptool_container_uses_the_shared_create_boundary(self):
        ref = device.SerialDevice(DEVICE, TARGET)

        with mock.patch.object(device, "resolve_esptool", return_value="container"), \
                mock.patch.object(
                    device, "_run_process",
                    side_effect=usb_recovery.DeviceError("esptool timed out"),
                ) as process:
            with self.assertRaisesRegex(usb_recovery.DeviceError, "timed out"):
                device._run_esptool(["chip_id"], ref, 1.0)

        command = process.call_args.args[0]
        name = command[command.index("--name") + 1]
        self.assertEqual(command[:2], ["docker", "create"])
        self.assertRegex(name, rf"^{device.CONTAINER_NAME_PREFIX}-[a-z0-9-]+$")
        self.assertNotIn("--rm", command)

    def test_live_flash_timeout_mismatching_readback_fails_without_reset_success(self):
        events = []
        image_bytes = b"firmware"

        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(image_bytes)
            digest = hashlib.sha256(image_bytes).hexdigest()

            read_count = [0]

            def fake_esptool(arguments, _device, _timeout, **_kwargs):
                events.append(arguments)
                if "read_flash" in arguments:
                    read_count[0] += 1
                    pathlib.Path(arguments[-1]).write_bytes(
                        b"old-data" if read_count[0] == 1 else b"wrong!!!"
                    )
                    return
                raise usb_recovery.DeviceError("esptool timed out")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app1"]}), \
                    mock.patch.object(device, "confirm_basename", return_value=None), \
                    mock.patch.object(device, "_run_baseline", return_value=None), \
                    mock.patch.object(device, "_run_esptool", side_effect=fake_esptool):
                result, _ = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])

        self.assertNotEqual(result, 0)
        self.assertEqual(len(events), 3)
        self.assertNotIn("chip_id", events[-1])

    def test_live_flash_pre_read_matching_is_explicit_noop(self):
        events = []
        image_bytes = b"firmware"

        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(image_bytes)
            digest = hashlib.sha256(image_bytes).hexdigest()

            def fake_esptool(arguments, _device, _timeout, **_kwargs):
                events.append(arguments)
                if "read_flash" in arguments:
                    pathlib.Path(arguments[-1]).write_bytes(image_bytes)

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app1"]}), \
                    mock.patch.object(device, "confirm_basename", return_value=None), \
                    mock.patch.object(device, "_run_baseline", return_value=None), \
                    mock.patch.object(device, "_run_esptool", side_effect=fake_esptool):
                result, output = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])

        self.assertEqual(result, 0)
        self.assertIn("read_flash", events[0])
        self.assertFalse(any("write_flash" in command for command in events))
        plan = json.loads(output)
        self.assertEqual(plan["status"], "already-matching")
        self.assertFalse(plan["written"])
        self.assertEqual(plan["activation"], "none")

    def test_live_flash_rejects_active_slot_before_read_or_write(self):
        image_bytes = b"firmware"
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(image_bytes)
            digest = hashlib.sha256(image_bytes).hexdigest()
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app0"]}), \
                    mock.patch.object(device, "_run_baseline", return_value=None), \
                    mock.patch.object(device, "_run_esptool") as esptool:
                result, _ = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])

        self.assertNotEqual(result, 0)
        esptool.assert_not_called()

    def test_live_flash_rejects_by_id_target_change_before_esptool(self):
        image_bytes = b"firmware"
        initial = device.SerialDevice(DEVICE, TARGET)
        changed = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(image_bytes)
            digest = hashlib.sha256(image_bytes).hexdigest()
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", side_effect=(initial, changed)), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app1"]}), \
                    mock.patch.object(device, "_run_baseline", return_value=None), \
                    mock.patch.object(device, "_run_esptool") as esptool:
                result, _ = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])

        self.assertNotEqual(result, 0)
        esptool.assert_not_called()

    def test_live_flash_uses_private_snapshot_after_source_mutation(self):
        events = []
        snapshot_bytes = b""
        image_bytes = b"firmware"
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(image_bytes)
            digest = hashlib.sha256(image_bytes).hexdigest()

            def fake_esptool(arguments, _device, _timeout, **_kwargs):
                nonlocal snapshot_bytes
                events.append(arguments)
                if "read_flash" in arguments:
                    pathlib.Path(arguments[-1]).write_bytes(b"old-data")
                elif "write_flash" in arguments:
                    snapshot = pathlib.Path(arguments[-1])
                    snapshot_bytes = snapshot.read_bytes()
                    image.write_bytes(b"mutated-after-snapshot")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app1"]}), \
                    mock.patch.object(device, "confirm_basename", return_value=None), \
                    mock.patch.object(device, "_run_baseline", return_value=None), \
                    mock.patch.object(device, "_run_esptool", side_effect=fake_esptool):
                result, _ = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])

        write = next(command for command in events if "write_flash" in command)
        self.assertEqual(result, 0)
        self.assertNotEqual(write[-1], str(image))
        self.assertEqual(snapshot_bytes, image_bytes)

    def test_live_flash_timeout_changed_to_matching_readback_stays_inactive(self):
        events = []
        image_bytes = b"firmware"
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(image_bytes)
            digest = hashlib.sha256(image_bytes).hexdigest()

            def fake_esptool(arguments, _device, _timeout, **_kwargs):
                events.append(arguments)
                if "read_flash" in arguments:
                    pathlib.Path(arguments[-1]).write_bytes(
                        b"old-data" if sum("read_flash" in item for item in events) == 1 else image_bytes
                    )
                elif "write_flash" in arguments:
                    raise usb_recovery.DeviceError("esptool timed out")

            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(device, "_ota_state", return_value={"active_offset": device.APP_SLOT_OFFSETS["app1"]}), \
                    mock.patch.object(device, "confirm_basename", return_value=None), \
                    mock.patch.object(device, "_run_baseline", return_value=None), \
                    mock.patch.object(device, "_run_esptool", side_effect=fake_esptool):
                result, output = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live",
                    "--confirm", "usb-test", "--sha256", digest,
                ])

        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output)["verification"], "readback_sha256")
        self.assertFalse(any("hard_reset" in command for command in events))
        self.assertFalse(any("chip_id" in command for command in events))

    def test_live_flash_rejects_missing_or_wrong_sha256_pin(self):
        with tempfile.TemporaryDirectory() as temp:
            root = pathlib.Path(temp)
            image = root / "build" / "idf" / "sms_forwarding_idf.bin"
            image.parent.mkdir(parents=True)
            image.write_bytes(b"firmware")
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "resolve_serial_device", return_value=device.SerialDevice(DEVICE, TARGET)), \
                    mock.patch.object(
                        device.subprocess,
                        "run",
                        return_value=mock.Mock(returncode=0, stdout="", stderr=""),
                    ) as run:
                missing, _ = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live", "--confirm", "usb-test",
                ])
                wrong, _ = self.run_main([
                    "--device", DEVICE, "flash-app0", str(image), "--live", "--confirm", "usb-test",
                    "--sha256", "0" * 64,
                ])
            self.assertNotEqual(missing, 0)
            self.assertNotEqual(wrong, 0)
            self.assertEqual(run.call_count, 2)

    def test_state_falls_back_to_container_on_host_permission_error(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            return mock.Mock(returncode=0, stdout='{"sta_connected":false}\n', stderr="")

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "resolve_esptool", return_value="container"), \
                mock.patch.object(device, "_run_process", side_effect=fake_run):
            result, output = self.run_main(["--device", DEVICE, "state"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output)["sta_connected"], False)
        self.assertIn(device.CONTAINER_DEVICE_PATH, calls[-1])
        self.assertIn(f"{TARGET}:{device.CONTAINER_DEVICE_PATH}", calls[-1])

    def test_state_fallback_executes_usb_backend_cli_with_internal_device_and_timeout(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        backend_calls = []
        process_calls = []

        def fake_transaction(path, timeout, command, payload, **kwargs):
            backend_calls.append((path, timeout, command, payload, kwargs))
            return usb_recovery.Frame(usb_recovery.RESPONSE_STATE, 0, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00")

        def fake_run(command, **kwargs):
            process_calls.append((command, kwargs))
            script = command.index("/workspace/tools/usb_recovery.py")
            backend_argv = command[script + 1:]
            output = io.StringIO()
            with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                    mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                    contextlib.redirect_stdout(output):
                result = usb_recovery.main(backend_argv)
            return mock.Mock(returncode=result, stdout=output.getvalue().encode(), stderr=b"")

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "_run_process", side_effect=fake_run):
            result, output = self.run_main(["--device", DEVICE, "state"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output)["sta_connected"], False)
        self.assertEqual(backend_calls[0][0:2], (device.CONTAINER_DEVICE_PATH, 5.0))
        self.assertTrue(backend_calls[0][4]["internal_container"])
        self.assertIn("deadline", backend_calls[0][4])
        lifecycle_timeout = (
            device.CONTAINER_TIMEOUT + device.CONTAINER_STARTUP_TIMEOUT * 2
        )
        self.assertLessEqual(
            process_calls[0][1]["timeout"],
            lifecycle_timeout,
        )
        self.assertGreater(
            process_calls[0][1]["timeout"],
            lifecycle_timeout - 1.0,
        )
        self.assertIn("--internal-container", process_calls[0][0])
        self.assertIn("--timeout", process_calls[0][0])
        self.assertIn("5.0", process_calls[0][0])
        self.assertEqual(
            process_calls[0][0][process_calls[0][0].index("--entrypoint") + 1],
            device.CONTAINER_PYTHON,
        )

    def test_state_transaction_timeout_uses_bounded_container_fallback(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        state = {
            "ap_mode": False,
            "boot_id": 1,
            "credential_configured": True,
            "ip": "",
            "sta_connected": False,
        }
        fallback = mock.Mock(return_value=state)
        with mock.patch.object(
            device.usb_recovery,
            "run_transaction",
            side_effect=usb_recovery.DeviceError("USB device timed out"),
        ), mock.patch.object(device, "_container_recovery", fallback):
            self.assertEqual(
                device._state(ref, deadline=device.time.monotonic() + device.CONTAINER_TIMEOUT),
                state,
            )
        fallback.assert_called_once()

    def test_state_command_keeps_full_container_budget_after_host_retries(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        clock = [100.0]
        state = {
            "ap_mode": False,
            "boot_id": 1,
            "credential_configured": True,
            "ip": "",
            "sta_connected": False,
        }

        def host_timeout(*_args, **_kwargs):
            clock[0] += device.STATE_TIMEOUT * 3
            raise usb_recovery.DeviceError("USB device timed out")

        fallback = mock.Mock(return_value=state)
        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(device.usb_recovery, "run_transaction", side_effect=host_timeout), \
                mock.patch.object(device, "_container_recovery", fallback), \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]):
            result, _ = self.run_main(["--device", DEVICE, "state"])

        self.assertEqual(result, 0)
        self.assertEqual(
            fallback.call_args.kwargs["caller_timeout"],
            device.CONTAINER_TIMEOUT + device.CONTAINER_STARTUP_TIMEOUT * 2,
        )

    def test_ota_state_fallback_passes_remaining_deadline_to_backend(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        state = {
            "active_offset": usb_recovery.APP1_OFFSET,
            "image_state": "valid",
            "pending_verify": False,
            "accepted": 0,
            "pending": 0,
            "pending_address": 0,
        }
        process_calls = []

        def fake_process(command, **kwargs):
            process_calls.append((command, kwargs))
            return mock.Mock(returncode=0, stdout=json.dumps(state), stderr=b"")

        with mock.patch.object(
            device.usb_recovery,
            "run_transaction",
            side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
        ), mock.patch.object(device, "_run_process", side_effect=fake_process), \
                mock.patch.object(device.time, "monotonic", return_value=100.0):
            result = device._ota_state(ref, deadline=130.0)

        self.assertEqual(result, state)
        command, kwargs = process_calls[0]
        self.assertEqual(
            float(command[command.index("--timeout") + 1]),
            device.CONTAINER_TIMEOUT,
        )
        self.assertEqual(kwargs["timeout"], device.CONTAINER_TIMEOUT)

    def test_ota_migration_fallback_uses_the_same_backend_budget(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        process_calls = []

        def fake_process(command, **kwargs):
            process_calls.append((command, kwargs))
            return mock.Mock(returncode=0, stdout='{"ok":true}', stderr=b"")

        with mock.patch.object(device, "_run_process", side_effect=fake_process), \
                mock.patch.object(device.time, "monotonic", return_value=100.0):
            result = device._container_recovery(
                ref, device.STATE_TIMEOUT, caller_timeout=device.CONTAINER_TIMEOUT,
                deadline=130.0, command=usb_recovery.COMMAND_OTA_MIGRATION_RECOVER,
            )

        self.assertEqual(result, {"ok": True})
        command, kwargs = process_calls[0]
        self.assertEqual(
            float(command[command.index("--timeout") + 1]),
            device.CONTAINER_TIMEOUT,
        )
        self.assertEqual(kwargs["timeout"], device.CONTAINER_TIMEOUT)

    def test_diag_fallback_passes_inner_timeout_to_backend_cli(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        backend_calls = []
        process_calls = []

        class BinaryCapture(io.StringIO):
            def __init__(self):
                super().__init__()
                self.buffer = io.BytesIO()

        def fake_transaction(path, timeout, command, payload, **kwargs):
            backend_calls.append((path, timeout, command, payload, kwargs))
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_MODEM_QUERY, 0,
                b"+ICCID: 8986001234567890123\r\nOK\r\n",
            )

        def fake_run(command, **kwargs):
            process_calls.append((command, kwargs))
            script = command.index("/workspace/tools/usb_recovery.py")
            output = BinaryCapture()
            with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                    mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                    mock.patch("sys.stdout", output):
                result = usb_recovery.main(command[script + 1:])
            return mock.Mock(returncode=result, stdout=output.buffer.getvalue(), stderr=b"")

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "_run_process", side_effect=fake_run):
            result, output = self.run_main(["--device", DEVICE, "diag", "iccid"])
        self.assertEqual(result, 0)
        self.assertNotIn("8986001234567890123", output)
        self.assertEqual(backend_calls[0][0:2], (device.CONTAINER_DEVICE_PATH, 3.0))
        self.assertEqual(backend_calls[0][4], {"internal_container": True})
        self.assertLessEqual(process_calls[0][1]["timeout"], device.CONTAINER_TIMEOUT)
        self.assertGreater(process_calls[0][1]["timeout"], device.CONTAINER_TIMEOUT - 1.0)

    def test_diag_container_busy_retries_twice_then_succeeds(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        backend_calls = []
        process_calls = []
        responses = [usb_recovery.CommandError(usb_recovery.STATUS_BUSY), usb_recovery.Frame(
            usb_recovery.RESPONSE_MODEM_QUERY, 0, b"OK\r\n"
        )]

        class BinaryCapture(io.StringIO):
            def __init__(self):
                super().__init__()
                self.buffer = io.BytesIO()

        def fake_transaction(path, timeout, command, payload, **kwargs):
            backend_calls.append((path, timeout, command, payload, kwargs))
            response = responses.pop(0)
            if isinstance(response, Exception):
                raise response
            return response

        def fake_run(command, **kwargs):
            process_calls.append((command, kwargs))
            script = command.index("/workspace/tools/usb_recovery.py")
            output = BinaryCapture()
            error = io.StringIO()
            with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                    mock.patch.object(usb_recovery, "run_transaction", side_effect=fake_transaction), \
                    mock.patch("sys.stdout", output), mock.patch("sys.stderr", error):
                result = usb_recovery.main(command[script + 1:])
            return mock.Mock(
                returncode=result, stdout=output.buffer.getvalue(), stderr=error.getvalue().encode()
            )

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "_run_process", side_effect=fake_run), \
                mock.patch.object(device.time, "sleep") as sleep:
            result, _ = self.run_main(["--device", DEVICE, "diag", "iccid"])
        self.assertEqual(result, 0)
        self.assertEqual(len(process_calls), 2)
        self.assertEqual(len(backend_calls), 2)
        self.assertEqual(sleep.call_args_list, [mock.call(5.0)])

    def test_diag_eacces_container_busy_preserves_bounded_reason(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        result = mock.Mock(
            returncode=1,
            stdout="",
            stderr="device rejected request (busy; gate_closed)\n",
        )
        with mock.patch.object(
            device.usb_recovery,
            "run_transaction",
            side_effect=usb_recovery.DeviceError("USB transport EACCES"),
        ), mock.patch.object(device, "_run_process", return_value=result), mock.patch.object(
            device, "BUSY_RETRIES", 0
        ):
            with self.assertRaises(usb_recovery.CommandError) as raised:
                device._diag_query(ref, "cpol", device.time.monotonic() + 10.0)
        self.assertEqual(raised.exception.reason, "gate_closed")

    def test_diag_eacces_container_malformed_busy_is_external_without_reflection(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        secret = "secret-like-suffix"
        result = mock.Mock(
            returncode=1,
            stdout="",
            stderr=f"device rejected request (busy; gate_closed) {secret}\n",
        )
        with mock.patch.object(
            device.usb_recovery,
            "run_transaction",
            side_effect=usb_recovery.DeviceError("USB transport EACCES"),
        ), mock.patch.object(device, "_run_process", return_value=result), mock.patch.object(
            device, "BUSY_RETRIES", 0
        ):
            with self.assertRaises(usb_recovery.DeviceError) as raised:
                device._diag_query(ref, "cpol", device.time.monotonic() + 10.0)
        self.assertIn("external-error", str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_diag_eacces_container_preserves_protocol_status_without_reflection(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        secret = "secret-like-suffix"
        statuses = (
            usb_recovery.STATUS_INVALID_ARG,
            usb_recovery.STATUS_NOT_READY,
            usb_recovery.STATUS_TIMEOUT,
            usb_recovery.STATUS_NO_MEM,
            usb_recovery.STATUS_INTERNAL,
        )
        for status in statuses:
            with self.subTest(status=status):
                result = mock.Mock(
                    returncode=1,
                    stdout="",
                    stderr=f"device rejected request ({usb_recovery.status_name(status)})\n",
                )
                with mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("USB transport EACCES"),
                ), mock.patch.object(device, "_run_process", return_value=result):
                    with self.assertRaises(usb_recovery.CommandError) as raised:
                        device._diag_query(ref, "cpol", device.time.monotonic() + 10.0)
                self.assertEqual(raised.exception.status, status)
                self.assertNotIn(secret, str(raised.exception))

        malformed = mock.Mock(
            returncode=1,
            stdout="",
            stderr=f"device rejected request (invalid-argument) {secret}\n",
        )
        with mock.patch.object(
            device.usb_recovery,
            "run_transaction",
            side_effect=usb_recovery.DeviceError("USB transport EACCES"),
        ), mock.patch.object(device, "_run_process", return_value=malformed):
            with self.assertRaises(usb_recovery.DeviceError) as raised:
                device._diag_query(ref, "cpol", device.time.monotonic() + 10.0)
        self.assertIn("external-error", str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_diag_container_busy_exhausts_two_retries(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        process_calls = []

        class BinaryCapture(io.StringIO):
            def __init__(self):
                super().__init__()
                self.buffer = io.BytesIO()

        def fake_run(command, **kwargs):
            process_calls.append((command, kwargs))
            script = command.index("/workspace/tools/usb_recovery.py")
            output = BinaryCapture()
            error = io.StringIO()
            with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                    mock.patch.object(
                        usb_recovery,
                        "run_transaction",
                        side_effect=usb_recovery.CommandError(usb_recovery.STATUS_BUSY),
                    ), \
                    mock.patch("sys.stdout", output), mock.patch("sys.stderr", error):
                result = usb_recovery.main(command[script + 1:])
            return mock.Mock(
                returncode=result, stdout=output.buffer.getvalue(), stderr=error.getvalue().encode()
            )

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "_run_process", side_effect=fake_run), \
                mock.patch.object(device.time, "sleep") as sleep:
            result, _ = self.run_main(["--device", DEVICE, "diag", "iccid"])
        self.assertNotEqual(result, 0)
        self.assertEqual(len(process_calls), 3)
        self.assertEqual(sleep.call_args_list, [mock.call(5.0), mock.call(5.0)])

    def test_diag_container_busy_does_not_sleep_when_deadline_cannot_fit_retry(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        clock = iter((100.0, 129.0, 129.0, 129.0, 129.0, 129.0))
        process_calls = []

        def fake_run(command, **kwargs):
            process_calls.append((command, kwargs))
            script = command.index("/workspace/tools/usb_recovery.py")
            output = io.BytesIO()
            error = io.StringIO()
            class BinaryCapture(io.StringIO):
                def __init__(self):
                    super().__init__()
                    self.buffer = output
            capture = BinaryCapture()
            with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                    mock.patch.object(
                        usb_recovery,
                        "run_transaction",
                        side_effect=usb_recovery.CommandError(usb_recovery.STATUS_BUSY),
                    ), \
                    mock.patch("sys.stdout", capture), mock.patch("sys.stderr", error):
                result = usb_recovery.main(command[script + 1:])
            return mock.Mock(returncode=result, stdout=output.getvalue(), stderr=error.getvalue().encode())

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "_run_process", side_effect=fake_run), \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: next(clock)), \
                mock.patch.object(device.time, "sleep") as sleep:
            result, _ = self.run_main(["--device", DEVICE, "diag", "iccid"])
        self.assertNotEqual(result, 0)
        sleep.assert_not_called()
        self.assertEqual(process_calls[0][1]["timeout"], 1.0)

    def test_reset_container_probe_near_deadline_does_not_overrun(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        fresh = device.SerialDevice(DEVICE, "/dev/ttyACM1")
        process_calls = []
        clock = iter((100.0, 100.0, 100.0, *(144.0 for _ in range(20))))

        def fake_run(command, **kwargs):
            process_calls.append((command, kwargs))
            boot_id = 1 if len(process_calls) == 1 else 2
            return mock.Mock(
                returncode=0,
                stdout=json.dumps({"sta_connected": False, "boot_id": boot_id}) + "\n",
                stderr=b"",
            )

        resolve_results = iter((ref, fresh))
        with mock.patch.object(device, "resolve_serial_device", side_effect=lambda _path: next(resolve_results)), \
                mock.patch.object(device, "RESET_TIMEOUT", 45.0), \
                mock.patch.object(device, "confirm_basename", return_value=None), \
                mock.patch.object(device, "run_esptool"), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "_run_process", side_effect=fake_run), \
                mock.patch.object(device.time, "monotonic", side_effect=lambda: next(clock)):
            result, _ = self.run_main([
                "--device", DEVICE, "reset", "--live", "--confirm", "usb-test",
            ])
        self.assertEqual(result, 0)
        self.assertEqual(len(process_calls), 2)
        self.assertEqual(process_calls[1][1]["timeout"], 1.0)

    def test_state_json_flag_keeps_default_json_contract(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    return_value=usb_recovery.Frame(
                        usb_recovery.RESPONSE_STATE, 0, b"\x00\x00\x00\x00\x00\x01\x00\x00\x00"
                    ),
                ):
            result, output = self.run_main(["--device", DEVICE, "state", "--json"])
        self.assertEqual(result, 0)
        self.assertIsInstance(json.loads(output), dict)

    def test_diag_falls_back_to_container_on_host_permission_error(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        calls = []

        def fake_run(command, **kwargs):
            calls.append(command)
            return mock.Mock(returncode=0, stdout="+ICCID: 8986001234567890123\\r\\nOK\\r\\n", stderr="")

        with mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device, "_run_process", side_effect=fake_run):
            result, output = self.run_main(["--device", DEVICE, "diag", "iccid"])
        self.assertEqual(result, 0)
        self.assertNotIn("8986001234567890123", output)
        self.assertIn(device.CONTAINER_DEVICE_PATH, calls[-1])
        self.assertIn(f"{TARGET}:{device.CONTAINER_DEVICE_PATH}", calls[-1])

    def test_diag_container_fallback_uses_remaining_absolute_deadline(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        clock = [100.0]
        process_calls = []

        def fake_transaction(*_args, **_kwargs):
            clock[0] = 104.0
            raise usb_recovery.DeviceError("could not claim the USB device (open: EACCES)")

        def fake_process(command, **kwargs):
            process_calls.append((command, kwargs))
            return mock.Mock(returncode=0, stdout=b"OK\r\n", stderr=b"")

        with mock.patch.object(device.time, "monotonic", side_effect=lambda: clock[0]), \
                mock.patch.object(device.usb_recovery, "run_transaction", side_effect=fake_transaction), \
                mock.patch.object(device, "_run_process", side_effect=fake_process):
            payload = device._diag_query(ref, "iccid", 130.0)

        self.assertEqual(payload, b"OK\r\n")
        self.assertEqual(process_calls[0][1]["timeout"], 26.0)

    def test_state_does_not_recurse_to_container_inside_container(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device.subprocess, "run") as run:
            result, _ = self.run_main(["--device", DEVICE, "state"])
        self.assertNotEqual(result, 0)
        run.assert_not_called()

    def test_diag_does_not_recurse_to_container_inside_container(self):
        ref = device.SerialDevice(DEVICE, TARGET)
        with mock.patch.dict(os.environ, {"SMS_DEVICE_IN_CONTAINER": "1"}), \
                mock.patch.object(device, "resolve_serial_device", return_value=ref), \
                mock.patch.object(
                    device.usb_recovery,
                    "run_transaction",
                    side_effect=usb_recovery.DeviceError("could not claim USB device (open: EACCES)"),
                ), \
                mock.patch.object(device.subprocess, "run") as run:
            result, _ = self.run_main(["--device", DEVICE, "diag", "iccid"])
        self.assertNotEqual(result, 0)
        run.assert_not_called()


def _config_fixture() -> bytes:
    return (
        b"SMSCFG01" + struct.pack("<HBBI", 1, 1, 1, 210000) + bytes(28) + bytes(16)
    )


def _ota_fixture(image: bytes = b"firmware" * 2000) -> bytes:
    manifest = json.dumps({
        "format": 1,
        "releaseCounter": 7,
        "sha256": hashlib.sha256(image).hexdigest(),
        "size": len(image),
        "target": "esp32c3",
        "version": "test-ota",
    }, sort_keys=True, separators=(",", ":")).encode("ascii")
    signature = bytes(range(1, 33))
    return b"SMSOTA1\n" + struct.pack(">I", len(manifest)) + manifest + struct.pack(">H", len(signature)) + signature + image


class _FakeTransferClient:
    state = None

    def __init__(self, host, user, password, timeout=device.WEB_REQUEST_TIMEOUT):
        if host != "fake-host" or user != "alice" or password != "secret":
            raise AssertionError("fake auth mismatch")

    def request(self, method, path, *, body=b"", headers=None, max_bytes=16384):
        state = self.state
        headers = headers or {}
        state.requests.append((method, path, headers, body))
        if method == "GET" and path == "/api/config":
            return device.WebResponse(200, {"content-type": "application/json"}, b'{"csrfToken":"0123456789abcdef0123456789abcdef"}')
        if headers.get("X-CSRF-Token") != "0123456789abcdef0123456789abcdef" and method == "POST":
            return device.WebResponse(403, {}, b"{}")
        parsed = urllib.parse.urlsplit(path)
        query = urllib.parse.parse_qs(parsed.query)
        if method == "POST" and parsed.path == "/api/config/export":
            if state.wrong_status:
                return device.WebResponse(500, {}, b"{}")
            state.job_kind = "backup"
            return self._action(202, True, "ACTION_JOB_ACCEPTED", {"jobId": 9})
        if method == "GET" and parsed.path == "/api/jobs":
            if state.job_mode == "timeout":
                body = b'{"id":9,"type":"job","state":"running"}'
            elif state.job_mode == "failed":
                body = b'{"id":9,"type":"job","state":"failed","result":{"success":false,"code":"ACTION_JOB_FAILED","data":{},"detail":""}}'
            else:
                code = "ACTION_CONFIG_EXPORT_READY" if state.job_kind == "backup" else "ACTION_OTA_READY"
                data = {"exportId": 12} if state.job_kind == "backup" else {}
                body = json.dumps({"id": 9, "type": state.job_kind, "state": "succeeded", "result": {"success": True, "code": code, "data": data, "detail": ""}}).encode()
            return device.WebResponse(200, {"content-type": "application/json"}, body)
        if method == "GET" and parsed.path == "/api/config/export" and query.get("id") == ["12"]:
            return device.WebResponse(200, {"content-type": "application/vnd.sms-forwarding.config"}, state.config)
        if method == "POST" and parsed.path == "/api/ota/start":
            if state.ota_start_error:
                status, code, detail = state.ota_start_error
                return self._action(status, False, code, {"secret": "body-secret"}, detail)
            fields = urllib.parse.parse_qs(body.decode())
            state.job_kind = "ota"
            state.manifest, state.signature = fields["manifest"][0], fields["signature"][0]
            return self._action(201, True, "ACTION_OTA_UPLOAD_STARTED", {"uploadId": 4, "chunkSize": 8192, "nextOffset": 0})
        if method == "POST" and parsed.path == "/api/ota/chunk":
            state.chunks.append((int(query["offset"][0]), body.decode()))
            raw = base64.b64decode(body, validate=True)
            return self._action(200, True, "ACTION_OTA_CHUNK_OK", {"nextOffset": int(query["offset"][0]) + len(raw)})
        if method == "POST" and parsed.path == "/api/ota/finish":
            return self._action(202, True, "ACTION_JOB_ACCEPTED", {"jobId": 9})
        return device.WebResponse(404, {}, b"{}")

    @staticmethod
    def _action(status, success, code, data=None, detail=""):
        return device.WebResponse(status, {"content-type": "application/json"}, json.dumps({"success": success, "code": code, "data": data or {}, "detail": detail}).encode())


class WebTransferTest(unittest.TestCase):
    def run_main(self, argv):
        output, errors = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(errors):
            result = device.main(argv)
        return result, output.getvalue(), errors.getvalue()

    def serve(self):
        state = type("State", (), {"requests": [], "config": _config_fixture(), "job_kind": "backup", "job_mode": "success", "wrong_status": False, "ota_start_error": None, "chunks": [], "manifest": "", "signature": ""})()
        return state, "fake-host"

    def test_ota_dry_run_does_not_use_network_and_rejects_bad_hash(self):
        with tempfile.TemporaryDirectory() as temp:
            package = pathlib.Path(temp) / "update.smsota"
            package.write_bytes(_ota_fixture())
            with mock.patch.object(device, "WebClient", side_effect=AssertionError("dry-run network")):
                result, output, error = self.run_main(["ota-upload", str(package), "--host", "fake-host"])
            self.assertEqual(result, 0)
            self.assertIn("package_sha256", output)
            self.assertNotIn("secret", output + error)
            package.write_bytes(package.read_bytes()[:-1] + b"!")
            result, _, error = self.run_main(["ota-upload", str(package)])
            self.assertNotEqual(result, 0)
            self.assertNotIn("secret", error)

    def test_backup_live_uses_basic_csrf_and_writes_exclusive_mode600(self):
        server, host = self.serve()
        _FakeTransferClient.state = server
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
                os.environ, {"SMS_WEB_PASSWORD": "secret", "SMS_CONFIG_PASSPHRASE": "a-passphrase-12"}, clear=True):
            output_path = pathlib.Path(temp) / "backup.smscfg"
            with mock.patch.object(device, "WebClient", _FakeTransferClient):
                result, output, error = self.run_main(["backup-config", str(output_path), "--host", host, "--user", "alice"])
            self.assertEqual(result, 0, error)
            self.assertEqual(output_path.read_bytes(), _config_fixture())
            self.assertEqual(output_path.stat().st_mode & 0o777, 0o600)
            self.assertTrue(any(item[0:2] == ("POST", "/api/config/export") for item in server.requests))
            self.assertNotIn("secret", output + error)
            with mock.patch.object(device, "WebClient", _FakeTransferClient):
                result, _, _ = self.run_main(["backup-config", str(output_path), "--host", host, "--user", "alice"])
            self.assertNotEqual(result, 0)

    def test_ota_live_uploads_8192_chunks_and_requires_exact_confirmation(self):
        server, host = self.serve()
        _FakeTransferClient.state = server
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
                os.environ, {"SMS_WEB_PASSWORD": "secret"}, clear=True):
            package = pathlib.Path(temp) / "update.smsota"
            package.write_bytes(_ota_fixture())
            with mock.patch.object(device, "WebClient", _FakeTransferClient):
                result, output, error = self.run_main([
                    "ota-upload", str(package), "--host", host, "--user", "alice",
                    "--live", "--confirm-host", host,
                ])
            self.assertEqual(result, 0, error)
            self.assertIn("ACTION_OTA_READY", output)
            self.assertEqual([offset for offset, _ in server.chunks], [0, 8192])
            self.assertEqual(base64.b64decode(server.chunks[0][1]), (b"firmware" * 2000)[:8192])
            self.assertNotIn("secret", output + error)

    def test_ota_action_error_exposes_status_and_code_only(self):
        server, host = self.serve()
        server.ota_start_error = (
            400,
            "ACTION_OTA_SIGNATURE_INVALID",
            "detail-secret signature=010203 manifest=private-manifest",
        )
        _FakeTransferClient.state = server
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
                os.environ, {"SMS_WEB_PASSWORD": "secret"}, clear=True):
            package = pathlib.Path(temp) / "update.smsota"
            package.write_bytes(_ota_fixture())
            with mock.patch.object(device, "WebClient", _FakeTransferClient):
                result, output, error = self.run_main([
                    "ota-upload", str(package), "--host", host, "--user", "alice",
                    "--live", "--confirm-host", host,
                ])
        self.assertNotEqual(result, 0)
        self.assertEqual(error.strip(), "OTA start returned HTTP 400 (ACTION_OTA_SIGNATURE_INVALID)")
        self.assertEqual(server.chunks, [])
        self.assertNotIn("detail-secret", output + error)
        self.assertNotIn("010203", output + error)
        self.assertNotIn("private-manifest", output + error)
        self.assertNotIn("body-secret", output + error)
        self.assertNotIn("secret", output + error)

    def test_malformed_action_error_stays_generic(self):
        response = device.WebResponse(400, {"content-type": "application/json"}, b"not-json")
        with self.assertRaisesRegex(device.DeviceTransferError, "OTA start returned unexpected HTTP status"):
            device._action(response, "OTA start", 201)

    def test_live_transfers_reject_wrong_status_and_failed_or_timed_out_job(self):
        server, host = self.serve()
        _FakeTransferClient.state = server
        with tempfile.TemporaryDirectory() as temp, mock.patch.dict(
                os.environ, {"SMS_WEB_PASSWORD": "secret", "SMS_CONFIG_PASSPHRASE": "a-passphrase-12"}, clear=True):
            output_path = pathlib.Path(temp) / "backup.smscfg"
            server.wrong_status = True
            with mock.patch.object(device, "WebClient", _FakeTransferClient):
                result, _, error = self.run_main(["backup-config", str(output_path), "--host", host, "--user", "alice"])
            self.assertNotEqual(result, 0)
            self.assertNotIn("secret", error)
            server.wrong_status = False
            server.job_mode = "failed"
            with mock.patch.object(device, "WebClient", _FakeTransferClient):
                result, _, _ = self.run_main(["backup-config", str(output_path), "--host", host, "--user", "alice"])
            self.assertNotEqual(result, 0)
            server.job_mode = "timeout"
            with mock.patch.object(device, "JOB_POLL_INTERVAL", 0), mock.patch.object(device, "JOB_TIMEOUT", 0.01):
                with mock.patch.object(device, "WebClient", _FakeTransferClient):
                    result, _, _ = self.run_main(["backup-config", str(output_path), "--host", host, "--user", "alice"])
            self.assertNotEqual(result, 0)


if __name__ == "__main__":
    unittest.main()
