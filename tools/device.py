#!/usr/bin/env python3
"""安全的 ESP-IDF build、診斷、reset 與 app slot 工具。"""

from __future__ import annotations

import argparse
import base64
import http.client
import hashlib
import json
import os
import re
import shutil
import stat
import struct
import subprocess
import ssl
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path
from dataclasses import dataclass

import usb_recovery
from check_idf_baseline import EXPECTED_IDF_IMAGE


ROOT = Path(__file__).resolve().parents[1]
IDF_HELPER = ROOT / "tools" / "idf.sh"
BASELINE_CHECK = ROOT / "tools" / "check_idf_baseline.py"
DEFAULT_APP_IMAGE = ROOT / "build" / "idf" / "sms_forwarding_idf.bin"
DEFAULT_BOOTLOADER_IMAGE = ROOT / "build" / "idf" / "bootloader" / "bootloader.bin"
OTA_TEST_PROFILE_DIR = ROOT / "build" / "idf-ota-test"
OTA_TEST_IMAGE = OTA_TEST_PROFILE_DIR / "sms_forwarding_idf.bin"
OTA_TEST_PRIVATE_KEY = OTA_TEST_PROFILE_DIR / "ota_test_private.pem"
OTA_TEST_PUBLIC_DER = OTA_TEST_PROFILE_DIR / "ota_test_public.der"
OTA_TEST_PUBLIC_KEY = OTA_TEST_PROFILE_DIR / "ota_test_public_key.der.b64"
OTA_TEST_SIGNER = ROOT / "scripts" / "sign-ota-release.py"
CONFIG_BACKUP_VERIFIER = ROOT / "tools" / "config_backup_verify.mjs"
NODE = shutil.which("node") or "node"
OTA_TEST_VERSION = "1.1.4-dev-test"
APP_IMAGE_RELATIVE_PATHS = (
    Path("build/idf/sms_forwarding_idf.bin"),
    Path("build/idf-usb-recovery/sms_forwarding_idf.bin"),
    Path("build/idf-ota-test/sms_forwarding_idf.bin"),
)
BOOTLOADER_IMAGE_RELATIVE_PATHS = (
    Path("build/idf/bootloader/bootloader.bin"),
    Path("build/idf-usb-recovery/bootloader/bootloader.bin"),
    Path("build/idf-ota-test/bootloader/bootloader.bin"),
)
ESPTOOL = os.environ.get("ESPTOOL", "esptool")
IDF_IMAGE = EXPECTED_IDF_IMAGE
CONTAINER_PYTHON = "/opt/esp/python_env/idf6.0_py3.12_env/bin/python"
CONTAINER_DEVICE_PATH = "/dev/sms-device"
DEVICE_PREFIX = "/dev/serial/by-id/"
SYSFS_TTY_ROOT = Path("/sys/class/tty")
SYSFS_DEVICES_ROOT = Path("/sys/devices")
APP_OFFSET = 0x10000
BOOTLOADER_OFFSET = 0x0
APP_SLOT_OFFSETS = {
    "app0": APP_OFFSET,
    "app1": 0x1F0000,
}
APP_MAX_SIZE = 0x1E0000
BOOTLOADER_MAX_SIZE = 0x7000
CONFIG_MAX_BYTES = 32828
CONFIG_HEADER_BYTES = 44
CONFIG_TAG_BYTES = 16
CONFIG_VERIFY_TIMEOUT = 10.0
OTA_MAGIC = b"SMSOTA1\n"
OTA_MAX_MANIFEST_BYTES = 512
OTA_CHUNK_BYTES = 8192
OTA_ACTION_CODES = frozenset((
    "ACTION_OTA_READY", "ACTION_OTA_HASH_INVALID", "ACTION_OTA_FINALIZE_FAILED",
    "ACTION_OTA_METADATA_FAILED", "ACTION_OTA_WRITE_FAILED", "ACTION_OTA_SESSION_INVALID",
))
WEB_ACTION_CODES = frozenset((
    "ACTION_BUSY", "ACTION_CONFIG_PASSPHRASE_INVALID", "ACTION_CSRF_INVALID",
    "ACTION_INPUT_INVALID", "ACTION_JOB_ACCEPTED", "ACTION_JOB_QUEUE_FULL",
    "ACTION_OTA_BEGIN_FAILED", "ACTION_OTA_BUSY", "ACTION_OTA_CHUNK_INVALID",
    "ACTION_OTA_CHUNK_OK", "ACTION_OTA_MANIFEST_INVALID", "ACTION_OTA_SIGNATURE_INVALID",
    "ACTION_OTA_UPLOAD_STARTED", *OTA_ACTION_CODES,
))
WEB_REQUEST_STAGES = frozenset((
    "Web request", "config snapshot", "config export", "OTA start", "OTA chunk",
    "OTA finish", "job status", "configuration download",
))
WEB_REQUEST_TIMEOUT = 10.0
JOB_TIMEOUT = 45.0
JOB_POLL_INTERVAL = 0.75
DEFAULT_WEB_HOST = "192.168.20.30"
DEFAULT_WEB_USER = "admin"
RESET_TIMEOUT = 90.0
STATE_TIMEOUT = 5.0
ACTIVE_FLASH_FAILURE = "active app flash failed; device left in ROM loader"
ACTIVE_PRE_READ_FAILURE = "active app pre-read failed; no flash was written"
ACTIVE_POST_RESET_FAILURE = "active app flash post-reset verification failed"
DIAG_INNER_TIMEOUT = 3.0
CPOL_DIAG_INNER_TIMEOUT = 8.0
DIAG_OUTER_TIMEOUT = 30.0
DIAG_ALL_TIMEOUT = 90.0
BUSY_RETRIES = 2
BUSY_DELAY = 5.0
CONTAINER_TIMEOUT = 30.0
CONTAINER_STARTUP_TIMEOUT = 30.0
CONTAINER_LIFECYCLE_TIMEOUT = CONTAINER_TIMEOUT + CONTAINER_STARTUP_TIMEOUT * 2
CONTAINER_NAME_PREFIX = "sms-forwarding-device"
FLASH_OPERATION_MIN_BYTES_PER_SECOND = 8 * 1024
FLASH_OPERATION_OVERHEAD = 60.0
FLASH_OPERATION_MAX_TIMEOUT = 300.0
EXPECTED_QUERY_NAMES = frozenset((
    "ati", "cpin", "cereg", "cops", "cgatt", "cgact", "cgpaddr",
    "iccid", "csq", "cesq", "cfun", "creg", "cgreg", "ceer",
    "cimi", "cpol", "cgdcont", "msslcipher",
))
QUERY_NAMES = tuple(usb_recovery.QUERY_COMMANDS)
if frozenset(QUERY_NAMES) != EXPECTED_QUERY_NAMES or len(QUERY_NAMES) != 18:
    raise RuntimeError("USB diagnostic query allowlist must contain exactly 18 IDs")

_ALLOW_DIAG_CONTAINER_FALLBACK = True
_MAX_BATCH_NESTING = 32
_BATCH_ALLOWED_KEYS = frozenset((
    "query_id", "valid", "model", "firmware", "line_count", "sha256",
    "redactions", "present", "length", "mcc", "raw_length", "record_count",
    "format_bitmap", "format_counts", "rat_complete", "rat_counts",
    "malformed_count", "parse_failed", "entry_count", "entries", "cid",
    "pdp_type", "apn", "address", "safe_flags", "apn_hashed", "address_hashed",
    "field_count", "mode", "stat", "act", "cause_flags", "home", "roaming",
    "registered", "location", "fields", "error", "state", "format", "operator",
    "attached", "active", "rssi", "ber", "rxlev", "rscp", "ecn0", "rsrq", "rsrp",
    "unknown", "last_error", "address_count", "ipv4", "ipv6", "0", "1", "2", "3",
    "supported", "c02b", "c02c", "c02f", "c030", "count", "count_bucket",
    "unknown_present", "other_line_present", "line_overflow",
    "contains_msslcipher_token", "contains_exact_official_prefix_anywhere",
    "leading_whitespace_before_prefix", "parentheses_present", "comma_present",
))


@dataclass(frozen=True)
class SerialDevice:
    by_id: str
    target: str
    stable_identity: tuple[str, ...] | None = None


class DeviceIdentityError(ValueError):
    """USB identity cannot be established from the serial endpoint."""

    def __init__(self, message: str, *, retryable: bool = False):
        super().__init__(message)
        self.retryable = retryable


class SerialEndpointUnavailable(ValueError):
    """The explicit by-id alias has no current target."""


def _serial_usb_identity(target: Path) -> tuple[str, ...]:
    tty_device = SYSFS_TTY_ROOT / target.name / "device"
    try:
        interface = tty_device.resolve(strict=True)
        devices_root = SYSFS_DEVICES_ROOT.resolve(strict=True)
    except OSError as exc:
        raise DeviceIdentityError("USB identity is unavailable", retryable=True) from exc
    try:
        interface_relative = interface.relative_to(devices_root)
    except ValueError as exc:
        raise DeviceIdentityError("USB identity is unavailable") from exc
    usb_device = interface.parent
    while (
        usb_device != devices_root
        and usb_device.is_relative_to(devices_root)
        and not (usb_device / "idVendor").is_file()
    ):
        usb_device = usb_device.parent
    if usb_device == devices_root:
        raise DeviceIdentityError("USB identity is unavailable")
    try:
        serial = (usb_device / "serial").read_text(encoding="ascii").strip()
        vendor = (usb_device / "idVendor").read_text(encoding="ascii").strip().lower()
        product = (usb_device / "idProduct").read_text(encoding="ascii").strip().lower()
        usb_relative = usb_device.relative_to(devices_root)
    except (OSError, UnicodeError, ValueError) as exc:
        raise DeviceIdentityError("USB identity is unavailable", retryable=True) from exc
    if (
        not serial or not re.fullmatch(r"[0-9a-f]{4}", vendor)
        or not re.fullmatch(r"[0-9a-f]{4}", product)
    ):
        raise DeviceIdentityError("USB identity is unavailable")
    return (serial, vendor, product, usb_relative.as_posix(), interface_relative.as_posix())


def resolve_device(value: str | None) -> str:
    """只接受明確的 by-id 裝置，不猜測 tty。"""
    path = value or os.environ.get("SMS_DEVICE", "")
    if not path:
        raise ValueError("--device or SMS_DEVICE is required")
    if not path.startswith(DEVICE_PREFIX):
        raise ValueError("device must be an explicit /dev/serial/by-id path")
    basename = path[len(DEVICE_PREFIX):]
    if not basename or "/" in basename or basename in {".", ".."}:
        raise ValueError("device must be an explicit /dev/serial/by-id path")
    return path


def resolve_serial_device(value: str | None) -> SerialDevice:
    by_id = resolve_device(value)
    link = Path(by_id)
    if not link.is_symlink():
        raise ValueError("device must be a /dev/serial/by-id symlink")
    try:
        target = link.resolve(strict=True)
        mode = target.stat().st_mode
    except OSError as exc:
        raise SerialEndpointUnavailable("device symlink target is unavailable") from exc
    if not stat.S_ISCHR(mode):
        raise ValueError("device symlink target is not a character device")
    return SerialDevice(by_id, str(target), _serial_usb_identity(target))


def _remaining(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise usb_recovery.DeviceError("device operation timed out")
    return remaining


def _safe_error_class(stderr: str | bytes | None) -> str:
    text = stderr.decode("utf-8", "ignore") if isinstance(stderr, bytes) else str(stderr or "")
    text = text.lower()
    if "permission" in text or "eacces" in text:
        return "permission-denied"
    if "timed out" in text or "timeout" in text:
        return "timeout"
    if "busy" in text and "device rejected request" not in text:
        return "busy"
    if "not found" in text or "no such file" in text:
        return "unavailable"
    return "external-error"


def _run_process(
    command: list[str], *, timeout: float | None = None, env=None,
    text: bool = True, stage: str = "external command", _docker_lifecycle: bool = True,
) -> subprocess.CompletedProcess:
    if _docker_lifecycle and command[:2] == ["docker", "create"]:
        if timeout is None:
            raise ValueError("Docker container timeout is required")
        return _run_docker_container(command, timeout=timeout, text=text, stage=stage)
    try:
        return subprocess.run(
            command,
            cwd=ROOT,
            env=env,
            timeout=timeout,
            check=False,
            capture_output=True,
            text=text,
        )
    except FileNotFoundError as exc:
        raise usb_recovery.DeviceError(f"{stage} unavailable") from exc
    except UnicodeError as exc:
        raise usb_recovery.DeviceError(f"{stage} invalid text") from exc
    except OSError as exc:
        raise usb_recovery.DeviceError(f"{stage} unavailable") from exc
    except subprocess.TimeoutExpired as exc:
        raise usb_recovery.DeviceError(f"{stage} timed out") from exc


def resolve_esptool() -> str:
    if shutil.which(ESPTOOL):
        return "host"
    if shutil.which("docker"):
        return "container"
    raise usb_recovery.DeviceError("esptool and docker are not installed")


def _container_path(path: Path) -> str:
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise usb_recovery.DeviceError("image is outside the mapped worktree") from exc
    return str(Path("/workspace") / relative)


def _new_container_name() -> str:
    return f"{CONTAINER_NAME_PREFIX}-{os.getpid()}-{time.monotonic_ns():x}"


def _owned_container_name(name: str) -> bool:
    return bool(re.fullmatch(
        rf"{re.escape(CONTAINER_NAME_PREFIX)}-[0-9]+-[0-9a-f]+", name,
    ))


def _cleanup_docker_container(name: str) -> None:
    """只刪除本次工具建立的 container，並由 Docker 確認已消失。"""
    if not (_owned_container_name(name) or re.fullmatch(r"[0-9a-f]{64}", name)):
        return

    def not_found(result: subprocess.CompletedProcess) -> bool:
        error = result.stderr if isinstance(result.stderr, str) else ""
        return result.returncode == 1 and any(
            marker in error
            for marker in (f"No such object: {name}", f"No such container: {name}")
        )

    for attempt in range(2):
        try:
            result = subprocess.run(
                ["docker", "rm", "--force", name],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise usb_recovery.DeviceError("USB container cleanup failed") from exc
        if result.returncode != 0 and not not_found(result):
            raise usb_recovery.DeviceError("USB container cleanup failed")
        try:
            result = subprocess.run(
                ["docker", "container", "inspect", name],
                cwd=ROOT,
                check=False,
                capture_output=True,
                text=True,
            )
        except (OSError, subprocess.SubprocessError) as exc:
            raise usb_recovery.DeviceError(
                "USB container cleanup could not be confirmed"
            ) from exc
        if not_found(result):
            return
        if result.returncode != 0 or attempt:
            raise usb_recovery.DeviceError("USB container cleanup could not be confirmed")


def _docker_command(
    arguments: list[str], device: SerialDevice, image: Path | None = None,
    program: str | None = "esptool", entrypoint: str | None = None,
    *, container_name: str | None = None, output: Path | None = None,
    output_mount: Path | None = None,
) -> list[str]:
    container_name = container_name or _new_container_name()
    if output is not None and output_mount is None:
        raise ValueError("container readback output requires a writable mount")
    mapped = []
    for argument in arguments:
        if argument == device.by_id:
            mapped.append(CONTAINER_DEVICE_PATH)
        elif output and argument == str(output):
            mapped.append(str(Path("/flash-readback") / output.name))
        elif image and argument == str(image):
            mapped.append(_container_path(image))
        else:
            mapped.append(argument)
    command = [
        "docker", "create", "--name", container_name,
        "--pull=never", "--network=none", "--read-only",
        "--env", "SMS_DEVICE_IN_CONTAINER=1",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
        "--volume", f"{ROOT.resolve()}:/workspace:ro",
        "--device", f"{device.target}:{CONTAINER_DEVICE_PATH}",
        "--workdir", "/workspace",
    ]
    if output_mount:
        command.extend(("--volume", f"{output_mount.resolve()}:/flash-readback:rw"))
    if entrypoint:
        command.extend(("--entrypoint", entrypoint))
    command.append(IDF_IMAGE)
    if program:
        command.append(program)
    return [*command, *mapped]


def _settled_docker_create(
    command: list[str], *, stage: str,
) -> tuple[subprocess.CompletedProcess, KeyboardInterrupt | None]:
    try:
        process = subprocess.Popen(
            command,
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            start_new_session=True,
        )
    except FileNotFoundError as exc:
        raise usb_recovery.DeviceError(f"{stage} unavailable") from exc
    except OSError as exc:
        raise usb_recovery.DeviceError(f"{stage} unavailable") from exc

    interrupted = None
    while True:
        try:
            stdout, stderr = process.communicate()
            break
        except KeyboardInterrupt as exc:
            interrupted = interrupted or exc
    return (
        subprocess.CompletedProcess(command, process.returncode, stdout, stderr),
        interrupted,
    )


def _run_docker_container(
    command: list[str], *, timeout: float, text: bool, stage: str,
) -> subprocess.CompletedProcess:
    try:
        name_index = command.index("--name")
        name = command[name_index + 1]
    except (ValueError, IndexError) as exc:
        raise usb_recovery.DeviceError(f"{stage} container create is invalid") from exc
    if command[:2] != ["docker", "create"] or not _owned_container_name(name):
        raise usb_recovery.DeviceError(f"{stage} container create is invalid")
    deadline = time.monotonic() + timeout
    container_id = None
    try:
        result, interrupted = _settled_docker_create(
            command,
            stage=f"{stage} container create",
        )
        if result.returncode:
            if interrupted is not None:
                raise interrupted
            raise usb_recovery.DeviceError(
                f"{stage} container create failed ({_safe_error_class(result.stderr)})"
            )
        raw_id = result.stdout if isinstance(result.stdout, str) else ""
        if not re.fullmatch(r"[0-9a-f]{64}\n?", raw_id):
            raise usb_recovery.DeviceError(f"{stage} container create returned invalid id")
        container_id = raw_id.rstrip("\n")
        if interrupted is not None:
            raise interrupted
        result = _run_process(
            ["docker", "start", "--attach", container_id],
            timeout=_remaining(deadline),
            text=text,
            stage=stage,
            _docker_lifecycle=False,
        )
        _remaining(deadline)
        return result
    finally:
        _cleanup_docker_container(container_id if container_id is not None else name)


def _run_esptool(
    arguments: list[str], device: SerialDevice, timeout: float,
    image: Path | None = None, *, output: Path | None = None,
    output_mount: Path | None = None,
) -> None:
    if resolve_esptool() == "host":
        command = [ESPTOOL, *arguments]
        result = _run_process(command, timeout=timeout, stage="esptool")
    else:
        result = _run_process(
            _docker_command(
                arguments, device, image, output=output, output_mount=output_mount,
            ),
            timeout=timeout, text=True, stage="esptool",
        )
    if result.returncode:
        raise usb_recovery.DeviceError(
            f"esptool failed (exit {result.returncode}; {_safe_error_class(result.stderr)})"
        )


def run_esptool(device: SerialDevice, timeout: float) -> None:
    """以固定 reset options 執行 esptool chip-id。"""
    device = _resolve_esptool_device(device, timeout)
    _run_esptool([
        "--chip", "esp32c3",
        "--port", device.by_id,
        "--before", "usb_reset",
        "--after", "hard_reset",
        "chip-id",
    ], device, timeout)


def _resolve_esptool_device(device: SerialDevice, timeout: float) -> SerialDevice:
    return _resolve_pinned_device(
        device.by_id, device.target, device.stable_identity,
        time.monotonic() + timeout,
    )


def _resolve_pinned_device(
    device_path: str, expected_target: str,
    stable_identity: tuple[str, ...] | None, deadline: float,
) -> SerialDevice:
    while True:
        try:
            fresh = resolve_serial_device(device_path)
        except DeviceIdentityError as exc:
            if not exc.retryable:
                raise usb_recovery.DeviceError("USB device identity is unavailable") from exc
            last_error = exc
        except SerialEndpointUnavailable as exc:
            last_error = exc
        except ValueError as exc:
            raise usb_recovery.DeviceError("USB device is unavailable") from exc
        else:
            if fresh.by_id != device_path:
                raise usb_recovery.DeviceError("device target changed")
            if stable_identity is None:
                if fresh.target != expected_target:
                    raise usb_recovery.DeviceError("device target changed")
            elif fresh.stable_identity != stable_identity:
                raise usb_recovery.DeviceError("USB device identity changed")
            return fresh
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise usb_recovery.DeviceError("USB device is unavailable") from last_error
        time.sleep(min(0.05, remaining))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class DeviceTransferError(ValueError):
    """固定且不洩漏敏感資料的 Web transfer 錯誤。"""


@dataclass(frozen=True)
class WebEndpoint:
    scheme: str
    hostname: str
    port: int


@dataclass(frozen=True)
class OtaPackage:
    manifest: str
    signature_hex: str
    firmware: bytes
    counter: int
    version: str
    package_sha256: str


@dataclass(frozen=True)
class WebResponse:
    status: int
    headers: dict[str, str]
    body: bytes


def _safe_web_error_class(error: BaseException) -> str:
    if isinstance(error, TimeoutError):
        return "timeout"
    if isinstance(error, ssl.SSLError):
        return "tls"
    if isinstance(error, http.client.HTTPException):
        return "protocol"
    if isinstance(error, (ConnectionError, OSError)):
        return "connect"
    return "external-error"


def _safe_web_stage(stage: object) -> str:
    if isinstance(stage, str) and stage in WEB_REQUEST_STAGES:
        return stage
    return "request"


def _parse_web_host(value: str) -> WebEndpoint:
    if not value or value != value.strip() or any(char in value for char in "\r\n"):
        raise DeviceTransferError("host is invalid")
    text = value if "://" in value else f"http://{value}"
    try:
        parsed = urllib.parse.urlsplit(text)
        hostname = parsed.hostname
        port = parsed.port
    except (ValueError, UnicodeError):
        raise DeviceTransferError("host is invalid") from None
    if parsed.scheme not in {"http", "https"} or not hostname or parsed.path not in {"", "/"} or parsed.query or parsed.fragment or parsed.username is not None or parsed.password is not None:
        raise DeviceTransferError("host is invalid")
    if any(char.isspace() for char in hostname) or any(char in hostname for char in "\r\n/"):
        raise DeviceTransferError("host is invalid")
    if port is None:
        port = 443 if parsed.scheme == "https" else 80
    if not 1 <= port <= 65535:
        raise DeviceTransferError("host is invalid")
    return WebEndpoint(parsed.scheme, hostname, port)


class WebClient:
    def __init__(self, host: str, user: str, password: str, timeout: float = WEB_REQUEST_TIMEOUT):
        self.endpoint = _parse_web_host(host)
        if not user or any(char in user for char in ":\r\n"):
            raise DeviceTransferError("user is invalid")
        if any(char in password for char in "\r\n"):
            raise DeviceTransferError("password is invalid")
        try:
            encoded = f"{user}:{password}".encode("utf-8")
        except UnicodeEncodeError:
            raise DeviceTransferError("credentials are invalid") from None
        self._authorization = "Basic " + base64.b64encode(encoded).decode("ascii")
        self.timeout = timeout

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
        max_bytes: int = 16384,
        stage: str = "Web request",
    ) -> WebResponse:
        if not path.startswith("/") or "\r" in path or "\n" in path:
            raise DeviceTransferError("request path is invalid")
        request_headers = {
            "Authorization": self._authorization,
            "Accept": "application/json",
            "Cache-Control": "no-store",
        }
        if headers:
            request_headers.update(headers)
        connection_type = http.client.HTTPSConnection if self.endpoint.scheme == "https" else http.client.HTTPConnection
        connection = None
        try:
            connection = connection_type(self.endpoint.hostname, self.endpoint.port, timeout=self.timeout)
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            payload = response.read(max_bytes + 1)
            if len(payload) > max_bytes:
                raise DeviceTransferError("HTTP response exceeded the bounded size")
            return WebResponse(
                response.status,
                {key.lower(): value for key, value in response.getheaders()},
                payload,
            )
        except DeviceTransferError:
            raise
        except (OSError, TimeoutError, http.client.HTTPException) as error:
            raise DeviceTransferError(
                f"{_safe_web_stage(stage)} failed ({_safe_web_error_class(error)})"
            ) from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass


def _reject_symlink_components_any(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor or "/")
    for part in absolute.parts[1:]:
        current /= part
        try:
            if current.is_symlink():
                raise DeviceTransferError("path must not contain symlinks")
        except OSError:
            raise DeviceTransferError("path is unavailable") from None


def _regular_file(path: Path, label: str, *, mode600: bool = False) -> Path:
    _reject_symlink_components_any(path)
    try:
        info = path.lstat()
    except OSError:
        raise DeviceTransferError(f"{label} is unavailable") from None
    if not stat.S_ISREG(info.st_mode):
        raise DeviceTransferError(f"{label} must be a regular file")
    if mode600 and stat.S_IMODE(info.st_mode) != 0o600:
        raise DeviceTransferError(f"{label} must use mode 600")
    return path


def _read_secret(env_name: str, file_value: str | None, label: str) -> str:
    if file_value:
        path = _regular_file(Path(file_value), label, mode600=True)
        try:
            if path.stat().st_size > 4096:
                raise DeviceTransferError(f"{label} is too large")
            data = path.read_bytes()
        except OSError:
            raise DeviceTransferError(f"{label} is unavailable") from None
        if data.endswith(b"\n"):
            data = data[:-1]
            if data.endswith(b"\r"):
                data = data[:-1]
        try:
            value = data.decode("utf-8")
        except UnicodeDecodeError:
            raise DeviceTransferError(f"{label} is invalid") from None
    else:
        value = os.environ.get(env_name)
        if value is None or value == "":
            raise DeviceTransferError(f"{env_name} or --{label.replace(' ', '-')} is required")
    if not value or any(char in value for char in "\r\n"):
        raise DeviceTransferError(f"{label} is invalid")
    return value


def _validate_passphrase(value: str) -> str:
    if not 12 <= len(value.encode("utf-8")) <= 128:
        raise DeviceTransferError("configuration passphrase is invalid")
    return value


def _json_object(response: WebResponse, stage: str, expected_status: int, *, check_status: bool = True) -> dict[str, object]:
    if check_status and response.status != expected_status:
        raise DeviceTransferError(f"{stage} returned unexpected HTTP status")
    try:
        value = json.loads(response.body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise DeviceTransferError(f"{stage} returned invalid JSON") from None
    if not isinstance(value, dict):
        raise DeviceTransferError(f"{stage} returned invalid JSON")
    return value


def _action(response: WebResponse, stage: str, expected_status: int) -> dict[str, object]:
    stage = _safe_web_stage(stage)
    error_status = response.status != expected_status
    if error_status and not 400 <= response.status <= 599:
        raise DeviceTransferError(f"{stage} returned unexpected HTTP status")
    try:
        value = _json_object(response, stage, expected_status, check_status=not error_status)
    except DeviceTransferError:
        if error_status:
            raise DeviceTransferError(f"{stage} returned unexpected HTTP status") from None
        raise
    if set(value) != {"success", "code", "data", "detail"} or not isinstance(value["success"], bool) or not isinstance(value["code"], str) or not isinstance(value["data"], dict) or not isinstance(value["detail"], str):
        if error_status:
            raise DeviceTransferError(f"{stage} returned unexpected HTTP status")
        raise DeviceTransferError(f"{stage} returned invalid action result")
    if error_status:
        if value["code"] not in WEB_ACTION_CODES:
            raise DeviceTransferError(f"{stage} returned HTTP {response.status}")
        raise DeviceTransferError(f"{stage} returned HTTP {response.status} ({value['code']})")
    return value


def _positive_int(value: object, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 < value <= 0xFFFFFFFF:
        raise DeviceTransferError(f"{label} is invalid")
    return value


def _csrf(client: WebClient) -> str:
    snapshot = _json_object(
        client.request("GET", "/api/config", max_bytes=16384, stage="config snapshot"),
        "config snapshot", 200,
    )
    token = snapshot.get("csrfToken")
    if not isinstance(token, str) or not 1 <= len(token.encode("utf-8")) < 40 or any(ord(char) < 0x20 or ord(char) > 0x7e for char in token):
        raise DeviceTransferError("config snapshot returned an invalid CSRF token")
    return token


def _post_form(client: WebClient, path: str, token: str, values: dict[str, object], stage: str, status: int) -> dict[str, object]:
    encoded = urllib.parse.urlencode({key: str(value) for key, value in values.items()}).encode("ascii")
    return _action(client.request("POST", path, body=encoded, headers={"X-CSRF-Token": token, "Content-Type": "application/x-www-form-urlencoded"}, max_bytes=4096, stage=stage), stage, status)


def _job(client: WebClient, job_id: int, token: str, timeout: float | None = None) -> dict[str, object]:
    timeout = JOB_TIMEOUT if timeout is None else timeout
    deadline = time.monotonic() + timeout
    while True:
        response = client.request("GET", f"/api/jobs?id={job_id}", headers={"X-CSRF-Token": token}, max_bytes=4096, stage="job status")
        value = _json_object(response, "job status", 200)
        if set(value) not in ({"id", "type", "state"}, {"id", "type", "state", "result"}):
            raise DeviceTransferError("job status is invalid")
        if value.get("id") != job_id or not isinstance(value.get("type"), str) or value.get("state") not in {"queued", "running", "succeeded", "failed"}:
            raise DeviceTransferError("job status is invalid")
        state = value["state"]
        if state in {"succeeded", "failed"}:
            result = value.get("result")
            if not isinstance(result, dict) or set(result) != {"success", "code", "data", "detail"} or not isinstance(result["success"], bool) or not isinstance(result["code"], str) or not isinstance(result["data"], dict) or not isinstance(result["detail"], str):
                raise DeviceTransferError("job result is invalid")
            return result
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise DeviceTransferError("job polling timed out")
        time.sleep(min(JOB_POLL_INTERVAL, remaining))


def _parse_ota_package(path: Path) -> OtaPackage:
    if path.suffix != ".smsota":
        raise DeviceTransferError("OTA package must use the .smsota suffix")
    _regular_file(path, "OTA package")
    try:
        size = path.stat().st_size
        if size <= len(OTA_MAGIC) + 4 + 2 or size > APP_MAX_SIZE + OTA_MAX_MANIFEST_BYTES + 2 + 72 + len(OTA_MAGIC) + 4:
            raise DeviceTransferError("OTA package size is invalid")
        package = path.read_bytes()
    except OSError:
        raise DeviceTransferError("OTA package is unavailable") from None
    if len(package) != size or not package.startswith(OTA_MAGIC):
        raise DeviceTransferError("OTA package is invalid")
    if len(package) < len(OTA_MAGIC) + 4:
        raise DeviceTransferError("OTA package is truncated")
    manifest_size = struct.unpack_from(">I", package, len(OTA_MAGIC))[0]
    manifest_start = len(OTA_MAGIC) + 4
    signature_size_offset = manifest_start + manifest_size
    if not 1 <= manifest_size <= OTA_MAX_MANIFEST_BYTES or signature_size_offset + 2 > len(package):
        raise DeviceTransferError("OTA manifest is invalid")
    try:
        manifest_bytes = package[manifest_start:signature_size_offset]
        manifest = manifest_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise DeviceTransferError("OTA manifest is invalid") from None
    signature_size = struct.unpack_from(">H", package, signature_size_offset)[0]
    firmware_start = signature_size_offset + 2 + signature_size
    if not 8 <= signature_size <= 72 or firmware_start > len(package):
        raise DeviceTransferError("OTA signature is invalid")
    signature = package[signature_size_offset + 2:firmware_start]
    firmware = package[firmware_start:]
    try:
        manifest_value = json.loads(manifest, parse_constant=lambda _value: (_ for _ in ()).throw(ValueError()))
    except (ValueError, json.JSONDecodeError):
        raise DeviceTransferError("OTA manifest is invalid") from None
    if not isinstance(manifest_value, dict) or set(manifest_value) != {"format", "releaseCounter", "sha256", "size", "target", "version"}:
        raise DeviceTransferError("OTA manifest is invalid")
    try:
        canonical = json.dumps(manifest_value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    except (TypeError, ValueError, UnicodeEncodeError):
        raise DeviceTransferError("OTA manifest is invalid") from None
    if canonical != manifest_bytes:
        raise DeviceTransferError("OTA manifest is not canonical")
    counter = manifest_value["releaseCounter"]
    image_size = manifest_value["size"]
    digest = manifest_value["sha256"]
    version = manifest_value["version"]
    if not isinstance(manifest_value["format"], int) or isinstance(manifest_value["format"], bool) or manifest_value["format"] != 1 or not isinstance(counter, int) or isinstance(counter, bool) or not 0 < counter <= 0xFFFFFFFF or not isinstance(image_size, int) or isinstance(image_size, bool) or not 0 < image_size <= APP_MAX_SIZE or manifest_value["target"] != "esp32c3" or not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or not isinstance(version, str) or not 0 < len(version) <= 32 or any(char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-" for char in version) or image_size != len(firmware) or hashlib.sha256(firmware).hexdigest() != digest:
        raise DeviceTransferError("OTA manifest does not match firmware")
    return OtaPackage(manifest, signature.hex(), firmware, counter, version, hashlib.sha256(package).hexdigest())


def _validate_config_backup(data: bytes) -> bytes:
    if not CONFIG_HEADER_BYTES + CONFIG_TAG_BYTES <= len(data) <= CONFIG_MAX_BYTES or len(data) < CONFIG_HEADER_BYTES or data[:8] != b"SMSCFG01":
        raise DeviceTransferError("configuration export is invalid")
    version, kdf, cipher, iterations = struct.unpack_from("<HBBI", data, 8)
    if (version, kdf, cipher, iterations) != (1, 1, 1, 210000):
        raise DeviceTransferError("configuration export header is invalid")
    return data


def _run_config_backup_verifier(path: Path, passphrase: str) -> dict[str, int]:
    try:
        verified_path = path.absolute()
        before = verified_path.stat(follow_symlinks=False)
    except OSError:
        raise DeviceTransferError("configuration backup verification failed") from None
    child_env = {
        key: value for key, value in os.environ.items()
        if not key.startswith("NODE_") and key not in {
            "SMS_CONFIG_PASSPHRASE", "SMS_WEB_PASSWORD",
        }
    }
    secret = bytearray(passphrase, "utf-8")
    try:
        result = subprocess.run(
            [NODE, str(CONFIG_BACKUP_VERIFIER), str(verified_path)],
            cwd=ROOT,
            env=child_env,
            input=secret,
            timeout=CONFIG_VERIFY_TIMEOUT,
            check=False,
            capture_output=True,
        )
    except (OSError, subprocess.SubprocessError, UnicodeError):
        raise DeviceTransferError("configuration backup verification failed") from None
    finally:
        secret[:] = b"\0" * len(secret)
    if result.returncode != 0 or result.stderr:
        raise DeviceTransferError("configuration backup verification failed")
    try:
        value = json.loads(result.stdout.decode("utf-8"))
        after = verified_path.stat(follow_symlinks=False)
    except (OSError, UnicodeDecodeError, json.JSONDecodeError):
        raise DeviceTransferError("configuration backup verification failed") from None
    if (before.st_dev, before.st_ino, before.st_size) != (
        after.st_dev, after.st_ino, after.st_size,
    ):
        raise DeviceTransferError("configuration backup changed during verification")
    size = after.st_size
    if (
        not isinstance(value, dict)
        or set(value) != {"bytes", "envelopeVersion", "schema", "generation"}
        or any(not isinstance(value[key], int) or isinstance(value[key], bool) for key in value)
        or value["bytes"] != size
        or value["envelopeVersion"] != 1
        or value["schema"] not in (6, 7)
        or value["generation"] != 0
    ):
        raise DeviceTransferError("configuration backup verification failed")
    return value


def _exclusive_atomic_write(path: Path, data: bytes, passphrase: str) -> dict[str, int]:
    _validate_output_target(path)
    temporary_name = None
    descriptor = -1
    identity = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(prefix=".smscfg-", dir=path.parent)
        temporary = Path(temporary_name)
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            descriptor = -1
            stream.write(data)
            stream.flush()
            created = os.fstat(stream.fileno())
        metadata = _run_config_backup_verifier(temporary, passphrase)
        current = temporary.lstat()
        identity = (created.st_dev, created.st_ino, created.st_size)
        if identity != (current.st_dev, current.st_ino, current.st_size):
            raise DeviceTransferError("temporary output changed during verification")
        os.link(temporary, path, follow_symlinks=False)
        final = path.lstat()
        if identity != (final.st_dev, final.st_ino, final.st_size):
            raise DeviceTransferError("published output changed during verification")
        temporary.unlink()
        temporary_name = None
        return metadata
    except FileExistsError:
        raise DeviceTransferError("output already exists") from None
    except OSError:
        raise DeviceTransferError("could not write output") from None
    finally:
        successful = sys.exc_info()[0] is None
        if not successful and identity is not None:
            try:
                final = path.lstat()
                if identity == (final.st_dev, final.st_ino, final.st_size):
                    path.unlink()
            except OSError:
                pass
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass
        if temporary_name:
            try:
                Path(temporary_name).unlink()
            except OSError:
                pass


def _validate_output_target(path: Path) -> None:
    _reject_symlink_components_any(path.parent)
    try:
        parent_info = path.parent.lstat()
    except OSError:
        raise DeviceTransferError("output parent is unavailable") from None
    if not stat.S_ISDIR(parent_info.st_mode) or path.parent.is_symlink():
        raise DeviceTransferError("output parent must be a regular directory")
    _reject_symlink_components_any(path)
    if path.exists() or path.is_symlink():
        raise DeviceTransferError("output already exists")


def _backup_command(args: argparse.Namespace) -> int:
    if bool(args.output) == bool(args.output_option):
        raise DeviceTransferError("one explicit output path is required")
    output = Path(args.output_option or args.output)
    _validate_output_target(output)
    if args.dry_run:
        print(json.dumps({"action": "backup-config", "host": args.host, "output": str(output), "live": False}, sort_keys=True))
        return 0
    passphrase = _validate_passphrase(_read_secret("SMS_CONFIG_PASSPHRASE", args.passphrase_file, "passphrase file"))
    password = _read_secret("SMS_WEB_PASSWORD", args.password_file, "password file")
    client = WebClient(args.host, args.user, password)
    token = _csrf(client)
    accepted = _post_form(client, "/api/config/export", token, {"passphrase": passphrase}, "config export", 202)
    if accepted["success"] is not True:
        raise DeviceTransferError("configuration export was rejected")
    job_id = _positive_int(accepted["data"].get("jobId"), "export job id")
    result = _job(client, job_id, token)
    if result["success"] is not True:
        raise DeviceTransferError("configuration export job failed")
    export_id = _positive_int(result["data"].get("exportId"), "export id")
    downloaded = client.request("GET", f"/api/config/export?id={export_id}", headers={"X-CSRF-Token": token, "Accept": "application/vnd.sms-forwarding.config"}, max_bytes=CONFIG_MAX_BYTES, stage="configuration download")
    if downloaded.status != 200 or downloaded.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/vnd.sms-forwarding.config":
        raise DeviceTransferError("configuration download returned an unexpected response")
    _exclusive_atomic_write(output, _validate_config_backup(downloaded.body), passphrase)
    print(json.dumps({"action": "backup-config", "host": args.host, "output": str(output), "bytes": len(downloaded.body), "live": True}, sort_keys=True))
    return 0


def _verify_backup_command(args: argparse.Namespace) -> int:
    backup = _regular_file(Path(args.backup), "configuration backup")
    passphrase = _validate_passphrase(
        _read_secret("SMS_CONFIG_PASSPHRASE", args.passphrase_file, "passphrase file")
    )
    print(json.dumps(_run_config_backup_verifier(backup, passphrase), sort_keys=True))
    return 0


def _ota_upload_command(args: argparse.Namespace) -> int:
    if bool(args.package) == bool(args.package_option):
        raise DeviceTransferError("one OTA package path is required")
    package = _parse_ota_package(Path(args.package_option or args.package))
    plan = {"action": "ota-upload", "host": args.host, "counter": package.counter, "version": package.version, "size": len(package.firmware), "package_sha256": package.package_sha256, "live": bool(args.live)}
    if not args.live:
        print(json.dumps(plan, sort_keys=True))
        return 0
    if args.confirm_host != args.host:
        raise DeviceTransferError("--confirm-host must exactly match --host")
    password = _read_secret("SMS_WEB_PASSWORD", args.password_file, "password file")
    client = WebClient(args.host, args.user, password)
    token = _csrf(client)
    accepted = _post_form(client, "/api/ota/start", token, {"manifest": package.manifest, "signature": package.signature_hex}, "OTA start", 201)
    if accepted["success"] is not True or accepted["code"] != "ACTION_OTA_UPLOAD_STARTED":
        raise DeviceTransferError("OTA start was rejected")
    data = accepted["data"]
    upload_id = _positive_int(data.get("uploadId"), "OTA upload id")
    if data.get("chunkSize") != OTA_CHUNK_BYTES or data.get("nextOffset") != 0:
        raise DeviceTransferError("OTA start returned invalid transfer bounds")
    offset = 0
    while offset < len(package.firmware):
        chunk = package.firmware[offset:offset + OTA_CHUNK_BYTES]
        encoded = base64.b64encode(chunk)
        result = _action(client.request("POST", f"/api/ota/chunk?id={upload_id}&offset={offset}", body=encoded, headers={"X-CSRF-Token": token, "Content-Type": "text/plain"}, max_bytes=4096, stage="OTA chunk"), "OTA chunk", 200)
        if result["success"] is not True or result["code"] != "ACTION_OTA_CHUNK_OK" or result["data"].get("nextOffset") != offset + len(chunk):
            raise DeviceTransferError("OTA chunk was rejected")
        offset += len(chunk)
    finished = _post_form(client, f"/api/ota/finish?id={upload_id}", token, {}, "OTA finish", 202)
    if finished["success"] is not True:
        raise DeviceTransferError("OTA finish was rejected")
    job_id = _positive_int(finished["data"].get("jobId"), "OTA job id")
    result = _job(client, job_id, token)
    if result["success"] is not True or result["code"] != "ACTION_OTA_READY":
        if result["code"] not in OTA_ACTION_CODES:
            raise DeviceTransferError("OTA validation failed")
        raise DeviceTransferError(f"OTA validation failed ({result['code']})")
    plan["code"] = "ACTION_OTA_READY"
    print(json.dumps(plan, sort_keys=True))
    return 0


def _run_ota_key_command(command: list[str], stage: str) -> subprocess.CompletedProcess[bytes]:
    try:
        result = subprocess.run(command, cwd=ROOT, capture_output=True, check=False)
    except (FileNotFoundError, OSError) as exc:
        raise usb_recovery.DeviceError(f"{stage} unavailable") from exc
    if result.returncode:
        raise usb_recovery.DeviceError(f"{stage} failed")
    return result


def _ota_test_profile_root() -> Path:
    expected = ROOT / "build" / "idf-ota-test"
    profile = OTA_TEST_PROFILE_DIR
    if profile.absolute() != expected.absolute():
        raise usb_recovery.DeviceError("OTA test profile must use build/idf-ota-test")
    build_root = ROOT / "build"
    if build_root.is_symlink() or (build_root.exists() and not build_root.is_dir()):
        raise usb_recovery.DeviceError("OTA test profile base must be a regular directory")
    if profile.is_symlink():
        raise usb_recovery.DeviceError("OTA test profile directory must not be a symlink")
    profile.mkdir(parents=True, exist_ok=True)
    if profile.is_symlink():
        raise usb_recovery.DeviceError("OTA test profile directory must not be a symlink")
    if not profile.is_dir():
        raise usb_recovery.DeviceError("OTA test profile must be a regular directory")
    return profile.resolve(strict=True)


def _validate_ota_test_material(path: Path, label: str, *, required: bool) -> Path:
    profile = _ota_test_profile_root()
    candidate = path if path.is_absolute() else ROOT / path
    if candidate.is_symlink():
        raise usb_recovery.DeviceError(f"{label} must not be a symlink")
    if candidate.exists() and not candidate.is_file():
        raise usb_recovery.DeviceError(f"{label} must be a regular file")
    try:
        resolved = candidate.resolve(strict=required)
    except FileNotFoundError as exc:
        raise usb_recovery.DeviceError(f"{label} is unavailable") from exc
    try:
        resolved.relative_to(profile)
    except ValueError as exc:
        raise usb_recovery.DeviceError(
            f"{label} must stay inside build/idf-ota-test"
        ) from exc
    if required and not candidate.is_file():
        raise usb_recovery.DeviceError(f"{label} must be a regular file")
    return candidate


def _ensure_ota_test_keypair() -> tuple[Path, Path, str]:
    _ota_test_profile_root()
    private_key = _validate_ota_test_material(
        OTA_TEST_PRIVATE_KEY, "OTA test private key", required=False
    )
    if not private_key.exists():
        temporary = _validate_ota_test_material(
            private_key.with_suffix(".tmp"), "OTA test private key temporary", required=False
        )
        if temporary.exists():
            temporary.unlink()
        _run_ota_key_command([
            "openssl", "genpkey", "-algorithm", "EC",
            "-pkeyopt", "ec_paramgen_curve:P-256", "-out", str(temporary),
        ], "OTA test key generation")
        temporary.chmod(0o600)
        temporary.replace(private_key)
    private_key = _validate_ota_test_material(
        private_key, "OTA test private key", required=True
    )
    private_key.chmod(0o600)
    derived = _run_ota_key_command([
        "openssl", "pkey", "-in", str(private_key),
        "-pubout", "-outform", "DER",
    ], "OTA test public key derivation")
    if not derived.stdout:
        raise usb_recovery.DeviceError("OTA test public key derivation returned no key")
    public_der = _validate_ota_test_material(
        OTA_TEST_PUBLIC_DER, "OTA test public DER", required=False
    )
    public_key = _validate_ota_test_material(
        OTA_TEST_PUBLIC_KEY, "OTA test public key", required=False
    )
    public_der.write_bytes(derived.stdout)
    public_key.write_text(
        base64.b64encode(derived.stdout).decode("ascii") + "\n", encoding="ascii"
    )
    return private_key, public_key, hashlib.sha256(derived.stdout).hexdigest()


def _ota_test_build_environment(public_key: Path, *, fail_health: bool = False) -> dict[str, str]:
    public_key = _validate_ota_test_material(public_key, "OTA test public key", required=True)
    env = os.environ.copy()
    env.update({
        "SMS_USB_RECOVERY": "1",
        "SMS_OTA_TEST_KEY": "1",
        "SMS_OTA_TEST_PUBLIC_KEY": str(public_key),
        "SMS_OTA_TEST_FAIL_HEALTH": "1" if fail_health else "0",
        "FIRMWARE_IS_RELEASE": "0",
    })
    return env


def _ota_test_build_dir(*, fail_health: bool) -> Path:
    _ota_test_profile_root()
    profile = ROOT / "build" / (
        "idf-ota-test-fail-health" if fail_health else "idf-ota-test"
    )
    if profile.is_symlink():
        raise usb_recovery.DeviceError("OTA test build directory must not be a symlink")
    if profile.exists() and not profile.is_dir():
        raise usb_recovery.DeviceError("OTA test build directory must be a directory")
    profile.mkdir(parents=True, exist_ok=True)
    return profile.resolve(strict=True)


def resolve_ota_test_image(path: Path, *, fail_health: bool = False) -> Path:
    candidate = path if path.is_absolute() else ROOT / path
    _reject_symlink_components(candidate)
    if candidate.is_symlink():
        raise ValueError("OTA test image must not be a symlink")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"OTA test image does not exist: {candidate}") from exc
    expected = ROOT / "build" / (
        "idf-ota-test-fail-health" if fail_health else "idf-ota-test"
    ) / "sms_forwarding_idf.bin"
    if resolved != expected.resolve():
        raise ValueError("OTA test image must be the OTA test build artifact")
    if not _is_regular_file(candidate):
        raise ValueError("OTA test image must be a regular file")
    return resolved


def resolve_ota_test_output(path: Path) -> Path:
    candidate = path if path.is_absolute() else ROOT / path
    try:
        relative = candidate.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise ValueError("OTA test package output must stay inside the repository") from exc
    if not relative.parts or relative.parts[0] not in {"build", "dist"}:
        raise ValueError("OTA test package output must stay in build/ or dist/")
    if candidate.suffix != ".smsota":
        raise ValueError("OTA test package output must use the .smsota suffix")
    if candidate.exists() and candidate.is_symlink():
        raise ValueError("OTA test package output must not be a symlink")
    candidate.parent.mkdir(parents=True, exist_ok=True)
    return candidate


def _is_regular_file(path: Path) -> bool:
    try:
        return stat.S_ISREG(path.lstat().st_mode)
    except OSError:
        return False


def _reject_symlink_components(path: Path) -> None:
    root = ROOT.absolute()
    candidate = path.absolute()
    try:
        relative = candidate.relative_to(root)
    except ValueError as exc:
        raise ValueError("app image must stay inside the repository") from exc
    current = root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            raise ValueError("app image must not use symlinked paths")


def _ota_test_profile_cache_is_verified(profile: Path) -> bool:
    cache = profile / "CMakeCache.txt"
    if cache.is_symlink() or not _is_regular_file(cache):
        return False
    expected = {
        "FIRMWARE_IS_RELEASE": "0",
        "SMS_USB_RECOVERY": "1",
        "SMS_OTA_TEST_KEY": "1",
    }
    found: dict[str, str] = {}
    try:
        lines = cache.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError):
        return False
    for line in lines:
        for key in expected:
            prefix = f"{key}:"
            if line.startswith(prefix) and "=" in line:
                value = line.split("=", 1)[1]
                if key in found and found[key] != value:
                    return False
                found[key] = value
    return found == expected


def resolve_app_image(path: Path) -> Path:
    candidate = path if path.is_absolute() else ROOT / path
    _reject_symlink_components(candidate)
    if candidate.is_symlink() or not _is_regular_file(candidate):
        raise ValueError("app image must be a regular file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"app image does not exist: {candidate}") from exc
    allowed = {(ROOT / relative).resolve() for relative in APP_IMAGE_RELATIVE_PATHS[:2]}
    ota_test_image = ROOT / "build" / "idf-ota-test" / "sms_forwarding_idf.bin"
    if resolved == ota_test_image.resolve():
        profile = ota_test_image.parent
        if not _ota_test_profile_cache_is_verified(profile):
            raise ValueError("OTA test image requires a verified dev profile cache")
    elif resolved not in allowed:
        raise ValueError("app image must be the repository app0 build artifact")
    return resolved


def validate_app0_image(path: Path) -> int:
    resolved = resolve_app_image(path)
    size = resolved.stat().st_size
    if not 0 < size <= APP_MAX_SIZE:
        raise ValueError(f"app image must be 1..{APP_MAX_SIZE} bytes")
    return size


def resolve_bootloader_image(path: Path) -> Path:
    candidate = path if path.is_absolute() else ROOT / path
    _reject_symlink_components(candidate)
    if candidate.is_symlink() or not _is_regular_file(candidate):
        raise ValueError("bootloader image must be a regular file")
    try:
        resolved = candidate.resolve(strict=True)
    except FileNotFoundError as exc:
        raise ValueError(f"bootloader image does not exist: {candidate}") from exc
    allowed = {(ROOT / relative).resolve() for relative in BOOTLOADER_IMAGE_RELATIVE_PATHS}
    if resolved not in allowed:
        raise ValueError("bootloader image must be a repository ESP-IDF build artifact")
    return resolved


def validate_bootloader_image(path: Path) -> int:
    resolved = resolve_bootloader_image(path)
    size = resolved.stat().st_size
    if not 0 < size <= BOOTLOADER_MAX_SIZE:
        raise ValueError(f"bootloader image must be 1..{BOOTLOADER_MAX_SIZE} bytes")
    return size


def confirm_basename(device: str, supplied: str | None = None) -> None:
    expected = Path(device).name
    if supplied is None:
        try:
            supplied = input(f"Type device basename '{expected}' to continue: ")
        except (EOFError, KeyboardInterrupt) as exc:
            raise ValueError("exact device basename confirmation is required") from exc
    if supplied != expected:
        raise ValueError("device basename confirmation did not match")


def _host_transport_unavailable(error: BaseException) -> bool:
    if os.environ.get("SMS_DEVICE_IN_CONTAINER") == "1":
        return False
    if isinstance(error, (ImportError, OSError)):
        return True
    text = str(error).lower()
    return "eacces" in text or "permission" in text or "could not claim usb device" in text


def _container_recovery(
    device: SerialDevice, timeout: float, query: str | None = None,
    *, caller_timeout: float | None = None, deadline: float | None = None,
    command: int = usb_recovery.COMMAND_STATE,
    legacy_ota_state: bool = False,
) -> bytes | dict[str, object] | usb_recovery.Frame:
    if deadline is not None and caller_timeout is None:
        caller_timeout = _remaining(deadline)
    if caller_timeout is not None:
        timeout = min(timeout, caller_timeout)
    ota_command = query is None and command in {
        usb_recovery.COMMAND_OTA_STATE,
        usb_recovery.COMMAND_OTA_MIGRATION_RECOVER,
    }
    process_budget = CONTAINER_LIFECYCLE_TIMEOUT
    process_timeout = min(process_budget, timeout if caller_timeout is None else caller_timeout)
    if deadline is not None:
        process_timeout = min(process_timeout, _remaining(deadline))
        timeout = min(timeout, process_timeout)
    backend_timeout = min(CONTAINER_TIMEOUT, process_timeout) if ota_command else timeout
    arguments = [
        "/workspace/tools/usb_recovery.py", "--device", CONTAINER_DEVICE_PATH,
        "--timeout", str(backend_timeout), "--internal-container",
    ]
    if query is None:
        if command == usb_recovery.COMMAND_STATE:
            arguments.append("state")
        elif command == usb_recovery.COMMAND_OTA_STATE:
            arguments.append("ota-state")
            if legacy_ota_state:
                arguments.append("--legacy")
        elif command == usb_recovery.COMMAND_OTA_MIGRATION_RECOVER:
            arguments.append("ota-migration-recover")
        else:
            raise ValueError("unsupported USB recovery command")
    else:
        arguments.extend(("query", query, "--raw"))
    result = _run_process(
        _docker_command(arguments, device, program=None, entrypoint=CONTAINER_PYTHON),
        timeout=process_timeout, text=query is not None, stage="USB recovery",
    )
    if result.returncode:
        status, reason_payload = usb_recovery.parse_protocol_error(result.stderr)
        if status is not None:
            raise usb_recovery.CommandError(status, reason_payload)
        error_class = _safe_error_class(result.stderr)
        raise usb_recovery.DeviceError(
            f"USB recovery failed (exit {result.returncode}; {error_class})"
        )
    if query is not None:
        output = result.stdout
        payload = output if isinstance(output, bytes) else output.encode() if isinstance(output, str) else b""
        if not payload.strip():
            raise usb_recovery.DeviceError("USB recovery returned empty query response")
        query_id = usb_recovery.QUERY_COMMANDS[query][0]
        payload, msslcipher_telemetry = usb_recovery._decode_query_payload(query_id, payload)
        if query_id == usb_recovery.QUERY_MSSLCIPHER:
            return usb_recovery.Frame(
                usb_recovery.RESPONSE_MODEM_QUERY,
                0,
                payload,
                bool(msslcipher_telemetry & usb_recovery.MSSLCIPHER_TELEMETRY_OTHER_LINE_PRESENT),
                msslcipher_telemetry,
            )
        return payload
    try:
        output = result.stdout.decode("utf-8") if isinstance(result.stdout, bytes) else result.stdout
        return json.loads(output)
    except (TypeError, ValueError, UnicodeError) as exc:
        raise usb_recovery.DeviceError("USB recovery returned invalid state") from exc


def _safe_batch_value(value: object, depth: int = 0) -> bool:
    if depth > _MAX_BATCH_NESTING:
        return False
    if isinstance(value, dict):
        return all(
            isinstance(key, str)
            and key in _BATCH_ALLOWED_KEYS
            and _safe_batch_value(item, depth + 1)
            for key, item in value.items()
        )
    if isinstance(value, list):
        return all(_safe_batch_value(item, depth + 1) for item in value)
    if isinstance(value, str):
        return len(value) <= usb_recovery.MAX_QUERY_RESPONSE and all(
            0x20 <= ord(char) <= 0x7E for char in value
        )
    return value is None or isinstance(value, bool) or isinstance(value, int)


def _safe_batch_hash(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _safe_batch_ascii(value: object, maximum: int) -> bool:
    return (
        isinstance(value, str)
        and len(value) <= maximum
        and all(0x20 <= ord(char) <= 0x7E for char in value)
    )


def _safe_batch_result(name: str, result: dict[str, object]) -> bool:
    common = {"query_id", "valid"}
    query_id = usb_recovery.QUERY_COMMANDS[name][0]
    if result.get("query_id") != query_id or not _safe_batch_value(result):
        return False
    if result.get("valid") is False:
        if name == "msslcipher":
            if result.get("error") == "unavailable":
                return set(result) == common | {"error"}
            telemetry = {
                "other_line_present", "line_overflow", "contains_msslcipher_token",
                "contains_exact_official_prefix_anywhere",
                "leading_whitespace_before_prefix", "parentheses_present", "comma_present",
            }
            old_shape = common | {"error", "other_line_present"}
            new_shape = common | {"error"} | telemetry
            if set(result) == old_shape:
                return (
                    result.get("error") in {"invalid-response", "unavailable"}
                    and isinstance(result["other_line_present"], bool)
                )
            return (
                set(result) == new_shape
                and result.get("error") in {"invalid-response", "unavailable"}
                and all(isinstance(result[key], bool) for key in telemetry)
            )
        return (
            set(result) == common | {"error"}
            and result.get("error") in {"invalid-response", "unavailable"}
        )
    if result.get("valid") is not True:
        return False
    if name == "ati":
        if set(result) != common | {"model", "firmware"}:
            return False
        model = result["model"]
        if model is not None and (
            not isinstance(model, str)
            or not 3 <= len(model) <= 32
            or not model[0].isupper()
            or not any(char.isdigit() for char in model)
            or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-" for char in model)
        ):
            return False
        firmware = result["firmware"]
        return firmware is None or (
            _safe_batch_ascii(firmware, 64)
            and (
                firmware.startswith(("Revision: ", "Firmware: ", "Version: "))
                or re.fullmatch(r"[A-Z][A-Z0-9._-]{2,63}", firmware) is not None
                or "<redacted>" in firmware
            )
        )
    if name == "cpin":
        return set(result) == common | {"state"} and result["state"] in {
            "ready", "sim-pin", "sim-puk", "ph-net-pin",
        }
    if name == "cops":
        if set(result) != common | {"mode", "format", "act", "operator"}:
            return False
        if result["mode"] not in {
            "automatic", "manual", "deregistered", "set-only", "manual-auto",
        } or result["format"] not in {None, "long", "short", "numeric"} or result["act"] not in {
            None, "gsm", "gsm-compact", "utran", "gsm-egprs", "utran-hsdpa",
            "utran-hsupa", "utran-hsdpa-hsupa", "e-utran",
        }:
            return False
        operator = result["operator"]
        if not isinstance(operator, dict) or not isinstance(operator.get("present"), bool):
            return False
        if not operator["present"]:
            return set(operator) == {"present"}
        return (
            set(operator) == {"present", "length", "sha256"}
            and isinstance(operator["length"], int)
            and not isinstance(operator["length"], bool)
            and 1 <= operator["length"] <= 32
            and _safe_batch_hash(operator["sha256"])
        )
    if name == "cgatt":
        return set(result) == common | {"attached"} and isinstance(result["attached"], bool)
    if name == "cgact":
        if set(result) != common | {"entry_count", "entries"}:
            return False
        entries = result["entries"]
        if (
            not isinstance(result["entry_count"], int)
            or isinstance(result["entry_count"], bool)
            or not 1 <= result["entry_count"] <= 16
            or not isinstance(entries, list)
            or result["entry_count"] != len(entries)
        ):
            return False
        seen: set[int] = set()
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"cid", "active"}
                or not isinstance(entry["cid"], int)
                or isinstance(entry["cid"], bool)
                or not 0 <= entry["cid"] <= 255
                or entry["cid"] in seen
                or not isinstance(entry["active"], bool)
            ):
                return False
            seen.add(entry["cid"])
        return True
    if name == "cgpaddr":
        if set(result) != common | {"entry_count", "entries"}:
            return False
        entries = result["entries"]
        if (
            not isinstance(result["entry_count"], int)
            or isinstance(result["entry_count"], bool)
            or not 0 <= result["entry_count"] <= 16
            or not isinstance(entries, list)
            or result["entry_count"] != len(entries)
        ):
            return False
        seen: set[int] = set()
        for entry in entries:
            if (
                not isinstance(entry, dict)
                or set(entry) != {"cid", "address_count", "ipv4", "ipv6"}
                or not isinstance(entry["cid"], int)
                or isinstance(entry["cid"], bool)
                or not 1 <= entry["cid"] <= 255
                or entry["cid"] in seen
                or not isinstance(entry["address_count"], int)
                or isinstance(entry["address_count"], bool)
                or not isinstance(entry["ipv4"], bool)
                or not isinstance(entry["ipv6"], bool)
                or entry["address_count"] != entry["ipv4"] + entry["ipv6"]
                or not 0 <= entry["address_count"] <= 2
            ):
                return False
            seen.add(entry["cid"])
        return True
    if name == "ceer":
        return set(result) == common | {"last_error"} and result["last_error"] == {
            "present": False,
        }
    if name == "csq":
        return (
            set(result) == common | {"rssi", "ber", "unknown"}
            and (result["rssi"] is None or (
                isinstance(result["rssi"], int)
                and not isinstance(result["rssi"], bool)
                and 0 <= result["rssi"] <= 31
            ))
            and (result["ber"] is None or (
                isinstance(result["ber"], int)
                and not isinstance(result["ber"], bool)
                and 0 <= result["ber"] <= 7
            ))
            and isinstance(result["unknown"], dict)
            and set(result["unknown"]) == {"rssi", "ber"}
            and all(isinstance(value, bool) for value in result["unknown"].values())
            and result["unknown"]["rssi"] == (result["rssi"] is None)
            and result["unknown"]["ber"] == (result["ber"] is None)
        )
    if name == "cesq":
        ranges = {"rxlev": (0, 63), "ber": (0, 7), "rscp": (0, 96),
                  "ecn0": (0, 49), "rsrq": (0, 34), "rsrp": (0, 97)}
        expected = common | set(ranges) | {"unknown"}
        if set(result) != expected or not isinstance(result["unknown"], dict):
            return False
        if set(result["unknown"]) != set(ranges) or not all(
            isinstance(value, bool) for value in result["unknown"].values()
        ):
            return False
        for field, (low, high) in ranges.items():
            value = result[field]
            if value is None:
                if result["unknown"][field] is not True:
                    return False
            elif (
                not isinstance(value, int)
                or isinstance(value, bool)
                or not low <= value <= high
                or result["unknown"][field] is not False
            ):
                return False
        return True
    if name == "cfun":
        return (
            set(result) == common | {"mode"}
            and isinstance(result["mode"], int)
            and not isinstance(result["mode"], bool)
            and 0 <= result["mode"] <= 4
        )
    if name == "iccid":
        if result.get("present") is False:
            return set(result) == common | {"present", "length"} and result["length"] == 0
        if set(result) != common | {"present", "length", "sha256"}:
            return False
        return (
            result["present"] is True
            and isinstance(result["length"], int)
            and not isinstance(result["length"], bool)
            and 15 <= result["length"] <= 32
            and _safe_batch_hash(result["sha256"])
        )
    if name == "cimi":
        if not {"present", "length"}.issubset(result):
            return False
        if result["present"] is False:
            return set(result) == common | {"present", "length"} and result["length"] == 0
        return (
            set(result) == common | {"present", "length", "sha256", "mcc"}
            and result["present"] is True
            and isinstance(result["length"], int)
            and not isinstance(result["length"], bool)
            and 14 <= result["length"] <= 16
            and _safe_batch_hash(result["sha256"])
            and isinstance(result["mcc"], str)
            and len(result["mcc"]) == 3
            and all("0" <= char <= "9" for char in result["mcc"])
        )
    if name == "cpol":
        return (
            set(result) == common | {
                "raw_length", "record_count", "format_bitmap", "format_counts",
                "rat_complete", "rat_counts", "malformed_count", "parse_failed",
            }
            and all(
                isinstance(result[field], int) and not isinstance(result[field], bool)
                and 0 <= result[field] <= 8192
                for field in ("raw_length", "record_count", "format_bitmap", "malformed_count")
            )
            and isinstance(result["rat_complete"], bool)
            and isinstance(result["parse_failed"], bool)
            and isinstance(result["format_counts"], dict)
            and set(result["format_counts"]) == {"0", "1", "2"}
            and all(isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 8192
                    for value in result["format_counts"].values())
            and isinstance(result["rat_counts"], dict)
            and set(result["rat_counts"]) == {"0", "1", "2", "3"}
            and all(isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 8192
                    for value in result["rat_counts"].values())
        )
    if name == "msslcipher":
        base = common | {
            "supported", "count", "count_bucket", "unknown_present", "other_line_present",
        }
        telemetry = {
            "line_overflow", "contains_msslcipher_token",
            "contains_exact_official_prefix_anywhere",
            "leading_whitespace_before_prefix", "parentheses_present", "comma_present",
        }
        if set(result) != base and set(result) != base | telemetry:
            return False
        supported = result["supported"]
        count = result["count"]
        valid = (
            isinstance(supported, dict)
            and set(supported) == {"c02b", "c02c", "c02f", "c030"}
            and all(isinstance(value, bool) for value in supported.values())
            and isinstance(count, int)
            and not isinstance(count, bool)
            and 0 < count <= usb_recovery.MSSLCIPHER_SUMMARY_MAX_COUNT
            and result["count_bucket"] == usb_recovery.msslcipher_count_bucket(count)
            and result["count_bucket"] in usb_recovery.MSSLCIPHER_COUNT_BUCKETS
            and isinstance(result["unknown_present"], bool)
            and isinstance(result["other_line_present"], bool)
        )
        return valid and (
            set(result) == base
            or all(isinstance(result[key], bool) for key in telemetry)
        )
    if name == "cgdcont":
        if set(result) != common | {"entry_count", "entries"}:
            return False
        entries = result["entries"]
        if not isinstance(result["entry_count"], int) or isinstance(result["entry_count"], bool):
            return False
        if not isinstance(entries, list) or result["entry_count"] != len(entries):
            return False
        for entry in entries:
            if not isinstance(entry, dict) or set(entry) != {
                "cid", "pdp_type", "apn", "address", "safe_flags",
            }:
                return False
            if (
                not isinstance(entry["cid"], int)
                or isinstance(entry["cid"], bool)
                or not 0 <= entry["cid"] <= 255
                or not isinstance(entry["pdp_type"], str)
                or not 1 <= len(entry["pdp_type"]) <= 16
                or not entry["pdp_type"][0].isalnum()
                or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789._-"
                       for char in entry["pdp_type"])
            ):
                return False
            for field in ("apn", "address"):
                value = entry[field]
                if not isinstance(value, dict) or set(value) - {"present", "sha256"}:
                    return False
                if not isinstance(value.get("present"), bool):
                    return False
                if value["present"] != ("sha256" in value) or (
                    value.get("present") and not _safe_batch_hash(value.get("sha256"))
                ):
                    return False
            flags = entry["safe_flags"]
            if flags != {
                "apn_hashed": entry["apn"]["present"],
                "address_hashed": entry["address"]["present"],
            }:
                return False
        return True
    if name in {"cereg", "creg", "cgreg"}:
        expected = common | {
            "line_count", "field_count", "mode", "stat", "act", "cause_flags",
            "home", "roaming", "registered", "location",
        }
        if set(result) != expected:
            return False
        if (
            not isinstance(result["line_count"], int)
            or isinstance(result["line_count"], bool)
            or result["line_count"] != 1
            or not isinstance(result["field_count"], int)
            or isinstance(result["field_count"], bool)
            or result["field_count"] not in (2, 5)
            or not isinstance(result["mode"], str)
            or result["mode"] not in {"disabled", "status", "location"}
            or not isinstance(result["stat"], str)
            or result["stat"] not in {
                "not-registered", "registered-home", "searching",
                "registration-denied", "unknown", "registered-roaming", "rlos-only",
            }
            or not all(isinstance(result[field], bool) for field in
                       ("home", "roaming", "registered"))
            or result["home"] != (result["stat"] == "registered-home")
            or result["roaming"] != (result["stat"] == "registered-roaming")
            or result["registered"] != (result["home"] or result["roaming"])
            or result["cause_flags"] != {"present": False}
        ):
            return False
        if result["field_count"] == 2:
            return (
                result["mode"] in {"disabled", "status"}
                and result["act"] is None
                and result["location"] == {"present": False}
            )
        if result["mode"] != "location" or result["act"] != "e-utran":
            return False
        location = result["location"]
        if (
            not isinstance(location, dict)
            or set(location) != {"present", "fields"}
            or location["present"] is not True
            or not isinstance(location["fields"], list)
            or len(location["fields"]) != 2
        ):
            return False
        for field, length in zip(location["fields"], (4, 8), strict=True):
            if (
                not isinstance(field, dict)
                or set(field) != {"present", "length", "sha256"}
                or field["present"] is not True
                or field["length"] != length
                or not _safe_batch_hash(field["sha256"])
            ):
                return False
        return True
    if set(result) != common | {"line_count", "sha256", "redactions"}:
        return False
    redactions = result["redactions"]
    return (
        isinstance(result["line_count"], int)
        and not isinstance(result["line_count"], bool)
        and 1 <= result["line_count"] <= 96
        and _safe_batch_hash(result["sha256"])
        and isinstance(redactions, list)
        and all(
            isinstance(item, dict)
            and set(item) == {"length", "sha256"}
            and isinstance(item["length"], int)
            and not isinstance(item["length"], bool)
            and 1 <= item["length"] <= 96
            and _safe_batch_hash(item["sha256"])
            for item in redactions
        )
    )


def _decode_container_batch(output: str | bytes | None, names: tuple[str, ...]) -> dict[str, object]:
    if isinstance(output, bytes):
        try:
            output = output.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise usb_recovery.DeviceError("USB recovery returned invalid batch text") from exc
    if not isinstance(output, str) or not output.strip():
        raise usb_recovery.DeviceError("USB recovery returned empty batch response")
    if len(output.encode("utf-8")) > 16 * 1024:
        raise usb_recovery.DeviceError("USB recovery returned oversized batch response")
    try:
        envelope = json.loads(output)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise usb_recovery.DeviceError("USB recovery returned invalid batch response") from exc
    if (
        not isinstance(envelope, dict)
        or set(envelope) != {"version", "results"}
        or envelope.get("version") != 1
    ):
        raise usb_recovery.DeviceError("USB recovery returned invalid batch response")
    results = envelope.get("results")
    if not isinstance(results, dict) or set(results) != set(names):
        raise usb_recovery.DeviceError("USB recovery returned incomplete batch response")
    checked: dict[str, object] = {}
    for name in names:
        result = results.get(name)
        query_id = usb_recovery.QUERY_COMMANDS[name][0]
        if (
            not isinstance(result, dict)
            or result.get("query_id") != query_id
            or not _safe_batch_result(name, result)
        ):
            raise usb_recovery.DeviceError("USB recovery returned invalid batch response")
        checked[name] = result
    return checked


def _container_recovery_batch(
    device: SerialDevice, names: tuple[str, ...] | list[str], *, deadline: float,
) -> dict[str, object]:
    names = tuple(names)
    if not names or len(names) != len(set(names)) or any(name not in QUERY_NAMES for name in names):
        raise usb_recovery.DeviceError("USB recovery batch query IDs are invalid")
    process_timeout = min(DIAG_ALL_TIMEOUT, _remaining(deadline))
    arguments = [
        "/workspace/tools/usb_recovery.py", "--device", CONTAINER_DEVICE_PATH,
        "--timeout", str(process_timeout), "--internal-container", "diag-batch", *names,
    ]
    result = _run_process(
        _docker_command(arguments, device, program=None, entrypoint=CONTAINER_PYTHON),
        timeout=process_timeout, text=True, stage="USB recovery",
    )
    if result.returncode:
        status, reason_payload = usb_recovery.parse_protocol_error(result.stderr)
        if status is not None:
            raise usb_recovery.CommandError(status, reason_payload)
        raise usb_recovery.DeviceError(
            f"USB recovery failed (exit {result.returncode}; {_safe_error_class(result.stderr)})"
        )
    return _decode_container_batch(result.stdout, names)


def _state(
    device: SerialDevice, timeout: float = STATE_TIMEOUT, *,
    container_timeout: float = CONTAINER_LIFECYCLE_TIMEOUT,
    deadline: float | None = None,
) -> dict[str, object]:
    try:
        transaction_args = {}
        if deadline is not None:
            transaction_args["deadline"] = deadline
        response = usb_recovery.run_transaction(
            device.by_id, timeout, usb_recovery.COMMAND_STATE, b"", **transaction_args
        )
        return usb_recovery.decode_state_payload(response.payload)
    except usb_recovery.CommandError:
        raise
    except (usb_recovery.DeviceError, OSError, ImportError) as error:
        if not (
            _host_transport_unavailable(error)
            or (isinstance(error, usb_recovery.DeviceError) and str(error) == "USB device timed out")
        ):
            raise
        if deadline is not None:
            container_timeout = min(container_timeout, _remaining(deadline))
        return _container_recovery(
            device, timeout, caller_timeout=container_timeout, deadline=deadline
        )  # type: ignore[return-value]


def _ota_state(
    device: SerialDevice, timeout: float = STATE_TIMEOUT, *,
    container_timeout: float = CONTAINER_LIFECYCLE_TIMEOUT,
    deadline: float | None = None,
    legacy: bool = False,
) -> dict[str, object]:
    try:
        transaction_args = {}
        if deadline is not None:
            transaction_args["deadline"] = deadline
        return usb_recovery.read_ota_state(
            device.by_id, timeout, legacy=legacy, **transaction_args
        )
    except usb_recovery.CommandError:
        raise
    except (usb_recovery.DeviceError, OSError, ImportError) as error:
        if not _host_transport_unavailable(error):
            raise
        if deadline is not None:
            container_timeout = min(container_timeout, _remaining(deadline))
        result = _container_recovery(
            device, timeout, caller_timeout=container_timeout, deadline=deadline,
            command=usb_recovery.COMMAND_OTA_STATE, legacy_ota_state=legacy,
        )
        return (
            usb_recovery.validate_legacy_ota_state(result)
            if legacy else usb_recovery.validate_ota_state(result)
        )


def _ota_migration_readback(
    device: SerialDevice, timeout: float, container_timeout: float,
    deadline: float | None, original_error: BaseException,
) -> None:
    try:
        state = _ota_state(
            device, timeout=min(STATE_TIMEOUT, timeout),
            container_timeout=container_timeout, deadline=deadline, legacy=True,
        )
    except (usb_recovery.DeviceError, OSError, ImportError) as readback_error:
        raise original_error from readback_error
    if state.get("image_state") == "valid" and state.get("pending") == 0:
        return
    raise original_error


def _ota_migration_recover(
    device: SerialDevice, timeout: float = STATE_TIMEOUT, *,
    container_timeout: float = CONTAINER_LIFECYCLE_TIMEOUT,
    deadline: float | None = None,
) -> None:
    try:
        transaction_args = {}
        if deadline is not None:
            transaction_args["deadline"] = deadline
        response = usb_recovery.run_transaction(
            device.by_id, timeout, usb_recovery.COMMAND_OTA_MIGRATION_RECOVER,
            b"", **transaction_args,
        )
        if response.payload:
            raise usb_recovery.DeviceError("USB recovery returned invalid migration response")
        return
    except usb_recovery.CommandError:
        raise
    except (usb_recovery.DeviceError, OSError, ImportError) as error:
        if _host_transport_unavailable(error):
            if deadline is not None:
                container_timeout = min(container_timeout, _remaining(deadline))
            try:
                result = _container_recovery(
                    device, timeout, caller_timeout=container_timeout, deadline=deadline,
                    command=usb_recovery.COMMAND_OTA_MIGRATION_RECOVER,
                )
            except usb_recovery.CommandError:
                raise
            except (usb_recovery.DeviceError, OSError, ImportError) as recovery_error:
                error = recovery_error
            else:
                if result == {"ok": True}:
                    return
                error = usb_recovery.DeviceError(
                    "USB recovery returned invalid migration response"
                )
        _ota_migration_readback(device, timeout, container_timeout, deadline, error)


def _try_resolve_exact_device(device_path: str) -> SerialDevice | None:
    try:
        device = resolve_serial_device(device_path)
    except (OSError, ValueError):
        return None
    return device if device is not None and device.by_id == device_path else None


def _reset_state_after_boot(
    device_path: str, previous_boot_id: int, deadline: float,
) -> dict[str, object]:
    last_probe_error: usb_recovery.DeviceError | None = None
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if last_probe_error is not None:
                raise usb_recovery.DeviceError("USB device did not report a fresh boot id") from last_probe_error
            raise usb_recovery.DeviceError("USB device did not return after reset")

        device = _try_resolve_exact_device(device_path)
        if device is not None:
            probe_timeout = min(STATE_TIMEOUT, remaining / 3)
            container_probe_timeout = min(CONTAINER_TIMEOUT, remaining)
            try:
                state = _state(
                    device,
                    probe_timeout,
                    container_timeout=container_probe_timeout,
                    deadline=deadline,
                )
                boot_id = state.get("boot_id")
                if (
                    isinstance(boot_id, int)
                    and not isinstance(boot_id, bool)
                    and 0 < boot_id <= 0xFFFFFFFF
                    and boot_id != previous_boot_id
                ):
                    if deadline - time.monotonic() <= 0:
                        raise usb_recovery.DeviceError("USB device timed out")
                    return state
                last_probe_error = usb_recovery.DeviceError("USB device boot id did not change")
            except usb_recovery.DeviceError as error:
                last_probe_error = error

        time.sleep(min(0.05, remaining))


def _diag_query(
    device: SerialDevice, query_name: str, deadline: float,
) -> bytes | usb_recovery.Frame:
    payload = usb_recovery.encode_modem_query(query_name)
    busy_retries = 0
    while True:
        remaining = _remaining(deadline)
        default_timeout = CPOL_DIAG_INNER_TIMEOUT if query_name == "cpol" else DIAG_INNER_TIMEOUT
        timeout = min(default_timeout, remaining)
        try:
            response = usb_recovery.run_transaction(
                device.by_id, timeout, usb_recovery.COMMAND_MODEM_QUERY, payload,
                deadline=deadline,
            )
            if time.monotonic() >= deadline:
                raise usb_recovery.DeviceError("device operation timed out")
            if not response.payload.strip():
                raise usb_recovery.DeviceError("empty modem query response")
            return response if query_name == "msslcipher" else response.payload
        except usb_recovery.CommandError as exc:
            if exc.status != usb_recovery.STATUS_BUSY or busy_retries >= BUSY_RETRIES:
                raise
            busy_retries += 1
            remaining = _remaining(deadline)
            if remaining <= BUSY_DELAY:
                raise usb_recovery.DeviceError("device operation timed out") from None
            time.sleep(BUSY_DELAY)
        except (usb_recovery.DeviceError, OSError, ImportError) as error:
            if not _ALLOW_DIAG_CONTAINER_FALLBACK or not _host_transport_unavailable(error):
                raise
            try:
                remaining = _remaining(deadline)
                return _container_recovery(
                    device, timeout, query_name, caller_timeout=remaining, deadline=deadline
                )
            except usb_recovery.CommandError as container_error:
                if (
                    container_error.status != usb_recovery.STATUS_BUSY
                    or busy_retries >= BUSY_RETRIES
                ):
                    raise
                busy_retries += 1
                remaining = _remaining(deadline)
                if remaining <= BUSY_DELAY:
                    raise usb_recovery.DeviceError("device operation timed out") from None
                time.sleep(BUSY_DELAY)


def _sanitize_diag_frame(query_id: int, response: usb_recovery.Frame) -> dict[str, object]:
    if query_id == usb_recovery.QUERY_MSSLCIPHER and response.other_line_present is not None:
        return usb_recovery.sanitize_query_response(
            query_id, response.payload,
            other_line_present=response.other_line_present,
            msslcipher_telemetry=response.msslcipher_telemetry,
        )
    return usb_recovery.sanitize_query_response(query_id, response.payload)


def _write_raw(payload: bytes) -> None:
    stream = getattr(sys.stdout, "buffer", None)
    if stream is None:
        sys.stdout.write(payload.decode("utf-8", "replace"))
    else:
        stream.write(payload)
        stream.flush()


def _diag_command(args: argparse.Namespace) -> int:
    device = resolve_serial_device(args.device)
    if args.all and (args.query_name or args.query_option):
        raise ValueError("choose one diagnostic query")
    if args.query_name and args.query_option:
        raise ValueError("choose one diagnostic query")
    query = "all" if args.all else (args.query_option or args.query_name or "all")
    names = QUERY_NAMES if query == "all" else (query,)
    budget = DIAG_ALL_TIMEOUT if query == "all" else DIAG_OUTER_TIMEOUT
    deadline = time.monotonic() + budget

    if query == "all":
        # Keep the existing host path and only switch to batch after host claim fails.
        global _ALLOW_DIAG_CONTAINER_FALLBACK
        previous_fallback = _ALLOW_DIAG_CONTAINER_FALLBACK
        _ALLOW_DIAG_CONTAINER_FALLBACK = False
        results: dict[str, object] = {}
        raw_payloads: list[usb_recovery.Frame] = []
        completed = 0
        try:
            while completed < len(names):
                name = names[completed]
                query_id = usb_recovery.QUERY_COMMANDS[name][0]
                try:
                    response = _diag_query(device, name, deadline)
                    if not isinstance(response, usb_recovery.Frame):
                        response = usb_recovery.Frame(
                            usb_recovery.RESPONSE_MODEM_QUERY, 0, response,
                        )
                except usb_recovery.CommandError:
                    if args.raw:
                        raise
                    results[name] = usb_recovery._unavailable_query_response(query_id)
                    completed += 1
                    continue
                if args.raw:
                    if query_id == usb_recovery.QUERY_CPOL:
                        safe = _sanitize_diag_frame(query_id, response)
                        if not safe["valid"]:
                            raise usb_recovery.DeviceError("CPOL response is not a safe summary")
                    raw_payloads.append(response)
                else:
                    results[name] = _sanitize_diag_frame(query_id, response)
                completed += 1
        except (usb_recovery.DeviceError, OSError, ImportError) as error:
            if not _host_transport_unavailable(error):
                raise
            batch_results = _container_recovery_batch(device, names[completed:], deadline=deadline)
            if args.raw:
                for name, response in zip(names[:completed], raw_payloads, strict=True):
                    results[name] = _sanitize_diag_frame(
                        usb_recovery.QUERY_COMMANDS[name][0], response,
                    )
                results.update(batch_results)
                print(json.dumps(results, sort_keys=True))
                return 0
            results.update(batch_results)
        finally:
            _ALLOW_DIAG_CONTAINER_FALLBACK = previous_fallback

        if args.raw:
            for response in raw_payloads:
                _write_raw(response.payload)
        else:
            print(json.dumps(results, sort_keys=True))
        return 0

    results: dict[str, object] = {}
    name = names[0]
    response = _diag_query(device, name, deadline)
    if not isinstance(response, usb_recovery.Frame):
        response = usb_recovery.Frame(
            usb_recovery.RESPONSE_MODEM_QUERY, 0, response,
        )
    query_id = usb_recovery.QUERY_COMMANDS[name][0]
    if args.raw:
        if query_id == usb_recovery.QUERY_CPOL:
            safe = _sanitize_diag_frame(query_id, response)
            if not safe["valid"]:
                raise usb_recovery.DeviceError("CPOL response is not a safe summary")
        _write_raw(response.payload)
    else:
        results[name] = _sanitize_diag_frame(query_id, response)
    if not args.raw:
        print(json.dumps(results[name], sort_keys=True))
    return 0


def _build_command(args: argparse.Namespace) -> int:
    usb_dev = args.usb_dev or args.build_mode == "usb-dev"
    if usb_dev and args.release:
        raise ValueError("--release cannot be combined with usb-dev")
    env = os.environ.copy()
    env["SMS_USB_RECOVERY"] = "1" if usb_dev else "0"
    env["SMS_OTA_TEST_KEY"] = "0"
    env["SMS_OTA_TEST_PUBLIC_KEY"] = ""
    env["SMS_OTA_TEST_FAIL_HEALTH"] = "0"
    env["FIRMWARE_IS_RELEASE"] = "1" if args.release else "0"
    try:
        result = subprocess.run(
            [str(IDF_HELPER), "build"], cwd=ROOT, env=env, check=False
        )
    except (FileNotFoundError, OSError) as exc:
        raise usb_recovery.DeviceError("tools/idf.sh could not be started") from exc
    return result.returncode


def _ota_test_package_command(args: argparse.Namespace) -> int:
    private_key, public_key, public_fingerprint = _ensure_ota_test_keypair()
    _ota_test_build_dir(fail_health=args.fail_health)
    output = resolve_ota_test_output(Path(args.output))
    try:
        result = subprocess.run(
            [str(IDF_HELPER), "build"], cwd=ROOT,
            env=_ota_test_build_environment(public_key, fail_health=args.fail_health), check=False,
        )
    except (FileNotFoundError, OSError) as exc:
        raise usb_recovery.DeviceError("tools/idf.sh could not be started") from exc
    if result.returncode:
        return result.returncode
    image = resolve_ota_test_image(
        ROOT / "build" / (
            "idf-ota-test-fail-health" if args.fail_health else "idf-ota-test"
        ) / "sms_forwarding_idf.bin",
        fail_health=args.fail_health,
    )

    size = image.stat().st_size
    if not 0 < size <= APP_MAX_SIZE:
        raise ValueError(f"OTA test image must be 1..{APP_MAX_SIZE} bytes")
    image_digest = sha256_file(image)
    if args.sha256 and (
        len(args.sha256) != 64
        or any(char not in "0123456789abcdefABCDEF" for char in args.sha256)
        or args.sha256.lower() != image_digest
    ):
        raise ValueError("--sha256 pin does not match OTA test image")

    result = _run_process([
        sys.executable, str(OTA_TEST_SIGNER), str(image), str(output),
        "--private-key", str(private_key),
        "--version", args.version, "--counter", str(args.counter),
        "--expected-public-sha256", public_fingerprint,
    ], stage="OTA test signer")
    if result.returncode:
        raise usb_recovery.DeviceError("OTA test signer failed")
    print(json.dumps({
        "action": "ota-test-package",
        "counter": args.counter,
        "image": str(image),
        "image_sha256": image_digest,
        "output": str(output),
        "package_sha256": sha256_file(output),
        "profile": "usb-dev-test-key",
        "public_key_sha256": public_fingerprint,
        "fail_health": bool(args.fail_health),
        "version": args.version,
    }, sort_keys=True))
    return 0


def _reset_command(args: argparse.Namespace) -> int:
    device_path = resolve_device(args.device)
    if not args.live:
        print(json.dumps({
            "action": "reset",
            "device": device_path,
            "live": False,
            "mode": "usb_reset",
            "timeout": RESET_TIMEOUT,
        }, sort_keys=True))
        return 0

    device = resolve_serial_device(device_path)
    confirm_basename(device_path, args.confirm)
    deadline = time.monotonic() + RESET_TIMEOUT
    old_state = _state(device, deadline=deadline)
    previous_boot_id = old_state.get("boot_id")
    if (
        not isinstance(previous_boot_id, int)
        or isinstance(previous_boot_id, bool)
        or not 0 < previous_boot_id <= 0xFFFFFFFF
    ):
        raise usb_recovery.DeviceError("USB state has an invalid boot id")
    run_esptool(device, _remaining(deadline))
    state = _reset_state_after_boot(device_path, previous_boot_id, deadline)
    print(json.dumps({
        "action": "reset",
        "device": device.by_id,
        "live": True,
        "mode": "usb_reset",
        "state": state,
    }, sort_keys=True))
    return 0


def _run_baseline(build_dir: Path) -> None:
    allowed = {(ROOT / relative.parent).resolve() for relative in APP_IMAGE_RELATIVE_PATHS}
    try:
        resolved_build_dir = build_dir.resolve(strict=True)
    except OSError as exc:
        raise usb_recovery.DeviceError("app build profile is unavailable") from exc
    if resolved_build_dir not in allowed:
        raise usb_recovery.DeviceError("app image is not from an allowed build profile")
    result = _run_process([
        sys.executable,
        str(BASELINE_CHECK),
        "--build-dir",
        str(resolved_build_dir),
    ])
    if result.returncode:
        raise usb_recovery.DeviceError("ESP-IDF baseline check failed")


def _is_esptool_timeout(error: BaseException) -> bool:
    text = str(error).lower()
    return isinstance(error, usb_recovery.DeviceError) and (
        "timed out" in text or "timeout" in text
    )


def _is_recoverable_app_flash_readback_error(error: BaseException) -> bool:
    if not isinstance(error, usb_recovery.DeviceError):
        return False
    return bool(re.fullmatch(
        r"esptool timed out|esptool failed \(exit -?\d+; (?:external-error|timeout)\)",
        str(error).strip(),
    ))


def _ensure_inactive_app_slot(device: SerialDevice, offset: int) -> None:
    active_offset = _ota_state(device, legacy=True).get("active_offset")
    if active_offset not in APP_SLOT_OFFSETS.values():
        raise usb_recovery.DeviceError("OTA state active slot is unknown")
    if active_offset == offset:
        raise usb_recovery.DeviceError("cannot flash the active app slot")


def _profile_cache_flags(profile: Path) -> dict[str, str]:
    cache = profile / "CMakeCache.txt"
    if cache.is_symlink() or not _is_regular_file(cache):
        raise usb_recovery.DeviceError("app build profile cache is unavailable")
    try:
        lines = cache.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise usb_recovery.DeviceError("app build profile cache is unavailable") from exc
    flags: dict[str, str] = {}
    for key in (
        "FIRMWARE_IS_RELEASE", "SMS_USB_RECOVERY", "SMS_OTA_TEST_KEY",
        "SMS_OTA_TEST_FAIL_HEALTH",
    ):
        matches = [
            line.split("=", 1)[1]
            for line in lines
            if line.startswith(f"{key}:") and "=" in line
        ]
        if len(matches) != 1:
            raise usb_recovery.DeviceError("app build profile identity is unavailable")
        flags[key] = matches[0]
    return flags


def _profile_cache_value(profile: Path, key: str) -> str:
    cache = profile / "CMakeCache.txt"
    if cache.is_symlink() or not _is_regular_file(cache):
        raise usb_recovery.DeviceError("app build profile cache is unavailable")
    try:
        lines = cache.read_text(encoding="ascii").splitlines()
    except (OSError, UnicodeError) as exc:
        raise usb_recovery.DeviceError("app build profile cache is unavailable") from exc
    matches = [
        line.split("=", 1)[1]
        for line in lines
        if line.startswith(f"{key}:") and "=" in line
    ]
    if len(matches) != 1:
        raise usb_recovery.DeviceError("app build profile identity is unavailable")
    return matches[0]


def _read_active_public_key(path: Path, *, encoded: bool, label: str) -> bytes:
    _reject_symlink_components(path)
    if path.is_symlink() or not _is_regular_file(path):
        raise usb_recovery.DeviceError(f"{label} is unavailable")
    try:
        raw = path.read_bytes()
        key = base64.b64decode(raw.strip(), validate=True) if encoded else raw
    except (OSError, ValueError) as exc:
        raise usb_recovery.DeviceError(f"{label} is unavailable") from exc
    if not key:
        raise usb_recovery.DeviceError(f"{label} is unavailable")
    return key


def _active_test_profile_identity(profile: Path) -> str:
    expected = {
        "FIRMWARE_IS_RELEASE": "0",
        "SMS_USB_RECOVERY": "1",
        "SMS_OTA_TEST_KEY": "1",
        "SMS_OTA_TEST_FAIL_HEALTH": "0",
    }
    if _profile_cache_flags(profile) != expected:
        raise usb_recovery.DeviceError("OTA test image requires a verified healthy dev profile")
    configured_key = _profile_cache_value(profile, "SMS_OTA_TEST_PUBLIC_KEY")
    key_path = profile / "ota_test_public_key.der.b64"
    try:
        configured_path = Path(configured_key)
        cache_root = Path(_profile_cache_value(profile, "CMAKE_HOME_DIRECTORY"))
        if not configured_path.is_absolute() or not cache_root.is_absolute():
            raise ValueError("profile paths must be absolute")
        if configured_path.relative_to(cache_root) != key_path.relative_to(ROOT):
            raise ValueError("key path mismatch")
    except (OSError, ValueError) as exc:
        raise usb_recovery.DeviceError("OTA test image key profile is unavailable") from exc
    key = _read_active_public_key(
        key_path, encoded=True, label="OTA test public key",
    )
    return hashlib.sha256(key).hexdigest()


def _production_image_identity() -> str:
    key = _read_active_public_key(
        ROOT / "components" / "idf_web" / "ota_public_key.der.b64",
        encoded=True, label="production OTA public key",
    )
    return hashlib.sha256(key).hexdigest()


def _active_test_image_identity(image: Path) -> str:
    profile = image.parent.resolve(strict=True)
    if profile != (ROOT / "build" / "idf-ota-test").resolve():
        raise usb_recovery.DeviceError("test-key rotation requires an OTA test build profile")
    return _active_test_profile_identity(profile)


def _active_image_identity(image: Path) -> str:
    profile = image.parent.resolve(strict=True)
    ota_test_profile = (ROOT / "build" / "idf-ota-test").resolve()
    usb_profile = (ROOT / "build" / "idf-usb-recovery").resolve()
    if profile == ota_test_profile:
        return _active_test_profile_identity(profile)
    if profile != usb_profile or _profile_cache_flags(profile) != {
        "FIRMWARE_IS_RELEASE": "0",
        "SMS_USB_RECOVERY": "1",
        "SMS_OTA_TEST_KEY": "0",
        "SMS_OTA_TEST_FAIL_HEALTH": "0",
    }:
        raise usb_recovery.DeviceError("active app replacement requires a USB recovery build profile")
    return _production_image_identity()


def _active_ota_state(device: SerialDevice, deadline: float) -> dict[str, object]:
    state = _ota_state(device, deadline=deadline, legacy=False)
    if state.get("public_key_sha256") is None:
        raise usb_recovery.DeviceError("active app replacement requires extended OTA state")
    return state


def _validate_active_ota_state(
    state: dict[str, object], offset: int, identity: str, *, allow_key_mismatch: bool = False,
) -> None:
    pending = state.get("pending")
    pending_address = state.get("pending_address")
    if (
        state.get("active_offset") != offset
        or state.get("image_state") != "valid"
        or state.get("pending_verify") is not False
        or not isinstance(pending, int) or isinstance(pending, bool) or pending != 0
        or not isinstance(pending_address, int)
        or isinstance(pending_address, bool) or pending_address != 0
        or (not allow_key_mismatch and state.get("public_key_sha256") != identity)
    ):
        raise usb_recovery.DeviceError("active app replacement OTA state is unsafe")


def _active_target(
    device_path: str, expected_target: str,
    stable_identity: tuple[str, ...] | None = None,
    deadline: float | None = None,
) -> SerialDevice:
    return _resolve_pinned_device(
        device_path, expected_target, stable_identity,
        deadline if deadline is not None else time.monotonic() + STATE_TIMEOUT,
    )


def _recheck_active_state(
    device_path: str, expected_target: str, offset: int,
    identity: str, initial: dict[str, object], deadline: float, *, allow_key_mismatch: bool = False,
    stable_identity: tuple[str, ...] | None = None,
) -> SerialDevice:
    device = _active_target(device_path, expected_target, stable_identity, deadline)
    state = _active_ota_state(device, deadline)
    _validate_active_ota_state(state, offset, identity, allow_key_mismatch=allow_key_mismatch)
    if state != initial:
        raise usb_recovery.DeviceError("active app replacement OTA state changed")
    return device


def _replace_active_app(
    device_path: str, expected_target: str, device: SerialDevice,
    image: Path, snapshot: Path, offset: int, size: int, digest: str,
    plan: dict[str, object], *, rotate_test_key: bool = False,
    confirmed_identity: str | None = None,
) -> int:
    identity = _active_test_image_identity(image) if rotate_test_key else _active_image_identity(image)
    production_identity = _production_image_identity() if rotate_test_key else None
    stable_identity = device.stable_identity
    if rotate_test_key:
        if confirmed_identity is None or confirmed_identity.lower() != identity:
            raise ValueError("--confirm-new-key must match the candidate public-key SHA-256")
        if identity == production_identity:
            raise usb_recovery.DeviceError("test-key rotation requires a non-production candidate key")
    operation_timeout = _flash_operation_timeout(size)
    deadline = time.monotonic() + operation_timeout + RESET_TIMEOUT + STATE_TIMEOUT
    initial_state = _active_ota_state(device, deadline)
    if rotate_test_key:
        current_identity = initial_state["public_key_sha256"]
        if current_identity == production_identity or current_identity == identity:
            raise usb_recovery.DeviceError("test-key rotation requires a different non-production key")
    _validate_active_ota_state(
        initial_state, offset, identity, allow_key_mismatch=rotate_test_key,
    )

    try:
        _read_app_flash_digest(
            device_path, expected_target, offset, size, operation_timeout,
            after="hard_reset", recover=False, stable_identity=stable_identity,
        )
    except (OSError, ValueError, usb_recovery.DeviceError, subprocess.SubprocessError) as error:
        raise usb_recovery.DeviceError(ACTIVE_PRE_READ_FAILURE) from error

    device = _recheck_active_state(
        device_path, expected_target, offset, identity, initial_state, deadline,
        allow_key_mismatch=rotate_test_key,
        stable_identity=stable_identity,
    )
    runtime_state = _state(device, deadline=deadline)
    previous_boot_id = runtime_state.get("boot_id")
    if (
        not isinstance(previous_boot_id, int)
        or isinstance(previous_boot_id, bool)
        or not 0 < previous_boot_id <= 0xFFFFFFFF
    ):
        raise usb_recovery.DeviceError("USB state has an invalid boot id")
    arguments = [
        "--chip", "esp32c3", "--port", device_path,
        "--before", "usb_reset", "--after", "no_reset",
        "write-flash", f"0x{offset:X}", str(snapshot),
    ]
    try:
        _flash_esptool(
            device_path, expected_target, arguments, operation_timeout,
            image=snapshot, recover=False, stable_identity=stable_identity,
        )
        _verify_app_flash(
            device_path, expected_target, snapshot, offset, operation_timeout,
            after="no_reset", recover=False, stable_identity=stable_identity,
        )
        after_digest = _read_app_flash_digest(
            device_path, expected_target, offset, size, operation_timeout,
            after="no_reset", recover=False, stable_identity=stable_identity,
        )
        if after_digest != digest:
            raise usb_recovery.DeviceError("active app flash readback mismatch")
    except (OSError, ValueError, usb_recovery.DeviceError, subprocess.SubprocessError) as error:
        raise usb_recovery.DeviceError(ACTIVE_FLASH_FAILURE) from error

    try:
        final_device = _active_target(device_path, expected_target, stable_identity, deadline)
        run_esptool(final_device, min(RESET_TIMEOUT, _remaining(deadline)))
        fresh_runtime = _reset_state_after_boot(device_path, previous_boot_id, deadline)
        fresh_boot_id = fresh_runtime.get("boot_id")
        if (
            not isinstance(fresh_boot_id, int)
            or isinstance(fresh_boot_id, bool)
            or not 0 < fresh_boot_id <= 0xFFFFFFFF
            or fresh_boot_id == previous_boot_id
        ):
            raise usb_recovery.DeviceError("USB device did not report a fresh boot id")
        post_device = _active_target(device_path, expected_target, stable_identity, deadline)
        post_state = _active_ota_state(post_device, deadline)
        _validate_active_ota_state(post_state, offset, identity)
    except (OSError, ValueError, usb_recovery.DeviceError, subprocess.SubprocessError) as error:
        raise usb_recovery.DeviceError(ACTIVE_POST_RESET_FAILURE) from error

    plan.update({
        "activation": "replace-active",
        "reset": "hard_reset",
        "sha256": digest,
        "status": "flashed",
        "verification": "readback_sha256+fresh_ota_state",
        "written": True,
    })
    print(json.dumps(plan, sort_keys=True))
    return 0


def _flash_operation_timeout(size: int) -> float:
    return min(
        FLASH_OPERATION_MAX_TIMEOUT,
        max(
            RESET_TIMEOUT,
            FLASH_OPERATION_OVERHEAD + size / FLASH_OPERATION_MIN_BYTES_PER_SECOND,
        ),
    )


def _recover_app_flash(device: SerialDevice) -> None:
    try:
        run_esptool(device, RESET_TIMEOUT)
    except BaseException:
        pass


def _flash_esptool(
    device_path: str, expected_target: str, arguments: list[str], timeout: float,
    *, image: Path | None = None, output: Path | None = None,
    output_mount: Path | None = None, recover: bool = True,
    stable_identity: tuple[str, ...] | None = None,
) -> None:
    device = _resolve_esptool_device(
        SerialDevice(device_path, expected_target, stable_identity), timeout,
    )
    try:
        _run_esptool(
            arguments, device, timeout, image=image, output=output,
            output_mount=output_mount,
        )
    except BaseException:
        if recover:
            _recover_app_flash(device)
        raise


def _read_app_flash_digest(
    device_path: str, expected_target: str, offset: int, size: int, timeout: float,
    *, after: str = "hard_reset", recover: bool = True,
    stable_identity: tuple[str, ...] | None = None,
) -> str:
    with tempfile.TemporaryDirectory(prefix="sms-forwarding-flash-") as directory:
        output = Path(directory) / "readback.bin"
        _flash_esptool(
            device_path, expected_target, [
                "--chip", "esp32c3", "--port", device_path,
                "--before", "usb_reset", "--after", after,
                "read-flash", f"0x{offset:X}", str(size), str(output),
            ], timeout, output=output, output_mount=Path(directory), recover=recover,
            stable_identity=stable_identity,
        )
        if output.stat().st_size != size:
            raise usb_recovery.DeviceError("app flash readback length mismatch")
        return sha256_file(output)


def _verify_app_flash(
    device_path: str, expected_target: str, image: Path, offset: int, timeout: float,
    *, after: str = "hard_reset", recover: bool = True,
    stable_identity: tuple[str, ...] | None = None,
) -> None:
    _flash_esptool(device_path, expected_target, [
        "--chip", "esp32c3", "--port", device_path,
        "--before", "usb_reset", "--after", after,
        "verify-flash", f"0x{offset:X}", str(image),
    ], timeout, image=image, recover=recover, stable_identity=stable_identity)


def _flash_command(args: argparse.Namespace) -> int:
    device_path = resolve_device(args.device)
    replace_active = bool(getattr(args, "replace_active", False))
    confirm_active = getattr(args, "confirm_active", None)
    rotate_test_key = bool(getattr(args, "rotate_test_key", False))
    confirm_new_key = getattr(args, "confirm_new_key", None)
    if rotate_test_key and not replace_active:
        raise ValueError("--rotate-test-key requires --replace-active")
    if confirm_new_key is not None and not rotate_test_key:
        raise ValueError("--confirm-new-key requires --rotate-test-key")
    if rotate_test_key and not args.live:
        raise ValueError("--rotate-test-key requires --live")
    if rotate_test_key and args.live and confirm_new_key is None:
        raise ValueError("--confirm-new-key is required for test-key rotation")
    if confirm_new_key is not None and (
        len(confirm_new_key) != 64
        or any(char not in "0123456789abcdefABCDEF" for char in confirm_new_key)
    ):
        raise ValueError("--confirm-new-key must be a 64-character SHA-256 pin")
    if confirm_active is not None and not replace_active:
        raise ValueError("--confirm-active requires --replace-active")
    if replace_active and confirm_active is not None and confirm_active != args.slot:
        raise ValueError("--confirm-active must match --slot")
    if replace_active and args.live and confirm_active is None:
        raise ValueError("--confirm-active must match --slot")
    if args.image and args.image_option:
        raise ValueError("choose one app image")
    try:
        offset = APP_SLOT_OFFSETS[args.slot]
    except KeyError:
        raise ValueError("slot must be app0 or app1") from None
    image = Path(args.image_option or args.image or str(DEFAULT_APP_IMAGE))
    image = resolve_app_image(image)
    size = validate_app0_image(image)
    plan = {
        "action": "flash-app0" if args.command == "flash-app0" else "flash-app",
        "device": device_path,
        "image": str(image),
        "live": bool(args.live),
        "max_size": APP_MAX_SIZE,
        "offset": f"0x{offset:X}",
        "slot": args.slot,
        "size": size,
        "activation": "replace-active" if replace_active else "none",
    }
    if not args.live:
        print(json.dumps(plan, sort_keys=True))
        return 0

    device = resolve_serial_device(device_path)
    expected_target = device.target
    _run_baseline(image.parent)
    with tempfile.TemporaryDirectory(prefix="sms-forwarding-image-", dir=ROOT) as directory:
        snapshot = Path(directory) / "image.bin"
        with image.open("rb") as source:
            descriptor = os.open(snapshot, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as target:
                shutil.copyfileobj(source, target)
        if snapshot.stat().st_size != size:
            raise usb_recovery.DeviceError("app image changed while snapshotting")
        digest = sha256_file(snapshot)
        pin = args.sha256_pin
        if len(pin) != 64 or any(char not in "0123456789abcdefABCDEF" for char in pin):
            raise ValueError("--sha256 must be a 64-character SHA-256 pin")
        if pin.lower() != digest:
            raise ValueError("SHA-256 pin does not match app image")
        confirm_basename(device_path, args.confirm)
        if replace_active:
            if confirm_active != args.slot:
                raise ValueError("--confirm-active must match --slot")
            return _replace_active_app(
                device_path, expected_target, device, image, snapshot,
                offset, size, digest, plan, rotate_test_key=rotate_test_key,
                confirmed_identity=confirm_new_key,
            )
        _ensure_inactive_app_slot(device, offset)

        operation_timeout = _flash_operation_timeout(size)
        try:
            before_digest = _read_app_flash_digest(
                device_path, expected_target, offset, size, operation_timeout,
                stable_identity=device.stable_identity,
            )
        except usb_recovery.DeviceError as error:
            if not _is_recoverable_app_flash_readback_error(error):
                raise
        else:
            if before_digest == digest:
                plan.update({
                    "status": "already-matching",
                    "verification": "pre_readback_sha256",
                    "sha256": digest,
                    "written": False,
                })
                print(json.dumps(plan, sort_keys=True))
                return 0

        _ensure_inactive_app_slot(device, offset)

        arguments = [
            "--chip", "esp32c3", "--port", device_path,
            "--before", "usb_reset", "--after", "hard_reset",
            "write-flash", f"0x{offset:X}", str(snapshot),
        ]
        reconciled = False
        try:
            _flash_esptool(
                device_path, expected_target, arguments, operation_timeout,
                image=snapshot, stable_identity=device.stable_identity,
            )
        except usb_recovery.DeviceError as error:
            if not _is_esptool_timeout(error):
                raise
            after_digest = _read_app_flash_digest(
                device_path, expected_target, offset, size, operation_timeout,
                stable_identity=device.stable_identity,
            )
            if after_digest != digest:
                raise usb_recovery.DeviceError("app flash readback SHA-256 mismatch") from error
            reconciled = True
        else:
            _verify_app_flash(
                device_path, expected_target, snapshot, offset, operation_timeout,
                stable_identity=device.stable_identity,
            )
        plan.update({
            "status": "reconciled" if reconciled else "flashed",
            "verification": "readback_sha256" if reconciled else "verify-flash",
            "sha256": digest,
            "written": True,
        })
        print(json.dumps(plan, sort_keys=True))
        return 0


def _flash_bootloader_command(args: argparse.Namespace) -> int:
    device_path = resolve_device(args.device)
    if args.image and args.image_option:
        raise ValueError("choose one bootloader image")
    image = Path(args.image_option or args.image or str(DEFAULT_BOOTLOADER_IMAGE))
    image = resolve_bootloader_image(image)
    size = validate_bootloader_image(image)
    plan = {
        "action": "flash-bootloader",
        "device": device_path,
        "image": str(image),
        "live": bool(args.live),
        "max_size": BOOTLOADER_MAX_SIZE,
        "offset": f"0x{BOOTLOADER_OFFSET:X}",
        "size": size,
        "preserves": ["otadata", "nvs", "appcfg", "coredump", "app0", "app1"],
    }
    if not args.live:
        print(json.dumps(plan, sort_keys=True))
        return 0

    device = resolve_serial_device(device_path)
    _run_baseline(image.parent.parent)
    digest = sha256_file(image)
    pin = args.sha256_pin
    if len(pin) != 64 or any(char not in "0123456789abcdefABCDEF" for char in pin):
        raise ValueError("--sha256 must be a 64-character SHA-256 pin")
    if pin.lower() != digest:
        raise ValueError("--sha256 pin does not match bootloader image")
    confirm_basename(device_path, args.confirm)
    arguments = [
        "--chip",
        "esp32c3",
        "--port",
        device.by_id,
        "--before",
        "usb_reset",
        "--after",
        "hard_reset",
        "write-flash",
        f"0x{BOOTLOADER_OFFSET:X}",
        str(image),
    ]
    device = _resolve_esptool_device(device, RESET_TIMEOUT)
    _run_esptool(arguments, device, RESET_TIMEOUT, image=image)
    plan["sha256"] = digest
    print(json.dumps(plan, sort_keys=True))
    return 0


def _ota_migration_recover_command(args: argparse.Namespace) -> int:
    device_path = resolve_device(args.device)
    plan = {
        "action": "ota-migration-recover",
        "device": device_path,
        "live": bool(args.live),
        "requires": "USB recovery build, pending-verify image, zero-or-absent OTA counters",
        "preserves": ["nvs", "appcfg", "app0", "app1"],
        "updates": ["running image state in otadata"],
    }
    if not args.live:
        print(json.dumps(plan, sort_keys=True))
        return 0

    device = resolve_serial_device(device_path)
    confirm_basename(device_path, args.confirm)
    deadline = time.monotonic() + CONTAINER_LIFECYCLE_TIMEOUT + STATE_TIMEOUT
    _ota_migration_recover(device, timeout=STATE_TIMEOUT, deadline=deadline)
    plan["status"] = "completed"
    print(json.dumps(plan, sort_keys=True))
    return 0


def _doctor_command(args: argparse.Namespace) -> int:
    configured = present = character_device = host_read_write = False
    permission_code = "device-not-configured"
    recommended_action = "configure-explicit-by-id"

    try:
        device_path = resolve_device(args.device)
    except ValueError:
        device_path = None
    if device_path is not None:
        configured = True
        present = os.path.lexists(device_path)
        permission_code = "device-not-present"
        recommended_action = "connect-device"
        if present:
            permission_code = "invalid-device"
            recommended_action = "check-device-symlink"
            try:
                resolved = resolve_serial_device(device_path)
                device_stat = Path(resolved.target).stat()
            except (OSError, ValueError):
                pass
            else:
                character_device = True
                host_read_write = os.access(resolved.target, os.R_OK | os.W_OK)
                permission_code = "ok" if host_read_write else "access-denied"
                recommended_action = "none" if host_read_write else "check-device-access"
                process_groups = {os.getegid(), *os.getgroups()}
                group_read_write = (
                    device_stat.st_mode & (stat.S_IRGRP | stat.S_IWGRP)
                    == stat.S_IRGRP | stat.S_IWGRP
                )
                if (
                    not host_read_write
                    and os.geteuid() != device_stat.st_uid
                    and device_stat.st_gid not in process_groups
                    and group_read_write
                ):
                    permission_code = "group-access-missing"
                    recommended_action = "join-device-group-and-start-new-login-session"

    docker_host = os.environ.get("DOCKER_HOST", "")
    docker_context = os.environ.get("DOCKER_CONTEXT", "")
    local_docker = (
        (not docker_host or docker_host.startswith("unix://"))
        and docker_context in {"", "default"}
    )
    image_present = False
    if local_docker:
        try:
            image_present = subprocess.run(
                [
                    "docker", "--host", "unix:///var/run/docker.sock",
                    "image", "inspect", IDF_IMAGE,
                ],
                cwd=ROOT,
                timeout=CONTAINER_STARTUP_TIMEOUT,
                check=False,
                capture_output=True,
                text=True,
            ).returncode == 0
        except (OSError, subprocess.SubprocessError):
            pass

    print(json.dumps({
        "device": {
            "character_device": character_device,
            "configured": configured,
            "host_read_write": host_read_write,
            "present": present,
        },
        "fallback": {"image_present": image_present},
        "permission": {
            "code": permission_code,
            "recommended_action": recommended_action,
        },
        "ready": character_device and (host_read_write or image_present),
    }, sort_keys=True))
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Safe ESP32-C3 device operations")
    parser.add_argument("--device", default=None, help="explicit /dev/serial/by-id path")
    commands = parser.add_subparsers(dest="command", required=True)

    build = commands.add_parser("build", help="build production or USB development firmware")
    build.add_argument("build_mode", nargs="?", choices=("production", "usb-dev"), default="production")
    build.add_argument("--usb-dev", action="store_true", help="enable the USB recovery build")
    build.add_argument("--release", action="store_true", help="explicitly build release firmware")

    ota_test = commands.add_parser(
        "ota-test-package", help="build and sign a non-production USB OTA test package"
    )
    ota_test.add_argument(
        "--output", default="dist/sms-forwarder-dev-test.smsota",
        help="ignored .smsota output path inside the repository",
    )
    ota_test.add_argument("--counter", type=int, default=1)
    ota_test.add_argument("--version", default=OTA_TEST_VERSION)
    ota_test.add_argument("--sha256", "--sha256-pin", dest="sha256", default="", help="optional SHA-256 image pin")
    ota_test.add_argument(
        "--fail-health", action="store_true",
        help="build the isolated dev image that rolls back during pending verification",
    )

    backup = commands.add_parser("backup-config", help="export an encrypted configuration backup")
    backup.add_argument("output", nargs="?", help="new .smscfg output path")
    backup.add_argument("--output", dest="output_option", default=None, help="new .smscfg output path")
    backup.add_argument("--host", default=DEFAULT_WEB_HOST)
    backup.add_argument("--user", default=DEFAULT_WEB_USER)
    backup.add_argument("--password-file", default=None)
    backup.add_argument("--passphrase-file", default=None)
    backup.add_argument("--dry-run", action="store_true", help="validate the output target without contacting the device")

    verify_backup = commands.add_parser(
        "verify-config-backup", help="verify a v6 or v7 encrypted configuration backup offline"
    )
    verify_backup.add_argument("backup", help="existing .smscfg backup path")
    verify_backup.add_argument("--passphrase-file", default=None)

    ota_upload = commands.add_parser("ota-upload", help="upload a signed .smsota package through Web OTA")
    ota_upload.add_argument("package", nargs="?", help="existing signed .smsota package")
    ota_upload.add_argument("--package", dest="package_option", default=None, help="existing signed .smsota package")
    ota_upload.add_argument("--host", default=DEFAULT_WEB_HOST)
    ota_upload.add_argument("--user", default=DEFAULT_WEB_USER)
    ota_upload.add_argument("--password-file", default=None)
    ota_upload.add_argument("--live", action="store_true", help="start the upload after exact host confirmation")
    ota_upload.add_argument("--confirm-host", default=None)

    state = commands.add_parser("state", help="read sanitized device state")
    state.add_argument("--json", action="store_true", help="write the default JSON state format")

    doctor = commands.add_parser("doctor", help="check read-only host device readiness")

    commands.add_parser("ota-state", help="read safe signed OTA state")

    diag = commands.add_parser("diag", help="run fixed read-only modem diagnostics")
    diag.add_argument("query_name", nargs="?", choices=(*QUERY_NAMES, "all"))
    diag.add_argument("--id", dest="query_option", choices=(*QUERY_NAMES, "all"))
    diag.add_argument("--all", action="store_true", help="run all 18 fixed queries")
    diag.add_argument("--raw", action="store_true", help="write raw response to stdout only")

    reset = commands.add_parser("reset", help="reset and probe one exact device")
    reset.add_argument("--live", action="store_true", help="perform the reset")
    reset.add_argument("--confirm", "--confirm-device", dest="confirm", help="exact device basename confirmation")

    flash = commands.add_parser("flash-app", help="flash one fixed app slot")
    flash.add_argument("image", nargs="?")
    flash.add_argument("--image", dest="image_option")
    flash.add_argument("--slot", choices=tuple(APP_SLOT_OFFSETS), required=True)
    flash.add_argument("--live", action="store_true", help="perform the flash")
    flash.add_argument("--confirm", "--confirm-device", dest="confirm", help="exact device basename confirmation")
    flash.add_argument("--sha256", "--sha256-pin", dest="sha256_pin", default="")
    flash.add_argument(
        "--replace-active", action="store_true",
        help="replace the selected active app slot during one-time recovery",
    )
    flash.add_argument(
        "--confirm-active", choices=tuple(APP_SLOT_OFFSETS), default=None,
        help="repeat the active slot name for one-time recovery",
    )
    flash.add_argument(
        "--rotate-test-key", action="store_true",
        help="replace the active app with a new non-production OTA test key",
    )
    flash.add_argument(
        "--confirm-new-key", default=None,
        help="confirm the replacement OTA test public-key SHA-256",
    )

    flash0 = commands.add_parser("flash-app0", help="flash only the app0 slot")
    flash0.add_argument("image", nargs="?")
    flash0.add_argument("--image", dest="image_option")
    flash0.add_argument("--live", action="store_true", help="perform the flash")
    flash0.add_argument("--confirm", "--confirm-device", dest="confirm", help="exact device basename confirmation")
    flash0.add_argument("--sha256", "--sha256-pin", dest="sha256_pin", default="")
    flash0.set_defaults(slot="app0")

    bootloader = commands.add_parser(
        "flash-bootloader", help="flash the fixed ESP-IDF bootloader at offset 0x0"
    )
    bootloader.add_argument("image", nargs="?")
    bootloader.add_argument("--image", dest="image_option")
    bootloader.add_argument("--live", action="store_true", help="perform the flash")
    bootloader.add_argument("--confirm", "--confirm-device", dest="confirm", help="exact device basename confirmation")
    bootloader.add_argument("--sha256", "--sha256-pin", dest="sha256_pin", default="")

    migration_recover = commands.add_parser(
        "ota-migration-recover", help="mark one pending USB-dev image valid during migration"
    )
    migration_recover.add_argument("--live", action="store_true", help="perform the one-time recovery")
    migration_recover.add_argument("--confirm", "--confirm-device", dest="confirm", help="exact device basename confirmation")

    for command in (
        commands.choices["state"], doctor, commands.choices["ota-state"], diag, reset,
        flash, flash0, bootloader, migration_recover,
    ):
        command.add_argument(
            "--device",
            default=argparse.SUPPRESS,
            help="explicit /dev/serial/by-id path (or SMS_DEVICE)",
        )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "build":
            return _build_command(args)
        if args.command == "ota-test-package":
            if not 0 < args.counter <= 0xFFFFFFFF:
                raise ValueError("--counter must be a non-zero uint32")
            if not 0 < len(args.version.encode("ascii")) <= 32 or any(
                char not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-"
                for char in args.version
            ):
                raise ValueError("--version must be 1-32 safe ASCII characters")
            return _ota_test_package_command(args)
        if args.command == "backup-config":
            return _backup_command(args)
        if args.command == "verify-config-backup":
            return _verify_backup_command(args)
        if args.command == "ota-upload":
            return _ota_upload_command(args)
        if args.command == "flash-bootloader":
            return _flash_bootloader_command(args)
        if args.command == "ota-migration-recover":
            return _ota_migration_recover_command(args)
        if args.command == "doctor":
            return _doctor_command(args)
        if args.command == "state":
            deadline = (
                time.monotonic() + CONTAINER_LIFECYCLE_TIMEOUT + STATE_TIMEOUT * 3
            )
            state = _state(resolve_serial_device(args.device), deadline=deadline)
            print(json.dumps(state, sort_keys=True))
            return 0
        if args.command == "ota-state":
            deadline = time.monotonic() + CONTAINER_LIFECYCLE_TIMEOUT
            state = _ota_state(resolve_serial_device(args.device), deadline=deadline)
            print(json.dumps(state, sort_keys=True))
            return 0
        if args.command == "diag":
            return _diag_command(args)
        if args.command == "reset":
            return _reset_command(args)
        return _flash_command(args)
    except (OSError, ValueError, usb_recovery.DeviceError, subprocess.SubprocessError) as exc:
        print(str(exc).strip() or "device operation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
