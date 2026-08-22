#!/usr/bin/env python3
"""安全的 ESP-IDF build、診斷、reset 與 app0 工具。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import time
from pathlib import Path
from dataclasses import dataclass

import usb_recovery
from check_idf_baseline import EXPECTED_IDF_IMAGE


ROOT = Path(__file__).resolve().parents[1]
IDF_HELPER = ROOT / "tools" / "idf.sh"
BASELINE_CHECK = ROOT / "tools" / "check_idf_baseline.py"
DEFAULT_APP_IMAGE = ROOT / "build" / "idf" / "sms_forwarding_idf.bin"
OTA_TEST_PROFILE_DIR = ROOT / "build" / "idf-ota-test"
OTA_TEST_IMAGE = OTA_TEST_PROFILE_DIR / "sms_forwarding_idf.bin"
OTA_TEST_PRIVATE_KEY = OTA_TEST_PROFILE_DIR / "ota_test_private.pem"
OTA_TEST_PUBLIC_DER = OTA_TEST_PROFILE_DIR / "ota_test_public.der"
OTA_TEST_PUBLIC_KEY = OTA_TEST_PROFILE_DIR / "ota_test_public_key.der.b64"
OTA_TEST_SIGNER = ROOT / "scripts" / "sign-ota-release.py"
OTA_TEST_VERSION = "1.1.4-dev-test"
APP_IMAGE_RELATIVE_PATHS = (
    Path("build/idf/sms_forwarding_idf.bin"),
    Path("build/idf-usb-recovery/sms_forwarding_idf.bin"),
    Path("build/idf-ota-test/sms_forwarding_idf.bin"),
)
ESPTOOL = os.environ.get("ESPTOOL", "esptool.py")
IDF_IMAGE = EXPECTED_IDF_IMAGE
CONTAINER_PYTHON = "/opt/esp/python_env/idf5.5_py3.12_env/bin/python"
CONTAINER_DEVICE_PATH = "/dev/sms-device"
DEVICE_PREFIX = "/dev/serial/by-id/"
APP_OFFSET = 0x10000
APP_MAX_SIZE = 0x1E0000
RESET_TIMEOUT = 90.0
STATE_TIMEOUT = 5.0
DIAG_INNER_TIMEOUT = 3.0
CPOL_DIAG_INNER_TIMEOUT = 8.0
DIAG_OUTER_TIMEOUT = 30.0
DIAG_ALL_TIMEOUT = 90.0
BUSY_RETRIES = 2
BUSY_DELAY = 5.0
CONTAINER_TIMEOUT = 30.0
EXPECTED_QUERY_NAMES = frozenset((
    "ati", "cpin", "cereg", "cops", "cgatt", "cgact", "cgpaddr",
    "iccid", "csq", "cesq", "cfun", "creg", "cgreg", "ceer",
    "cimi", "cpol", "cgdcont",
))
QUERY_NAMES = tuple(usb_recovery.QUERY_COMMANDS)
if frozenset(QUERY_NAMES) != EXPECTED_QUERY_NAMES or len(QUERY_NAMES) != 17:
    raise RuntimeError("USB diagnostic query allowlist must contain exactly 17 IDs")

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
    "unknown", "last_error", "0", "1", "2", "3",
))


@dataclass(frozen=True)
class SerialDevice:
    by_id: str
    target: str


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
        raise ValueError("device symlink target is unavailable") from exc
    if not stat.S_ISCHR(mode):
        raise ValueError("device symlink target is not a character device")
    return SerialDevice(by_id, str(target))


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
    text: bool = True, stage: str = "external command",
) -> subprocess.CompletedProcess:
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
    raise usb_recovery.DeviceError("esptool.py and docker are not installed")


def _container_path(path: Path) -> str:
    try:
        relative = path.resolve().relative_to(ROOT.resolve())
    except ValueError as exc:
        raise usb_recovery.DeviceError("image is outside the mapped worktree") from exc
    return str(Path("/workspace") / relative)


def _docker_command(
    arguments: list[str], device: SerialDevice, image: Path | None = None,
    program: str | None = "esptool.py", entrypoint: str | None = None,
) -> list[str]:
    mapped = []
    for argument in arguments:
        if argument == device.by_id:
            mapped.append(CONTAINER_DEVICE_PATH)
        elif image and argument == str(image):
            mapped.append(_container_path(image))
        else:
            mapped.append(argument)
    command = [
        "docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
        "--env", "SMS_DEVICE_IN_CONTAINER=1",
        "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=16m",
        "--volume", f"{ROOT.resolve()}:/workspace:ro",
        "--device", f"{device.target}:{CONTAINER_DEVICE_PATH}",
        "--workdir", "/workspace",
    ]
    if entrypoint:
        command.extend(("--entrypoint", entrypoint))
    command.append(IDF_IMAGE)
    if program:
        command.append(program)
    return [*command, *mapped]


def _run_esptool(arguments: list[str], device: SerialDevice, timeout: float, image: Path | None = None) -> None:
    if resolve_esptool() == "host":
        command = [ESPTOOL, *arguments]
    else:
        command = _docker_command(arguments, device, image)
    result = _run_process(command, timeout=timeout, stage="esptool")
    if result.returncode:
        raise usb_recovery.DeviceError(
            f"esptool failed (exit {result.returncode}; {_safe_error_class(result.stderr)})"
        )


def run_esptool(device: SerialDevice, timeout: float) -> None:
    """以固定 reset options 執行 esptool chip_id。"""
    _run_esptool([
        "--chip", "esp32c3",
        "--port", device.by_id,
        "--before", "usb_reset",
        "--after", "hard_reset",
        "chip_id",
    ], device, timeout)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


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
) -> bytes | dict[str, object]:
    if deadline is not None and caller_timeout is None:
        caller_timeout = _remaining(deadline)
    if caller_timeout is not None:
        timeout = min(timeout, caller_timeout)
    process_timeout = min(CONTAINER_TIMEOUT, timeout if caller_timeout is None else caller_timeout)
    if deadline is not None:
        process_timeout = min(process_timeout, _remaining(deadline))
        timeout = min(timeout, process_timeout)
    arguments = [
        "/workspace/tools/usb_recovery.py", "--device", CONTAINER_DEVICE_PATH,
        "--timeout", str(timeout), "--internal-container",
    ]
    if query is None:
        arguments.append("ota-state" if command == usb_recovery.COMMAND_OTA_STATE else "state")
    else:
        arguments.extend(("query", query, "--raw"))
    result = _run_process(
        _docker_command(arguments, device, program=None, entrypoint=CONTAINER_PYTHON),
        timeout=process_timeout,
        text=query is not None,
        stage="USB recovery",
    )
    if deadline is not None:
        _remaining(deadline)
    if result.returncode:
        if query is not None:
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
        return (
            set(result) == common | {"error"}
            and result.get("error") == "invalid-response"
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
        return result == {
            "query_id": query_id,
            "valid": True,
            "entry_count": 0,
            "entries": [],
        }
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
        for field, length in zip(location["fields"], (4, 8)):
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
        timeout=process_timeout,
        text=True,
        stage="USB recovery",
    )
    _remaining(deadline)
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
    container_timeout: float = CONTAINER_TIMEOUT, deadline: float | None = None,
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
        if not _host_transport_unavailable(error):
            raise
        if deadline is not None:
            container_timeout = min(container_timeout, _remaining(deadline))
        return _container_recovery(
            device, timeout, caller_timeout=container_timeout, deadline=deadline
        )  # type: ignore[return-value]


def _ota_state(
    device: SerialDevice, timeout: float = STATE_TIMEOUT, *,
    container_timeout: float = CONTAINER_TIMEOUT, deadline: float | None = None,
) -> dict[str, object]:
    try:
        transaction_args = {}
        if deadline is not None:
            transaction_args["deadline"] = deadline
        response = usb_recovery.run_transaction(
            device.by_id, timeout, usb_recovery.COMMAND_OTA_STATE, b"", **transaction_args
        )
        return usb_recovery.decode_ota_state_payload(response.payload)
    except usb_recovery.CommandError:
        raise
    except (usb_recovery.DeviceError, OSError, ImportError) as error:
        if not _host_transport_unavailable(error):
            raise
        if deadline is not None:
            container_timeout = min(container_timeout, _remaining(deadline))
        result = _container_recovery(
            device, timeout, caller_timeout=container_timeout, deadline=deadline,
            command=usb_recovery.COMMAND_OTA_STATE,
        )
        return usb_recovery.validate_ota_state(result)


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


def _diag_query(device: SerialDevice, query_name: str, deadline: float) -> bytes:
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
            return response.payload
        except usb_recovery.CommandError as exc:
            if exc.status != usb_recovery.STATUS_BUSY or busy_retries >= BUSY_RETRIES:
                raise
            busy_retries += 1
            remaining = _remaining(deadline)
            if remaining <= BUSY_DELAY:
                raise usb_recovery.DeviceError("device operation timed out")
            time.sleep(BUSY_DELAY)
        except (usb_recovery.DeviceError, OSError, ImportError) as error:
            if not _ALLOW_DIAG_CONTAINER_FALLBACK or not _host_transport_unavailable(error):
                raise
            try:
                remaining = _remaining(deadline)
                return _container_recovery(
                    device, timeout, query_name, caller_timeout=remaining, deadline=deadline
                )  # type: ignore[return-value]
            except usb_recovery.CommandError as container_error:
                if (
                    container_error.status != usb_recovery.STATUS_BUSY
                    or busy_retries >= BUSY_RETRIES
                ):
                    raise
                busy_retries += 1
                remaining = _remaining(deadline)
                if remaining <= BUSY_DELAY:
                    raise usb_recovery.DeviceError("device operation timed out")
                time.sleep(BUSY_DELAY)


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
        raw_payloads: list[bytes] = []
        completed = 0
        try:
            while completed < len(names):
                name = names[completed]
                payload = _diag_query(device, name, deadline)
                query_id = usb_recovery.QUERY_COMMANDS[name][0]
                if args.raw:
                    if query_id == usb_recovery.QUERY_CPOL:
                        safe = usb_recovery.sanitize_query_response(query_id, payload)
                        if not safe["valid"]:
                            raise usb_recovery.DeviceError("CPOL response is not a safe summary")
                    raw_payloads.append(payload)
                else:
                    results[name] = usb_recovery.sanitize_query_response(query_id, payload)
                completed += 1
        except (usb_recovery.DeviceError, OSError, ImportError) as error:
            if not _host_transport_unavailable(error):
                raise
            batch_results = _container_recovery_batch(device, names[completed:], deadline=deadline)
            if args.raw:
                for name, payload in zip(names[:completed], raw_payloads):
                    results[name] = usb_recovery.sanitize_query_response(
                        usb_recovery.QUERY_COMMANDS[name][0], payload,
                    )
                results.update(batch_results)
                print(json.dumps(results, sort_keys=True))
                return 0
            results.update(batch_results)
        finally:
            _ALLOW_DIAG_CONTAINER_FALLBACK = previous_fallback

        if args.raw:
            for payload in raw_payloads:
                _write_raw(payload)
        else:
            print(json.dumps(results, sort_keys=True))
        return 0

    results: dict[str, object] = {}
    name = names[0]
    payload = _diag_query(device, name, deadline)
    query_id = usb_recovery.QUERY_COMMANDS[name][0]
    if args.raw:
        if query_id == usb_recovery.QUERY_CPOL:
            safe = usb_recovery.sanitize_query_response(query_id, payload)
            if not safe["valid"]:
                raise usb_recovery.DeviceError("CPOL response is not a safe summary")
        _write_raw(payload)
    else:
        results[name] = usb_recovery.sanitize_query_response(query_id, payload)
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


def _flash_command(args: argparse.Namespace) -> int:
    device_path = resolve_device(args.device)
    if args.image and args.image_option:
        raise ValueError("choose one app image")
    image = Path(args.image_option or args.image or str(DEFAULT_APP_IMAGE))
    image = resolve_app_image(image)
    size = validate_app0_image(image)
    plan = {
        "action": "flash-app0",
        "device": device_path,
        "image": str(image),
        "live": bool(args.live),
        "max_size": APP_MAX_SIZE,
        "offset": f"0x{APP_OFFSET:X}",
        "size": size,
    }
    if not args.live:
        print(json.dumps(plan, sort_keys=True))
        return 0

    device = resolve_serial_device(device_path)
    _run_baseline(image.parent)
    digest = sha256_file(image)
    pin = args.sha256_pin
    if len(pin) != 64 or any(char not in "0123456789abcdefABCDEF" for char in pin):
        raise ValueError("--sha256 must be a 64-character SHA-256 pin")
    if pin.lower() != digest:
        raise ValueError("SHA-256 pin does not match app image")
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
        "write_flash",
        f"0x{APP_OFFSET:X}",
        str(image),
    ]
    _run_esptool(arguments, device, RESET_TIMEOUT, image=image)
    plan["sha256"] = digest
    print(json.dumps(plan, sort_keys=True))
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

    state = commands.add_parser("state", help="read sanitized device state")
    state.add_argument("--json", action="store_true", help="write the default JSON state format")

    commands.add_parser("ota-state", help="read safe signed OTA state")

    diag = commands.add_parser("diag", help="run fixed read-only modem diagnostics")
    diag.add_argument("query_name", nargs="?", choices=(*QUERY_NAMES, "all"))
    diag.add_argument("--id", dest="query_option", choices=(*QUERY_NAMES, "all"))
    diag.add_argument("--all", action="store_true", help="run all 17 fixed queries")
    diag.add_argument("--raw", action="store_true", help="write raw response to stdout only")

    reset = commands.add_parser("reset", help="reset and probe one exact device")
    reset.add_argument("--live", action="store_true", help="perform the reset")
    reset.add_argument("--confirm", "--confirm-device", dest="confirm", help="exact device basename confirmation")

    flash = commands.add_parser("flash-app0", help="flash only the app0 slot")
    flash.add_argument("image", nargs="?")
    flash.add_argument("--image", dest="image_option")
    flash.add_argument("--live", action="store_true", help="perform the flash")
    flash.add_argument("--confirm", "--confirm-device", dest="confirm", help="exact device basename confirmation")
    flash.add_argument("--sha256", "--sha256-pin", dest="sha256_pin", default="")

    for command in (commands.choices["state"], commands.choices["ota-state"], diag, reset, flash):
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
        if args.command == "state":
            deadline = time.monotonic() + CONTAINER_TIMEOUT
            state = _state(resolve_serial_device(args.device), deadline=deadline)
            print(json.dumps(state, sort_keys=True))
            return 0
        if args.command == "ota-state":
            deadline = time.monotonic() + CONTAINER_TIMEOUT
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
