#!/usr/bin/env python3
"""Bounded USB recovery protocol and its small command-line client."""

from __future__ import annotations

import argparse
import dataclasses
import errno
import fcntl
import getpass
import hashlib
import json
import math
import os
import re
import secrets
import select
import struct
import sys
import termios
import time
import tty
from collections.abc import Iterable


MAGIC = b"SR"
VERSION = 1
COMMAND_STATE = 0x01
COMMAND_WIFI_PROVISION = 0x02
COMMAND_WIFI_PROVISION_ASYNC = 0x03
COMMAND_WIFI_PROVISION_STATUS = 0x04
COMMAND_MODEM_QUERY = 0x05
COMMAND_OTA_STATE = 0x06
COMMAND_OTA_MIGRATION_RECOVER = 0x07
RETRYABLE_READ_COMMANDS = frozenset((COMMAND_STATE, COMMAND_OTA_STATE))
RESPONSE_MASK = 0x80
RESPONSE_STATE = COMMAND_STATE | RESPONSE_MASK
RESPONSE_WIFI_PROVISION = COMMAND_WIFI_PROVISION | RESPONSE_MASK
RESPONSE_WIFI_PROVISION_ASYNC = COMMAND_WIFI_PROVISION_ASYNC | RESPONSE_MASK
RESPONSE_WIFI_PROVISION_STATUS = COMMAND_WIFI_PROVISION_STATUS | RESPONSE_MASK
RESPONSE_MODEM_QUERY = COMMAND_MODEM_QUERY | RESPONSE_MASK
RESPONSE_OTA_STATE = COMMAND_OTA_STATE | RESPONSE_MASK
RESPONSE_OTA_MIGRATION_RECOVER = COMMAND_OTA_MIGRATION_RECOVER | RESPONSE_MASK
QUERY_ATI = 0x01
QUERY_CPIN = 0x02
QUERY_CEREG = 0x03
QUERY_COPS = 0x04
QUERY_CGATT = 0x05
QUERY_CGACT = 0x06
QUERY_CGPADDR = 0x07
QUERY_ICCID = 0x08
QUERY_CSQ = 0x09
QUERY_CESQ = 0x0A
QUERY_CFUN = 0x0B
QUERY_CREG = 0x0C
QUERY_CGREG = 0x0D
QUERY_CEER = 0x0E
QUERY_CIMI = 0x0F
QUERY_CPOL = 0x10
QUERY_CGDCONT = 0x11
QUERY_COMMANDS = {
    "ati": (QUERY_ATI, "ATI"),
    "cpin": (QUERY_CPIN, "AT+CPIN?"),
    "cereg": (QUERY_CEREG, "AT+CEREG?"),
    "cops": (QUERY_COPS, "AT+COPS?"),
    "cgatt": (QUERY_CGATT, "AT+CGATT?"),
    "cgact": (QUERY_CGACT, "AT+CGACT?"),
    "cgpaddr": (QUERY_CGPADDR, "AT+CGPADDR"),
    "iccid": (QUERY_ICCID, "AT+ICCID"),
    "csq": (QUERY_CSQ, "AT+CSQ"),
    "cesq": (QUERY_CESQ, "AT+CESQ"),
    "cfun": (QUERY_CFUN, "AT+CFUN?"),
    "creg": (QUERY_CREG, "AT+CREG?"),
    "cgreg": (QUERY_CGREG, "AT+CGREG?"),
    "ceer": (QUERY_CEER, "AT+CEER"),
    "cimi": (QUERY_CIMI, "AT+CIMI"),
    "cpol": (QUERY_CPOL, "AT+CPOL?"),
    "cgdcont": (QUERY_CGDCONT, "AT+CGDCONT?"),
}
REQUEST_COMMANDS = frozenset((
    COMMAND_STATE,
    COMMAND_WIFI_PROVISION,
    COMMAND_WIFI_PROVISION_ASYNC,
    COMMAND_WIFI_PROVISION_STATUS,
    COMMAND_MODEM_QUERY,
    COMMAND_OTA_STATE,
    COMMAND_OTA_MIGRATION_RECOVER,
))
RESPONSE_COMMANDS = frozenset((
    RESPONSE_STATE,
    RESPONSE_WIFI_PROVISION,
    RESPONSE_WIFI_PROVISION_ASYNC,
    RESPONSE_WIFI_PROVISION_STATUS,
    RESPONSE_MODEM_QUERY,
    RESPONSE_OTA_STATE,
    RESPONSE_OTA_MIGRATION_RECOVER,
))
ALL_COMMANDS = REQUEST_COMMANDS | RESPONSE_COMMANDS

STATUS_OK = 0
STATUS_INVALID_ARG = 1
STATUS_NOT_FOUND = 2
STATUS_INVALID_STATE = 3
STATUS_TIMEOUT = 4
STATUS_NO_MEM = 5
STATUS_BUSY = 6
STATUS_NOT_READY = 7
STATUS_INTERNAL = 255

STATUS_NAMES = {
    STATUS_OK: "ok",
    STATUS_INVALID_ARG: "invalid-argument",
    STATUS_NOT_FOUND: "not-found",
    STATUS_INVALID_STATE: "invalid-state",
    STATUS_TIMEOUT: "timeout",
    STATUS_NO_MEM: "no-memory",
    STATUS_BUSY: "busy",
    STATUS_NOT_READY: "not-ready",
    STATUS_INTERNAL: "internal-error",
}
STATUS_CODES = {name: status for status, name in STATUS_NAMES.items()}
BUSY_REASON_NAMES = {
    1: "gate_closed",
    2: "mutex_timeout",
    3: "slots_full",
    4: "queue_full",
}
BUSY_REASON_CODES = {name: code for code, name in BUSY_REASON_NAMES.items()}
_PROTOCOL_ERROR = re.compile(
    r"device rejected request \((?:"
    rf"(?P<status>{'|'.join(re.escape(name) for status, name in STATUS_NAMES.items() if status not in (STATUS_OK, STATUS_BUSY))})"
    rf"|busy(?:; (?P<reason>{'|'.join(re.escape(name) for name in BUSY_REASON_CODES)}))?"
    r")\)\r?\n?"
)

MAX_SSID_BYTES = 31
MAX_PASSWORD_BYTES = 63
MAX_PAYLOAD = 100
MAX_ASYNC_PROVISION_PAYLOAD = 104
MAX_QUERY_PAYLOAD = 1
MAX_QUERY_RESPONSE = 96
APP0_OFFSET = 0x10000
APP1_OFFSET = 0x1F0000
OTA_IMAGE_STATE_OTHER = 0
OTA_IMAGE_STATE_PENDING_VERIFY = 1
OTA_IMAGE_STATE_VALID = 2
OTA_IMAGE_STATE_NAMES = {
    OTA_IMAGE_STATE_OTHER: "other",
    OTA_IMAGE_STATE_PENDING_VERIFY: "pending-verify",
    OTA_IMAGE_STATE_VALID: "valid",
}
OTA_STATE_STRUCT = struct.Struct("<IBBIII")
OTA_STATE_PAYLOAD_SIZE = OTA_STATE_STRUCT.size
HEADER = struct.Struct("<2sBBHB")
HEADER_SIZE = HEADER.size
CRC_SIZE = 2
MAX_FRAME = HEADER_SIZE + MAX_ASYNC_PROVISION_PAYLOAD + CRC_SIZE
PARSER_BUFFER_SIZE = MAX_FRAME * 2
PARSER_IDLE_TIMEOUT = 1.0
STATE_TIMEOUT = 5.0
STATE_PAYLOAD_SIZE = 9
PROVISION_TIMEOUT = 90.0
PROVISION_IDLE = 0
PROVISION_PENDING = 1
PROVISION_SETUP_STARTED = 2
PROVISION_FAILED = 3
PROVISION_TERMINAL = frozenset((PROVISION_SETUP_STARTED, PROVISION_FAILED))
PROVISION_STATUS_PAYLOAD = 11
QUERY_TIMEOUT = 3.0
CPOL_QUERY_TIMEOUT = 8.0
BATCH_QUERY_TIMEOUT = 90.0
BATCH_BUSY_RETRIES = 2
BATCH_BUSY_DELAY = 5.0
MAX_TIMEOUT = 90.0
INTERNAL_DEVICE_PATH = "/dev/sms-device"
_sequence_value = secrets.randbelow(256)


class DeviceError(RuntimeError):
    pass


def validate_timeout(timeout: float) -> float:
    if not math.isfinite(timeout) or not 0 < timeout <= MAX_TIMEOUT:
        raise ValueError("timeout must be finite, positive, and no more than 90 seconds")
    return timeout


def busy_reason_name(payload: bytes) -> str | None:
    if not payload:
        return None
    if len(payload) != 1:
        return "unknown"
    return BUSY_REASON_NAMES.get(payload[0], "unknown")


def parse_protocol_error(error: str | bytes | None) -> tuple[int | None, bytes]:
    """將 child stderr 的固定 protocol error 轉成 status/reason，不回傳原文。"""
    if isinstance(error, bytes):
        try:
            error = error.decode("ascii")
        except UnicodeDecodeError:
            return None, b""
    if not isinstance(error, str):
        return None, b""
    match = _PROTOCOL_ERROR.fullmatch(error)
    if match is None:
        return None, b""
    status_name_value = match.group("status") or "busy"
    status = STATUS_CODES[status_name_value]
    reason_name = match.group("reason")
    if reason_name is None:
        return status, b""
    return status, bytes((BUSY_REASON_CODES[reason_name],))


def busy_reason_payload_from_error(error: str | bytes | None) -> bytes:
    """將 child stderr 的 busy 行轉成有限 reason payload，不回傳原文。"""
    status, payload = parse_protocol_error(error)
    return payload if status == STATUS_BUSY else bytes((0,))


class CommandError(DeviceError):
    def __init__(self, status: int, reason_payload: bytes = b""):
        self.status = status
        self.reason = busy_reason_name(reason_payload) if status == STATUS_BUSY else None
        detail = f"; {self.reason}" if self.reason is not None else ""
        super().__init__(f"device rejected request ({status_name(status)}{detail})")


@dataclasses.dataclass(frozen=True)
class Frame:
    command: int
    sequence: int
    payload: bytes


def crc16(data: bytes) -> int:
    value = 0xFFFF
    for byte in data:
        value ^= byte << 8
        for _ in range(8):
            value = ((value << 1) ^ 0x1021) & 0xFFFF if value & 0x8000 else (value << 1) & 0xFFFF
    return value


def _build_unchecked_frame(command: int, payload: bytes, sequence: int) -> bytes:
    header = HEADER.pack(MAGIC, VERSION, command, len(payload), sequence & 0xFF)
    return header + payload + struct.pack("<H", crc16(header + payload))


def _max_payload(command: int) -> int:
    if command == COMMAND_WIFI_PROVISION_ASYNC:
        return MAX_ASYNC_PROVISION_PAYLOAD
    if command == COMMAND_MODEM_QUERY:
        return MAX_QUERY_PAYLOAD
    if command in (COMMAND_OTA_STATE, COMMAND_OTA_MIGRATION_RECOVER):
        return 0
    return MAX_PAYLOAD


def build_frame(command: int, payload: bytes, sequence: int) -> bytes:
    if command not in ALL_COMMANDS:
        raise ValueError("unsupported command")
    max_payload = _max_payload(command)
    if len(payload) > max_payload:
        raise ValueError("payload is too large")
    if not 0 <= sequence <= 0xFF:
        raise ValueError("sequence is out of range")
    return _build_unchecked_frame(command, payload, sequence)


class FrameParser:
    """Resynchronize on MAGIC while retaining at most two bounded frames."""

    def __init__(self, allowed_commands: Iterable[int]):
        self._allowed = frozenset(allowed_commands)
        self._buffer = bytearray()
        self._last_activity = 0.0

    @property
    def buffered(self) -> int:
        return len(self._buffer)

    def feed(self, data: bytes) -> list[Frame]:
        if data:
            self._last_activity = time.monotonic()
        if len(data) > PARSER_BUFFER_SIZE:
            data = data[-PARSER_BUFFER_SIZE:]
        self._buffer.extend(data)
        if len(self._buffer) > PARSER_BUFFER_SIZE:
            del self._buffer[:-PARSER_BUFFER_SIZE]

        frames: list[Frame] = []
        while True:
            magic_at = self._buffer.find(MAGIC)
            if magic_at < 0:
                if self._buffer[-1:] == MAGIC[:1]:
                    self._buffer[:] = self._buffer[-1:]
                else:
                    self._buffer.clear()
                break
            if magic_at:
                del self._buffer[:magic_at]
            if len(self._buffer) < HEADER_SIZE:
                break
            magic, version, command, payload_len, sequence = HEADER.unpack_from(self._buffer)
            max_payload = _max_payload(command)
            if magic != MAGIC or version != VERSION or command not in self._allowed or payload_len > max_payload:
                del self._buffer[0]
                continue
            frame_len = HEADER_SIZE + payload_len + CRC_SIZE
            if len(self._buffer) < frame_len:
                break
            candidate = bytes(self._buffer[:frame_len])
            expected = struct.unpack_from("<H", candidate, frame_len - CRC_SIZE)[0]
            if crc16(candidate[:-CRC_SIZE]) != expected:
                del self._buffer[0]
                continue
            frames.append(Frame(command, sequence, candidate[HEADER_SIZE:frame_len - CRC_SIZE]))
            del self._buffer[:frame_len]
        return frames

    def reset_if_idle(self, now: float | None = None) -> None:
        if self._buffer and (now if now is not None else time.monotonic()) - self._last_activity >= PARSER_IDLE_TIMEOUT:
            self._buffer.clear()


def new_provision_nonce() -> int:
    return secrets.randbits(64) or 1


def _next_sequence() -> int:
    global _sequence_value
    sequence = _sequence_value
    _sequence_value = (sequence + 1) & 0xFF
    return sequence


def encode_wifi_provision(ssid: str, password: str) -> bytes:
    ssid_bytes = ssid.encode("utf-8")
    password_bytes = password.encode("utf-8")
    if not 1 <= len(ssid_bytes) <= MAX_SSID_BYTES or b"\x00" in ssid_bytes:
        raise ValueError("SSID length is invalid")
    if len(password_bytes) not in (0,) and not 8 <= len(password_bytes) <= MAX_PASSWORD_BYTES:
        raise ValueError("password length is invalid")
    if any(byte < 0x20 or byte > 0x7E for byte in password_bytes):
        raise ValueError("password characters are invalid")
    payload = bytes((len(ssid_bytes), len(password_bytes))) + ssid_bytes + password_bytes
    if len(payload) > MAX_PAYLOAD:
        raise ValueError("WiFi request is too large")
    return payload


def encode_wifi_provision_async(ssid: str, password: str, *, nonce: int) -> bytes:
    if not 1 <= nonce <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("provision nonce is invalid")
    payload = encode_wifi_provision(ssid, password)
    payload = nonce.to_bytes(8, "little") + payload
    if len(payload) > MAX_ASYNC_PROVISION_PAYLOAD:
        raise ValueError("WiFi request is too large")
    return payload


def encode_modem_query(query: str | int) -> bytes:
    if isinstance(query, str):
        try:
            query_id = QUERY_COMMANDS[query.lower()][0]
        except KeyError as exc:
            raise ValueError("unknown modem query") from exc
    else:
        query_id = query
    if query_id not in {item[0] for item in QUERY_COMMANDS.values()}:
        raise ValueError("unknown modem query")
    return bytes((query_id,))


_LONG_DIGITS = re.compile(r"(?<![0-9])[0-9]{15,}(?![0-9])")
_ATI_NUMERIC_ID = re.compile(r"(?<![0-9])[0-9]{8,}(?![0-9])")
_ATI_IDENTIFIER = re.compile(r"\b(?:imei|imsi|iccid|meid|esn|serial(?:\s+number)?)\b", re.I)
_ATI_MODEL = re.compile(r"^model\s*[:=]\s*(.+)$", re.I)
_CIMI = re.compile(r"[0-9]{14,16}")
_CPOL_SUMMARY = re.compile(
    r'^CPOL1;len=(\d{1,5});rec=(\d{1,4});fmt=(\d{1,2}),(\d{1,4}),(\d{1,4}),(\d{1,4});'
    r'rat=(complete|missing),(\d{1,4}),(\d{1,4}),(\d{1,4}),(\d{1,4});'
    r'bad=(\d{1,4});fail=([01])$'
)
_CPOL_RAW_MAX = 8192
_CGDCONT = re.compile(
    r'^\+CGDCONT:\s*([0-9]{1,3})\s*,\s*"([^",]*)"\s*,\s*"([^",]*)"'
    r'(?:\s*,\s*"([^",]*)")?$'
)
_PDP_TYPE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,15}")
_CEREG_STATUS = re.compile(
    r"^\+CEREG:[ ]*([0-5])[ ]*,[ ]*(0|[1-5]|11)$"
)
_CEREG_LOCATION = re.compile(
    r'^\+CEREG:[ ]*([0-5])[ ]*,[ ]*(0|[1-5]|11)[ ]*,[ ]*'
    r'"([0-9A-Fa-f]{4})"[ ]*,[ ]*"([0-9A-Fa-f]{8})"[ ]*,[ ]*7$'
)
_CEREG_STAT_NAMES = {
    0: "not-registered",
    1: "registered-home",
    2: "searching",
    3: "registration-denied",
    4: "unknown",
    5: "registered-roaming",
    11: "rlos-only",
}
_CEREG_ACT_NAMES = {7: "e-utran"}
_CEREG_MODE_NAMES = {0: "disabled", 1: "status", 2: "location"}
_CPIN_STATE_NAMES = {
    "READY": "ready",
    "SIM PIN": "sim-pin",
    "SIM PUK": "sim-puk",
    "PH-NET PIN": "ph-net-pin",
}
_COPS_MODE_NAMES = {
    0: "automatic",
    1: "manual",
    2: "deregistered",
    3: "set-only",
    4: "manual-auto",
}
_COPS_FORMAT_NAMES = {0: "long", 1: "short", 2: "numeric"}
_COPS_ACT_NAMES = {
    0: "gsm",
    1: "gsm-compact",
    2: "utran",
    3: "gsm-egprs",
    4: "utran-hsdpa",
    5: "utran-hsupa",
    6: "utran-hsdpa-hsupa",
    7: "e-utran",
}
_COPS = re.compile(
    r'^\+COPS:[ ]*([0-4])(?:[ ]*,[ ]*([0-2])(?:[ ]*,[ ]*"([^"]{0,32})"'
    r'(?:[ ]*,[ ]*([0-7]))?)?)?$'
)
_CGATT = re.compile(r'^\+CGATT:[ ]*([01])$')
_CGACT = re.compile(r'^\+CGACT:[ ]*([0-9]{1,3})[ ]*,[ ]*([01])$')
_CSQ = re.compile(r'^\+CSQ:[ ]*([0-9]{1,2}|99)[ ]*,[ ]*([0-9]{1}|99)$')
_CESQ = re.compile(
    r'^\+CESQ:[ ]*([0-9]{1,2}|99)[ ]*,[ ]*([0-9]{1,2}|99)[ ]*,[ ]*'
    r'([0-9]{1,3}|255)[ ]*,[ ]*([0-9]{1,2}|255)[ ]*,[ ]*'
    r'([0-9]{1,2}|255)[ ]*,[ ]*([0-9]{1,2}|255)$'
)
_CFUN = re.compile(r'^\+CFUN:[ ]*([0-4])$')
_ICCID = re.compile(r'^\+ICCID:[ ]*([0-9]{15,32})$')
_MAX_CGACT_ENTRIES = 16
_MAX_COPS_OPERATOR_BYTES = 32
_CSQ_RANGES = ((0, 31, 99), (0, 7, 99))
_CESQ_RANGES = ((0, 63, 99), (0, 7, 99), (0, 96, 255),
                (0, 49, 255), (0, 34, 255), (0, 97, 255))


def parse_ati_summary(payload: bytes) -> dict[str, str | None]:
    """Return safe ATI model/firmware labels without exposing modem IDs."""
    safe = _sanitize_ati(payload)
    if not safe.get("valid"):
        return {"model": None, "firmware": None}
    return {"model": safe["model"], "firmware": safe["firmware"]}


def _invalid_query_response(query_id: int) -> dict[str, object]:
    return {"query_id": query_id, "valid": False, "error": "invalid-response"}


def _unavailable_query_response(query_id: int) -> dict[str, object]:
    return {"query_id": query_id, "valid": False, "error": "unavailable"}


def _has_forbidden_controls(text: str) -> bool:
    return any(
        (ord(char) < 0x20 and char not in "\r\n") or 0x7F <= ord(char) <= 0x9F
        for char in text
    )


def _query_data_lines(payload: bytes) -> list[str] | None:
    if len(payload) > MAX_QUERY_RESPONSE:
        return None
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        return None
    if _has_forbidden_controls(text):
        return None
    lines = text.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    while lines and not lines[0].strip(" \t"):
        lines.pop(0)
    while lines and not lines[-1].strip(" \t"):
        lines.pop()
    if not lines or lines[-1].strip(" \t") != "OK":
        return None
    data = [line.strip(" \t") for line in lines[:-1]]
    if any(not line or line in {"ERROR", "+CME ERROR", "+CMS ERROR"} or
           line.startswith("ERROR") or line.startswith("+CME ERROR") or
           line.startswith("+CMS ERROR") for line in data):
        return None
    return data


_GENERIC_QUERY_PATTERNS = {
    QUERY_CPIN: re.compile(r'^\+CPIN:\s*(READY|SIM PIN|SIM PUK|PH-NET PIN)$'),
    QUERY_CEREG: re.compile(r'^\+CEREG:\s*[0-5](?:\s*,\s*[0-9A-Fa-f]{1,8}){0,2}$'),
    QUERY_COPS: re.compile(r'^\+COPS:\s*[0-4](?:\s*,\s*[0-4](?:\s*,\s*"[ -~]{0,32}")?(?:\s*,\s*[0-9]{1,3})?)?$'),
    QUERY_CGATT: re.compile(r'^\+CGATT:\s*[01]$'),
    QUERY_CGACT: re.compile(r'^\+CGACT:\s*[0-9]{1,3}\s*,\s*[01]$'),
    QUERY_CGPADDR: re.compile(r'^\+CGPADDR:\s*[0-9]{1,3}(?:\s*,\s*[0-9A-Fa-f:.]{1,39})?$'),
    QUERY_ICCID: re.compile(r'^\+ICCID:\s*[0-9]{15,32}$'),
    QUERY_CSQ: re.compile(r'^\+CSQ:\s*(?:[0-9]{1,3}|99)\s*,\s*(?:[0-9]{1,3}|99)$'),
    QUERY_CESQ: re.compile(r'^\+CESQ:\s*(?:[0-9]{1,3}|255)(?:\s*,\s*(?:[0-9]{1,3}|255)){5}$'),
    QUERY_CFUN: re.compile(r'^\+CFUN:\s*[0-9]{1,2}$'),
    QUERY_CREG: re.compile(r'^\+CREG:\s*[0-5](?:\s*,\s*[0-9A-Fa-f]{1,8}){0,2}$'),
    QUERY_CGREG: re.compile(r'^\+CGREG:\s*[0-5](?:\s*,\s*[0-9A-Fa-f]{1,8}){0,2}$'),
    QUERY_CEER: re.compile(r'^\+CEER:\s*[ -~]{0,64}$'),
}


def _sanitize_ati(payload: bytes) -> dict[str, object]:
    query_id = QUERY_ATI
    data = _query_data_lines(payload)
    if data is None or not data:
        return _invalid_query_response(query_id)
    model: str | None = None
    firmware: str | None = None
    ignored_marker = False
    for line in data:
        if line.upper() == "ATI":
            continue
        if line.startswith("+"):
            return _invalid_query_response(query_id)
        if _ATI_IDENTIFIER.search(line):
            continue
        firmware_match = re.fullmatch(
            r"((?:Revision|Firmware|Version)\s*[:=]\s*)([A-Za-z0-9._-]{1,32})",
            line,
            re.I,
        )
        if firmware_match is not None:
            if firmware is not None:
                return _invalid_query_response(query_id)
            firmware = firmware_match.group(1) + _ATI_NUMERIC_ID.sub(
                "<redacted>", firmware_match.group(2)
            )
            continue
        candidate = _ATI_MODEL.match(line)
        candidate_text = candidate.group(1).strip() if candidate else line
        if (
            model is None
            and re.fullmatch(r"[A-Z][A-Z0-9._-]{2,31}", candidate_text)
            and any(char.isdigit() for char in candidate_text)
        ):
            if _ATI_NUMERIC_ID.search(candidate_text):
                return _invalid_query_response(query_id)
            model = candidate_text
            continue
        if (
            firmware is None
            and model is not None
            and re.fullmatch(r"[A-Z][A-Z0-9._-]{2,31}", candidate_text)
            and any(char.isdigit() for char in candidate_text)
            and candidate_text.startswith(model)
        ):
            firmware = _ATI_NUMERIC_ID.sub("<redacted>", candidate_text)
            continue
        # 部分 ATI 回覆會在 model 前帶一個未標記的 vendor marker；只忽略，不回傳。
        if (
            model is None
            and firmware is None
            and not ignored_marker
            and re.fullmatch(r"[A-Z]{3,16}", candidate_text)
        ):
            ignored_marker = True
            continue
        return _invalid_query_response(query_id)
    return {
        "query_id": query_id,
        "valid": True,
        "model": model,
        "firmware": firmware,
    }


def _safe_text_field(value: str, maximum_bytes: int) -> bool:
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return (
        0 <= len(encoded) <= maximum_bytes
        and all(char.isprintable() and char not in "\r\n" for char in value)
    )


def _sanitize_cpin(payload: bytes) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(QUERY_CPIN)
    match = re.fullmatch(r"\+CPIN:[ ]*(READY|SIM PIN|SIM PUK|PH-NET PIN)", data[0])
    if match is None:
        return _invalid_query_response(QUERY_CPIN)
    return {"query_id": QUERY_CPIN, "valid": True, "state": _CPIN_STATE_NAMES[match.group(1)]}


def _sanitize_cops(payload: bytes) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(QUERY_COPS)
    match = _COPS.fullmatch(data[0])
    if match is None:
        return _invalid_query_response(QUERY_COPS)
    mode_code = int(match.group(1))
    format_code = match.group(2)
    operator_value = match.group(3)
    act_code = match.group(4)
    if operator_value is not None and not _safe_text_field(operator_value, _MAX_COPS_OPERATOR_BYTES):
        return _invalid_query_response(QUERY_COPS)
    if operator_value is not None and format_code is None:
        return _invalid_query_response(QUERY_COPS)
    operator: dict[str, object] = {"present": bool(operator_value)}
    if operator_value:
        operator.update({
            "length": len(operator_value.encode("utf-8")),
            "sha256": _hash_value(operator_value),
        })
    return {
        "query_id": QUERY_COPS,
        "valid": True,
        "mode": _COPS_MODE_NAMES[mode_code],
        "format": None if format_code is None else _COPS_FORMAT_NAMES[int(format_code)],
        "act": None if act_code is None else _COPS_ACT_NAMES[int(act_code)],
        "operator": operator,
    }


def _sanitize_cgatt(payload: bytes) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(QUERY_CGATT)
    match = _CGATT.fullmatch(data[0])
    if match is None:
        return _invalid_query_response(QUERY_CGATT)
    return {"query_id": QUERY_CGATT, "valid": True, "attached": match.group(1) == "1"}


def _strict_decimal(value: str, maximum: int) -> int | None:
    if not re.fullmatch(r"(?:0|[1-9][0-9]*)", value):
        return None
    parsed = int(value)
    return parsed if parsed <= maximum else None


def _sanitize_cgact(payload: bytes) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None or not 1 <= len(data) <= _MAX_CGACT_ENTRIES:
        return _invalid_query_response(QUERY_CGACT)
    entries: list[dict[str, object]] = []
    seen: set[int] = set()
    for line in data:
        match = _CGACT.fullmatch(line)
        if match is None:
            return _invalid_query_response(QUERY_CGACT)
        cid = _strict_decimal(match.group(1), 255)
        if cid is None or cid in seen:
            return _invalid_query_response(QUERY_CGACT)
        seen.add(cid)
        entries.append({"cid": cid, "active": match.group(2) == "1"})
    return {
        "query_id": QUERY_CGACT,
        "valid": True,
        "entry_count": len(entries),
        "entries": entries,
    }


def _signal_value(token: str, low: int, high: int, unknown: int) -> tuple[int | None, bool] | None:
    if not re.fullmatch(r"(?:0|[1-9][0-9]{0,2})", token):
        return None
    value = int(token)
    if value == unknown:
        return None, True
    if low <= value <= high:
        return value, False
    return None


def _sanitize_csq(payload: bytes) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(QUERY_CSQ)
    match = _CSQ.fullmatch(data[0])
    if match is None:
        return _invalid_query_response(QUERY_CSQ)
    values = [_signal_value(token, *bounds) for token, bounds in zip(match.groups(), _CSQ_RANGES, strict=True)]
    if any(value is None for value in values):
        return _invalid_query_response(QUERY_CSQ)
    (rssi, rssi_unknown), (ber, ber_unknown) = values  # type: ignore[misc]
    return {
        "query_id": QUERY_CSQ,
        "valid": True,
        "rssi": rssi,
        "ber": ber,
        "unknown": {"rssi": rssi_unknown, "ber": ber_unknown},
    }


def _sanitize_cesq(payload: bytes) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(QUERY_CESQ)
    match = _CESQ.fullmatch(data[0])
    if match is None:
        return _invalid_query_response(QUERY_CESQ)
    parsed = [_signal_value(token, *bounds) for token, bounds in zip(match.groups(), _CESQ_RANGES, strict=True)]
    if any(value is None for value in parsed):
        return _invalid_query_response(QUERY_CESQ)
    values = [value for value, _unknown in parsed]  # type: ignore[misc]
    unknown = {
        name: unknown_value
        for name, (_value, unknown_value) in zip(
            ("rxlev", "ber", "rscp", "ecn0", "rsrq", "rsrp"), parsed, strict=True
        )
    }
    return {
        "query_id": QUERY_CESQ,
        "valid": True,
        "rxlev": values[0],
        "ber": values[1],
        "rscp": values[2],
        "ecn0": values[3],
        "rsrq": values[4],
        "rsrp": values[5],
        "unknown": unknown,
    }


def _sanitize_cfun(payload: bytes) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(QUERY_CFUN)
    match = _CFUN.fullmatch(data[0])
    if match is None:
        return _invalid_query_response(QUERY_CFUN)
    return {"query_id": QUERY_CFUN, "valid": True, "mode": int(match.group(1))}


def _sanitize_registration(payload: bytes, query_id: int, prefix: str) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(query_id)
    status_re = re.compile(rf"^\+{prefix}:[ ]*([0-2])[ ]*,[ ]*(0|[1-5]|11)$")
    location_re = re.compile(
        rf'^\+{prefix}:[ ]*([0-2])[ ]*,[ ]*(0|[1-5]|11)[ ]*,[ ]*'
        r'"([0-9A-Fa-f]{4})"[ ]*,[ ]*"([0-9A-Fa-f]{8})"[ ]*,[ ]*7$'
    )
    status_match = status_re.fullmatch(data[0])
    location_match = location_re.fullmatch(data[0])
    if status_match is not None:
        mode_code, stat_code = (int(value) for value in status_match.groups())
        location = {"present": False}
        act: str | None = None
        field_count = 2
        if mode_code == 2:
            return _invalid_query_response(query_id)
    elif location_match is not None:
        mode_code = int(location_match.group(1))
        stat_code = int(location_match.group(2))
        location = {
            "present": True,
            "fields": [
                {"present": True, "length": len(value), "sha256": _hash_value(value)}
                for value in location_match.groups()[2:]
            ],
        }
        act = _CEREG_ACT_NAMES[7]
        field_count = 5
        if mode_code != 2:
            return _invalid_query_response(query_id)
    else:
        return _invalid_query_response(query_id)
    stat = _CEREG_STAT_NAMES[int(stat_code)]
    home = stat == "registered-home"
    roaming = stat == "registered-roaming"
    return {
        "query_id": query_id,
        "valid": True,
        "line_count": 1,
        "field_count": field_count,
        "mode": _CEREG_MODE_NAMES[mode_code],
        "stat": stat,
        "act": act,
        "cause_flags": {"present": False},
        "home": home,
        "roaming": roaming,
        "registered": home or roaming,
        "location": location,
    }


def _sanitize_creg(payload: bytes, query_id: int, prefix: str) -> dict[str, object]:
    return _sanitize_registration(payload, query_id, prefix)


def _sanitize_iccid(payload: bytes) -> dict[str, object]:
    data = _query_data_lines(payload)
    if data is None:
        return _invalid_query_response(QUERY_ICCID)
    if not data:
        return {"query_id": QUERY_ICCID, "valid": True, "present": False, "length": 0}
    if len(data) != 1:
        return _invalid_query_response(QUERY_ICCID)
    match = _ICCID.fullmatch(data[0])
    if match is None:
        return _invalid_query_response(QUERY_ICCID)
    value = match.group(1)
    return {
        "query_id": QUERY_ICCID,
        "valid": True,
        "present": True,
        "length": len(value),
        "sha256": _hash_value(value),
    }


def _sanitize_empty_success(payload: bytes, query_id: int) -> dict[str, object]:
    if payload not in (b"OK\n", b"OK\r\n"):
        return _invalid_query_response(query_id)
    if query_id == QUERY_CEER:
        return {"query_id": query_id, "valid": True, "last_error": {"present": False}}
    return {"query_id": query_id, "valid": True, "entry_count": 0, "entries": []}


def _hash_value(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _sanitize_cimi(payload: bytes) -> dict[str, object]:
    query_id = QUERY_CIMI
    data = _query_data_lines(payload)
    if data is None:
        return _invalid_query_response(query_id)
    if not data:
        return {"query_id": query_id, "valid": True, "present": False, "length": 0}
    if len(data) != 1 or _CIMI.fullmatch(data[0]) is None:
        return _invalid_query_response(query_id)
    value = data[0]
    result: dict[str, object] = {
        "query_id": query_id,
        "valid": True,
        "present": True,
        "length": len(value),
        "sha256": _hash_value(value),
        "mcc": value[:3],
    }
    return result


def _sanitize_cpol(payload: bytes) -> dict[str, object]:
    query_id = QUERY_CPOL
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(query_id)
    match = _CPOL_SUMMARY.fullmatch(data[0])
    if match is None:
        return _invalid_query_response(query_id)
    response_length = int(match.group(1))
    record_count = int(match.group(2))
    format_bitmap = int(match.group(3))
    format_counts = [int(match.group(index)) for index in range(4, 7)]
    rat_status = match.group(7)
    rat_counts = [int(match.group(index)) for index in range(8, 12)]
    malformed_count = int(match.group(12))
    parse_failed = match.group(13) == "1"
    expected_bitmap = sum(1 << index for index, count in enumerate(format_counts) if count)
    if (response_length > _CPOL_RAW_MAX or record_count > _CPOL_RAW_MAX or
            malformed_count > _CPOL_RAW_MAX or any(count > _CPOL_RAW_MAX for count in format_counts) or
            any(count > _CPOL_RAW_MAX for count in rat_counts) or
            sum(format_counts) != record_count or format_bitmap != expected_bitmap or
            parse_failed != (malformed_count > 0) or
            any(count > record_count for count in rat_counts) or
            (rat_status == "missing" and record_count < 2 and any(rat_counts)) or
            (rat_status == "complete" and record_count == 0)):
        return _invalid_query_response(query_id)
    result: dict[str, object] = {
        "query_id": query_id,
        "valid": True,
        "raw_length": response_length,
        "record_count": record_count,
        "format_bitmap": format_bitmap,
        "format_counts": {str(index): count for index, count in enumerate(format_counts)},
        "rat_complete": rat_status == "complete",
        "malformed_count": malformed_count,
        "parse_failed": parse_failed,
    }
    result["rat_counts"] = {str(index): count for index, count in enumerate(rat_counts)}
    return result


def _sanitize_cgdcont(payload: bytes) -> dict[str, object]:
    query_id = QUERY_CGDCONT
    data = _query_data_lines(payload)
    if data is None or not data:
        return _invalid_query_response(query_id)
    entries: list[dict[str, object]] = []
    seen_cids: set[int] = set()
    for line in data:
        match = _CGDCONT.fullmatch(line)
        if match is None:
            return _invalid_query_response(query_id)
        cid = int(match.group(1))
        pdp_type = match.group(2)
        apn_value = match.group(3)
        address_value = match.group(4) or ""
        if (cid in seen_cids or not 0 <= cid <= 255 or
                _PDP_TYPE.fullmatch(pdp_type) is None):
            return _invalid_query_response(query_id)
        if not all(
            all(0x20 <= ord(char) <= 0x7E for char in field)
            for field in (pdp_type, apn_value, address_value)
        ):
            return _invalid_query_response(query_id)
        seen_cids.add(cid)

        apn_present = bool(apn_value)
        address_present = bool(address_value)
        apn: dict[str, object] = {"present": apn_present}
        address: dict[str, object] = {"present": address_present}
        if apn_present:
            apn["sha256"] = _hash_value(apn_value)
        if address_present:
            address["sha256"] = _hash_value(address_value)
        entries.append({
            "cid": cid,
            "pdp_type": pdp_type,
            "apn": apn,
            "address": address,
            "safe_flags": {
                "apn_hashed": apn_present,
                "address_hashed": address_present,
            },
        })
    return {
        "query_id": query_id,
        "valid": True,
        "entry_count": len(entries),
        "entries": entries,
    }


def _sanitize_cereg(payload: bytes) -> dict[str, object]:
    query_id = QUERY_CEREG
    data = _query_data_lines(payload)
    if data is None or len(data) != 1:
        return _invalid_query_response(query_id)

    line = data[0]
    status_match = _CEREG_STATUS.fullmatch(line)
    location_match = _CEREG_LOCATION.fullmatch(line)
    if status_match is not None:
        mode_code, stat_code = (int(value) for value in status_match.groups())
        if mode_code not in (0, 1) or stat_code not in _CEREG_STAT_NAMES:
            return _invalid_query_response(query_id)
        location = {"present": False}
        act: str | None = None
        field_count = 2
    elif location_match is not None:
        mode_code = int(location_match.group(1))
        stat_code = int(location_match.group(2))
        first_location = location_match.group(3)
        second_location = location_match.group(4)
        act_code = 7
        if (
            mode_code != 2
            or stat_code not in _CEREG_STAT_NAMES
            or act_code not in _CEREG_ACT_NAMES
        ):
            return _invalid_query_response(query_id)
        location = {
            "present": True,
            "fields": [
                {
                    "present": True,
                    "length": len(value),
                    "sha256": _hash_value(value),
                }
                for value in (first_location, second_location)
            ],
        }
        act = _CEREG_ACT_NAMES[act_code]
        field_count = 5
    else:
        return _invalid_query_response(query_id)

    stat = _CEREG_STAT_NAMES[stat_code]
    home = stat_code == 1
    roaming = stat_code == 5
    return {
        "query_id": query_id,
        "valid": True,
        "line_count": 1,
        "field_count": field_count,
        "mode": _CEREG_MODE_NAMES[mode_code],
        "stat": stat,
        "act": act,
        "cause_flags": {"present": False},
        "home": home,
        "roaming": roaming,
        "registered": home or roaming,
        "location": location,
    }


def sanitize_query_response(query_id: int, payload: bytes) -> dict[str, object]:
    if query_id not in {item[0] for item in QUERY_COMMANDS.values()}:
        return _invalid_query_response(query_id)
    if query_id == QUERY_CIMI:
        return _sanitize_cimi(payload)
    if query_id == QUERY_ATI:
        return _sanitize_ati(payload)
    if query_id == QUERY_CPOL:
        return _sanitize_cpol(payload)
    if query_id == QUERY_CGDCONT:
        return _sanitize_cgdcont(payload)
    if query_id == QUERY_CEREG:
        return _sanitize_cereg(payload)
    if query_id == QUERY_CPIN:
        return _sanitize_cpin(payload)
    if query_id == QUERY_COPS:
        return _sanitize_cops(payload)
    if query_id == QUERY_CGATT:
        return _sanitize_cgatt(payload)
    if query_id == QUERY_CGACT:
        return _sanitize_cgact(payload)
    if query_id == QUERY_CGPADDR:
        return _sanitize_empty_success(payload, query_id)
    if query_id == QUERY_CSQ:
        return _sanitize_csq(payload)
    if query_id == QUERY_CESQ:
        return _sanitize_cesq(payload)
    if query_id == QUERY_CFUN:
        return _sanitize_cfun(payload)
    if query_id == QUERY_CREG:
        return _sanitize_creg(payload, query_id, "CREG")
    if query_id == QUERY_CGREG:
        return _sanitize_creg(payload, query_id, "CGREG")
    if query_id == QUERY_CEER:
        return _sanitize_empty_success(payload, query_id)
    if query_id == QUERY_ICCID:
        return _sanitize_iccid(payload)
    data = _query_data_lines(payload)
    pattern = _GENERIC_QUERY_PATTERNS.get(query_id)
    if (
        data is None
        or not data
        or pattern is None
        or any(pattern.fullmatch(line) is None for line in data)
    ):
        return _invalid_query_response(query_id)
    redactions: list[dict[str, object]] = []

    def redact(match: re.Match[str]) -> str:
        value = match.group(0)
        redactions.append({
            "length": len(value),
            "sha256": hashlib.sha256(value.encode("ascii")).hexdigest(),
        })
        return "<redacted>"

    text = payload.decode("utf-8")
    _LONG_DIGITS.sub(redact, text)
    return {
        "query_id": query_id,
        "valid": True,
        "line_count": len(data),
        "sha256": hashlib.sha256(payload).hexdigest(),
        "redactions": redactions,
    }


def status_name(status: int) -> str:
    return STATUS_NAMES.get(status, "unknown-error")


def decode_state_payload(payload: bytes) -> dict[str, object]:
    if len(payload) != STATE_PAYLOAD_SIZE:
        raise DeviceError("malformed state response")
    flags = payload[0]
    boot_id = int.from_bytes(payload[5:9], "little")
    if boot_id == 0:
        raise DeviceError("malformed state response")
    state: dict[str, object] = {
        "ap_mode": bool(flags & 0x02),
        "credential_configured": bool(flags & 0x04),
        "ip": ".".join(str(part) for part in payload[1:5]) if flags & 0x08 else "",
        "sta_connected": bool(flags & 0x01),
        "boot_id": boot_id,
    }
    return state


def decode_ota_state_payload(payload: bytes) -> dict[str, object]:
    if len(payload) != OTA_STATE_PAYLOAD_SIZE:
        raise DeviceError("malformed OTA state response")
    active_offset, image_state, pending_verify, accepted, pending, pending_address = (
        OTA_STATE_STRUCT.unpack(payload)
    )
    if active_offset not in {APP0_OFFSET, APP1_OFFSET}:
        raise DeviceError("malformed OTA state response")
    state_name = OTA_IMAGE_STATE_NAMES.get(image_state)
    if state_name is None or pending_verify not in (0, 1):
        raise DeviceError("malformed OTA state response")
    if pending_address not in {0, APP0_OFFSET, APP1_OFFSET}:
        raise DeviceError("malformed OTA state response")
    if bool(pending_verify) != (image_state == OTA_IMAGE_STATE_PENDING_VERIFY):
        raise DeviceError("malformed OTA state response")
    return {
        "active_offset": active_offset,
        "image_state": state_name,
        "pending_verify": bool(pending_verify),
        "accepted": accepted,
        "pending": pending,
        "pending_address": pending_address,
    }


def validate_ota_state(value: object) -> dict[str, object]:
    if not isinstance(value, dict) or set(value) != {
        "active_offset", "image_state", "pending_verify",
        "accepted", "pending", "pending_address",
    }:
        raise DeviceError("malformed OTA state response")
    active_offset = value["active_offset"]
    image_state = value["image_state"]
    pending_verify = value["pending_verify"]
    accepted = value["accepted"]
    pending = value["pending"]
    pending_address = value["pending_address"]
    if (
        not isinstance(active_offset, int) or isinstance(active_offset, bool)
        or active_offset not in {APP0_OFFSET, APP1_OFFSET}
        or not isinstance(image_state, str)
        or image_state not in OTA_IMAGE_STATE_NAMES.values()
        or not isinstance(pending_verify, bool)
        or pending_verify != (image_state == "pending-verify")
        or not all(
            isinstance(counter, int) and not isinstance(counter, bool)
            and 0 <= counter <= 0xFFFFFFFF
            for counter in (accepted, pending)
        )
        or not isinstance(pending_address, int)
        or isinstance(pending_address, bool)
        or pending_address not in {0, APP0_OFFSET, APP1_OFFSET}
    ):
        raise DeviceError("malformed OTA state response")
    return {
        "active_offset": active_offset,
        "image_state": image_state,
        "pending_verify": pending_verify,
        "accepted": accepted,
        "pending": pending,
        "pending_address": pending_address,
    }


def decode_provision_status_payload(payload: bytes) -> dict[str, int]:
    if len(payload) != PROVISION_STATUS_PAYLOAD:
        raise DeviceError("malformed WiFi provision status")
    return {
        "nonce": int.from_bytes(payload[:8], "little"),
        "state": payload[8],
        "error": payload[9],
        "connection": payload[10],
    }


def _wait_for_provision(
    device: str,
    nonce: int,
    deadline: float,
    request_error: DeviceError | None,
    *,
    internal_container: bool = False,
) -> None:
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            if request_error is not None:
                raise request_error
            raise DeviceError("USB WiFi provisioning timed out")
        try:
            response = run_transaction(
                device,
                min(STATE_TIMEOUT, remaining),
                COMMAND_WIFI_PROVISION_STATUS,
                nonce.to_bytes(8, "little"),
                deadline=deadline,
                **({"internal_container": True} if internal_container else {}),
            )
            state = decode_provision_status_payload(response.payload)
        except CommandError as error:
            if error.status != STATUS_NOT_FOUND:
                raise
            state = None
        except DeviceError:
            state = None
        if state is not None and state["nonce"] == nonce:
            job_state = state["state"]
            if job_state == PROVISION_SETUP_STARTED:
                return
            if job_state == PROVISION_FAILED:
                raise CommandError(int(state["error"]))
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            continue
        time.sleep(min(0.25, remaining))


def _wait(fd: int, readable: bool, deadline: float) -> None:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise DeviceError("USB device timed out")
    ready = select.select([fd] if readable else [], [] if readable else [fd], [], remaining)
    if time.monotonic() >= deadline:
        raise DeviceError("USB device timed out")
    if not ready[0] and not ready[1]:
        raise DeviceError("USB device timed out")


class Device:
    def __init__(self, path: str, timeout: float = 5.0, *, internal_container: bool = False):
        prefix = "/dev/serial/by-id/"
        if path == INTERNAL_DEVICE_PATH:
            if not internal_container or os.environ.get("SMS_DEVICE_IN_CONTAINER") != "1":
                raise ValueError("--device must be an explicit /dev/serial/by-id path")
        elif not path.startswith(prefix):
            raise ValueError("--device must be an explicit /dev/serial/by-id path")
        name = path[len(prefix):] if path.startswith(prefix) else ""
        if path != INTERNAL_DEVICE_PATH and (not name or "/" in name or name in {".", ".."}):
            raise ValueError("--device must be an explicit /dev/serial/by-id path")
        self.path = path
        self.timeout = validate_timeout(timeout)
        self.fd: int | None = None
        self._saved_termios = None

    def __enter__(self) -> "Device":
        fd: int | None = None
        saved_termios = None
        stage = "open"
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK | os.O_CLOEXEC)
            stage = "flock"
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            stage = "TIOCEXCL"
            fcntl.ioctl(fd, termios.TIOCEXCL)
            stage = "termios"
            saved_termios = termios.tcgetattr(fd)
            tty.setraw(fd)
        except OSError as exc:
            if fd is not None:
                if saved_termios is not None:
                    try:
                        termios.tcsetattr(fd, termios.TCSANOW, saved_termios)
                    except OSError:
                        pass
                try:
                    os.close(fd)
                except OSError:
                    pass
            code = errno.errorcode.get(exc.errno, str(exc.errno))
            raise DeviceError(f"could not claim the USB device ({stage}: {code})") from exc
        except AttributeError as exc:
            if fd is not None:
                if saved_termios is not None:
                    try:
                        termios.tcsetattr(fd, termios.TCSANOW, saved_termios)
                    except OSError:
                        pass
                try:
                    os.close(fd)
                except OSError:
                    pass
            raise DeviceError(f"could not claim the USB device ({stage}: unsupported host API)") from exc
        self.fd = fd
        self._saved_termios = saved_termios
        return self

    def __exit__(self, *_: object) -> None:
        if self.fd is not None:
            fd = self.fd
            saved_termios = self._saved_termios
            self.fd = None
            self._saved_termios = None
            try:
                if saved_termios is not None:
                    termios.tcsetattr(fd, termios.TCSANOW, saved_termios)
                fcntl.flock(fd, fcntl.LOCK_UN)
                os.close(fd)
            except OSError as exc:
                raise DeviceError("USB device cleanup failed") from exc

    def _write_all(self, data: bytes, deadline: float) -> None:
        if self.fd is None:
            raise DeviceError("USB device is closed")
        offset = 0
        while offset < len(data):
            try:
                written = os.write(self.fd, data[offset:])
            except BlockingIOError:
                _wait(self.fd, False, deadline)
                continue
            except OSError as exc:
                raise DeviceError("USB device disconnected") from exc
            if written <= 0:
                raise DeviceError("USB device disconnected")
            offset += written

    def transact(self, command: int, payload: bytes, sequence: int | None = None) -> Frame:
        if command not in REQUEST_COMMANDS:
            raise ValueError("unsupported request")
        if self.fd is None:
            raise DeviceError("USB device is closed")
        if sequence is None:
            sequence = _next_sequence()
        deadline = time.monotonic() + self.timeout
        self._write_all(build_frame(command, payload, sequence), deadline)
        parser = FrameParser(RESPONSE_COMMANDS)
        expected_command = command | RESPONSE_MASK
        while True:
            parser.reset_if_idle()
            _wait(self.fd, True, deadline)
            try:
                chunk = os.read(self.fd, MAX_FRAME)
            except BlockingIOError:
                continue
            except OSError as exc:
                raise DeviceError("USB device disconnected") from exc
            if not chunk:
                raise DeviceError("USB device disconnected")
            parser.reset_if_idle()
            for frame in parser.feed(chunk):
                if frame.command == expected_command and frame.sequence == sequence:
                    if not frame.payload:
                        raise DeviceError("malformed USB response")
                    if frame.payload[0] != STATUS_OK:
                        raise CommandError(frame.payload[0], frame.payload[1:])
                    return Frame(frame.command, frame.sequence, frame.payload[1:])


def run_transaction(
    path: str, timeout: float, command: int, payload: bytes, *,
    internal_container: bool = False, deadline: float | None = None,
) -> Frame:
    timeout = validate_timeout(timeout)
    last_error: DeviceError | None = None
    attempts = 3 if command in RETRYABLE_READ_COMMANDS else 1
    for attempt in range(attempts):
        attempt_timeout = timeout
        if deadline is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeviceError("USB device timed out")
            attempt_timeout = min(timeout, remaining)
        try:
            device_kwargs = {"internal_container": True} if internal_container else {}
            with Device(path, attempt_timeout, **device_kwargs) as device:
                response = device.transact(command, payload)
                if deadline is not None and time.monotonic() >= deadline:
                    raise DeviceError("USB device timed out")
                return response
        except CommandError:
            raise
        except (DeviceError, OSError) as exc:
            last_error = exc if isinstance(exc, DeviceError) else DeviceError("USB device transport failed")
            if deadline is not None and deadline - time.monotonic() <= 0:
                raise DeviceError("USB device timed out") from exc
            if attempt + 1 < attempts:
                if deadline is None:
                    time.sleep(0.25)
                else:
                    remaining = deadline - time.monotonic()
                    if remaining > 0:
                        time.sleep(min(0.25, remaining))
    assert last_error is not None
    raise last_error


def _state_command(args: argparse.Namespace) -> int:
    timeout = validate_timeout(STATE_TIMEOUT if args.timeout is None else args.timeout)
    internal = {"internal_container": True} if getattr(args, "internal_container", False) else {}
    deadline = time.monotonic() + timeout
    response = run_transaction(
        args.device, timeout, COMMAND_STATE, b"", deadline=deadline, **internal
    )
    print(json.dumps(decode_state_payload(response.payload), sort_keys=True))
    return 0


def _ota_state_command(args: argparse.Namespace) -> int:
    timeout = validate_timeout(STATE_TIMEOUT if args.timeout is None else args.timeout)
    internal = {"internal_container": True} if getattr(args, "internal_container", False) else {}
    deadline = time.monotonic() + timeout
    response = run_transaction(
        args.device, timeout, COMMAND_OTA_STATE, b"", deadline=deadline, **internal,
    )
    print(json.dumps(decode_ota_state_payload(response.payload), sort_keys=True))
    return 0


def _ota_migration_recover_command(args: argparse.Namespace) -> int:
    if not getattr(args, "internal_container", False):
        raise ValueError("OTA migration recovery is available through tools/device.py")
    timeout = validate_timeout(STATE_TIMEOUT if args.timeout is None else args.timeout)
    internal = {"internal_container": True} if getattr(args, "internal_container", False) else {}
    deadline = time.monotonic() + timeout
    response = run_transaction(
        args.device, timeout, COMMAND_OTA_MIGRATION_RECOVER, b"",
        deadline=deadline, **internal,
    )
    if response.payload:
        raise DeviceError("malformed OTA migration response")
    print('{"ok":true}')
    return 0


def _query_command(args: argparse.Namespace) -> int:
    query_name = args.query_option or args.query_name
    if not query_name:
        raise ValueError("query requires --id or a query name")
    query_id = QUERY_COMMANDS[query_name][0]
    default_timeout = CPOL_QUERY_TIMEOUT if query_id == QUERY_CPOL else QUERY_TIMEOUT
    timeout = validate_timeout(default_timeout if args.timeout is None else args.timeout)
    internal = {"internal_container": True} if getattr(args, "internal_container", False) else {}
    response = run_transaction(
        args.device, timeout, COMMAND_MODEM_QUERY, encode_modem_query(query_name),
        **internal,
    )
    if not response.payload or not response.payload.strip():
        raise DeviceError("empty modem query response")
    if args.raw:
        if query_id == QUERY_CPOL and not sanitize_query_response(query_id, response.payload)["valid"]:
            raise DeviceError("CPOL response is not a safe summary")
        sys.stdout.buffer.write(response.payload)
        return 0
    print(json.dumps(sanitize_query_response(query_id, response.payload), sort_keys=True))
    return 0


def _diag_batch_command(args: argparse.Namespace) -> int:
    """Run fixed modem IDs in one development-container process."""
    if (
        not getattr(args, "internal_container", False)
        or args.device != INTERNAL_DEVICE_PATH
        or os.environ.get("SMS_DEVICE_IN_CONTAINER") != "1"
    ):
        raise ValueError("diag-batch is an internal command")
    names = tuple(args.query_names)
    if not names or len(names) != len(set(names)):
        raise ValueError("diagnostic query IDs must be unique")
    if any(name not in QUERY_COMMANDS for name in names):
        raise ValueError("unknown modem query")
    timeout = validate_timeout(
        BATCH_QUERY_TIMEOUT if args.timeout is None else args.timeout
    )
    deadline = time.monotonic() + timeout
    results: dict[str, dict[str, object]] = {}
    for name in names:
        query_id = QUERY_COMMANDS[name][0]
        retries = 0
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise DeviceError("USB device timed out")
            query_timeout = min(
                CPOL_QUERY_TIMEOUT if query_id == QUERY_CPOL else QUERY_TIMEOUT,
                remaining,
            )
            try:
                response = run_transaction(
                    args.device,
                    query_timeout,
                    COMMAND_MODEM_QUERY,
                    encode_modem_query(name),
                    internal_container=True,
                    deadline=deadline,
                )
                if time.monotonic() >= deadline:
                    raise DeviceError("USB device timed out")
                if not response.payload or not response.payload.strip():
                    raise DeviceError("empty modem query response")
                safe = sanitize_query_response(query_id, response.payload)
                if safe.get("valid") is not True:
                    results[name] = _invalid_query_response(query_id)
                    break
                results[name] = safe
                break
            except CommandError as error:
                if error.status != STATUS_BUSY or retries >= BATCH_BUSY_RETRIES:
                    results[name] = _unavailable_query_response(query_id)
                    break
                retries += 1
                remaining = deadline - time.monotonic()
                if remaining <= BATCH_BUSY_DELAY:
                    results[name] = _unavailable_query_response(query_id)
                    break
                time.sleep(BATCH_BUSY_DELAY)
    print(json.dumps(
        {"version": 1, "results": results},
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ))
    return 0


def _wifi_command(args: argparse.Namespace) -> int:
    timeout = validate_timeout(PROVISION_TIMEOUT if args.timeout is None else args.timeout)
    password = getpass.getpass("WiFi password (leave empty only for an open network with a populated Web scan cache): ")
    nonce = new_provision_nonce()
    payload = encode_wifi_provision_async(args.ssid, password, nonce=nonce)
    deadline = time.monotonic() + timeout
    request_error = None
    try:
        run_transaction(
            args.device, timeout, COMMAND_WIFI_PROVISION_ASYNC, payload,
            deadline=deadline,
            **({"internal_container": True} if getattr(args, "internal_container", False) else {}),
        )
    except CommandError:
        raise
    except DeviceError as error:
        request_error = error
    _wait_for_provision(
        args.device, nonce, deadline, request_error,
        internal_container=getattr(args, "internal_container", False),
    )
    print('{"ok":true}')
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Development USB WiFi recovery")
    parser.add_argument("--device", required=True, help="explicit /dev/serial/by-id path")
    parser.add_argument(
        "--timeout", type=float, default=None,
        help="override the default timeout (5s for state, 90s for wifi-provision)",
    )
    parser.add_argument("--internal-container", action="store_true", help=argparse.SUPPRESS)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("state")
    commands.add_parser("ota-state")
    commands.add_parser("ota-migration-recover", help=argparse.SUPPRESS)
    wifi = commands.add_parser(
        "wifi-provision",
        help="provision a network; an open network requires a populated Web scan cache",
    )
    wifi.add_argument("--ssid", required=True)
    query = commands.add_parser("query", help="run one fixed read-only modem query")
    query.add_argument("query_name", nargs="?", choices=sorted(QUERY_COMMANDS))
    query.add_argument("--id", dest="query_option", choices=sorted(QUERY_COMMANDS))
    query.add_argument("--raw", action="store_true", help="print the raw response")
    batch = commands.add_parser("diag-batch", help=argparse.SUPPRESS)
    batch.add_argument(
        "query_names", nargs="+", choices=sorted(QUERY_COMMANDS), help=argparse.SUPPRESS,
    )
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        if args.command == "state":
            return _state_command(args)
        if args.command == "ota-state":
            return _ota_state_command(args)
        if args.command == "ota-migration-recover":
            return _ota_migration_recover_command(args)
        if args.command == "query":
            return _query_command(args)
        if args.command == "diag-batch":
            return _diag_batch_command(args)
        return _wifi_command(args)
    except (CommandError, DeviceError, ValueError) as exc:
        print(str(exc).strip() or "USB recovery operation failed", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
