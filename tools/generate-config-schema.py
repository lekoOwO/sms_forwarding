#!/usr/bin/env python3
"""Generate the native ESP-IDF configuration constants from schema v5."""

from __future__ import annotations

import argparse
import difflib
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MANIFEST_PATH = ROOT / "dev_doc/config-schema/manifest.json"
FIRMWARE_OUTPUT = ROOT / "components/idf_config/include/config_schema_generated.h"


def wire_header_bytes(schema: dict, codec: dict) -> int:
    widths = {"u8": 1, "u16": 2, "u32": 4, "u64": 8}
    total = 0
    for field in schema["x-binaryCodec"]["header"]:
        try:
            total += widths[field.rsplit(":", 1)[1]]
        except (IndexError, KeyError) as exc:
            raise ValueError(f"invalid CFG2 header field: {field}") from exc
    if total != codec["headerBytes"]:
        raise ValueError("wire header metadata does not match x-binaryCodec")
    return total


def wire_size(node: dict, codec: dict, path: str = "config") -> int:
    node_type = node.get("type")
    if node_type == "string":
        return codec["stringLengthPrefixBytes"] + node["x-maxUtf8Bytes"]
    if node_type in ("boolean", "integer"):
        return codec["scalarBytes"][node_type]
    if node_type == "object":
        properties = node["properties"]
        alternatives = node.get("x-wireWorstCaseAlternatives", [])
        alternative_fields = {name for group in alternatives for name in group}
        if len(alternative_fields) != sum(len(group) for group in alternatives):
            raise ValueError(f"{path} has overlapping wire-size alternatives")
        if any(name not in properties for name in alternative_fields):
            raise ValueError(f"{path} has an unknown wire-size alternative field")
        ordered = sorted(properties.items(), key=lambda item: item[1]["x-codecOrder"])
        base = sum(
            wire_size(field, codec, f"{path}.{name}")
            for name, field in ordered
            if name not in alternative_fields
        )
        if not alternatives:
            return base
        choices = [
            sum(wire_size(properties[name], codec, f"{path}.{name}") for name in group)
            for group in alternatives
        ]
        return base + max(choices)
    if node_type == "array":
        count = node.get("x-itemCount")
        if count is None or node.get("minItems") != count or node.get("maxItems") != count:
            raise ValueError(f"{path} must declare an exact x-itemCount")
        return codec["arrayCountBytes"] + count * wire_size(node["items"], codec, f"{path}[]")
    raise ValueError(f"{path} has unsupported wire type {node_type!r}")


def validate_codec_order(properties: dict, label: str) -> None:
    ordered = [field["x-codecOrder"] for field in properties.values()]
    if sorted(ordered) != list(range(len(ordered))):
        raise ValueError(f"{label} x-codecOrder values must be unique and contiguous")


def validate_string_caps(node: object, path: str = "config") -> None:
    if not isinstance(node, dict):
        return
    if node.get("type") == "string" and "x-maxUtf8Bytes" not in node:
        raise ValueError(f"{path} is missing x-maxUtf8Bytes")
    for name, child in node.get("properties", {}).items():
        validate_string_caps(child, f"{path}.{name}")
    if "items" in node:
        validate_string_caps(node["items"], f"{path}[]")


def c_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def enum_lines(mapping: dict[str, int]) -> str:
    return "\n".join(f"  {name} = {value}," for name, value in mapping.items())


def render_firmware(schema: dict, manifest: dict) -> str:
    root = schema["properties"]
    config = root["config"]["properties"]
    channel = config["pushChannels"]["items"]["properties"]
    account = config["webAccounts"]["items"]["properties"]
    wifi = config["wifiProfiles"]["items"]["properties"]
    sim = config["simCredentials"]["items"]["properties"]
    task = config["schedTasks"]["items"]["properties"]
    envelope = manifest["backupEnvelope"]
    codec = schema["x-wireCodec"]
    header_bytes = wire_header_bytes(schema, codec)
    payload_bytes = wire_size(root["config"], codec)
    binary_bytes = header_bytes + payload_bytes
    headroom_bytes = manifest["maxBinaryBytes"] - binary_bytes
    expected_wire = schema["x-wireWorstCase"]
    if expected_wire != {
        "payloadBytes": payload_bytes,
        "binaryBytes": binary_bytes,
        "headroomBytes": headroom_bytes,
    }:
        raise ValueError("x-wireWorstCase is stale; regenerate its declared values")
    if binary_bytes > manifest["maxBinaryBytes"]:
        raise ValueError(
            f"worst-case binary size {binary_bytes} exceeds {manifest['maxBinaryBytes']}"
        )

    validate_codec_order(config, "config")
    validate_codec_order(account, "web account")
    validate_codec_order(channel, "push channel")
    validate_codec_order(wifi, "WiFi profile")
    validate_codec_order(sim, "SIM credential")
    validate_codec_order(task, "scheduled task")
    validate_string_caps(schema)

    push_types = channel["type"]["x-enumMapping"]
    if set(push_types.values()) != set(range(13)):
        raise ValueError("push type mapping must cover 0..12")
    network_modes = config["networkMode"]["x-enumMapping"]
    tx_powers = config["wifiTxPowerQuarterDbm"]["x-enumMapping"]
    locales = config["notificationLocale"]["enum"]
    if locales != ["zh-TW", "zh-CN", "en"]:
        raise ValueError("notification locale order is part of the generated ABI")

    return f"""// Generated by tools/generate-config-schema.py. Do not edit.
#ifndef CONFIG_SCHEMA_GENERATED_H
#define CONFIG_SCHEMA_GENERATED_H

#include <stddef.h>
#include <stdint.h>

constexpr const char CONFIG_FORMAT[] = {c_string(root['format']['const'])};
constexpr const char CONFIG_MIME_TYPE[] = {c_string(manifest['mimeType'])};
constexpr uint16_t CONFIG_SCHEMA_VERSION = {root['schemaVersion']['const']};
constexpr size_t MAX_CONFIG_BLOB_SIZE = {manifest['maxBinaryBytes']};
constexpr size_t CONFIG_WIRE_HEADER_BYTES = {header_bytes};
constexpr size_t CONFIG_WIRE_STRING_LENGTH_PREFIX_BYTES = {codec['stringLengthPrefixBytes']};
constexpr size_t CONFIG_WIRE_ARRAY_COUNT_BYTES = {codec['arrayCountBytes']};
constexpr size_t CONFIG_WIRE_PAYLOAD_BYTES = {payload_bytes};
constexpr size_t CONFIG_WORST_CASE_BINARY_BYTES = {binary_bytes};
constexpr size_t CONFIG_BINARY_HEADROOM_BYTES = {headroom_bytes};
constexpr const char BACKUP_ENVELOPE_MAGIC[] = {c_string(envelope['magic'])};
constexpr uint16_t BACKUP_ENVELOPE_VERSION = {envelope['version']};
constexpr uint8_t BACKUP_KDF_ID = {envelope['kdfId']};
constexpr uint32_t BACKUP_KDF_ITERATIONS = {envelope['iterations']};
constexpr size_t BACKUP_SALT_BYTES = {envelope['saltBytes']};
constexpr uint8_t BACKUP_CIPHER_ID = {envelope['cipherId']};
constexpr size_t BACKUP_IV_BYTES = {envelope['ivBytes']};
constexpr size_t BACKUP_TAG_BYTES = {envelope['tagBytes']};
constexpr size_t BACKUP_HEADER_BYTES = {envelope['headerBytes']};
constexpr bool BACKUP_LITTLE_ENDIAN = {'true' if envelope['byteOrder'] == 'little-endian' else 'false'};
constexpr size_t BACKUP_AAD_BYTES = {envelope['aadBytes']};
constexpr size_t MAX_ENCRYPTED_CONFIG_BYTES = {envelope['maxEncryptedBytes']};
#define MAX_PUSH_CHANNELS {config['pushChannels']['x-itemCount']}
#define MAX_WEB_ACCOUNTS {config['webAccounts']['x-itemCount']}
#define MAX_WIFI_PROFILES {config['wifiProfiles']['x-itemCount']}
#define MAX_SIM_CREDENTIALS {config['simCredentials']['x-itemCount']}
#define MAX_SCHED_TASKS {config['schedTasks']['x-itemCount']}

enum PushType {{
{enum_lines(push_types)}
}};

enum NetworkMode {{
{enum_lines(network_modes)}
}};

enum WifiTxPowerQuarterDbm {{
{enum_lines(tx_powers)}
}};

constexpr size_t MAX_DEVICE_NAME_BYTES = {config['deviceName']['x-maxUtf8Bytes']};
constexpr size_t MAX_HOSTNAME_LENGTH = {config['hostname']['maxLength']};
constexpr const char PORTABLE_DEVICE_NAME[] = {c_string(config['deviceName']['x-portableValue'])};
constexpr const char PORTABLE_HOSTNAME[] = {c_string(config['hostname']['x-portableValue'])};
constexpr size_t MAX_NOTIFICATION_LOCALE_BYTES = {config['notificationLocale']['x-maxUtf8Bytes']};
constexpr size_t MAX_SMTP_SERVER_BYTES = {config['smtpServer']['x-maxUtf8Bytes']};
constexpr size_t MAX_SMTP_USER_BYTES = {config['smtpUser']['x-maxUtf8Bytes']};
constexpr size_t MAX_SMTP_PASSWORD_BYTES = {config['smtpPass']['x-maxUtf8Bytes']};
constexpr size_t MAX_SMTP_RECIPIENT_BYTES = {config['smtpSendTo']['x-maxUtf8Bytes']};
constexpr size_t MAX_ADMIN_PHONE_BYTES = {config['adminPhone']['x-maxUtf8Bytes']};
constexpr size_t MAX_BLACKLIST_BYTES = {config['numberBlackList']['x-maxUtf8Bytes']};
constexpr size_t MAX_FORWARD_RULES_BYTES = {config['forwardRules']['x-maxUtf8Bytes']};
constexpr size_t MAX_WEB_USERNAME_BYTES = {account['username']['x-maxUtf8Bytes']};
constexpr size_t MAX_WEB_PASSWORD_BYTES = {account['password']['x-maxUtf8Bytes']};
constexpr size_t MAX_WIFI_SSID_BYTES = {wifi['ssid']['x-maxUtf8Bytes']};
constexpr size_t MAX_WIFI_PASSWORD_BYTES = {wifi['password']['x-maxUtf8Bytes']};
constexpr size_t MAX_KEEPALIVE_TARGET_BYTES = {config['kaTarget']['x-maxUtf8Bytes']};
constexpr size_t MAX_KEEPALIVE_URL_BYTES = {config['kaUrl']['x-maxUtf8Bytes']};
constexpr size_t MAX_KEEPALIVE_PROFILE_BYTES = {config['kaProfile']['x-maxUtf8Bytes']};
constexpr size_t MAX_NTP_SERVER_BYTES = {config['ntpServer']['x-maxUtf8Bytes']};
constexpr size_t MAX_MDNS_HOST_BYTES = {config['mdnsHost']['x-maxUtf8Bytes']};
constexpr size_t MAX_APN_BYTES = {config['apn']['x-maxUtf8Bytes']};
constexpr size_t MAX_OPERATOR_PLMN_BYTES = {config['operatorPlmn']['x-maxUtf8Bytes']};
constexpr size_t MAX_PHONE_NUMBER_BYTES = {config['phoneNumber']['x-maxUtf8Bytes']};
constexpr size_t MAX_SIM_ICCID_BYTES = {sim['iccid']['x-maxUtf8Bytes']};
constexpr size_t MAX_SIM_PIN_BYTES = {sim['pin']['x-maxUtf8Bytes']};
constexpr size_t MAX_SIM_PUK_BYTES = {sim['puk']['x-maxUtf8Bytes']};
constexpr size_t MAX_SCHEDULE_NAME_BYTES = {task['name']['x-maxUtf8Bytes']};
constexpr size_t MAX_SCHEDULE_PROFILE_BYTES = {task['profile']['x-maxUtf8Bytes']};
constexpr size_t MAX_SCHEDULE_TARGET_BYTES = {task['target']['x-maxUtf8Bytes']};
constexpr size_t MAX_SCHEDULE_PAYLOAD_BYTES = {task['payload']['x-maxUtf8Bytes']};
constexpr uint16_t MIN_HEARTBEAT_INTERVAL_HOURS = {config['heartbeatInterval']['minimum']};
constexpr uint16_t MAX_HEARTBEAT_INTERVAL_HOURS = {config['heartbeatInterval']['maximum']};
constexpr uint16_t DEFAULT_HEARTBEAT_INTERVAL_HOURS = {config['heartbeatInterval']['default']};
constexpr size_t MAX_PUSH_NAME_BYTES = {channel['name']['x-maxUtf8Bytes']};
constexpr size_t MAX_PUSH_URL_BYTES = {channel['url']['x-maxUtf8Bytes']};
constexpr size_t MAX_PUSH_KEY1_BYTES = {channel['key1']['x-maxUtf8Bytes']};
constexpr size_t MAX_PUSH_KEY2_BYTES = {channel['key2']['x-maxUtf8Bytes']};
constexpr size_t MAX_TITLE_TEMPLATE_BYTES = {channel['titleTemplate']['x-maxUtf8Bytes']};
constexpr size_t MAX_BODY_TEMPLATE_BYTES = {channel['bodyTemplate']['x-maxUtf8Bytes']};
constexpr size_t MAX_CUSTOM_BODY_BYTES = {channel['customBody']['x-maxUtf8Bytes']};
constexpr size_t MAX_RENDERED_TITLE_BYTES = {channel['titleTemplate']['x-maxRenderedUtf8Bytes']};
constexpr size_t MAX_RENDERED_BODY_BYTES = {channel['bodyTemplate']['x-maxRenderedUtf8Bytes']};
constexpr size_t MAX_RENDERED_CUSTOM_BODY_BYTES = {channel['customBody']['x-maxRenderedUtf8Bytes']};
constexpr const char NOTIFICATION_LOCALE_ZH_TW[] = {c_string(locales[0])};
constexpr const char NOTIFICATION_LOCALE_ZH_CN[] = {c_string(locales[1])};
constexpr const char NOTIFICATION_LOCALE_EN[] = {c_string(locales[2])};
constexpr const char DEFAULT_NOTIFICATION_LOCALE[] = {c_string(locales[0])};

#endif
"""


def load_inputs() -> tuple[dict, dict]:
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
    version = str(manifest["currentVersion"])
    schema_path = MANIFEST_PATH.parent / manifest["versions"][version]
    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    if version != "5" or schema["properties"]["schemaVersion"]["const"] != 5:
        raise ValueError("current schema must be v5")
    if schema["properties"]["format"]["const"] != manifest["format"]:
        raise ValueError("manifest and current schema formats differ")
    envelope = manifest["backupEnvelope"]
    if envelope["byteOrder"] != "little-endian":
        raise ValueError("only the little-endian backup envelope is supported")
    if envelope["aad"] != "header" or envelope["aadBytes"] != envelope["headerBytes"]:
        raise ValueError("backup AAD must cover the complete header")
    if envelope["maxEncryptedBytes"] != manifest["maxBinaryBytes"] + envelope["headerBytes"] + envelope["tagBytes"]:
        raise ValueError("encrypted backup size invariant is invalid")
    return manifest, schema


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    manifest, schema = load_inputs()
    expected = render_firmware(schema, manifest)
    if args.check:
        actual = FIRMWARE_OUTPUT.read_text(encoding="utf-8") if FIRMWARE_OUTPUT.exists() else ""
        if actual == expected:
            return 0
        print("".join(difflib.unified_diff(
            actual.splitlines(True), expected.splitlines(True),
            fromfile=str(FIRMWARE_OUTPUT), tofile="generated",
        )), end="")
        return 1
    FIRMWARE_OUTPUT.write_text(expected, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
