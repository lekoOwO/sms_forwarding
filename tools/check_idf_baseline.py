#!/usr/bin/env python3
"""Check the reproducible ESP-IDF baseline without requiring ESP-IDF locally."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_IDF = "6.0.2"
EXPECTED_IDF_IMAGE = (
    "espressif/idf@sha256:"
    "e3d941cb983e028aad1e2f5ecb2837254e467f2b71f3e0af67e7337bd27ae177"
)
EXPECTED_PARTITIONS = {
    "nvs": ("data", "nvs", 0x9000, 0x5000),
    "otadata": ("data", "ota", 0xE000, 0x2000),
    "app0": ("app", "ota_0", 0x10000, 0x1E0000),
    "app1": ("app", "ota_1", 0x1F0000, 0x1E0000),
    "appcfg": ("data", "nvs", 0x3D0000, 0x20000),
    "coredump": ("data", "coredump", 0x3F0000, 0x10000),
}


def fail(message: str) -> None:
    raise SystemExit(f"baseline check failed: {message}")


def parse_number(value: str) -> int:
    return int(value.strip(), 0)


def read_partitions(path: Path) -> dict[str, tuple[str, str, int, int]]:
    partitions: dict[str, tuple[str, str, int, int]] = {}
    with path.open(encoding="utf-8", newline="") as stream:
        for row in csv.reader(line for line in stream if not line.lstrip().startswith("#")):
            if not row or not row[0].strip():
                continue
            if len(row) < 5:
                fail(f"invalid partition row: {row!r}")
            name, kind, subtype, offset, size = (field.strip() for field in row[:5])
            if name in partitions:
                fail(f"duplicate partition name: {name}")
            partitions[name] = (kind, subtype, parse_number(offset), parse_number(size))
    return partitions


def check_partition_table() -> None:
    path = ROOT / "partitions_ota_1m6.csv"
    actual = read_partitions(path)
    if actual != EXPECTED_PARTITIONS:
        fail(f"partition policy mismatch: expected {EXPECTED_PARTITIONS!r}, got {actual!r}")
    end = max(offset + size for _, _, offset, size in actual.values())
    if end != 0x400000:
        fail(f"partition table does not fill 4 MiB: ends at 0x{end:X}")
    if any(name in actual for name in ("smsdata", "inbox")):
        fail("persistent smsdata/inbox partition is not allowed")


def check_idf_pins() -> None:
    workflow = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    helper = (ROOT / "tools/idf.ps1").read_text(encoding="utf-8")
    shell_helper = (ROOT / "tools/idf.sh").read_text(encoding="utf-8")
    if f"container: {EXPECTED_IDF_IMAGE}" not in workflow:
        fail(f"CI is not pinned to {EXPECTED_IDF_IMAGE}")
    if f"esp-idf-v{EXPECTED_IDF}" not in helper:
        fail(f"local helper default is not pinned to esp-idf-v{EXPECTED_IDF}")
    if f"ExpectedIdfVersion = '{EXPECTED_IDF}'" not in helper:
        fail("local helper does not enforce its ESP-IDF version")
    if f'expected_idf_version="{EXPECTED_IDF}"' not in shell_helper:
        fail("POSIX helper does not pin its ESP-IDF version")
    if (
        'idf.py -B build/idf -D SDKCONFIG=build/sdkconfig build' not in workflow
        and './tools/idf.sh build' not in workflow
    ):
        fail("CI build command is not deterministic")


def validate_esptool_commands(device_source: str, workflow_source: str) -> None:
    stale = ("esptool.py", "chip_id", "read_flash", "write_flash", "verify_flash", "merge_bin")
    for token in stale:
        if token in device_source or token in workflow_source:
            fail(f"legacy esptool command remains: {token}")
    if 'ESPTOOL = os.environ.get("ESPTOOL", "esptool")' not in device_source:
        fail("device helper does not default to the IDF6 esptool executable")
    if 'program: str | None = "esptool"' not in device_source:
        fail("container helper does not use the IDF6 esptool executable")
    for command in ("chip-id", "read-flash", "write-flash", "verify-flash"):
        if f'"{command}"' not in device_source:
            fail(f"device helper is missing the IDF6 esptool command: {command}")
    if "esptool --chip esp32c3 merge-bin" not in workflow_source:
        fail("CI does not use the IDF6 merge-bin command")


def check_esptool_commands() -> None:
    device_source = (ROOT / "tools/device.py").read_text(encoding="utf-8")
    workflow_source = (ROOT / ".github/workflows/build.yml").read_text(encoding="utf-8")
    validate_esptool_commands(device_source, workflow_source)


def check_license_notice() -> None:
    license_path = ROOT / "components/idf_pdu/LICENSE"
    license_text = license_path.read_text(encoding="utf-8")
    if "GNU LESSER GENERAL PUBLIC LICENSE" not in license_text:
        fail("PDUlib license text is missing")
    notice = ROOT / "THIRD_PARTY_NOTICES.md"
    notice_text = notice.read_text(encoding="utf-8")
    if "LGPL-2.1-or-later" not in notice_text:
        fail("third-party notice does not identify LGPL-2.1-or-later")
    if "components/idf_pdu/LICENSE" not in notice_text:
        fail("third-party notice does not point to the PDUlib license")
    if "tools/idf.sh build" not in notice_text or "check_idf_baseline.py" not in notice_text:
        fail("third-party notice does not point to the rebuild command")


def cmake_cache_value(cache: Path, key: str) -> str | None:
    prefix = f"{key}:"
    for line in cache.read_text(encoding="utf-8").splitlines():
        if line.startswith(prefix) and "=" in line:
            return line.split("=", 1)[1]
    return None


def generated_sdkconfig_path(build_dir: Path) -> Path:
    cache = build_dir / "CMakeCache.txt"
    if not cache.exists():
        fail(f"build cache not found: {cache}")
    raw_path = cmake_cache_value(cache, "SDKCONFIG")
    if not raw_path:
        fail(f"build cache does not identify SDKCONFIG: {cache}")

    configured_home = cmake_cache_value(cache, "CMAKE_HOME_DIRECTORY")
    path = Path(raw_path)
    if not path.is_absolute() and configured_home:
        path = Path(configured_home) / path
    if path.exists():
        return path

    # Build artifacts may have been produced in a container whose checkout
    # path differs from this checkout. Preserve the cache-relative path.
    if configured_home:
        try:
            relative = path.relative_to(Path(configured_home))
        except ValueError:
            relative = None
        if relative is not None:
            mapped = ROOT / relative
            if mapped.exists():
                return mapped
    fail(f"generated sdkconfig not found: {path}")


def config_line_enabled(path: Path, expected: str) -> bool:
    return any(line.strip() == expected for line in path.read_text(encoding="utf-8").splitlines())


def check_rollback_config(build_dir: Path) -> None:
    sdkconfig = generated_sdkconfig_path(build_dir)
    header = build_dir / "config" / "sdkconfig.h"
    if not header.exists():
        fail(f"generated sdkconfig header not found: {header}")
    if not config_line_enabled(sdkconfig, "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y"):
        fail(f"OTA build rollback is not enabled in generated sdkconfig: {sdkconfig}")
    if not config_line_enabled(header, "#define CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE 1"):
        fail(f"OTA build rollback is not enabled in generated sdkconfig.h: {header}")


def check_app_size(build_dir: Path) -> None:
    check_rollback_config(build_dir)
    image = build_dir / "sms_forwarding_idf.bin"
    if not image.exists():
        fail(f"firmware image not found: {image}")
    size = image.stat().st_size
    slot_size = EXPECTED_PARTITIONS["app0"][3]
    if size > slot_size:
        fail(f"firmware image is {size} bytes, larger than OTA slot {slot_size} bytes")
    print(f"firmware={size} bytes; ota_headroom={slot_size - size} bytes")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--build-dir",
        type=Path,
        help="validate an existing IDF build image as well as the source baseline",
    )
    args = parser.parse_args()
    check_partition_table()
    check_idf_pins()
    check_esptool_commands()
    check_license_notice()
    if args.build_dir:
        check_app_size(args.build_dir)
    print("ESP-IDF baseline checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
