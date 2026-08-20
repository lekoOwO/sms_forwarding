#!/usr/bin/env python3
"""Check the reproducible ESP-IDF baseline without requiring ESP-IDF locally."""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_IDF = "5.5.4"
EXPECTED_IDF_IMAGE = (
    "espressif/idf@sha256:"
    "b9f2d6ea1c19e0c9f7959bdb74a9e3c775642f9d0f3b841937c5fa3363db892b"
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
    if 'idf.py -B build/idf -D SDKCONFIG=build/sdkconfig build' not in workflow:
        fail("CI build command is not deterministic")


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


def check_app_size(build_dir: Path) -> None:
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
    check_license_notice()
    if args.build_dir:
        check_app_size(args.build_dir)
    print("ESP-IDF baseline checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
