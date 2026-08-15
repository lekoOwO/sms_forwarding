#!/usr/bin/env python3
import argparse
import hashlib
import json
import struct
import subprocess
from pathlib import Path


MAGIC = b"SMSOTA1\n"
TARGET = "esp32c3"
MAX_FIRMWARE_SIZE = 0x1E0000


def openssl(*arguments: str, input_bytes: bytes | None = None) -> bytes:
    return subprocess.run(
        ["openssl", *arguments], input=input_bytes, check=True, capture_output=True
    ).stdout


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("firmware", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--private-key", required=True, type=Path)
    parser.add_argument("--version", required=True)
    parser.add_argument("--counter", required=True, type=int)
    parser.add_argument("--expected-public-sha256")
    args = parser.parse_args()

    firmware = args.firmware.read_bytes()
    if not firmware or len(firmware) > MAX_FIRMWARE_SIZE:
        raise SystemExit("firmware does not fit an OTA slot")
    if not 0 < args.counter <= 0xFFFFFFFF:
        raise SystemExit("counter must be a non-zero uint32")
    if not 0 < len(args.version.encode("ascii")) <= 32 or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-"
        for character in args.version
    ):
        raise SystemExit("version must be 1-32 safe ASCII characters")

    public_der = openssl("pkey", "-in", str(args.private_key), "-pubout", "-outform", "DER")
    public_fingerprint = hashlib.sha256(public_der).hexdigest()
    if args.expected_public_sha256 and public_fingerprint != args.expected_public_sha256:
        raise SystemExit("OTA private key does not match the firmware public key")

    manifest = json.dumps(
        {
            "format": 1,
            "releaseCounter": args.counter,
            "sha256": hashlib.sha256(firmware).hexdigest(),
            "size": len(firmware),
            "target": TARGET,
            "version": args.version,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    signature = openssl("dgst", "-sha256", "-sign", str(args.private_key), input_bytes=manifest)
    if len(signature) > 0xFFFF:
        raise SystemExit("signature is too large")
    package = MAGIC + struct.pack(">I", len(manifest)) + manifest + struct.pack(">H", len(signature)) + signature + firmware
    args.output.write_bytes(package)


if __name__ == "__main__":
    main()
