#!/usr/bin/env python3
import argparse
import base64
import hashlib
import re
from pathlib import Path


def hashes(pem: bytes) -> list[bytes]:
    blocks = re.findall(
        rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", pem, re.S
    )
    values = sorted({hashlib.sha256(base64.b64decode(re.sub(rb"\s+", b"", block), validate=True)).digest()
                     for block in blocks})
    if not values:
        raise ValueError("empty CA bundle")
    return values


def render(values: list[bytes]) -> str:
    rows = ",\n".join("    {" + ",".join(f"0x{byte:02x}" for byte in value) + "}" for value in values)
    return (
        "#pragma once\n#include <array>\n#include <cstdint>\n\n"
        f"inline constexpr std::array<std::array<uint8_t, 32>, {len(values)}> "
        f"IDF_PUSH_CA_ALLOWLIST = {{{{\n{rows}\n}}}};\n"
    )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    output = render(hashes(args.input.read_bytes()))
    args.output.write_text(output)


if __name__ == "__main__":
    main()
