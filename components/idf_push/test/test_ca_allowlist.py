#!/usr/bin/env python3
import base64
import hashlib
import importlib.util
import tempfile
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "generate_ca_allowlist.py"
spec = importlib.util.spec_from_file_location("allowlist", SCRIPT)
module = importlib.util.module_from_spec(spec)
assert spec.loader
spec.loader.exec_module(module)


def cert(data: bytes) -> bytes:
    return b"-----BEGIN CERTIFICATE-----\n" + base64.b64encode(data) + b"\n-----END CERTIFICATE-----\n"


values = module.hashes(cert(b"two") + cert(b"one") + cert(b"two"))
assert values == sorted([hashlib.sha256(b"one").digest(), hashlib.sha256(b"two").digest()])
rendered = module.render(values)
assert rendered.startswith("#pragma once\n")
assert rendered.count("std::array<uint8_t, 32>") == 1
assert hashlib.sha256(b"one").hexdigest()[:2] in rendered
with tempfile.TemporaryDirectory() as directory:
    path = Path(directory) / "empty.pem"
    path.write_bytes(b"")
    try:
        module.hashes(path.read_bytes())
    except ValueError:
        pass
    else:
        raise AssertionError("empty bundle accepted")
