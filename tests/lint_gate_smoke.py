#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path


def rejects(command: list[str], source: str, suffix: str) -> None:
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory, f"bad{suffix}")
        path.write_text(source, encoding="utf-8")
        result = subprocess.run([*command, path.name], cwd=directory, capture_output=True, text=True)
        if result.returncode == 0:
            raise SystemExit(f"{' '.join(command)} accepted an invalid fixture")


rejects(["eslint", "--no-config-lookup", "--rule", "no-undef:error"], "missing();\n", ".js")
rejects(["ruff", "check", "--isolated", "--select", "F821"], "print(missing)\n", ".py")
rejects(["shellcheck"], "#!/bin/sh\necho $missing\n", ".sh")
rejects(
    ["cppcheck", "--quiet", "--error-exitcode=1", "--enable=warning"],
    "void f() { int *p = nullptr; *p = 1; }\n",
    ".cpp",
)
