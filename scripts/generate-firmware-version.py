#!/usr/bin/env python3
import argparse
import json
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION_PATH = ROOT / "firmware-version.json"
HEADER_PATH = ROOT / "code" / "firmware_version_generated.h"
SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def load_version() -> dict[str, object]:
    version = json.loads(VERSION_PATH.read_text())
    if set(version) != {"releaseVersion", "devBuild"}:
        raise SystemExit("firmware-version.json has unknown or missing fields")
    if not isinstance(version["releaseVersion"], str) or not SEMVER.fullmatch(version["releaseVersion"]):
        raise SystemExit("releaseVersion must be MAJOR.MINOR.PATCH")
    if not isinstance(version["devBuild"], int) or not 0 < version["devBuild"] <= 0x7FFFFFFF:
        raise SystemExit("devBuild must be a positive 31-bit integer")
    return version


def render_header(version: dict[str, object]) -> str:
    release = version["releaseVersion"]
    build = version["devBuild"]
    return f"""#ifndef FIRMWARE_VERSION_GENERATED_H
#define FIRMWARE_VERSION_GENERATED_H

#define FIRMWARE_RELEASE_VERSION \"{release}\"
#define FIRMWARE_DEV_BUILD {build}
#define FIRMWARE_DEV_BUILD_TEXT \"{build}\"
#define FIRMWARE_RELEASE_LABEL \"{release} ({build})\"

#ifndef FIRMWARE_IS_RELEASE
#define FIRMWARE_IS_RELEASE 0
#endif

#endif
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bump", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.bump and args.check:
        raise SystemExit("--bump and --check cannot be combined")

    version = load_version()
    if args.bump:
        version["devBuild"] += 1
        VERSION_PATH.write_text(json.dumps(version, indent=2) + "\n")

    expected = render_header(version)
    if args.check:
        if not HEADER_PATH.exists() or HEADER_PATH.read_text() != expected:
            raise SystemExit("firmware version header is out of date")
        return
    HEADER_PATH.write_text(expected)


if __name__ == "__main__":
    main()
