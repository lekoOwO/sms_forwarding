#!/usr/bin/env python3
import argparse
import json
import re
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
VERSION_PATH = ROOT / "firmware-version.json"
HEADER_PATH = ROOT / "components" / "idf_config" / "include" / "firmware_version_generated.h"
SEMVER = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)")


def validate_version(version: object) -> dict[str, object]:
    if not isinstance(version, dict):
        raise SystemExit("firmware-version.json must contain an object")
    if set(version) != {"releaseVersion", "devBuild"}:
        raise SystemExit("firmware-version.json has unknown or missing fields")
    if not isinstance(version["releaseVersion"], str) or not SEMVER.fullmatch(version["releaseVersion"]):
        raise SystemExit("releaseVersion must be MAJOR.MINOR.PATCH")
    if type(version["devBuild"]) is not int or not 0 < version["devBuild"] <= 0x7FFFFFFF:
        raise SystemExit("devBuild must be a positive 31-bit integer")
    return version


def load_version() -> dict[str, object]:
    return validate_version(json.loads(VERSION_PATH.read_text(encoding="utf-8")))


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

#if FIRMWARE_IS_RELEASE
#define FIRMWARE_DISPLAY_VERSION FIRMWARE_RELEASE_LABEL
#else
#define FIRMWARE_DISPLAY_VERSION FIRMWARE_DEV_BUILD_TEXT
#endif

#endif
"""


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bump", action="store_true")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--validate-tag")
    parser.add_argument("--print-dev-build", action="store_true")
    args = parser.parse_args()
    if sum((args.bump, args.check, args.validate_tag is not None, args.print_dev_build)) > 1:
        raise SystemExit("version operations cannot be combined")

    if args.validate_tag is not None or args.print_dev_build:
        try:
            version = validate_version(json.load(sys.stdin))
        except (json.JSONDecodeError, UnicodeDecodeError) as error:
            raise SystemExit(f"invalid firmware-version.json: {error}") from error
        if args.validate_tag is not None and args.validate_tag != "v" + str(version["releaseVersion"]):
            raise SystemExit("releaseVersion does not match tag")
        print(version["devBuild"])
        return

    version = load_version()
    if args.bump:
        if version["devBuild"] == 0x7FFFFFFF:
            raise SystemExit("devBuild cannot be increased beyond a positive 31-bit integer")
        version["devBuild"] += 1
        VERSION_PATH.write_text(json.dumps(version, indent=2) + "\n", encoding="utf-8")

    expected = render_header(version)
    if args.check:
        if not HEADER_PATH.exists() or HEADER_PATH.read_text(encoding="utf-8") != expected:
            raise SystemExit("firmware version header is out of date")
        return
    HEADER_PATH.write_text(expected, encoding="utf-8")


if __name__ == "__main__":
    main()
