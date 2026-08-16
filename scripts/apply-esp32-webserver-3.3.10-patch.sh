#!/bin/sh
set -eu

core_root="${1:-/opt/arduino/data/packages/esp32/hardware/esp32/3.3.10}"
target="$core_root/libraries/WebServer/src/Parsing.cpp"
patch_file="$(CDPATH='' cd -- "$(dirname "$0")" && pwd)/patches/esp32-webserver-3.3.10-request-limits.patch"
original=522a46a1b8bed19b5482b65eb96bb87fe068c937c4516d17111179b2e8b88adc
patched=2dfea7725ea715a9e94bc256ba7ada831bebbca5a3bfeee417e4000c86034610
actual="$(sha256sum "$target" | awk '{print $1}')"

case "$actual" in
  "$patched") exit 0 ;;
  "$original") patch -d "$core_root" -p1 < "$patch_file" ;;
  *) echo "Unexpected ESP32 WebServer Parsing.cpp hash: $actual" >&2; exit 1 ;;
esac

"$(dirname "$0")/check-esp32-webserver-3.3.10-patch.sh" "$core_root"
