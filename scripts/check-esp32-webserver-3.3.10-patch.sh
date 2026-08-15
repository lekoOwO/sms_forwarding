#!/bin/sh
set -eu

target="${1:-/opt/arduino/data/packages/esp32/hardware/esp32/3.3.10}/libraries/WebServer/src/Parsing.cpp"
expected=2dfea7725ea715a9e94bc256ba7ada831bebbca5a3bfeee417e4000c86034610
actual="$(sha256sum "$target" | awk '{print $1}')"
test "$actual" = "$expected" || {
  echo "ESP32 WebServer request-limit patch missing or changed: $actual" >&2
  exit 1
}
