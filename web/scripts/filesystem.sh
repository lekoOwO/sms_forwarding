#!/bin/sh
set -eu

tool="$(find /opt/arduino/data/packages/esp32/tools/mklittlefs -type f -name mklittlefs | head -n 1)"
test -n "$tool"
mkdir -p build
"$tool" -c ../code/data -p 256 -b 4096 -s 0x1C0000 build/littlefs.bin
"$tool" -l build/littlefs.bin
