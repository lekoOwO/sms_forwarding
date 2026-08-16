#!/usr/bin/env bash
set -euo pipefail

expected_idf_version="5.5.4"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="$repo_root/build/idf"
sdkconfig="$repo_root/build/sdkconfig"

if [[ -z "${IDF_PATH:-}" || ! -f "$IDF_PATH/export.sh" ]]; then
  echo "IDF_PATH must point to ESP-IDF ${expected_idf_version}" >&2
  exit 2
fi

# shellcheck source=/dev/null
source "$IDF_PATH/export.sh"
idf_version="$(idf.py --version 2>&1)"
if [[ "$idf_version" != *"$expected_idf_version"* ]]; then
  echo "ESP-IDF ${expected_idf_version} is required; got: ${idf_version}" >&2
  exit 2
fi

case "${1:-build}" in
  build)
    idf.py -B "$build_dir" -D "SDKCONFIG=$sdkconfig" build
    python3 "$repo_root/tools/check_idf_baseline.py" --build-dir "$build_dir"
    ;;
  reconfigure|clean|fullclean)
    idf.py -B "$build_dir" -D "SDKCONFIG=$sdkconfig" "$1"
    ;;
  *)
    echo "usage: $0 [build|reconfigure|clean|fullclean]" >&2
    exit 2
    ;;
esac
