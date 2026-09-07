#!/usr/bin/env bash
set -euo pipefail

expected_idf_version="6.0.2"
repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
build_dir="$repo_root/build/idf"
sdkconfig="$repo_root/build/sdkconfig"
sms_usb_recovery="${SMS_USB_RECOVERY:-0}"
release_firmware="${FIRMWARE_IS_RELEASE:-0}"
ota_test_key="${SMS_OTA_TEST_KEY:-0}"
ota_test_public_key="${SMS_OTA_TEST_PUBLIC_KEY:-}"
ota_test_fail_health="${SMS_OTA_TEST_FAIL_HEALTH:-0}"
export SDKCONFIG_DEFAULTS="$repo_root/sdkconfig.defaults"

if [[ "$sms_usb_recovery" != "0" && "$sms_usb_recovery" != "1" ]]; then
  echo "SMS_USB_RECOVERY must be 0 or 1" >&2
  exit 2
fi
if [[ "$release_firmware" != "0" && "$release_firmware" != "1" ]]; then
  echo "FIRMWARE_IS_RELEASE must be 0 or 1" >&2
  exit 2
fi
if [[ "$ota_test_key" != "0" && "$ota_test_key" != "1" ]]; then
  echo "SMS_OTA_TEST_KEY must be 0 or 1" >&2
  exit 2
fi
if [[ "$ota_test_fail_health" != "0" && "$ota_test_fail_health" != "1" ]]; then
  echo "SMS_OTA_TEST_FAIL_HEALTH must be 0 or 1" >&2
  exit 2
fi
if [[ "$ota_test_key" == "1" && "$release_firmware" == "1" ]]; then
  echo "SMS_OTA_TEST_KEY cannot be enabled in a release firmware" >&2
  exit 2
fi
if [[ "$ota_test_key" == "1" && "$sms_usb_recovery" != "1" ]]; then
  echo "SMS_OTA_TEST_KEY requires USB recovery development profile" >&2
  exit 2
fi
if [[ "$ota_test_fail_health" == "1" &&
      ("$release_firmware" != "0" || "$sms_usb_recovery" != "1" || "$ota_test_key" != "1") ]]; then
  echo "SMS_OTA_TEST_FAIL_HEALTH requires non-release USB recovery with the OTA test key" >&2
  exit 2
fi
if [[ "$ota_test_key" == "1" ]]; then
  ota_test_key_dir="$repo_root/build/idf-ota-test"
  ota_test_profile_dir="$ota_test_key_dir"
  if [[ "$ota_test_fail_health" == "1" ]]; then
    ota_test_profile_dir="$repo_root/build/idf-ota-test-fail-health"
  fi
  if [[ -L "$repo_root/build" || ! -d "$repo_root/build"
        || -L "$ota_test_key_dir" || ! -d "$ota_test_key_dir"
        || -L "$ota_test_profile_dir" || ! -d "$ota_test_profile_dir" ]]; then
    echo "SMS_OTA_TEST_KEY requires real OTA test build directories" >&2
    exit 2
  fi
  if [[ -z "$ota_test_public_key" || -L "$ota_test_public_key" || ! -f "$ota_test_public_key" ]]; then
    echo "SMS_OTA_TEST_KEY requires a real regular public key path" >&2
    exit 2
  fi
  repo_real="$(realpath -e -- "$repo_root")"
  profile_real="$(realpath -e -- "$ota_test_profile_dir")"
  public_real="$(realpath -e -- "$ota_test_public_key")"
  if [[ "$public_real" != "$repo_real/build/idf-ota-test"/* ]]; then
    echo "SMS_OTA_TEST_PUBLIC_KEY must stay inside build/idf-ota-test" >&2
    exit 2
  fi
  if [[ "$profile_real" != "$repo_real/build/$(basename "$ota_test_profile_dir")" ]]; then
    echo "SMS_OTA_TEST_KEY profile must resolve to its fixed OTA test directory" >&2
    exit 2
  fi
  build_dir="$ota_test_profile_dir"
  sdkconfig="$repo_root/build/sdkconfig-ota-test"
  if [[ "$ota_test_fail_health" == "1" ]]; then
    sdkconfig="$repo_root/build/sdkconfig-ota-test-fail-health"
  fi
  export SDKCONFIG_DEFAULTS="$SDKCONFIG_DEFAULTS;$repo_root/sdkconfig.usb-recovery"
elif [[ "$sms_usb_recovery" == "1" ]]; then
  build_dir="$repo_root/build/idf-usb-recovery"
  sdkconfig="$repo_root/build/sdkconfig-usb-recovery"
  export SDKCONFIG_DEFAULTS="$SDKCONFIG_DEFAULTS;$repo_root/sdkconfig.usb-recovery"
fi

idf_args=(-B "$build_dir" -D "SDKCONFIG=$sdkconfig"
  -D "SDKCONFIG_DEFAULTS=$SDKCONFIG_DEFAULTS"
  -D "FIRMWARE_IS_RELEASE=$release_firmware" -D "SMS_USB_RECOVERY=$sms_usb_recovery"
  -D "SMS_OTA_TEST_KEY=$ota_test_key" -D "SMS_OTA_TEST_FAIL_HEALTH=$ota_test_fail_health"
  -D "SMS_OTA_TEST_PUBLIC_KEY=$ota_test_public_key")

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

refresh_sdkconfig() {
  if [[ -f "$sdkconfig" ]] && grep -q '^CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y$' "$sdkconfig" \
    && grep -q '^CONFIG_MBEDTLS_HAVE_TIME_DATE=y$' "$sdkconfig"; then
    return
  fi
  echo "Regenerating ${sdkconfig} from ESP-IDF defaults (old file is preserved as .old)" >&2
  idf.py "${idf_args[@]}" set-target esp32c3
}

case "${1:-build}" in
  build)
    refresh_sdkconfig
    idf.py "${idf_args[@]}" build
    python3 "$repo_root/tools/check_idf_baseline.py" --build-dir "$build_dir"
    ;;
  reconfigure)
    refresh_sdkconfig
    idf.py "${idf_args[@]}" reconfigure
    ;;
  clean|fullclean)
    idf.py "${idf_args[@]}" "$1"
    ;;
  *)
    echo "usage: $0 [build|reconfigure|clean|fullclean]" >&2
    exit 2
    ;;
esac
