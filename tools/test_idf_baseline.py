#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import check_idf_baseline


class RollbackBuildGateTests(unittest.TestCase):
    def make_build(self, sdkconfig: str, header: str):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        build = root / "build" / "idf"
        build.joinpath("config").mkdir(parents=True)
        sdkconfig_path = root / "build" / "sdkconfig"
        sdkconfig_path.write_text(sdkconfig, encoding="utf-8")
        build.joinpath("config/sdkconfig.h").write_text(header, encoding="utf-8")
        (build / "sms_forwarding_idf.bin").write_bytes(b"ok")
        (build / "CMakeCache.txt").write_text(
            "SDKCONFIG:UNINITIALIZED=build/sdkconfig\n"
            f"CMAKE_HOME_DIRECTORY:INTERNAL={root}\n",
            encoding="utf-8",
        )
        return temp, build

    def test_ota_build_rejects_stale_certificate_date_config_or_header(self):
        for config_date, header_date in (
            ("# CONFIG_MBEDTLS_HAVE_TIME_DATE is not set\n", "#define CONFIG_MBEDTLS_HAVE_TIME_DATE 1\n"),
            ("CONFIG_MBEDTLS_HAVE_TIME_DATE=y\n", "/* CONFIG_MBEDTLS_HAVE_TIME_DATE is not set */\n"),
        ):
            with self.subTest(config_date=config_date, header_date=header_date):
                temp, build = self.make_build(
                    "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\n" + config_date,
                    "#define CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE 1\n" + header_date,
                )
                with temp, self.assertRaisesRegex(SystemExit, "certificate date"):
                    check_idf_baseline.check_app_size(build)

    def test_ota_build_requires_rollback_in_generated_config_and_header(self):
        temp, build = self.make_build(
            "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\nCONFIG_MBEDTLS_HAVE_TIME_DATE=y\n",
            "#define CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE 1\n#define CONFIG_MBEDTLS_HAVE_TIME_DATE 1\n",
        )
        with temp:
            check_idf_baseline.check_app_size(build)

    def test_ota_build_fails_when_generated_sdkconfig_disables_rollback(self):
        temp, build = self.make_build(
            "# CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE is not set\n",
            "#define CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE 1\n",
        )
        with temp, self.assertRaisesRegex(SystemExit, "rollback"):
            check_idf_baseline.check_app_size(build)

    def test_ota_build_fails_when_generated_header_disables_rollback(self):
        temp, build = self.make_build(
            "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\n",
            "/* CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE is not set */\n",
        )
        with temp, self.assertRaisesRegex(SystemExit, "rollback"):
            check_idf_baseline.check_app_size(build)


class EsptoolCommandGateTests(unittest.TestCase):
    def test_idf6_esptool_commands_are_current(self):
        check_idf_baseline.check_esptool_commands()

    def test_legacy_esptool_executable_is_rejected(self):
        device_source = 'ESPTOOL = os.environ.get("ESPTOOL", "esptool.py")'
        with self.assertRaisesRegex(SystemExit, "legacy esptool"):
            check_idf_baseline.validate_esptool_commands(device_source, "")

    def test_legacy_esptool_subcommand_is_rejected(self):
        device_source = (
            'ESPTOOL = os.environ.get("ESPTOOL", "esptool")\n'
            'program: str | None = "esptool"\n'
            '"chip-id" "read-flash" "write_flash" "verify-flash"'
        )
        with self.assertRaisesRegex(SystemExit, "legacy esptool"):
            check_idf_baseline.validate_esptool_commands(device_source, "")

    def test_legacy_merge_subcommand_is_rejected(self):
        device_source = (
            'ESPTOOL = os.environ.get("ESPTOOL", "esptool")\n'
            'program: str | None = "esptool"\n'
            '"chip-id" "read-flash" "write-flash" "verify-flash"'
        )
        with self.assertRaisesRegex(SystemExit, "legacy esptool"):
            check_idf_baseline.validate_esptool_commands(device_source, "merge_bin")


class RequiredConfigRefreshTests(unittest.TestCase):
    def test_real_helper_refreshes_stale_dates_but_preserves_compliant_config(self):
        for date_config, expected_actions in (
            ("# CONFIG_MBEDTLS_HAVE_TIME_DATE is not set\n", ["set-target", "reconfigure"]),
            ("CONFIG_MBEDTLS_HAVE_TIME_DATE=y\n", ["reconfigure"]),
        ):
            with self.subTest(date_config=date_config), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                (root / "tools").mkdir()
                (root / "build").mkdir()
                (root / "idf").mkdir()
                shutil.copyfile(check_idf_baseline.ROOT / "tools/idf.sh", root / "tools/idf.sh")
                (root / "build/sdkconfig").write_text(
                    "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\n" + date_config
                )
                (root / "idf/export.sh").write_text(":\n")
                executable = root / "idf/idf.py"
                # 只替換昂貴的外部建置命令；實際 shell helper 決定是否重新產生設定。
                executable.write_text(
                    "#!/usr/bin/env python3\nimport json, sys\n"
                    "if sys.argv[1:] == ['--version']: print('ESP-IDF v6.0.2')\n"
                    "else: print(json.dumps(sys.argv[1:]))\n"
                )
                executable.chmod(0o755)
                env = dict(os.environ, IDF_PATH=str(root / "idf"),
                           PATH=str(root / "idf") + os.pathsep + os.environ["PATH"],
                           SMS_USB_RECOVERY="0", FIRMWARE_IS_RELEASE="0", SMS_OTA_TEST_KEY="0",
                           SMS_OTA_TEST_FAIL_HEALTH="0", SMS_OTA_TEST_PUBLIC_KEY="")
                result = subprocess.run(
                    ["bash", str(root / "tools/idf.sh"), "reconfigure"],
                    env=env, text=True, capture_output=True, timeout=10, check=True,
                )
                commands = [json.loads(line) for line in result.stdout.splitlines()]
                actions = [command[-2] if command[-1] == "esp32c3" else command[-1]
                           for command in commands]
                self.assertEqual(actions, expected_actions)
                for command in commands:
                    self.assertIn(f"SDKCONFIG={root / 'build/sdkconfig'}", command)
                    self.assertIn(f"SDKCONFIG_DEFAULTS={root / 'sdkconfig.defaults'}", command)


if __name__ == "__main__":
    unittest.main()
