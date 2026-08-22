#!/usr/bin/env python3
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

    def test_ota_build_requires_rollback_in_generated_config_and_header(self):
        temp, build = self.make_build(
            "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y\n",
            "#define CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE 1\n",
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


if __name__ == "__main__":
    unittest.main()
