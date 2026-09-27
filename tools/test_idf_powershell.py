#!/usr/bin/env python3
"""Structural helper checks only; these do not execute or emulate PowerShell."""

import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().with_name("idf.ps1")


class PowerShellHelperStructureTests(unittest.TestCase):
    def setUp(self):
        self.source = SOURCE.read_text(encoding="utf-8")

    def function(self, name):
        marker = f"function {name} {{"
        self.assertIn(marker, self.source)
        return self.source.split(marker, 1)[1].split("\n}", 1)[0]

    def action(self, name, next_name=None):
        body = self.source.split(f"    '{name}' {{", 1)[1]
        return body.split(f"    '{next_name}' {{", 1)[0] if next_name else body

    def test_native_failures_cannot_continue_to_success(self):
        body = self.function("Invoke-CheckedNative")
        self.assertIn("& $Command @CommandArgs", body)
        self.assertIn("if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }", body)
        self.assertLess(body.index("& $Command @CommandArgs"), body.index("if ($LASTEXITCODE"))
        self.assertIn("Invoke-CheckedNative 'idf.py' @('--version')", self.source)
        self.assertNotIn("ninja -C", self.source)
        self.assertNotIn("idf.py @IdfArgs", self.source)

    def test_stale_config_regenerates_at_same_native_paths(self):
        body = self.function("Update-RequiredConfig")
        self.assertIn("Get-Content -LiteralPath $SdkConfig", body)
        self.assertIn("$lines -ccontains 'CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y'", body)
        self.assertIn("-and", body)
        self.assertIn("$lines -ccontains 'CONFIG_MBEDTLS_HAVE_TIME_DATE=y'", body)
        self.assertLess(body.index("return"), body.index("'set-target', 'esp32c3'"))
        self.assertIn("Invoke-CheckedNative 'idf.py'", body)
        self.assertIn('"SDKCONFIG=$SdkConfig"', self.source)
        self.assertIn('"SDKCONFIG_DEFAULTS=$SdkConfigDefaults"', self.source)
        self.assertIn("$SdkConfigDefaults = Join-Path $RepoRoot 'sdkconfig.defaults'", self.source)
        self.assertNotIn("Remove-Item", body)
        self.assertNotIn("Set-Content", body)

    def test_build_and_flash_cannot_skip_the_existing_python_gate(self):
        gate = self.function("Test-BuildBaseline")
        self.assertIn("Invoke-CheckedNative 'python'", gate)
        self.assertIn("'tools/check_idf_baseline.py'", gate)
        self.assertIn("'--build-dir', $BuildDir", gate)
        build = self.action("build", "flash")
        self.assertLess(build.index("Update-RequiredConfig"), build.index("'reconfigure'"))
        self.assertLess(build.index("'reconfigure'"), build.index("'ninja'"))
        self.assertLess(build.index("'ninja'"), build.index("Test-BuildBaseline"))
        flash = self.action("flash", "monitor")
        self.assertLess(flash.index("Test-BuildBaseline"), flash.index("'flash'"))
        self.assertNotIn("Update-RequiredConfig", flash)
        reconfigure = self.action("reconfigure", "clean")
        self.assertLess(reconfigure.index("Update-RequiredConfig"), reconfigure.index("'reconfigure'"))

    def test_monitor_and_clean_do_not_gain_configuration_mutations(self):
        for action, following in (("monitor", "reconfigure"), ("clean", "fullclean"), ("fullclean", None)):
            with self.subTest(action=action):
                body = self.action(action, following)
                self.assertIn("Invoke-CheckedNative 'idf.py'", body)
                self.assertIn(f"'{action}'", body)
                self.assertNotIn("Update-RequiredConfig", body)
                self.assertNotIn("Test-BuildBaseline", body)


if __name__ == "__main__":
    unittest.main()
