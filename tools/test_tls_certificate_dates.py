#!/usr/bin/env python3
"""Offline native verification with the pinned IDF's unmodified Mbed TLS source."""

import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest

from check_idf_baseline import EXPECTED_IDF_IMAGE


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tools/testdata/tls_dates"


def run(*args):
    result = subprocess.run(args, text=True, capture_output=True, timeout=240)
    if result.returncode:
        raise RuntimeError(f"command failed: {args!r}\n{result.stdout}\n{result.stderr}")
    return result.stdout


class CertificateDateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix="tls-dates-")
        cls.addClassCleanup(cls.temp.cleanup)
        output = Path(cls.temp.name)
        idf = Path(os.environ["IDF_PATH"])
        # 直接沿用 pinned IDF 的設定映射，沒有複製日期驗證演算法。
        esp_config = (idf / "components/mbedtls/port/include/mbedtls/esp_config.h").read_text()
        mapping = re.search(
            r"#ifdef CONFIG_MBEDTLS_HAVE_TIME_DATE\n.*?\n#endif", esp_config, re.S
        )
        if mapping is None:
            raise RuntimeError("pinned IDF certificate-date mapping was not found")
        defaults = (ROOT / "sdkconfig.defaults").read_text().splitlines()
        enabled = "CONFIG_MBEDTLS_HAVE_TIME_DATE=y" in defaults
        (output / "sdkconfig.h").write_text("")
        config = output / "date_config.h"
        config.write_text(
            ("#define CONFIG_MBEDTLS_HAVE_TIME_DATE 1\n" if enabled else "")
            + mapping.group(0) + "\n"
        )
        run("cmake", "-S", str(FIXTURES), "-B", str(output / "build"), "-G", "Ninja",
            "-DCMAKE_BUILD_TYPE=Release", f"-DDATE_CONFIG={config}")
        run("cmake", "--build", str(output / "build"), "--target", "verify_dates", "--parallel", "4")
        cls.verifier = output / "build/verify_dates"

    def test_dates_hostname_and_trust_are_enforced_by_native_verifier(self):
        # 根憑證有效期 2020–2040；葉憑證 2025–2030，SAN 為保留測試網域。
        # 2028/2032/2024/1970 UTC 的固定時間與 X.509 flags 是獨立預期值。
        cases = (
            ("valid", "root.pem", "tls-dates.example.invalid", 1830297600, 0, 0),
            ("expired", "root.pem", "tls-dates.example.invalid", 1956528000, -0x2700, 0x01),
            ("future", "root.pem", "tls-dates.example.invalid", 1704067200, -0x2700, 0x200),
            ("cold_boot", "root.pem", "tls-dates.example.invalid", 0, -0x2700, 0x200),
            ("hostname", "root.pem", "wrong.example.invalid", 1830297600, -0x2700, 0x04),
            ("untrusted", "other-root.pem", "tls-dates.example.invalid", 1830297600, -0x2700, 0x08),
        )
        for name, anchor, hostname, now, expected_result, expected_flags in cases:
            with self.subTest(case=name):
                output = run(str(self.verifier), str(FIXTURES / anchor),
                             str(FIXTURES / "server.pem"), hostname, str(now))
                self.assertEqual(tuple(map(int, output.split())), (expected_result, expected_flags))


if __name__ == "__main__":
    if "--native" in sys.argv:
        sys.argv.remove("--native")
        unittest.main()
    else:
        # 不下載、掛設備或修改 checkout；原始碼唯讀，host compiler 產物只在 tmpfs。
        sys.exit(subprocess.call([
            "docker", "run", "--rm", "--pull=never", "--network=none", "--read-only",
            "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
            "--tmpfs", "/tmp:rw,nosuid,nodev,exec,size=512m",
            "--tmpfs", "/opt/esp/idf/.git:ro,nosuid,nodev,noexec,size=1m",
            "--mount", f"type=bind,src={ROOT},dst=/workspace,readonly",
            "--workdir", "/workspace", "--env", "PYTHONDONTWRITEBYTECODE=1",
            EXPECTED_IDF_IMAGE, "python3", "tools/test_tls_certificate_dates.py", "--native",
            *sys.argv[1:],
        ]))
