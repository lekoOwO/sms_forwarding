#!/usr/bin/env python3
"""Exercise the pinned ESP-IDF certificate-bundle verifier offline."""

from __future__ import annotations

import datetime as dt
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

from check_idf_baseline import EXPECTED_IDF_IMAGE


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tools/testdata/tls_bundle"
DATE_FIXTURES = ROOT / "tools/testdata/tls_dates"
CROSS_FIXTURES = ROOT / "tools/testdata/tls_cross_signed"
GSMA_CERT = ROOT / "components/idf_lpa/certs/gsma_rsp_tls_roots.pem"
# The two public PEM fixtures under tls_cross_signed are copied from Espressif
# commit 0e03327f698a9e69217fde1a647f5b8d4f34fd94.  Its private test key is
# intentionally not part of this repository or this offline test.


def run(*args: str) -> str:
    result = subprocess.run(args, text=True, capture_output=True, timeout=240)
    if result.returncode:
        raise RuntimeError(f"command failed: {args!r}\n{result.stdout}\n{result.stderr}")
    return result.stdout


def write_intermediate_fixtures(directory: Path) -> None:
    """Create public-only chain inputs with an independently dated issuer.

    Keys exist only in memory.  The bundle receives the root certificate, and
    the server input contains a broad-validity leaf followed by an
    intermediate whose 2025-2035 window is separately checked by the test.
    """
    directory.mkdir()
    root_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    intermediate_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    utc = dt.timezone.utc

    def name(common_name: str) -> x509.Name:
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])

    def cert(
        subject: x509.Name,
        issuer: x509.Name,
        public_key,
        signer,
        serial: int,
        start: dt.datetime,
        end: dt.datetime,
        is_ca: bool,
        san: str | None = None,
    ) -> x509.Certificate:
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(public_key)
            .serial_number(serial)
            .not_valid_before(start)
            .not_valid_after(end)
            .add_extension(
                x509.BasicConstraints(ca=is_ca, path_length=1 if is_ca else None),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(public_key),
                critical=False,
            )
        )
        if san is not None:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(san)]), critical=False
            )
        return builder.sign(private_key=signer, algorithm=hashes.SHA256())

    root_name = name("Synthetic Intermediate Date Root")
    root = cert(
        root_name,
        root_name,
        root_key.public_key(),
        root_key,
        0x7101,
        dt.datetime(2020, 1, 1, tzinfo=utc),
        dt.datetime(2050, 1, 1, tzinfo=utc),
        True,
    )
    intermediate_name = name("Synthetic Intermediate Date CA")
    intermediate = cert(
        intermediate_name,
        root_name,
        intermediate_key.public_key(),
        root_key,
        0x7102,
        dt.datetime(2025, 1, 1, tzinfo=utc),
        dt.datetime(2035, 1, 1, tzinfo=utc),
        True,
    )
    leaf = cert(
        name("tls-intermediate.example.invalid"),
        intermediate_name,
        leaf_key.public_key(),
        intermediate_key,
        0x7103,
        dt.datetime(2020, 1, 1, tzinfo=utc),
        dt.datetime(2050, 1, 1, tzinfo=utc),
        False,
        "tls-intermediate.example.invalid",
    )
    pem = serialization.Encoding.PEM
    directory.joinpath("root.pem").write_bytes(root.public_bytes(pem))
    directory.joinpath("server_chain.pem").write_bytes(
        leaf.public_bytes(pem) + intermediate.public_bytes(pem)
    )


class CertificateBundleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        defaults = (ROOT / "sdkconfig.defaults").read_text()
        required = (
            "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_DEFAULT_FULL=y",
            "CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE=y",
            'CONFIG_MBEDTLS_CUSTOM_CERTIFICATE_BUNDLE_PATH="components/idf_lpa/certs/gsma_rsp_tls_roots.pem"',
            "CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY=y",
        )
        missing = [entry for entry in required if entry not in defaults.splitlines()]
        if missing:
            raise AssertionError(
                "sdkconfig.defaults is missing the pinned IDF trust-bundle settings: "
                + ", ".join(missing)
            )
        if not GSMA_CERT.is_file():
            raise AssertionError(f"GSMA trust bundle payload is missing: {GSMA_CERT}")
        if not (CROSS_FIXTURES / "server_cert_chain.pem").is_file():
            raise AssertionError("official cross-signed chain fixture is missing")
        if not (CROSS_FIXTURES / "server_root.pem").is_file():
            raise AssertionError("official cross-signed root fixture is missing")

        # Compose mounts /tmp with noexec. Keep this ephemeral native build on
        # the worktree's ignored build volume instead; the standalone Docker
        # fallback remains able to use /tmp when the source bind is read-only.
        temp_parent = ROOT / "build"
        try:
            temp_parent.mkdir(exist_ok=True)
        except OSError:
            temp_parent = None
        try:
            cls.temp = tempfile.TemporaryDirectory(
                prefix="tls-bundle-", dir=temp_parent
            )
        except (OSError, PermissionError):
            cls.temp = tempfile.TemporaryDirectory(prefix="tls-bundle-")
        cls.addClassCleanup(cls.temp.cleanup)
        output = Path(cls.temp.name)
        intermediate_fixtures = output / "intermediate"
        write_intermediate_fixtures(intermediate_fixtures)
        cls.intermediate_fixtures = intermediate_fixtures
        patched_source = output / "esp_crt_bundle.c"
        run(
            sys.executable,
            str(ROOT / "tools/patch_idf_tls_source.py"),
            "--input",
            str(Path(os.environ["IDF_PATH"]) /
                "components/mbedtls/esp_crt_bundle/esp_crt_bundle.c"),
            "--output",
            str(patched_source),
        )
        config_dir = output / "config"
        config_dir.mkdir()
        # These are the same sdkconfig switches consumed by pinned esp_config.h.
        # The native build still compiles the IDF implementation and Mbed TLS;
        # this header only supplies the target's generated Kconfig contract.
        sdkconfig = config_dir / "sdkconfig.h"
        sdkconfig.write_text(
            "#define CONFIG_IDF_TARGET_LINUX 1\n"
            "#define CONFIG_MBEDTLS_CUSTOM_MEM_ALLOC 1\n"
            "#define CONFIG_MBEDTLS_HAVE_TIME 1\n"
            "#define CONFIG_MBEDTLS_X509_USE_C 1\n"
            "#define CONFIG_MBEDTLS_PEM_PARSE_C 1\n"
            "#define CONFIG_MBEDTLS_PK_C 1\n"
            "#define CONFIG_MBEDTLS_PK_PARSE_C 1\n"
            "#define CONFIG_MBEDTLS_X509_CRT_PARSE_C 1\n"
            "#define CONFIG_MBEDTLS_FS_IO 1\n"
            "#define CONFIG_MBEDTLS_ASN1_PARSE_C 1\n"
            "#define CONFIG_MBEDTLS_CERTIFICATE_BUNDLE 1\n"
            "#define CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY 1\n"
            "#define CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_MAX_CERTS 200\n"
            "#define CONFIG_MBEDTLS_HAVE_TIME_DATE 1\n"
            "#define CONFIG_MBEDTLS_X509_TRUSTED_CERT_CALLBACK 1\n"
            "#define CONFIG_MBEDTLS_RSA_C 1\n"
            "#define CONFIG_MBEDTLS_ECP_C 1\n"
            "#define CONFIG_MBEDTLS_ECP_DP_SECP256R1_ENABLED 1\n"
            "#define CONFIG_MBEDTLS_ECDH_C 1\n"
            "#define CONFIG_MBEDTLS_ECDSA_C 1\n"
            "#define CONFIG_MBEDTLS_MD_C 1\n"
            "#define CONFIG_MBEDTLS_SHA1_C 1\n"
            "#define CONFIG_MBEDTLS_SHA256_C 1\n"
            "#define CONFIG_MBEDTLS_SHA384_C 1\n"
            "#define CONFIG_MBEDTLS_SHA512_C 1\n"
            "#define CONFIG_MBEDTLS_BASE64_C 1\n"
            "#define CONFIG_MBEDTLS_AES_C 1\n"
            "#define CONFIG_MBEDTLS_GCM_C 1\n"
            "#define CONFIG_MBEDTLS_TLS_ENABLED 1\n"
            "#define CONFIG_MBEDTLS_SSL_PROTO_TLS1_2 1\n"
            "#define CONFIG_MBEDTLS_TLS_CLIENT 1\n"
            "#define CONFIG_MBEDTLS_KEY_EXCHANGE_RSA 1\n"
            "#define CONFIG_MBEDTLS_KEY_EXCHANGE_ELLIPTIC_CURVE 1\n"
            "#define CONFIG_MBEDTLS_KEY_EXCHANGE_ECDHE_RSA 1\n"
            "#define CONFIG_MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA 1\n"
            "#define CONFIG_MBEDTLS_CTR_DRBG_C 1\n"
            "#define CONFIG_MBEDTLS_HMAC_DRBG_C 1\n"
            "#define CONFIG_MBEDTLS_PKCS1_V15 1\n"
            "#define CONFIG_MBEDTLS_PKCS1_V21 1\n"
            "#define CONFIG_LOG_DEFAULT_LEVEL 0\n"
            "#define CONFIG_LOG_DEFAULT_LEVEL_NONE 1\n"
            "#define MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG 1\n"
        )

        idf = Path(os.environ["IDF_PATH"])
        run(
            "cmake",
            "-S",
            str(FIXTURES),
            "-B",
            str(output / "build"),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DBUNDLE_CONFIG_DIR={config_dir}",
            f"-DIDF_MBEDTLS={idf / 'components/mbedtls'}",
            f"-DPATCHED_CRT_BUNDLE_DIR={patched_source.parent}",
            f"-DGSMA_CERT={GSMA_CERT}",
            f"-DSYNTHETIC_CERT_DIR={DATE_FIXTURES}",
            f"-DCROSS_SIGNED_CERT_DIR={CROSS_FIXTURES}",
            f"-DINTERMEDIATE_CERT_DIR={intermediate_fixtures}",
        )
        run(
            "cmake",
            "--build",
            str(output / "build"),
            "--target",
            "verify_bundle",
            "verify_bundle_untrusted",
            "verify_cross_signed",
            "verify_intermediate",
            "--parallel",
            "4",
        )
        cls.verifier = output / "build/verify_bundle"
        cls.untrusted_verifier = output / "build/verify_bundle_untrusted"
        cls.cross_verifier = output / "build/verify_cross_signed"
        cls.intermediate_verifier = output / "build/verify_intermediate"

        # Build the same pinned verifier once with the cross-signed Kconfig
        # switch absent.  This keeps the OFF/ON comparison in the native IDF
        # implementation rather than changing the trust decision in Python.
        off_config = output / "config-off"
        off_config.mkdir()
        off_header = (config_dir / "sdkconfig.h").read_text()
        off_header = off_header.replace(
            "#define CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY 1\n",
            "",
        )
        (off_config / "sdkconfig.h").write_text(off_header)
        off_build = output / "build-off"
        run(
            "cmake",
            "-S",
            str(FIXTURES),
            "-B",
            str(off_build),
            "-G",
            "Ninja",
            "-DCMAKE_BUILD_TYPE=Release",
            f"-DBUNDLE_CONFIG_DIR={off_config}",
            f"-DIDF_MBEDTLS={idf / 'components/mbedtls'}",
            f"-DPATCHED_CRT_BUNDLE_DIR={patched_source.parent}",
            f"-DGSMA_CERT={GSMA_CERT}",
            f"-DSYNTHETIC_CERT_DIR={DATE_FIXTURES}",
            f"-DCROSS_SIGNED_CERT_DIR={CROSS_FIXTURES}",
            f"-DINTERMEDIATE_CERT_DIR={intermediate_fixtures}",
        )
        run(
            "cmake",
            "--build",
            str(off_build),
            "--target",
            "verify_bundle",
            "verify_bundle_untrusted",
            "verify_cross_signed",
            "verify_intermediate",
            "--parallel",
            "4",
        )
        cls.off_verifier = off_build / "verify_bundle"
        cls.off_untrusted_verifier = off_build / "verify_bundle_untrusted"
        cls.off_cross_verifier = off_build / "verify_cross_signed"
        cls.off_intermediate_verifier = off_build / "verify_intermediate"

    def assert_case(self, verifier: Path, anchor: str, hostname: str, now: int,
                    expected_result: int, expected_flags: int,
                    expected_direct_result: int | None = None,
                    expected_direct_flags: int | None = None):
        if expected_direct_result is None:
            expected_direct_result = expected_result
        if expected_direct_flags is None:
            expected_direct_flags = expected_flags
        result = subprocess.run(
            (
                str(verifier),
                str(DATE_FIXTURES / anchor),
                str(DATE_FIXTURES / "server.pem"),
                hostname,
                str(now),
            ),
            text=True,
            capture_output=True,
            check=True,
        )
        output = result.stdout
        self.assertEqual(
            tuple(map(int, output.split())),
            (expected_result, expected_flags, expected_direct_result,
             expected_direct_flags, 2),
        )

    def test_bundle_callback_keeps_time_hostname_and_trust_checks(self):
        # The first two certificates are synthetic test inputs; the second
        # input is the public GSMA RSP root payload used by the product bundle.
        # The verifier reports the generated bundle count so an empty custom
        # input cannot make this test pass accidentally.
        cases = (
            ("valid", "tls-dates.example.invalid", 1830297600, 0, 0),
            ("expired", "tls-dates.example.invalid", 1956528000, -0x2700, 0x01),
            ("future", "tls-dates.example.invalid", 1704067200, -0x2700, 0x200),
            ("cold_boot", "tls-dates.example.invalid", 0, -0x2700, 0x200),
            ("hostname", "wrong.example.invalid", 1830297600, -0x2700, 0x04),
        )
        for name, hostname, now, expected_result, expected_flags in cases:
            with self.subTest(case=name):
                self.assert_case(
                    self.verifier,
                    "root.pem",
                    hostname,
                    now,
                    expected_result,
                    expected_flags,
                )

    def test_bundle_callback_rejects_an_untrusted_root(self):
        # esp_crt_verify_callback returns MBEDTLS_ERR_X509_CERT_VERIFY_FAILED
        # when the bundle has no matching issuer. Pinned Mbed TLS treats a
        # non-zero verification-callback return as fatal and sets flags to
        # UINT32_MAX; keep that rejection contract distinct from direct X.509
        # verification, which reports the normal NOT_TRUSTED flag.
        self.assert_case(
            self.untrusted_verifier,
            "other-root.pem",
            "tls-dates.example.invalid",
            1830297600,
            -0x3000,
            0xFFFFFFFF,
            -0x2700,
            0x08,
        )

    def test_cross_signed_fixture_changes_synthetic_root_time_result(self):
        def run_fixture(verifier: Path) -> tuple[int, int, int, int, int, int]:
            result = subprocess.run(
                (
                    str(verifier),
                    str(CROSS_FIXTURES / "server_root.pem"),
                    str(CROSS_FIXTURES / "server_cert_chain.pem"),
                    "localhost",
                    "1830297600",
                ),
                text=True,
                capture_output=True,
                check=True,
            )
            return tuple(map(int, result.stdout.split()))

        # The official ESP-IDF test at commit 0e03327 enables this switch for
        # its cross-signed TLS handshake.  The raw public fixture can also be
        # accepted by the legacy callback, so the oracle below deliberately
        # checks the synthetic parent that the CA callback creates: OFF keeps
        # its invalid time flags, while ON clears only those generated flags.
        on = run_fixture(self.cross_verifier)
        off = run_fixture(self.off_cross_verifier)
        self.assertEqual(on[0:2], (0, 0))
        self.assertEqual(off[0:2], (0, 0))
        self.assertEqual(on[2:4], (0, 0))
        self.assertNotEqual(off[2], 0)
        self.assertNotEqual(off[3] & (0x01 | 0x200), 0)
        self.assertEqual(on[4:], (2, 2))
        self.assertEqual(off[4:], (2, 2))

    def test_bundle_callback_rejects_invalid_intermediate_dates(self):
        def run_case(now: int) -> tuple[int, int, int, int, int]:
            result = subprocess.run(
                (
                    str(self.intermediate_verifier),
                    str(self.intermediate_fixtures / "root.pem"),
                    str(self.intermediate_fixtures / "server_chain.pem"),
                    "tls-intermediate.example.invalid",
                    str(now),
                ),
                text=True,
                capture_output=True,
                check=True,
            )
            return tuple(map(int, result.stdout.split()))

        # The leaf remains valid for both dates.  Only its intermediate is
        # outside the 2025-2035 window, so a callback that clears all date
        # flags would make either case pass incorrectly.
        expired = run_case(2051222401)  # just after 2035-01-01: expired
        future = run_case(1640995200)  # 2022-01-01: intermediate not yet valid
        self.assertNotEqual(expired[0], 0)
        self.assertNotEqual(future[0], 0)
        self.assertTrue(expired[1] & 0x01)
        self.assertTrue(future[1] & 0x200)
        self.assertEqual(expired[4], 2)
        self.assertEqual(future[4], 2)


if __name__ == "__main__":
    if "--native" in sys.argv:
        sys.argv.remove("--native")
        unittest.main()
    else:
        # No downloads, device access, or checkout writes. Native artifacts
        # stay in the container's temporary filesystem.
        sys.exit(
            subprocess.call(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--pull=never",
                    "--network=none",
                    "--read-only",
                    "--cap-drop=ALL",
                    "--security-opt=no-new-privileges:true",
                    "--tmpfs",
                    "/tmp:rw,nosuid,nodev,exec,size=512m",
                    "--tmpfs",
                    "/opt/esp/idf/.git:ro,nosuid,nodev,noexec,size=1m",
                    "--mount",
                    f"type=bind,src={ROOT},dst=/workspace,readonly",
                    "--workdir",
                    "/workspace",
                    "--env",
                    "PYTHONDONTWRITEBYTECODE=1",
                    EXPECTED_IDF_IMAGE,
                    "python3",
                    "tools/test_tls_certificate_bundle.py",
                    "--native",
                    *sys.argv[1:],
                ]
            )
        )
