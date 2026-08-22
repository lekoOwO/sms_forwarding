#!/usr/bin/env python3
"""Checks for the non-production signed OTA test profile."""

from __future__ import annotations

import base64
import hashlib
import os
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "components" / "idf_web"
PRODUCTION_KEY = WEB / "ota_public_key.der.b64"
SIGNER = ROOT / "scripts" / "sign-ota-release.py"
WORKFLOW = ROOT / ".github" / "workflows" / "build.yml"
PRODUCTION_KEY_FINGERPRINT = "a3b8325cb8bbff1acaa402b7f1a39124b1297462da44f4c57b60929c996c4735"


def load_device():
    sys.path.insert(0, str(ROOT / "tools"))
    import device
    return device


def parse_package(package: bytes) -> tuple[bytes, bytes, bytes]:
    if not package.startswith(b"SMSOTA1\n"):
        raise AssertionError("invalid package magic")
    manifest_size = struct.unpack(">I", package[8:12])[0]
    manifest_end = 12 + manifest_size
    signature_size = struct.unpack(">H", package[manifest_end:manifest_end + 2])[0]
    signature_end = manifest_end + 2 + signature_size
    return package[12:manifest_end], package[manifest_end + 2:signature_end], package[signature_end:]


class OtaTestProfileTests(unittest.TestCase):
    def test_production_key_fingerprint_is_unchanged_and_dev_key_is_ephemeral(self):
        production = base64.b64decode(PRODUCTION_KEY.read_text().strip(), validate=True)
        self.assertEqual(hashlib.sha256(production).hexdigest(), PRODUCTION_KEY_FINGERPRINT)
        device = load_device()
        private, public, fingerprint = device._ensure_ota_test_keypair()
        test_key = base64.b64decode(public.read_text().strip(), validate=True)
        self.assertEqual(hashlib.sha256(test_key).hexdigest(), fingerprint)
        self.assertNotEqual(production, test_key)
        self.assertEqual(private.stat().st_mode & 0o077, 0)
        before = private.read_bytes()
        again = device._ensure_ota_test_keypair()
        self.assertEqual(again, (private, public, fingerprint))
        self.assertEqual(private.read_bytes(), before)
        profile = (ROOT / "build" / "idf-ota-test").resolve()
        for path in (private, device.OTA_TEST_PUBLIC_DER, public):
            self.assertTrue(path.is_file())
            self.assertFalse(path.is_symlink())
            self.assertTrue(path.resolve().is_relative_to(profile))

    def test_device_rejects_external_public_key_path(self):
        device = load_device()
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / "ota_test_public_key.der.b64"
            external.write_text("external\n", encoding="ascii")
            with self.assertRaisesRegex(device.usb_recovery.DeviceError, "build/idf-ota-test"):
                device._ota_test_build_environment(external)

    def test_device_rejects_symlinked_profile_directory(self):
        device = load_device()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            build = root / "build"
            target = root / "target"
            build.mkdir()
            target.mkdir()
            profile = build / "idf-ota-test"
            profile.symlink_to(target, target_is_directory=True)
            public = target / "ota_test_public_key.der.b64"
            public.write_text("external\n", encoding="ascii")
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "OTA_TEST_PROFILE_DIR", profile), \
                    self.assertRaisesRegex(device.usb_recovery.DeviceError, "symlink"):
                device._ota_test_build_environment(public)

    def test_device_rejects_symlinked_build_directory(self):
        device = load_device()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            real_build = root / "real-build"
            real_profile = real_build / "idf-ota-test"
            real_profile.mkdir(parents=True)
            build = root / "build"
            build.symlink_to(real_build, target_is_directory=True)
            public = real_profile / "ota_test_public_key.der.b64"
            public.write_text("external\n", encoding="ascii")
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "OTA_TEST_PROFILE_DIR", build / "idf-ota-test"), \
                    self.assertRaisesRegex(device.usb_recovery.DeviceError, "base"):
                device._ota_test_build_environment(public)

    def test_device_rejects_symlinked_private_key(self):
        device = load_device()
        source_private, _, _ = device._ensure_ota_test_keypair()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "build" / "idf-ota-test"
            profile.mkdir(parents=True)
            external = root / "private.pem"
            external.write_bytes(source_private.read_bytes())
            private = profile / "ota_test_private.pem"
            private.symlink_to(external)
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "OTA_TEST_PROFILE_DIR", profile), \
                    mock.patch.object(device, "OTA_TEST_PRIVATE_KEY", private), \
                    mock.patch.object(device, "OTA_TEST_PUBLIC_DER", profile / "public.der"), \
                    mock.patch.object(device, "OTA_TEST_PUBLIC_KEY", profile / "ota_test_public_key.der.b64"), \
                    self.assertRaisesRegex(device.usb_recovery.DeviceError, "symlink"):
                device._ensure_ota_test_keypair()

    def test_device_rejects_symlinked_public_key(self):
        device = load_device()
        source_private, _, _ = device._ensure_ota_test_keypair()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "build" / "idf-ota-test"
            profile.mkdir(parents=True)
            private = profile / "ota_test_private.pem"
            private.write_bytes(source_private.read_bytes())
            public_der = profile / "public.der"
            public_key = profile / "ota_test_public_key.der.b64"
            external = root / "public-key.der.b64"
            external.write_text("old\n", encoding="ascii")
            public_key.symlink_to(external)
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "OTA_TEST_PROFILE_DIR", profile), \
                    mock.patch.object(device, "OTA_TEST_PRIVATE_KEY", private), \
                    mock.patch.object(device, "OTA_TEST_PUBLIC_DER", public_der), \
                    mock.patch.object(device, "OTA_TEST_PUBLIC_KEY", public_key), \
                    self.assertRaisesRegex(device.usb_recovery.DeviceError, "symlink"):
                device._ensure_ota_test_keypair()

    def test_device_rejects_symlinked_public_der(self):
        device = load_device()
        source_private, _, _ = device._ensure_ota_test_keypair()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "build" / "idf-ota-test"
            profile.mkdir(parents=True)
            private = profile / "ota_test_private.pem"
            private.write_bytes(source_private.read_bytes())
            public_der = profile / "ota_test_public.der"
            external = root / "public.der"
            external.write_bytes(b"external")
            public_der.symlink_to(external)
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "OTA_TEST_PROFILE_DIR", profile), \
                    mock.patch.object(device, "OTA_TEST_PRIVATE_KEY", private), \
                    mock.patch.object(device, "OTA_TEST_PUBLIC_DER", public_der), \
                    mock.patch.object(device, "OTA_TEST_PUBLIC_KEY", profile / "ota_test_public_key.der.b64"), \
                    self.assertRaisesRegex(device.usb_recovery.DeviceError, "symlink"):
                device._ensure_ota_test_keypair()

    def test_device_rejects_nonregular_public_key(self):
        device = load_device()
        source_private, _, _ = device._ensure_ota_test_keypair()
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            profile = root / "build" / "idf-ota-test"
            profile.mkdir(parents=True)
            private = profile / "ota_test_private.pem"
            private.write_bytes(source_private.read_bytes())
            public_key = profile / "ota_test_public_key.der.b64"
            public_key.mkdir()
            with mock.patch.object(device, "ROOT", root), \
                    mock.patch.object(device, "OTA_TEST_PROFILE_DIR", profile), \
                    mock.patch.object(device, "OTA_TEST_PRIVATE_KEY", private), \
                    mock.patch.object(device, "OTA_TEST_PUBLIC_DER", profile / "public.der"), \
                    mock.patch.object(device, "OTA_TEST_PUBLIC_KEY", public_key), \
                    self.assertRaisesRegex(device.usb_recovery.DeviceError, "regular file"):
                device._ensure_ota_test_keypair()

    def test_test_package_verifies_with_dev_key_but_not_production_key(self):
        firmware = b"dev-only-ota-test-image"
        device = load_device()
        private, public, fingerprint = device._ensure_ota_test_keypair()
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            image = work / "image.bin"
            package = work / "image.smsota"
            public_test = work / "test-public.pem"
            public_production = work / "production-public.pem"
            manifest_file = work / "manifest.json"
            signature_file = work / "signature.bin"
            image.write_bytes(firmware)
            for encoded, path in ((public, public_test), (PRODUCTION_KEY, public_production)):
                der = base64.b64decode(encoded.read_text().strip(), validate=True)
                subprocess.run(
                    ["openssl", "pkey", "-pubin", "-inform", "DER", "-in", "/dev/stdin",
                     "-pubout", "-out", str(path)], input=der, check=True, capture_output=True,
                )
            subprocess.run(
                [
                    sys.executable, str(SIGNER), str(image), str(package),
                    "--private-key", str(private), "--version", "1.1.4-dev-test",
                    "--counter", "1", "--expected-public-sha256", fingerprint,
                ], cwd=ROOT, check=True, capture_output=True, text=True,
            )
            package_bytes = package.read_bytes()
            private_body = b"".join(
                line.encode() for line in private.read_text().splitlines()
                if not line.startswith("-----")
            )
            self.assertNotIn(private_body, package_bytes)
            manifest, signature, payload = parse_package(package_bytes)
            self.assertEqual(payload, firmware)
            manifest_file.write_bytes(manifest)
            signature_file.write_bytes(signature)
            accepted = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(public_test),
                 "-signature", str(signature_file), str(manifest_file)],
                check=False, capture_output=True,
            )
            rejected = subprocess.run(
                ["openssl", "dgst", "-sha256", "-verify", str(public_production),
                 "-signature", str(signature_file), str(manifest_file)],
                check=False, capture_output=True,
            )
            self.assertEqual(accepted.returncode, 0, accepted.stderr.decode())
            self.assertNotEqual(rejected.returncode, 0)

    def test_test_key_requires_generated_public_path_and_dev_profile_in_cmake(self):
        cmake = (ROOT / "CMakeLists.txt").read_text(encoding="utf-8")
        self.assertIn("SMS_OTA_TEST_PUBLIC_KEY", cmake)
        self.assertIn("generated public key", cmake)
        cmake_bin = shutil.which("cmake")
        if not cmake_bin:
            self.skipTest("cmake is not installed")
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "tools" / "cmake").mkdir(parents=True)
            (work / "firmware-version.json").write_text(
                (ROOT / "firmware-version.json").read_text(encoding="utf-8"), encoding="utf-8"
            )
            (work / "CMakeLists.txt").write_text(cmake, encoding="utf-8")
            (work / "tools" / "cmake" / "project.cmake").write_text(
                "function(idf_build_set_property)\nendfunction()\n", encoding="utf-8"
            )
            profile = work / "build" / "idf-ota-test"
            profile.mkdir(parents=True)
            public_real = profile / "generated.der.b64"
            public_real.write_text(PRODUCTION_KEY.read_text(encoding="ascii"), encoding="ascii")
            public_key = profile / "ota_test_public_key.der.b64"
            public_key.write_text(PRODUCTION_KEY.read_text(encoding="ascii"), encoding="ascii")
            env = os.environ.copy()
            env["IDF_PATH"] = str(work)
            env.pop("SMS_OTA_TEST_KEY", None)
            env.pop("SMS_OTA_TEST_PUBLIC_KEY", None)

            def configure_at(build_dir: Path, *values: str) -> subprocess.CompletedProcess[str]:
                return subprocess.run(
                    [cmake_bin, "-S", str(work), "-B", str(build_dir), *values],
                    env=env, capture_output=True, text=True, check=False,
                )

            def configure(*values: str) -> subprocess.CompletedProcess[str]:
                return configure_at(work / "build", *values)

            rejected_release = configure_at(work / "release-build",
                "-DFIRMWARE_IS_RELEASE=1", "-DSMS_USB_RECOVERY=1", "-DSMS_OTA_TEST_KEY=1",
            )
            self.assertNotEqual(rejected_release.returncode, 0)
            self.assertIn("release firmware", rejected_release.stderr)
            rejected_non_usb = configure_at(work / "non-usb-build",
                "-DFIRMWARE_IS_RELEASE=0", "-DSMS_USB_RECOVERY=0", "-DSMS_OTA_TEST_KEY=1",
            )
            self.assertNotEqual(rejected_non_usb.returncode, 0)
            self.assertIn("USB recovery", rejected_non_usb.stderr)

            env["SMS_OTA_TEST_KEY"] = "1"
            env["SMS_OTA_TEST_PUBLIC_KEY"] = str(public_key)
            accepted = configure("-DFIRMWARE_IS_RELEASE=0", "-DSMS_USB_RECOVERY=1")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            env.pop("SMS_OTA_TEST_KEY")
            env.pop("SMS_OTA_TEST_PUBLIC_KEY")
            stale_cache_safe = configure("-DFIRMWARE_IS_RELEASE=0", "-DSMS_USB_RECOVERY=1")
            self.assertEqual(stale_cache_safe.returncode, 0, stale_cache_safe.stderr)
            direct_build = work / "direct-build"
            rejected_direct = subprocess.run(
                [
                    cmake_bin, "-S", str(work), "-B", str(direct_build),
                    "-DFIRMWARE_IS_RELEASE=0", "-DSMS_USB_RECOVERY=1",
                    "-DSMS_OTA_TEST_KEY=1",
                ], env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(rejected_direct.returncode, 0)
            self.assertIn("generated public key", rejected_direct.stderr)

            env["SMS_OTA_TEST_KEY"] = "1"
            external = work / "outside" / "ota_test_public_key.der.b64"
            external.parent.mkdir()
            external.write_text(PRODUCTION_KEY.read_text(encoding="ascii"), encoding="ascii")
            env["SMS_OTA_TEST_PUBLIC_KEY"] = str(external)
            rejected_external = configure("-DFIRMWARE_IS_RELEASE=0", "-DSMS_USB_RECOVERY=1")
            self.assertNotEqual(rejected_external.returncode, 0)
            self.assertIn("build/idf-ota-test", rejected_external.stderr)

            public_key.unlink()
            public_key.symlink_to(public_real)
            env["SMS_OTA_TEST_PUBLIC_KEY"] = str(public_key)
            rejected_symlink = configure("-DFIRMWARE_IS_RELEASE=0", "-DSMS_USB_RECOVERY=1")
            self.assertNotEqual(rejected_symlink.returncode, 0)
            self.assertIn("generated public key", rejected_symlink.stderr)

            public_key.unlink()
            public_key.mkdir()
            rejected_directory = configure("-DFIRMWARE_IS_RELEASE=0", "-DSMS_USB_RECOVERY=1")
            self.assertNotEqual(rejected_directory.returncode, 0)
            self.assertIn("generated public key", rejected_directory.stderr)

            public_key.rmdir()
            os.mkfifo(public_key)
            env["SMS_OTA_TEST_PUBLIC_KEY"] = str(public_key)
            rejected_fifo = subprocess.run(
                [
                    cmake_bin, "-S", str(work), "-B", str(work / "fifo-build"),
                    "-DFIRMWARE_IS_RELEASE=0", "-DSMS_USB_RECOVERY=1",
                ], env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(rejected_fifo.returncode, 0)
            self.assertIn("regular file", rejected_fifo.stderr)

    def test_idf_helper_rejects_external_public_key_before_toolchain_lookup(self):
        with tempfile.TemporaryDirectory() as directory:
            external = Path(directory) / "ota_test_public_key.der.b64"
            external.write_text("external\n", encoding="ascii")
            env = os.environ.copy()
            env.update({
                "FIRMWARE_IS_RELEASE": "0",
                "SMS_USB_RECOVERY": "1",
                "SMS_OTA_TEST_KEY": "1",
                "SMS_OTA_TEST_PUBLIC_KEY": str(external),
            })
            env.pop("IDF_PATH", None)
            result = subprocess.run(
                [str(ROOT / "tools" / "idf.sh"), "build"],
                cwd=ROOT, env=env, capture_output=True, text=True, check=False,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("build/idf-ota-test", result.stderr)

    def test_release_workflow_and_firmware_artifacts_do_not_contain_private_key(self):
        workflow = WORKFLOW.read_text(encoding="utf-8")
        self.assertNotIn("ota_test_private", workflow)
        self.assertNotIn("ota_test_public_key", workflow)
        self.assertIn("release-input/scripts/sign-ota-release.py", workflow)
        self.assertNotIn("tools/fixtures", workflow)
        device = load_device()
        private, _, _ = device._ensure_ota_test_keypair()
        private_body = b"".join(
            line.encode() for line in private.read_text().splitlines()
            if not line.startswith("-----")
        )
        artifact_paths = [
            ROOT / "build" / "idf" / "sms_forwarding_idf.bin",
            ROOT / "build" / "idf-usb-recovery" / "sms_forwarding_idf.bin",
            ROOT / "build" / "idf-ota-test" / "sms_forwarding_idf.bin",
            *(ROOT / "dist").glob("*.bin"),
        ]
        for path in artifact_paths:
            if path.is_file():
                self.assertNotIn(private_body, path.read_bytes())

    def test_dev_runtime_uses_separate_nvs_namespace(self):
        runtime = (WEB / "idf_web_ota.cpp").read_text(encoding="utf-8")
        self.assertIn('OTA_NAMESPACE = "ota_test_meta"', runtime)
        self.assertIn('OTA_NAMESPACE = "ota_meta"', runtime)
        self.assertIn("ota_test_public_key_der_b64_start", runtime)
        self.assertIn("ota_public_key_der_b64_start", runtime)

    def test_device_ota_test_package_selects_only_the_dev_profile(self):
        device = load_device()
        command = device.build_parser().parse_args(["ota-test-package"])
        self.assertEqual(command.counter, 1)
        self.assertEqual(command.version, "1.1.4-dev-test")
        self.assertEqual(command.output, "dist/sms-forwarder-dev-test.smsota")
        _, public, _ = device._ensure_ota_test_keypair()
        env = device._ota_test_build_environment(public)
        self.assertEqual(env["SMS_USB_RECOVERY"], "1")
        self.assertEqual(env["SMS_OTA_TEST_KEY"], "1")
        self.assertEqual(env["SMS_OTA_TEST_PUBLIC_KEY"], str(public))
        self.assertEqual(env["FIRMWARE_IS_RELEASE"], "0")

    def test_device_command_reuses_signer_and_reports_pinned_hashes(self):
        device = load_device()
        output = ROOT / "build" / "ota-test-profile-test.smsota"
        device.OTA_TEST_IMAGE.parent.mkdir(parents=True, exist_ok=True)
        previous = device.OTA_TEST_IMAGE.read_bytes() if device.OTA_TEST_IMAGE.exists() else None
        device.OTA_TEST_IMAGE.write_bytes(b"dev-profile-image")
        real_run = device.subprocess.run

        def run(command, **kwargs):
            if command[:2] == [str(device.IDF_HELPER), "build"]:
                return type("Result", (), {"returncode": 0})()
            return real_run(command, **kwargs)

        try:
            image_sha = hashlib.sha256(device.OTA_TEST_IMAGE.read_bytes()).hexdigest()
            args = device.build_parser().parse_args([
                "ota-test-package", "--output", str(output), "--sha256", image_sha,
            ])
            with mock.patch.object(device.subprocess, "run", side_effect=run):
                self.assertEqual(device._ota_test_package_command(args), 0)
            self.assertTrue(output.is_file())
        finally:
            output.unlink(missing_ok=True)
            if previous is None:
                device.OTA_TEST_IMAGE.unlink(missing_ok=True)
            else:
                device.OTA_TEST_IMAGE.write_bytes(previous)


if __name__ == "__main__":
    unittest.main()
