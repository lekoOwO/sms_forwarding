import json
import struct
import subprocess
import unittest
import zlib
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def _string(value: str) -> bytes:
    encoded = value.encode()
    return struct.pack("<H", len(encoded)) + encoded


def portable_v2_golden(source_hostname: str, source_admin_password: str) -> bytes:
    payload = struct.pack("<I", 465)
    for value in (
        "Portable backup",
        "portable-backup",
        "zh-TW",
        "smtp.example.com",
        "sender@example.com",
        "smtp-secret",
        "to@example.com",
        "",
        "",
    ):
        payload += _string(value)
    payload += (_string("") + _string("")) * 10
    channel = b"\x00\x01" + b"".join(_string(value) for value in ("Channel", "", "", "", "", "", ""))
    payload += channel * 5
    header = struct.pack("<IHHIII", 0x32474643, 2, 0, 0, len(payload), zlib.crc32(payload))
    assert source_hostname.encode() not in payload
    assert source_admin_password.encode() not in payload
    return header + payload


class ConfigSchemaTest(unittest.TestCase):
    def test_versioned_schemas_and_generated_firmware_constants_stay_in_sync(self):
        schema_dir = ROOT / "dev_doc/config-schema"
        manifest = json.loads((schema_dir / "manifest.json").read_text())
        v1 = json.loads((schema_dir / manifest["versions"]["1"]).read_text())
        v2 = json.loads((schema_dir / manifest["versions"]["2"]).read_text())

        self.assertEqual(manifest["currentVersion"], 2)
        self.assertEqual(v1["properties"]["schemaVersion"]["const"], 1)
        self.assertEqual(v2["properties"]["schemaVersion"]["const"], 2)
        config = v2["properties"]["config"]
        self.assertEqual(config["properties"]["deviceName"]["x-maxUtf8Bytes"], 64)
        self.assertEqual(config["properties"]["hostname"]["maxLength"], 32)
        self.assertEqual(
            config["properties"]["notificationLocale"]["enum"],
            ["zh-TW", "zh-CN", "en"],
        )
        channel = config["properties"]["pushChannels"]["items"]
        self.assertTrue(
            {"titleTemplate", "bodyTemplate", "customBody"}
            <= set(channel["properties"])
        )

        subprocess.run(
            ["python3", "scripts/generate-config-schema.py", "--check"],
            cwd=ROOT,
            check=True,
        )

    def test_codec_migrates_v1_and_portable_restore_preserves_target_identity(self):
        types = (ROOT / "code/config_types.h").read_text()
        header = (ROOT / "code/config.h").read_text()
        source = (ROOT / "code/config.cpp").read_text()

        for field in (
            "deviceName",
            "hostname",
            "notificationLocale",
            "titleTemplate",
            "bodyTemplate",
        ):
            self.assertIn(f"String {field};", types)
        self.assertIn("encodePortableConfig", header)
        self.assertIn("decodePortableConfig", header)
        self.assertIn("decodeConfigV1Payload", source)
        self.assertIn("target.deviceName", source)
        self.assertIn("target.hostname", source)
        self.assertIn("target.webAccounts", source)

        blob = portable_v2_golden("source-secret-host", "source-admin-secret")
        self.assertNotIn(b"source-secret-host", blob)
        self.assertNotIn(b"source-admin-secret", blob)
        self.assertIn(b"portable-backup", blob)
        self.assertIn("encodeConfig(value, 0, true, output)", source)

    def test_schema_owns_binary_security_and_field_metadata(self):
        schema_dir = ROOT / "dev_doc/config-schema"
        manifest = json.loads((schema_dir / "manifest.json").read_text())
        schema = json.loads((schema_dir / manifest["versions"]["2"]).read_text())
        config = schema["properties"]["config"]["properties"]
        channel = config["pushChannels"]["items"]["properties"]

        self.assertEqual(manifest["mimeType"], "application/vnd.sms-forwarding.config")
        self.assertEqual(manifest["backupEnvelope"]["magic"], "SMSCFG01")
        self.assertEqual(manifest["backupEnvelope"]["cipher"], "AES-256-GCM")
        self.assertEqual(manifest["backupEnvelope"]["iterations"], 210000)
        self.assertEqual(manifest["backupEnvelope"]["byteOrder"], "little-endian")
        self.assertEqual(manifest["backupEnvelope"]["aad"], "header")
        self.assertEqual(manifest["backupEnvelope"]["aadBytes"], 44)
        self.assertEqual(manifest["backupEnvelope"]["headerBytes"], 44)
        self.assertEqual(manifest["backupEnvelope"]["maxEncryptedBytes"], 32828)
        firmware = (ROOT / "code/config_schema_generated.h").read_text()
        web = (ROOT / "web/src/lib/config-schema.generated.ts").read_text()
        self.assertIn("BACKUP_AAD_BYTES = 44", firmware)
        self.assertIn("aadBytes: 44", web)
        self.assertEqual(config["webAccounts"]["x-itemCount"], 10)
        self.assertEqual(config["pushChannels"]["x-itemCount"], 5)
        self.assertTrue(config["smtpPass"]["x-sensitive"])
        self.assertEqual(channel["type"]["x-enumMapping"]["PUSH_TYPE_TELEGRAM"], 10)
        self.assertEqual(channel["bodyTemplate"]["x-maxRenderedUtf8Bytes"], 8192)

    def test_notification_catalog_is_the_only_new_runtime_cjk_source(self):
        push = (ROOT / "code/push.cpp").read_text()
        catalog = (ROOT / "code/notification_locale.cpp").read_text()
        sms = (ROOT / "code/sms_process.cpp").read_text()

        self.assertNotRegex(push, r"[\u3400-\u9fff]")
        for locale in ("NOTIFICATION_LOCALE_ZH_CN", "NOTIFICATION_LOCALE_EN"):
            self.assertIn(locale, catalog)
        self.assertIn("來自 {sender} 的簡訊", catalog)
        self.assertIn("{device}", catalog)
        self.assertIn("buildDefaultSmsNotification", sms)


if __name__ == "__main__":
    unittest.main()
