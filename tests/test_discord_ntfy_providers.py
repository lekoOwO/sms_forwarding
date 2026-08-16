import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class DiscordNtfyProviderTest(unittest.TestCase):
    def test_schema_and_management_contract_publish_both_provider_values(self):
        manifest = json.loads((ROOT / "dev_doc/config-schema/manifest.json").read_text())
        schema = json.loads(
            (ROOT / "dev_doc/config-schema" / manifest["versions"][str(manifest["currentVersion"])]).read_text()
        )
        push_type = schema["properties"]["config"]["properties"]["pushChannels"]["items"]["properties"]["type"]
        self.assertEqual(manifest["currentVersion"], 4)
        self.assertEqual(push_type["x-enumMapping"]["PUSH_TYPE_DISCORD"], 11)
        self.assertEqual(push_type["x-enumMapping"]["PUSH_TYPE_NTFY"], 12)
        self.assertEqual(push_type["maximum"], 12)
        v2 = json.loads((ROOT / "dev_doc/config-schema/v2.json").read_text())
        self.assertEqual(
            v2["properties"]["config"]["properties"]["pushChannels"]["items"]["properties"]["type"]["maximum"],
            10,
        )

        openapi = json.loads((ROOT / "dev_doc/openapi.json").read_text())
        self.assertEqual(openapi["components"]["schemas"]["PushChannel"]["properties"]["type"]["maximum"], 12)
        self.assertEqual(
            openapi["components"]["schemas"]["ConfigUpdate"]["patternProperties"]["^push[0-4]type$"]["maximum"],
            12,
        )

    def test_firmware_discord_and_ntfy_http_contracts_are_fail_closed(self):
        source = (ROOT / "code/push.cpp").read_text()
        discord_body = source.split("case PUSH_TYPE_DISCORD:", 1)[1].split("case PUSH_TYPE_NTFY:", 1)[0]
        self.assertIn('json["content"] = content;', discord_body)
        self.assertIn('json["allowed_mentions"]["parse"].to<JsonArray>();', discord_body)
        self.assertIn("utf8CodePointCount(content.c_str(), 2000)", discord_body)
        self.assertIn("postJson(http, cellular, channel.url, json, httpCode)", discord_body)
        self.assertNotIn('"{\\"content\\"', discord_body)

        ntfy_body = source.split("case PUSH_TYPE_NTFY:", 1)[1].split("default:", 1)[0]
        self.assertIn('postPayload(http, cellular, channel.url, "text/plain",', ntfy_body)
        self.assertIn('"Title: " + notificationTitle, notificationBody, httpCode)', ntfy_body)
        self.assertNotIn("priority", ntfy_body.lower())

        config = (ROOT / "code/config.cpp").read_text()
        self.assertIn("type > PUSH_TYPE_NTFY", config)
        self.assertIn("decodeConfigV2Payload(cursor, end, value, PUSH_TYPE_TELEGRAM)", config)
        self.assertIn("decodeConfigV2Payload(cursor, end, value, PUSH_TYPE_NTFY)", config)
        self.assertIn("case PUSH_TYPE_DISCORD:", config)
        self.assertIn("case PUSH_TYPE_NTFY:", config)
        self.assertIn("channel.titleTemplate.indexOf('\\r')", config)
        self.assertIn("channel.titleTemplate.indexOf('\\n')", config)


if __name__ == "__main__":
    unittest.main()
