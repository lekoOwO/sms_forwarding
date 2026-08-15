import json
import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class RequestedFeaturesTest(unittest.TestCase):
    def test_contract_supports_ten_web_accounts(self):
        spec = json.loads((ROOT / "dev_doc/openapi.json").read_text())
        config = spec["components"]["schemas"]["DeviceSnapshot"]["properties"]["config"]
        accounts = config["properties"]["webAccounts"]
        self.assertEqual(accounts["maxItems"], 10)
        self.assertIn("webAccounts", config["required"])

    def test_firmware_supports_ten_accounts_and_multipart_sms(self):
        types = (ROOT / "code/config_types.h").read_text()
        generated = (ROOT / "code/config_schema_generated.h").read_text()
        modem = (ROOT / "code/modem.cpp").read_text()
        self.assertIn("#define MAX_WEB_ACCOUNTS 10", generated)
        self.assertIn("WebAccount webAccounts[MAX_WEB_ACCOUNTS]", types)
        self.assertIn("encodePDU(phoneNumber, part.c_str(), reference", modem)

    def test_all_locales_include_the_new_controls(self):
        required = {"darkMode", "dayMode", "commonEnabled", "commonDisabled", "account"}
        for locale in ("en", "zh-TW", "zh-CN"):
            messages = json.loads((ROOT / f"web/src/lib/locales/{locale}.json").read_text())
            self.assertTrue(required <= messages.keys(), locale)

    def test_ui_uses_flat_shadcn_composition(self):
        page = (ROOT / "web/src/routes/+page.svelte").read_text()
        result = (ROOT / "web/src/lib/components/ActionResult.svelte").read_text()
        trigger = (ROOT / "web/src/lib/components/ui/accordion/accordion-trigger.svelte").read_text()
        self.assertNotIn("Card.", page)
        self.assertNotIn("Table.Root", page)
        self.assertNotIn("accountTab", page)
        self.assertNotIn("Alert.Root", result)
        self.assertIn("<dl", page)
        self.assertIn("text-base font-semibold", trigger)
        for component in ("Accordion.Root", "NavigationMenu.Root", "InputGroup.Root"):
            self.assertIn(component, page)

    def test_management_ui_layout_opens_first_accordion_per_tab(self):
        page = (ROOT / "web/src/routes/+page.svelte").read_text()
        self.assertIn('<title>{snapshot?.config.deviceName || t("appName")}</title>', page)
        for value in ('notification-locale', 'sms', 'identity', '0'):
            self.assertIn(f'<Accordion.Root type="single" value="{value}">', page)
        self.assertIn('data-overview-group="identity"', page)
        self.assertIn('data-overview-group="details"', page)
        self.assertIn('value="config-backup"', page)
        self.assertIn('value="config-restore"', page)
        self.assertNotIn('class={channel.enabled ? "bg-primary', page)

    def test_provider_change_applies_editable_template_defaults(self):
        helper = ROOT / "web/src/lib/push-template-defaults.js"
        self.assertTrue(helper.exists())
        script = """
          import { applyProviderTemplateDefaults } from './web/src/lib/push-template-defaults.js';
          const channel = { type: 1, titleTemplate: 'old', bodyTemplate: 'old', customBody: '' };
          applyProviderTemplateDefaults(channel, 7, 'title', 'body');
          if (channel.titleTemplate || channel.bodyTemplate || !channel.customBody.includes('{message}')) process.exit(1);
          applyProviderTemplateDefaults(channel, 2, 'title', 'body');
          if (channel.customBody || channel.titleTemplate !== 'title' || channel.bodyTemplate !== 'body') process.exit(2);
        """
        subprocess.run(
            ["node", "--input-type=module", "--eval", script],
            cwd=ROOT,
            check=True,
        )

    def test_notification_templates_offer_device_context_values(self):
        push = (ROOT / "code/push.cpp").read_text()
        modem = (ROOT / "code/modem.cpp").read_text()
        hints = "\n".join(
            json.loads((ROOT / f"web/src/lib/locales/{locale}.json").read_text())["templateValuesHint"]
            for locale in ("en", "zh-TW", "zh-CN")
        )
        for token in ("{localNumber}", "{ip}", "{device}", "{hostname}", "{wifi}"):
            self.assertIn(token, push)
            self.assertIn(token, hints)
        self.assertIn('sendATCommand("AT+CNUM", 2000)', modem)
        self.assertIn("modemGetLocalNumber()", push)

    def test_firmware_version_is_repo_owned_and_published_by_channel(self):
        version = json.loads((ROOT / "firmware-version.json").read_text())
        self.assertRegex(version["releaseVersion"], r"^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$")
        self.assertGreaterEqual(version["devBuild"], 1)
        generated = (ROOT / "code/firmware_version_generated.h").read_text()
        self.assertIn(f'#define FIRMWARE_RELEASE_VERSION "{version["releaseVersion"]}"', generated)
        self.assertIn(f'#define FIRMWARE_DEV_BUILD {version["devBuild"]}', generated)
        hook = (ROOT / ".githooks/pre-commit").read_text()
        self.assertIn('git branch --show-current', hook)
        self.assertIn('generate-firmware-version.py --bump', hook)

        workflow = (ROOT / ".github/workflows/build.yml").read_text()
        self.assertIn("branches: [develop, master]", workflow)
        self.assertIn("tags: ['v*']", workflow)
        self.assertIn("--prerelease", workflow)
        self.assertIn("FIRMWARE_DEV_BUILD * 2 + 1", workflow)
        self.assertNotIn("GITHUB_RUN_NUMBER", workflow)
        self.assertIn('test "$current_build" -gt "$previous_build"', workflow)

        page = (ROOT / "web/src/routes/+page.svelte").read_text()
        self.assertIn("snapshot.status.firmwareVersion", page)


if __name__ == "__main__":
    unittest.main()
