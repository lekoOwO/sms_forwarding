import json
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
        modem = (ROOT / "code/modem.cpp").read_text()
        self.assertIn("#define MAX_WEB_ACCOUNTS 10", types)
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


if __name__ == "__main__":
    unittest.main()
