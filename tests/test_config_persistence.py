import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class ConfigPersistenceTest(unittest.TestCase):
    def test_save_failures_are_checked_and_reported(self):
        header = (ROOT / "code/config.h").read_text()
        config = (ROOT / "code/config.cpp").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()

        self.assertIn("bool saveConfig();", header)
        self.assertIn("static bool putStringChecked", config)
        self.assertIn('if (!preferences.begin("sms_config", false))', config)
        self.assertIn("preferences.getType(key) == PT_STR", config)
        self.assertIn("preferences.putInt", config)
        self.assertIn("preferences.putBool", config)
        self.assertIn("preferences.putUChar", config)
        self.assertNotIn("void saveConfig()", config)

        failure = handlers.index("if (!saveConfig())")
        notification = handlers.index('String subject = "短信转发器配置已更新"')
        self.assertIn('ACTION_CONFIG_SAVE_FAILED', handlers[failure:notification])
        self.assertLess(failure, notification)


if __name__ == "__main__":
    unittest.main()
