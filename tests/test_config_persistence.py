import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class AtomicSlots:
    """Small executable model of the firmware's blob-then-marker protocol."""

    def __init__(self, active=b"old"):
        self.slots = [{"blob": active, "marker": active}, {"blob": None, "marker": None}]

    def boot(self):
        valid = [slot["blob"] for slot in self.slots if slot["blob"] == slot["marker"]]
        return valid[-1] if valid else None

    def save_with_cut(self, value, cut_after):
        self.slots[1]["blob"] = value
        if cut_after == "blob":
            return
        self.slots[1]["marker"] = value


class InitialMigration:
    def __init__(self):
        self.state = "empty"
        self.blob = None
        self.marker = None

    def migrate_with_cut(self, cut_after):
        self.state = "migrating"
        if cut_after == "state":
            return
        self.blob = b"legacy"
        if cut_after == "blob":
            return
        self.marker = b"legacy"
        if cut_after == "marker":
            return
        self.state = "ready"

    def boot(self):
        if self.blob is not None and self.blob == self.marker:
            self.state = "ready"
            return b"legacy"
        if self.state == "migrating":
            return "retry"
        return None


class ConfigPersistenceTest(unittest.TestCase):
    def test_power_cut_selects_a_complete_old_or_new_config(self):
        for cut, expected in (("blob", b"old"), ("marker", b"new")):
            storage = AtomicSlots()
            storage.save_with_cut(b"new", cut)
            self.assertEqual(expected, storage.boot())

    def test_initial_migration_retries_until_a_marker_is_committed(self):
        for cut in ("state", "blob"):
            storage = InitialMigration()
            storage.migrate_with_cut(cut)
            self.assertEqual("retry", storage.boot())
        for cut in ("marker", "ready"):
            storage = InitialMigration()
            storage.migrate_with_cut(cut)
            self.assertEqual(b"legacy", storage.boot())
            self.assertEqual("ready", storage.state)

    def test_firmware_uses_versioned_verified_double_slots(self):
        header = (ROOT / "code/config.h").read_text()
        source = (ROOT / "code/config.cpp").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        sketch = (ROOT / "code/code.ino").read_text()

        self.assertIn("ConfigLoadStatus loadConfig();", header)
        self.assertIn("bool saveConfig(const Config& candidate);", header)
        self.assertIn('preferences.begin("config", false, "appcfg")', source)
        for token in ("cfgA", "cfgB", "markA", "markB", "CONFIG_SCHEMA_VERSION", "crc32"):
            self.assertIn(token, source)
        self.assertIn("CONFIG_STATE_MIGRATING", source)
        self.assertIn("CONFIG_STATE_READY", source)
        self.assertIn("readSlot", source)
        self.assertIn("loadLegacyConfig", source)
        self.assertIn("CONFIG_LOAD_STORAGE_ERROR", source)
        self.assertIn("Config next = config;", handlers)
        self.assertIn("if (!saveConfig(next))", handlers)
        self.assertIn("config = next;", handlers)
        self.assertIn("configLoadStatus != CONFIG_LOAD_STORAGE_ERROR", sketch)
        self.assertIn("if (configStorageAvailable)", sketch)
        self.assertIn("管理HTTP已停用", sketch)


if __name__ == "__main__":
    unittest.main()
