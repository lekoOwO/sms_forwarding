#!/usr/bin/env python3
"""Deterministic source and fault-model checks for IDF configuration storage."""

from __future__ import annotations

import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "components/idf_config/idf_config.cpp"
STORAGE = ROOT / "components/idf_config/idf_config_storage.cpp"
MAIN = ROOT / "main/app_main.cpp"
HEADER = ROOT / "components/idf_config/include/idf_config.h"
CMAKE = ROOT / "components/idf_config/CMakeLists.txt"


class AtomicSlotModel:
    def __init__(self) -> None:
        self.slots = [{"blob": b"old", "marker": b"old"}, {"blob": b"stale", "marker": b"stale"}]

    def boot(self) -> bytes | None:
        valid = [slot["blob"] for slot in self.slots if slot["blob"] is not None and slot["blob"] == slot["marker"]]
        return valid[-1] if valid else None

    def save_with_power_cut(self, value: bytes, cut_after: str) -> None:
        # The implementation erases the inactive marker in its own commit
        # before replacing that slot's blob.  A cut therefore leaves an
        # incomplete slot, never a mismatched committed pair.
        self.slots[1]["marker"] = None
        self.slots[1]["blob"] = value
        if cut_after == "blob_commit":
            return
        self.slots[1]["marker"] = value


class ConfigPersistenceTest(unittest.TestCase):
    def test_power_cut_keeps_a_whole_old_or_new_slot(self) -> None:
        for cut, expected in (("blob_commit", b"old"), ("marker_commit", b"new")):
            storage = AtomicSlotModel()
            storage.save_with_power_cut(b"new", cut)
            self.assertEqual(storage.boot(), expected)

    def test_invalid_present_slots_fail_closed(self) -> None:
        storage = AtomicSlotModel()
        storage.slots = [{"blob": b"bad", "marker": b"old"}, {"blob": b"bad2", "marker": b"bad3"}]
        self.assertIsNone(storage.boot())

    def test_idf_source_owns_versioned_appcfg_protocol(self) -> None:
        source = "\n".join(
            path.read_text(encoding="utf-8") for path in (SOURCE, STORAGE)
        )
        main = MAIN.read_text(encoding="utf-8")
        for token in (
            'nvs_open_from_partition', '"appcfg"', '"config"', '"cfgA"', '"cfgB"',
            '"markA"', '"markB"', 'crc32', 'CONFIG_SCHEMA_VERSION', 'nvs_get_blob',
            'nvs_commit', 'nvs_erase_key', 'CONFIG_STATE_MIGRATING', 'CONFIG_STATE_READY',
        ):
            self.assertIn(token, source)
        self.assertIn("idf_config_load()", main)
        self.assertIn("return;", main)
        self.assertEqual(main.count("idf_push_enqueue_startup_notification()"), 1)
        self.assertNotIn("nvs_flash_erase()", main)

    def test_storage_contracts_cover_marker_heap_selection_and_fail_closed_paths(self) -> None:
        storage = STORAGE.read_text(encoding="utf-8")
        config = SOURCE.read_text(encoding="utf-8")
        header = HEADER.read_text(encoding="utf-8")
        cmake = CMAKE.read_text(encoding="utf-8")

        # MRK2 is the shipped 20-byte marker; schema remains in CFG2's header.
        self.assertIn("constexpr size_t kMarkerBytes = 20", storage)
        self.assertNotIn("Slot slots[2]", storage)
        self.assertIn("std::unique_ptr<Slot[]>", storage)
        self.assertIn("-Werror=frame-larger-than=4096", cmake)
        self.assertIn("sizeof(IdfConfig) == 3212", config)

        # A bad sibling must not erase a valid prior; only a newer authenticated
        # future schema blocks startup.  The implementation-connected codec test
        # exercises the same internal slot selector.
        self.assertIn("generationNewer", storage)
        self.assertIn("unsupportedGeneration", storage)
        self.assertNotIn("nvs_flash_erase_partition", storage)

        # Legacy migration must cover both the develop key spellings and all
        # account slots, while v1-v3 keep the shipped payload semantics.
        for key in ("wifiSSID", "wifiPass", "wifiSSID2", "wifiPass2", "account%duser", "account%dpass", "remark"):
            self.assertIn(key, storage)
        self.assertIn("idf_config_storage_factory_reset", config)
        self.assertIn("idf_config_save_accounts", header)
        self.assertIn("idf_config_save_accounts", config)
        self.assertNotIn("save_config_to_nvs", config)
        for api in (
            "idf_config_save_identity", "idf_config_save_notification_locale",
            "idf_config_save_network_mode", "idf_config_save_heartbeat",
        ):
            self.assertIn(api, header)
            self.assertIn(api, config)

        # Update entrypoints must begin from the live snapshot while persistence
        # is serialized; this guard prevents reintroducing stale whole-config
        # writes during concurrent section saves.
        self.assertIn("begin_config_update", config)
        self.assertIn("finish_config_update", config)


if __name__ == "__main__":
    unittest.main()
