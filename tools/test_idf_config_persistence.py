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
    def test_defaults_do_not_use_formatters(self) -> None:
        storage = STORAGE.read_text(encoding="utf-8")
        defaults = storage[storage.index("IdfConfig defaults()"):storage.index("\nbool semanticallyValid")]
        self.assertNotRegex(defaults, r"\b(?:v?printf|v?s(?:n)?printf|v?fprintf|v?asprintf)\s*\(")

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

        portable_decode_start = storage.index("IdfPortableConfigStatus idf_config_storage_decode_portable")
        portable_decode = storage[portable_decode_start:storage.index("\nesp_err_t idf_config_storage_save", portable_decode_start)]
        self.assertNotIn("    IdfConfig decoded;", portable_decode)
        self.assertIn("std::unique_ptr<IdfConfig> decoded(new IdfConfig);", portable_decode)
        self.assertNotIn("value = defaults();", storage)
        self.assertNotIn("out = defaults();", storage)
        self.assertGreaterEqual(storage.count("initializeDefaults(value);"), 4)
        self.assertIn("initializeDefaults(out);", storage)

        # MRK2 is the shipped 20-byte marker; schema remains in CFG2's header.
        self.assertIn("constexpr size_t kMarkerBytes = 20", storage)
        self.assertNotIn("Slot slots[2]", storage)
        self.assertIn("std::unique_ptr<Slot[]>", storage)
        self.assertIn("-Werror=frame-larger-than=4096", cmake)
        self.assertIn("sizeof(IdfConfig) == 3356", config)

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
        self.assertIn("pushCellularUrlSet", header)
        self.assertIn("view.pushCellularUrlSet[i] = !s_config.pushChannels[i].cellularUrl.empty();", config)
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

    def test_scheduler_view_exposes_only_the_keepalive_action_needed_by_scheduler(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        config = SOURCE.read_text(encoding="utf-8")
        view = header.split("struct IdfSchedulerView", 1)[1].split("};", 1)[0]
        populate_start = config.index("IdfSchedulerView idf_config_get_scheduler_view")
        populate = config[populate_start:config.index("\nbool idf_config_get_push_channel", populate_start)]
        self.assertIn("uint8_t kaAction = 1;", view)
        self.assertIn("view.kaAction = s_config.kaAction;", populate)
        self.assertNotIn("kaUrl", view)
        self.assertNotIn("kaProfile", view)
        self.assertNotIn("smtpPass", view)

    def test_cellular_http_action_is_publicly_documented_as_unsupported(self) -> None:
        header = HEADER.read_text(encoding="utf-8")
        self.assertIn("1=cellular HTTP unsupported", header)
        self.assertNotIn("1=cellular HTTP ping", header)


if __name__ == "__main__":
    unittest.main()
