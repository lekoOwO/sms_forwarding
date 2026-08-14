import gzip
import json
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_GZIP_BYTES = 256 * 1024


class WebBundleContractTest(unittest.TestCase):
    def test_frontend_is_a_separate_project(self):
        self.assertTrue((ROOT / "web/package.json").is_file())
        self.assertTrue((ROOT / "web/src/routes/+page.svelte").is_file())
        self.assertFalse((ROOT / "code/web_html.cpp").exists())
        self.assertFalse((ROOT / "code/web_html.h").exists())

    def test_firmware_serves_the_littlefs_bundle(self):
        sketch = (ROOT / "code/code.ino").read_text()
        handlers = (ROOT / "code/web_handlers.cpp").read_text()
        self.assertIn("LittleFS.begin", sketch)
        self.assertIn('server.on("/api/config"', sketch)
        self.assertIn('LittleFS.open("/index.html.gz"', handlers)
        self.assertNotIn('#include "web_html.h"', handlers)

    def test_bundle_is_self_contained_and_bounded(self):
        bundle = ROOT / "code/data/index.html.gz"
        self.assertTrue(bundle.is_file())
        self.assertLessEqual(bundle.stat().st_size, MAX_GZIP_BYTES)
        html = gzip.decompress(bundle.read_bytes()).decode()
        self.assertNotIn('<script src="', html)
        self.assertNotIn('rel="stylesheet" href="', html)
        for locale in ("zh-TW", "zh-CN", "en"):
            self.assertIn(locale, html)

    def test_locale_keys_stay_in_sync(self):
        locale_dir = ROOT / "web/src/lib/locales"
        dictionaries = [json.loads((locale_dir / f"{locale}.json").read_text()) for locale in ("zh-TW", "zh-CN", "en")]
        self.assertEqual(set(dictionaries[0]), set(dictionaries[1]))
        self.assertEqual(set(dictionaries[0]), set(dictionaries[2]))


if __name__ == "__main__":
    unittest.main()
