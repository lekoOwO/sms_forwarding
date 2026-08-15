import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PushSafetyTest(unittest.TestCase):
    def test_delivery_paths_check_results_time_and_html_context(self):
        source = (ROOT / "code/push.cpp").read_text()
        self.assertIn("static bool hasValidEpoch()", source)
        self.assertIn("static String htmlEscape", source)
        self.assertIn("if (!smtp.authenticate", source)
        self.assertIn("if (smtp.send(msg))", source)
        self.assertNotIn("status.text", source)
        self.assertNotIn("http.errorToString", source)
        self.assertIn("httpCode >= 200 && httpCode < 300", source)


if __name__ == "__main__":
    unittest.main()
