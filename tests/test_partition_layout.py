import csv
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PartitionLayoutTest(unittest.TestCase):
    def test_no_ota_layout_has_dedicated_config_and_expected_filesystem(self):
        rows = []
        with (ROOT / "code/partitions.csv").open() as stream:
            for row in csv.reader(line for line in stream if not line.startswith("#")):
                rows.append([cell.strip() for cell in row])
        by_name = {row[0]: row for row in rows}
        self.assertNotIn("app1", by_name)
        self.assertEqual(["data", "nvs", "0x210000", "0x20000"], by_name["appcfg"][1:5])
        self.assertEqual(["app", "factory", "0x10000", "0x200000"], by_name["app0"][1:5])
        self.assertEqual(["data", "spiffs", "0x230000", "0x1C0000"], by_name["spiffs"][1:5])


if __name__ == "__main__":
    unittest.main()
