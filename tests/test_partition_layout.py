import csv
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PartitionLayoutTest(unittest.TestCase):
    def test_ota_layout_has_dedicated_config_and_equal_slots(self):
        rows = []
        with (ROOT / "code/partitions.csv").open() as stream:
            for row in csv.reader(line for line in stream if not line.startswith("#")):
                rows.append([cell.strip() for cell in row])
        by_name = {row[0]: row for row in rows}
        self.assertEqual(["data", "nvs", "0x3D0000", "0x20000"], by_name["appcfg"][1:5])
        self.assertEqual(["app", "ota_0", "0x10000", "0x1E0000"], by_name["ota_0"][1:5])
        self.assertEqual(["app", "ota_1", "0x1F0000", "0x1E0000"], by_name["ota_1"][1:5])
        self.assertNotIn("spiffs", by_name)


if __name__ == "__main__":
    unittest.main()
