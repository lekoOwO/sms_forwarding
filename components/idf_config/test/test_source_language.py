import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
CJK = re.compile(
    r"[\u1100-\u11ff\u3000-\u30ff\u3100-\u318f\u31a0-\u31bf\u31f0-\u31ff"
    r"\u3400-\u4dbf\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff\uff00-\uffef"
    r"\U00020000-\U000323af]"
)


class SourceLanguageTest(unittest.TestCase):
    def test_config_and_main_sources_use_english(self):
        sources = list((ROOT / "components/idf_config").rglob("*.cpp"))
        sources += list((ROOT / "components/idf_config").rglob("*.h"))
        sources.append(ROOT / "main/app_main.cpp")

        matches = []
        for source in sources:
            lines = source.read_text(encoding="utf-8").splitlines()
            for line_number, line in enumerate(lines, 1):
                if CJK.search(line):
                    matches.append(f"{source.relative_to(ROOT)}:{line_number}: {line.strip()}")

        self.assertEqual([], matches, "CJK text found:\n" + "\n".join(matches))


if __name__ == "__main__":
    unittest.main()
