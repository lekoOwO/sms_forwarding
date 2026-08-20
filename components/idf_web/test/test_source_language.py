#!/usr/bin/env python3
import re
from pathlib import Path


WEB = Path(__file__).resolve().parents[1]
CJK = re.compile(
    r"[\u3400-\u4dbf\u4e00-\u9fff\uf900-\ufaff\u3040-\u30ff\uac00-\ud7af"
    r"\u3001\u3002\uff01\uff08\uff09\uff0c\uff1a\uff1b\uff1f]"
)


def main() -> None:
    offenders = []
    for path in sorted((*WEB.glob("*.cpp"), *WEB.glob("include/*.h"))):
        for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if CJK.search(line):
                offenders.append(f"{path.relative_to(WEB)}:{line_number}: {line.strip()}")
    assert not offenders, "Firmware Web sources must be English-only:\n" + "\n".join(offenders)


if __name__ == "__main__":
    main()
