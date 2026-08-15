import os
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


class PduBoundsTest(unittest.TestCase):
    def test_decode_rejects_every_truncated_prefix(self):
        source = r'''
#include <cassert>
#include <cstring>
#include "pdulib.h"

int main() {
  const char fixture[] = "00040A91214365870900004210100000000005E8329BFD06";
  PDU pdu(256);
  assert(pdu.decodePDU(fixture, sizeof(fixture) - 1));
  assert(std::strcmp(pdu.getText(), "hello") == 0);
  for (size_t length = 0; length + 1 < sizeof(fixture); ++length)
    assert(!pdu.decodePDU(fixture, length));
  assert(!pdu.decodePDU("00GG", 4));
}
'''
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            test_cpp = work / "pdulib_bounds.cpp"
            binary = work / "pdulib_bounds"
            test_cpp.write_text(source)
            subprocess.run(
                [
                    "g++",
                    "-std=gnu++11",
                    "-DDESKTOP_PDU",
                    "-fsanitize=address,undefined",
                    "-fno-omit-frame-pointer",
                    "-I",
                    str(ROOT / "code/src/pdulib"),
                    str(test_cpp),
                    str(ROOT / "code/src/pdulib/pdulib.cpp"),
                    "-o",
                    str(binary),
                ],
                check=True,
            )
            subprocess.run(
                [str(binary)], check=True, env={**os.environ, "ASAN_OPTIONS": "detect_leaks=0"}
            )


if __name__ == "__main__":
    unittest.main()
