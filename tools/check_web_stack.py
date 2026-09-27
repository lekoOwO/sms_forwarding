#!/usr/bin/env python3
"""檢查 Web 儲存工作留給 NVS 呼叫鏈的 stack 空間。"""
import sys
from pathlib import Path


def check_stack_usage(path: Path) -> None:
    frames = []
    for line in path.read_text().splitlines():
        fields = line.split("\t")
        if len(fields) == 3 and "handle_modern_save(" in fields[0]:
            frames.append(int(fields[1]))
    if not frames:
        raise ValueError("Web save stack frame is missing from compiler report")
    if max(frames) > 2048:
        raise ValueError(f"Web save stack frame {max(frames)} exceeds 2048 bytes")
    print(f"Web save stack frame: {max(frames)} / 2048 bytes")


if __name__ == "__main__":
    check_stack_usage(Path(sys.argv[1]))
