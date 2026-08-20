#!/usr/bin/env python3
import re
import unittest
from collections import Counter
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
COMPONENTS = ROOT / "components"
CJK = re.compile(
    r"[\u1100-\u11ff\u2e80-\u30ff\u3100-\u31ef\u3400-\u4dbf"
    r"\u4e00-\u9fff\uac00-\ud7af\uf900-\ufaff\uff00-\uffef"
    r"\U00020000-\U000323af]"
)
VENDOR_COMPONENT = "idf_pdu"
ALLOWED_CJK_LINES = {
    Path("idf_push/idf_push.cpp"): Counter((
        'title = "短信转发器已启动";',
        'body = "设备：" + cfg.deviceName + "\\n状态：已启动\\n设备网址：" + url;',
        'title = "簡訊轉發器已啟動";',
        'body = "裝置：" + cfg.deviceName + "\\n狀態：已啟動\\n裝置網址：" + url;',
        'title = "短信转发器心跳";',
        'body = "设备：" + cfg.deviceName + "\\n主机名：" + cfg.hostname +',
        '"\\n本机号码：" + local_number + "\\n网络地址：" + wifi.ip +',
        '"\\n设备网址：" + url + "\\n事件：设备在线\\n时间：" + event_time;',
        'title = "簡訊轉發器心跳";',
        'body = "裝置：" + cfg.deviceName + "\\n主機名稱：" + cfg.hostname +',
        '"\\n本機號碼：" + local_number + "\\n網路位址：" + wifi.ip +',
        '"\\n裝置網址：" + url + "\\n事件：設備在線\\n時間：" + event_time;',
    )),
    Path("idf_push/idf_push_core.cpp"): Counter((
        'const char* default_title = "來自 {sender} 的簡訊";',
        'const char* default_body = "裝置：{device}\\n寄件者：{sender}\\n時間：{timestamp}\\n內容：{message}";',
        'default_title = "来自 {sender} 的短信";',
        'default_body = "设备：{device}\\n发件人：{sender}\\n时间：{timestamp}\\n内容：{message}";',
    )),
}


def source_language_errors(relative: Path, source: str) -> list[str]:
    expected = ALLOWED_CJK_LINES.get(relative, Counter())
    seen = Counter()
    errors = []
    for line_number, line in enumerate(source.splitlines(), 1):
        if not CJK.search(line):
            continue
        text = line.strip()
        if seen[text] < expected[text]:
            seen[text] += 1
        else:
            errors.append(f"{relative}:{line_number}: {text}")
    for text, count in (expected - seen).items():
        errors.append(f"{relative}: missing localized line ({count}): {text}")
    return errors


class FirmwareLanguageTest(unittest.TestCase):
    def test_unlisted_cjk_is_rejected(self) -> None:
        relative = Path("idf_push/idf_push.cpp")
        source = '\n'.join(ALLOWED_CJK_LINES[relative].elements()) + '\nidf_log_line("不允许");\n'
        self.assertIn('idf_log_line("不允许");', source_language_errors(relative, source)[0])

    def test_cjk_is_limited_to_notification_localization(self) -> None:
        errors = []
        for path in COMPONENTS.rglob("*"):
            if path.suffix not in {".cpp", ".h"}:
                continue
            relative = path.relative_to(COMPONENTS)
            if relative.parts[0] == VENDOR_COMPONENT:
                continue
            errors.extend(source_language_errors(relative, path.read_text(encoding="utf-8")))
        self.assertEqual([], errors, "Unexpected CJK firmware text:\n" + "\n".join(errors))


if __name__ == "__main__":
    unittest.main()
