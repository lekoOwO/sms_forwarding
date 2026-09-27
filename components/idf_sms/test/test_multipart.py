import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]


class MultipartTest(unittest.TestCase):
    def test_late_segments_capacity_and_backpressure(self):
        source = (ROOT / "components/idf_sms/idf_sms.cpp").read_text()
        body = source[source.index("static void clear_concat_slot("):
                      source.index("static PduDecodeOutcome decode_pdu_line(")]
        start = body.index("static SmsProcessResult process_sms_content(",
                           body.index("static ConcatSlot* find_concat_slot("))
        end = body.index("struct PduDecodeOutcome", start)
        # 真實合併函式；只替換最下游入隊邊界，不接觸硬體或通知服務。
        body = body[:start] + '''static SmsProcessResult process_sms_content(
            const char*, const char* text, const char*, bool, bool supplement) {
            if (blocked) return {false, false};
            outputs.push_back({text, supplement}); return {true, true};
        }
        ''' + body[end:]
        fixture = '''#include <algorithm>
#include <array>
#include <string>
#include <vector>
#include <cstdint>
#include <cassert>
static int64_t now_us=0;
static int64_t esp_timer_get_time() { return now_us; }
template<class... T> static void idf_logf(const char*, T...) {}
static uint32_t hash32(const std::string& text) { return std::hash<std::string>{}(text); }
struct Output { std::string text; bool supplement; };
static std::vector<Output> outputs;
static bool blocked=false;
static bool idf_push_enqueue_forward(const char*, const char* text, const char*, uint32_t, bool supplement) {
    if (blocked) return false;
    outputs.push_back({text, supplement}); return true;
}
'''
        fixture += source[source.index("static constexpr size_t CONCAT_SLOTS"):
                          source.index("struct OutgoingSmsJob")]
        fixture += source[source.index("struct DecodedSms"):
                          source.index("static SemaphoreHandle_t")]
        fixture += source[source.index("struct PendingForwardJob"):
                          source.index("struct DecodedSms")]
        fixture += '''static constexpr size_t PENDING_FORWARD_MAX=3;
static std::array<PendingForwardJob, PENDING_FORWARD_MAX> s_pending_forwards;
static size_t s_pending_forward_head=0, s_pending_forward_count=0;
'''
        fixture += source[source.index("static bool enqueue_pending_forward("):
                          source.index("static std::string canonical_phone(")]
        fixture += "static std::array<ConcatSlot, CONCAT_SLOTS> s_concat;\n" + body
        fixture += source[source.index("static void expire_concat_slots("):
                          source.index("// ===== Call notifications")]
        fixture += (Path(__file__).with_name("multipart_fixture.inc")).read_text()
        with tempfile.TemporaryDirectory(prefix="sms-multipart-") as tmp:
            exe = str(Path(tmp) / "fixture")
            subprocess.run(["g++", "-std=c++17", "-x", "c++", "-", "-o", exe],
                           input=fixture, text=True, check=True)
            subprocess.run([exe], check=True)


if __name__ == "__main__":
    unittest.main()
