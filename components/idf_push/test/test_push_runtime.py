#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PUSH = ROOT / "components/idf_push"


def main() -> None:
    harness = r'''
#include <cassert>
#include <string>

#include "idf_push_core.h"

int main() {
    IdfPushTemplateValues values{
        "+886900000001", "OTP {device}: 1234", "2026-08-16 12:34:56",
        "Hallway C3", "+886900000002", "192.0.2.4", "sms-hall", "Office WiFi"
    };
    std::string output;
    assert(idf_push_render_template(
        "{sender}|{message}|{timestamp}|{device}|{localNumber}|{ip}|{hostname}|{wifi}|{receiver}|{local_number}",
        values, 512, false, output));
    assert(output == "+886900000001|OTP {device}: 1234|2026-08-16 12:34:56|Hallway C3|"
                     "+886900000002|192.0.2.4|sms-hall|Office WiFi|+886900000002|+886900000002");

    std::string title;
    std::string body;
    assert(idf_push_render_sms_notification("en", "", "", values, title, body));
    assert(title == "SMS from +886900000001");
    assert(body == "Device: Hallway C3\nSender: +886900000001\nTime: 2026-08-16 12:34:56\nMessage: OTP {device}: 1234");

    assert(idf_push_render_sms_notification("zh-CN", "", "", values, title, body));
    assert(title == "来自 +886900000001 的短信");
    assert(body == "设备：Hallway C3\n发件人：+886900000001\n时间：2026-08-16 12:34:56\n内容：OTP {device}: 1234");

    assert(idf_push_render_sms_notification("zh-TW", "", "", values, title, body));
    assert(title == "來自 +886900000001 的簡訊");
    assert(body == "裝置：Hallway C3\n寄件者：+886900000001\n時間：2026-08-16 12:34:56\n內容：OTP {device}: 1234");

    assert(!idf_push_render_template("bad\nheader", values, 256, true, output));
    assert(!idf_push_render_template("bad\theader", values, 256, true, output));
    assert(!idf_push_render_template(std::string("bad\xC0\xAF", 5), values, 256, false, output));
    assert(!idf_push_render_template("{message}", values, 3, false, output));
    assert(idf_push_utf8_codepoint_count("A\xF0\x9F\x98\x80", 2) == 2);
    assert(idf_push_utf8_codepoint_count("A\xF0\x9F\x98\x80", 1) == 2);

    assert(idf_push_select_network(NETWORK_MODE_WIFI_ONLY, true) == IdfPushNetworkDecision::Wifi);
    assert(idf_push_select_network(NETWORK_MODE_WIFI_ONLY, false) == IdfPushNetworkDecision::Defer);
    assert(idf_push_select_network(NETWORK_MODE_4G_ONLY, true) == IdfPushNetworkDecision::Unsupported);
    assert(idf_push_select_network(NETWORK_MODE_4G_ONLY, false) == IdfPushNetworkDecision::Unsupported);
    assert(idf_push_select_network(NETWORK_MODE_MIX, true) == IdfPushNetworkDecision::Wifi);
    assert(idf_push_select_network(NETWORK_MODE_MIX, false) == IdfPushNetworkDecision::Defer);
}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        harness_path = Path(temp_dir) / "push_runtime_test.cpp"
        binary_path = Path(temp_dir) / "push_runtime_test"
        harness_path.write_text(harness)
        subprocess.run(
            [
                "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                f"-I{PUSH / 'include'}", f"-I{ROOT / 'components/idf_config/include'}",
                str(PUSH / "idf_push_core.cpp"), str(harness_path), "-o", str(binary_path),
            ],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True)

    source = (PUSH / "idf_push.cpp").read_text()
    assert "idf_modem_cellular_http_get" not in source
    assert "enum : uint8_t" not in source
    discord = source.split("case PUSH_TYPE_DISCORD:", 2)[2].split("case PUSH_TYPE_NTFY:", 1)[0]
    assert r'\"allowed_mentions\":{\"parse\":[]}' in discord
    assert "idf_push_utf8_codepoint_count(content, 2000)" in discord
    ntfy = source.split("case PUSH_TYPE_NTFY:", 2)[2].split("default:", 1)[0]
    assert 'content_type = "text/plain"' in ntfy
    assert 'extra_header_name = "Title"' in ntfy
    purge = source.split("static bool purge_push_jobs_disabled()", 1)[1].split(
        "static bool process_push_one()", 1
    )[0]
    assert "cancel_forward_completion_locked(job.completionId)" in purge
    assert "job = PushJob()" in purge
    assert "idf_inbox_set_forwarded(inbox_ids[i], false)" in purge

    push_worker = source.split("static bool process_push_one()", 1)[1].split(
        "static bool process_email_one()", 1
    )[0]
    assert "if (!cfg.pushEnabled) return purge_push_jobs_disabled()" in push_worker
    unsupported = push_worker.split(
        "if (network == IdfPushNetworkDecision::Unsupported)", 1
    )[1].split("IdfPushChannel channel", 1)[0]
    assert "fail_push_job_without_retry" in unsupported
    assert "Cellular push is not supported" in unsupported
    assert "job.attempts++" not in unsupported
    locked_selection = push_worker.split(
        "for (size_t i = 0; i < s_push_jobs.size(); ++i)", 1
    )[1].split("xSemaphoreGive(s_mutex)", 1)[0]
    assert "cfg.pushChannels[s_push_jobs[i].channel]" in locked_selection
    assert "channel_waits_for_time(channel)" in locked_selection
    assert "s_push_jobs[i].nextUs = now + 5000000LL" in locked_selection
    assert locked_selection.index("channel_waits_for_time(channel)") < locked_selection.index(
        "job = s_push_jobs[i]"
    )
    post_pop = push_worker.split("xSemaphoreGive(s_mutex)", 1)[1]
    assert "requeue_push_without_attempt" not in post_pop

    tests = source.split("static bool process_test_one()", 1)[1].split(
        "static bool process_startup_notification()", 1
    )[0]
    assert 'fail_pending_tests("Cellular push is not supported; test stopped")' in tests
    assert "channel_waits_for_time(cfg.pushChannels[i])" in tests
    assert "s_test_jobs[i].nextUs = now + 5000000LL" in tests

    startup = source.split("static bool process_startup_notification()", 1)[1].split(
        "static void push_task", 1
    )[0]
    assert "if (!wifi.staConnected) return false" in startup
    assert startup.index("idf_push_enqueue_email") < startup.index("s_startup_email_pending = false")
    startup_enqueue = source.split("bool idf_push_enqueue_startup_notification(void)", 1)[1].split(
        "bool idf_push_heartbeat_tick", 1
    )[0]
    assert "email.emailEnabled" in startup_enqueue
    assert "email.emailConfigured" in startup_enqueue
    assert "if (!s_startup_email_done) s_startup_email_pending = true" in startup_enqueue


if __name__ == "__main__":
    main()
