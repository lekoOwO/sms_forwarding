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

#include "idf_push_ca_policy.h"
#include "idf_push_core.h"

static_assert(!idf_push_ca_extensions_valid(false, false, false));
static_assert(!idf_push_ca_extensions_valid(false, true, true));
static_assert(idf_push_ca_extensions_valid(true, false, false));
static_assert(idf_push_ca_extensions_valid(true, true, true));
static_assert(!idf_push_ca_extensions_valid(true, true, false));

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
    assert(idf_push_select_network(NETWORK_MODE_4G_ONLY, true) == IdfPushNetworkDecision::Cellular);
    assert(idf_push_select_network(NETWORK_MODE_4G_ONLY, false) == IdfPushNetworkDecision::Cellular);
    assert(idf_push_select_network(NETWORK_MODE_MIX, true) == IdfPushNetworkDecision::Wifi);
    assert(idf_push_select_network(NETWORK_MODE_MIX, false) == IdfPushNetworkDecision::Cellular);

    IdfPushTestJobState cleanup_only;
    idf_push_complete_test_job(cleanup_only, false, "HTTPS cleanup failed",
                               "HTTPS cleanup socket close failed",
                               IdfModemHttpsDiagnosticReason::none,
                               IdfModemHttpsDiagnosticReason::timeout, true);
    assert(!cleanup_only.pending && !cleanup_only.running && cleanup_only.done);
    assert(!cleanup_only.success);
    assert(cleanup_only.message == "HTTPS cleanup failed");
    assert(cleanup_only.cleanupMessage == "HTTPS cleanup socket close failed");
    assert(cleanup_only.cleanupReason == IdfModemHttpsDiagnosticReason::timeout);
    assert(cleanup_only.resetNeeded);
    assert(idf_push_serialize_test_status(cleanup_only, false) ==
           "{\"queued\":false,\"running\":false,\"done\":true,\"success\":false,"
           "\"message\":\"HTTPS cleanup failed\"}");
    assert(idf_push_serialize_test_status(cleanup_only, true) ==
           "{\"queued\":false,\"running\":false,\"done\":true,\"success\":false,"
           "\"message\":\"HTTPS cleanup failed\","
           "\"cleanupMessage\":\"HTTPS cleanup socket close failed\","
           "\"cleanupReason\":\"timeout\",\"resetNeeded\":true}");

    IdfPushTestJobState trusted_cleanup;
    idf_push_complete_test_job(trusted_cleanup, false, "HTTPS cleanup failed",
                               "HTTPS cleanup socket close failed",
                               IdfModemHttpsDiagnosticReason::none,
                               IdfModemHttpsDiagnosticReason::command_failure, false);
    assert(trusted_cleanup.resetNeeded);

    IdfPushTestJobState empty_failure;
    idf_push_complete_test_job(empty_failure, false, "", "");
    assert(empty_failure.message == "Test push failed; see the log");
    assert(empty_failure.cleanupMessage.empty());

    IdfPushTestJobState primary_failure;
    idf_push_complete_test_job(primary_failure, false, "HTTPS request write failed",
                               "HTTPS cleanup socket close failed");
    assert(primary_failure.message == "HTTPS request write failed");
    assert(primary_failure.cleanupMessage == "HTTPS cleanup socket close failed");
    assert(idf_push_serialize_test_status(primary_failure, true).find(
        "\"message\":\"HTTPS request write failed\",\"cleanupMessage\":"
        "\"HTTPS cleanup socket close failed\"") != std::string::npos);

    IdfPushTestJobState primary_reason;
    idf_push_complete_test_job(primary_reason, false,
                               "HTTPS modem connected-state poll failed", "",
                               IdfModemHttpsDiagnosticReason::response_invalid,
                               IdfModemHttpsDiagnosticReason::none, false,
                               IdfPushTransportPath::Cellular, true,
                               IdfHttpsFailureStage::registration, -1,
                               IdfModemHttpsParseReason::state,
                               IdfModemHttpsParseReason::none);
    assert(idf_push_serialize_test_status(primary_reason, true).find(
        "\"failureReason\":\"response_invalid\"") != std::string::npos);
    assert(idf_push_serialize_test_status(primary_reason, true).find(
        "\"failureParseReason\":\"state\"") != std::string::npos);
    primary_reason.failureParseShape.available = true;
    primary_reason.failureParseShape.fieldCount = 5;
    primary_reason.failureParseShape.presenceMask = IdfModemHttpsParsePresence::mipstate;
    primary_reason.failureParseShape.stateClass = IdfModemHttpsParseStateClass::unknown;
    const std::string primary_shape_json = idf_push_serialize_test_status(primary_reason, true);
    assert(primary_shape_json.find("\"failureParseShape\":") != std::string::npos);
    assert(primary_shape_json.find("\"stateClass\":\"unknown\"") != std::string::npos);
    assert(primary_shape_json.find("\"singleFieldClass\":\"none\"") != std::string::npos);
    primary_reason.failureParseShape.singleFieldClass =
        IdfModemHttpsParseSingleFieldClass::nonzero;
    assert(idf_push_serialize_test_status(primary_reason, true).find(
               "\"failureParseShape\":") == std::string::npos);
    primary_reason.failureParseShape.singleFieldClass =
        IdfModemHttpsParseSingleFieldClass::none;
    assert(idf_push_serialize_test_status(primary_reason, false).find("ParseShape") ==
           std::string::npos);

    IdfPushTestJobState cleanup_parse;
    idf_push_complete_test_job(cleanup_parse, false, "HTTPS cleanup failed", "cleanup",
                               IdfModemHttpsDiagnosticReason::none,
                               IdfModemHttpsDiagnosticReason::response_invalid, true,
                               IdfPushTransportPath::Cellular, true,
                               IdfHttpsFailureStage::cleanup, -1,
                               IdfModemHttpsParseReason::none,
                               IdfModemHttpsParseReason::terminal);
    const std::string cleanup_parse_json =
        idf_push_serialize_test_status(cleanup_parse, true);
    assert(cleanup_parse_json.find("\"cleanupParseReason\":\"terminal\"") !=
           std::string::npos);
    cleanup_parse.cleanupParseShape.available = true;
    cleanup_parse.cleanupParseShape.fieldCount = 0;
    cleanup_parse.cleanupParseShape.presenceMask = IdfModemHttpsParsePresence::mipclose;
    cleanup_parse.cleanupParseShape.lineClass = IdfModemHttpsParseLineClass::missing;
    const std::string cleanup_shape_json = idf_push_serialize_test_status(cleanup_parse, true);
    assert(cleanup_shape_json.find("\"cleanupParseShape\":") != std::string::npos);
    assert(cleanup_shape_json.find("\"lineClass\":\"missing\"") != std::string::npos);
    assert(cleanup_shape_json.find("\"singleFieldClass\":\"none\"") != std::string::npos);

    IdfPushTestJobState parse_without_response_reason;
    idf_push_complete_test_job(parse_without_response_reason, false, "timeout", "",
                               IdfModemHttpsDiagnosticReason::timeout,
                               IdfModemHttpsDiagnosticReason::none, false,
                               IdfPushTransportPath::Cellular, true,
                               IdfHttpsFailureStage::modem, -1,
                               IdfModemHttpsParseReason::state,
                               IdfModemHttpsParseReason::none);
    assert(idf_push_serialize_test_status(parse_without_response_reason, true).find(
               "ParseReason") == std::string::npos);
    parse_without_response_reason.failureParseShape.available = true;
    parse_without_response_reason.failureParseShape.stateClass =
        IdfModemHttpsParseStateClass::unknown;
    assert(idf_push_serialize_test_status(parse_without_response_reason, true).find(
               "ParseShape") == std::string::npos);

    IdfPushTestJobState unknown_parse;
    idf_push_complete_test_job(
        unknown_parse, false, "invalid response", "",
        IdfModemHttpsDiagnosticReason::response_invalid,
        IdfModemHttpsDiagnosticReason::none, false, IdfPushTransportPath::Cellular, true,
        IdfHttpsFailureStage::response, -1,
        static_cast<IdfModemHttpsParseReason>(77), IdfModemHttpsParseReason::none);
    assert(idf_push_serialize_test_status(unknown_parse, true).find(
               "\"failureParseReason\":\"unknown\"") != std::string::npos);

    IdfPushTestJobState unknown_reason;
    idf_push_complete_test_job(
        unknown_reason, false, "bounded failure", "bounded cleanup",
        static_cast<IdfModemHttpsDiagnosticReason>(77),
        IdfModemHttpsDiagnosticReason::terminal_failure, true);
    const std::string unknown_json = idf_push_serialize_test_status(unknown_reason, true);
    assert(unknown_json.find("\"failureReason\":\"unknown\"") != std::string::npos);
    assert(unknown_json.find("\"cleanupReason\":\"unknown\"") != std::string::npos);
    assert(unknown_json.find("\"resetNeeded\":true") != std::string::npos);
    assert(unknown_json.find("AT+") == std::string::npos);

    IdfPushTestJobState success;
    idf_push_complete_test_job(success, true, "", "");
    assert(success.success && success.done && success.message == "Test push sent");
    assert(success.cleanupMessage.empty());
    assert(idf_push_serialize_test_status(success, true) ==
           "{\"queued\":false,\"running\":false,\"done\":true,\"success\":true,"
           "\"message\":\"Test push sent\"}");

    IdfPushTestJobState active_with_shape;
    active_with_shape.pending = true;
    active_with_shape.message = "Test push queued";
    active_with_shape.failureReason = IdfModemHttpsDiagnosticReason::response_invalid;
    active_with_shape.failureParseReason = IdfModemHttpsParseReason::state;
    active_with_shape.failureParseShape.available = true;
    assert(idf_push_serialize_test_status(active_with_shape, true).find("ParseShape") ==
           std::string::npos);

    IdfPushTestJobState wifi_success;
    idf_push_complete_test_job(wifi_success, true, "", "",
                               IdfModemHttpsDiagnosticReason::none,
                               IdfModemHttpsDiagnosticReason::none, false,
                               IdfPushTransportPath::Wifi, true,
                               IdfHttpsFailureStage::none, 204);
    assert(idf_push_serialize_test_status(wifi_success, false) ==
           "{\"queued\":false,\"running\":false,\"done\":true,\"success\":true,"
           "\"message\":\"Test push sent\"}");
    assert(idf_push_serialize_test_status(wifi_success, true) ==
           "{\"queued\":false,\"running\":false,\"done\":true,\"success\":true,"
           "\"message\":\"Test push sent\",\"transportPath\":\"wifi\","
           "\"dispatchAttempted\":true,\"failureStage\":\"none\",\"httpStatus\":204}");

    IdfPushTestJobState cellular_http_failure;
    idf_push_complete_test_job(cellular_http_failure, false, "HTTP failed", "",
                               IdfModemHttpsDiagnosticReason::none,
                               IdfModemHttpsDiagnosticReason::none, false,
                               IdfPushTransportPath::Cellular, true,
                               IdfHttpsFailureStage::http, 503);
    const std::string cellular_json = idf_push_serialize_test_status(cellular_http_failure, true);
    assert(cellular_json.find("\"transportPath\":\"cellular\"") != std::string::npos);
    assert(cellular_json.find("\"dispatchAttempted\":true") != std::string::npos);
    assert(cellular_json.find("\"failureStage\":\"http\"") != std::string::npos);
    assert(cellular_json.find("\"httpStatus\":503") != std::string::npos);

    IdfPushTestJobState invalid_status;
    idf_push_complete_test_job(invalid_status, false, "request failed", "",
                               IdfModemHttpsDiagnosticReason::none,
                               IdfModemHttpsDiagnosticReason::none, false,
                               IdfPushTransportPath::Cellular, true,
                               IdfHttpsFailureStage::request, 600);
    assert(idf_push_serialize_test_status(invalid_status, true).find("httpStatus") ==
           std::string::npos);

    IdfPushTestJobState active_with_stale_diagnostic;
    active_with_stale_diagnostic.pending = true;
    active_with_stale_diagnostic.message = "Test push queued";
    active_with_stale_diagnostic.transportPath = IdfPushTransportPath::Cellular;
    active_with_stale_diagnostic.dispatchAttempted = true;
    active_with_stale_diagnostic.failureStage = IdfHttpsFailureStage::http;
    active_with_stale_diagnostic.httpStatus = 503;
    active_with_stale_diagnostic.failureReason = IdfModemHttpsDiagnosticReason::response_invalid;
    active_with_stale_diagnostic.failureParseReason = IdfModemHttpsParseReason::state;
    active_with_stale_diagnostic.cleanupReason = IdfModemHttpsDiagnosticReason::response_invalid;
    active_with_stale_diagnostic.cleanupParseReason = IdfModemHttpsParseReason::terminal;
    assert(idf_push_serialize_test_status(active_with_stale_diagnostic, true).find(
               "transportPath") == std::string::npos);

    IdfPushTestJobState pending;
    pending.pending = true;
    pending.message = "Test push queued";
    pending.cleanupMessage = "must not appear before completion";
    assert(idf_push_serialize_test_status(pending, true) ==
           "{\"queued\":true,\"running\":false,\"done\":false,\"success\":false,"
           "\"message\":\"Test push queued\"}");

    IdfPushTestJobState escaped;
    idf_push_complete_test_job(escaped, false, "", "fixed \\\"label\\\\line\nend");
    assert(escaped.cleanupMessage == "fixed \\\"label\\\\line\nend");
    assert(idf_push_serialize_test_status(escaped, true).find(
        "\"cleanupMessage\":\"fixed \\\\\\\"label\\\\\\\\line\\nend\"") != std::string::npos);
    IdfPushTestJobState bounded;
    idf_push_complete_test_job(bounded, false, "", std::string(160, 'x'));
    assert(bounded.cleanupMessage.size() == IdfPushTestJobState::MAX_CLEANUP_MESSAGE - 1);
    assert(idf_push_serialize_test_status(bounded, true).find(std::string(96, 'x')) ==
           std::string::npos);
}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        harness_path = Path(temp_dir) / "push_runtime_test.cpp"
        binary_path = Path(temp_dir) / "push_runtime_test"
        harness_path.write_text(harness)
        subprocess.run(
            [
                "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                f"-I{PUSH}", f"-I{PUSH / 'include'}",
                f"-I{ROOT / 'components/idf_modem/include'}",
                f"-I{ROOT / 'components/idf_config/include'}",
                f"-I{ROOT / 'components/idf_logbuf/include'}",
                str(ROOT / "components/idf_logbuf/idf_util.cpp"),
                str(PUSH / "idf_push_core.cpp"), str(harness_path), "-o", str(binary_path),
            ],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True)

        core_source = (PUSH / "idf_push_core.cpp").read_text()
        mutations = {
            "raw_leakage": core_source.replace(
                "std::string(idf_modem_https_diagnostic_reason_name(job.failureReason))",
                "std::string(\"AT+leak\")",
                1,
            ),
            "reset_inversion": core_source.replace(
                "job.resetNeeded = reset_needed || cleanup_reason != IdfModemHttpsDiagnosticReason::none;",
                "job.resetNeeded = !reset_needed && cleanup_reason != IdfModemHttpsDiagnosticReason::none;",
                1,
            ),
        }
        for name, mutated in mutations.items():
            assert mutated != core_source
            mutated_source = Path(temp_dir) / f"{name}.cpp"
            mutated_binary = Path(temp_dir) / name
            mutated_source.write_text(mutated)
            subprocess.run(
                [
                    "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                    f"-I{PUSH}", f"-I{PUSH / 'include'}",
                    f"-I{ROOT / 'components/idf_modem/include'}",
                    f"-I{ROOT / 'components/idf_config/include'}",
                    f"-I{ROOT / 'components/idf_logbuf/include'}",
                    str(ROOT / "components/idf_logbuf/idf_util.cpp"),
                    str(mutated_source), str(harness_path), "-o", str(mutated_binary),
                ],
                check=True,
            )
            mutated_run = subprocess.run([str(mutated_binary)], check=False,
                                         capture_output=True, text=True)
            assert mutated_run.returncode != 0, name

    source = (PUSH / "idf_push.cpp").read_text()
    header = (PUSH / "include/idf_push.h").read_text()
    core_header = (PUSH / "include/idf_push_core.h").read_text()
    core_source = (PUSH / "idf_push_core.cpp").read_text()
    transport_header = (PUSH / "include/idf_push_transport.h").read_text()
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
    send = source.split("static bool send_to_channel", 1)[1].split(
        "static bool enqueue_push_job_locked", 1
    )[0]
    assert "std::string* failure_message = nullptr" in send
    assert "std::string* cleanup_message = nullptr" in send
    assert "IdfModemHttpsDiagnosticReason* failure_reason = nullptr" in send
    assert "IdfModemHttpsDiagnosticReason* cleanup_reason = nullptr" in send
    assert "bool* cleanup_requires_reset = nullptr" in send
    assert "cleanup_message->clear()" in send
    assert "*failure_message = transport.message" in send
    assert send.count("*failure_message = transport.message") == 1
    assert "*cleanup_message = transport.cleanupMessage" in send
    assert send.count("*cleanup_message = transport.cleanupMessage") == 1
    assert send.index("*failure_message = transport.message") < send.index("return ok")
    assert send.index("*cleanup_message = transport.cleanupMessage") < send.index("return ok")
    assert "std::string cleanupMessage" in transport_header
    assert "IdfModemHttpsDiagnosticReason failureReason" in transport_header
    assert "IdfModemHttpsDiagnosticReason cleanupReason" in transport_header
    assert "bool cleanupRequiresReset" in transport_header
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
    assert "network, false, &result" in tests
    assert "std::string cleanup_result" in tests
    assert "&result, nullptr, &cleanup_result" in tests
    assert "idf_push_complete_test_job(job, ok, std::move(result)," in tests
    assert "std::move(cleanup_result)," in tests
    assert "failure_reason, cleanup_reason, cleanup_requires_reset" in tests
    post_send = tests.split("&result, nullptr, &cleanup_result,", 1)[1]
    completion_call = post_send.split("idf_push_complete_test_job", 1)[0]
    assert "cleanup_result.clear" not in completion_call

    assert "bool idf_push_test_active(void)" in source
    assert "bool idf_push_test_channel_active(uint8_t channel)" in header
    assert "idf_push_test_status_json(uint8_t channel, bool include_cleanup = false)" in header
    test_active = source.split("bool idf_push_test_active(void)", 1)[1].split(
        "bool idf_push_test_channel_active", 1
    )[0]
    assert "if (!ensure_init()) return true" in test_active
    assert "xSemaphoreTake(s_mutex" in test_active
    assert "job.pending || job.running" in test_active
    assert "return true" in test_active
    assert "expire_test_jobs_locked" in test_active
    channel_active = source.split("bool idf_push_test_channel_active", 1)[1].split(
        "bool idf_push_enqueue_test", 1
    )[0]
    assert "expire_test_jobs_locked" in channel_active
    enqueue_test = source.split("bool idf_push_enqueue_test", 1)[1].split(
        "std::string idf_push_test_status_json", 1
    )[0]
    duplicate = enqueue_test.split("if (busy)", 1)[1]
    assert "return false" in duplicate
    assert enqueue_test.index("if (busy)") < enqueue_test.index("idf_push_select_network")
    assert "PUSH_TEST_PENDING_MAX_US" in source
    assert "int64_t deadlineUs = 0" in core_header
    assert "job.deadlineUs = esp_timer_get_time() + PUSH_TEST_PENDING_MAX_US" in enqueue_test
    assert enqueue_test.index("if (!s_started)") < enqueue_test.index("job.pending = true")
    assert "expire_test_jobs_locked" in enqueue_test
    process_test = source.split("static bool process_test_one()", 1)[1].split(
        "static bool process_startup_notification", 1
    )[0]
    assert "expire_test_jobs_locked" in process_test
    assert process_test.index("expire_test_jobs_locked") < process_test.index("IdfPushNetworkDecision::Defer")
    completion = process_test.split("if (s_mutex &&", 1)[1]
    assert "xSemaphoreTake(s_mutex, portMAX_DELAY)" in completion
    assert 'if (ok) result = "Test push sent";' not in process_test
    assert 'result = "Test push failed; see the log"' not in process_test
    assert "idf_push_complete_test_job(job, ok, std::move(result)," in completion
    status = source.split("std::string idf_push_test_status_json", 1)[1]
    assert "expire_test_jobs_locked" in status
    assert "Push test status is temporarily unavailable" in status
    assert "return idf_push_serialize_test_status(copy, include_cleanup)" in status
    before_serialize = status.split("return idf_push_serialize_test_status", 1)[0]
    assert "copy.cleanupMessage.clear" not in before_serialize
    assert "include_cleanup && job.done && !job.cleanupMessage.empty()" in core_source
    assert "failureReason" in core_header
    assert "cleanupReason" in core_header
    assert "resetNeeded" in core_header

    assert "using TestJob = IdfPushTestJobState" in source
    fail_pending = source.split("static bool fail_pending_tests", 1)[1].split(
        "static bool expire_test_jobs_locked", 1
    )[0]
    expire_pending = source.split("static bool expire_test_jobs_locked", 1)[1].split(
        "static bool process_test_one", 1
    )[0]
    assert "cleanupMessage.clear()" in fail_pending
    assert "cleanupMessage.clear()" in expire_pending
    assert "cleanupMessage.clear()" in enqueue_test

    # The normal retrying push worker does not request or retain cleanup telemetry.
    assert "cleanup_result" not in push_worker

    # Web clients accept the additive diagnostics only for valid terminal states.
    web_api = (ROOT / "web/src/lib/api.ts").read_text()
    validator = web_api.split("function isPushTestStatus", 1)[1].split("function demoResponse", 1)[0]
    assert "Object.keys(status)" in validator
    assert "pushTestDiagnosticKeys" in validator
    assert "pushTestTransportDiagnosticKeys" in validator
    assert "const pushTestDiagnosticReasons: readonly PushTestDiagnosticReason[]" in web_api
    assert "const pushTestCleanupReasons: readonly PushTestCleanupReason[]" in web_api
    assert "pushTestFailureStages" in web_api
    assert "pushTestTransportPaths" in web_api
    assert "status.done" in validator

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
