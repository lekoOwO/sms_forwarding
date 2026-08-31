import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


SOURCE = Path(__file__).resolve().parents[1] / "idf_modem.cpp"
REPO_ROOT = SOURCE.parents[2]


def production_cellular_http_call_sites():
    sites = []
    excluded_parts = {".git", "build", "dist", "test", "tests"}
    for path in REPO_ROOT.rglob("*"):
        if path.suffix not in {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp"}:
            continue
        if excluded_parts.intersection(path.parts):
            continue
        source = path.read_text(errors="replace")
        for match in re.finditer(r"\bidf_modem_cellular_http_get\s*\(", source):
            prefix = source[max(0, match.start() - 80):match.start()]
            if re.search(r"\besp_err_t\s*$", prefix):
                continue
            line = source.count("\n", 0, match.start()) + 1
            sites.append(f"{path.relative_to(REPO_ROOT)}:{line}")
    return sites


def function_body(source: str, name: str) -> str:
    match = re.search(rf"\b{name}\s*\([^;]*?\)\s*\{{", source, re.S)
    if not match:
        raise AssertionError(f"missing function: {name}")
    start = match.end()
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated function: {name}")


class UartOwnerContractTest(unittest.TestCase):
    def test_dev_usb_query_is_fixed_id_and_uses_the_existing_owner_queue(self):
        source = SOURCE.read_text()
        body = function_body(source, "idf_modem_usb_query")
        self.assertIn("submit_owner_command", body)
        self.assertNotIn("owner_uart_read", body)
        self.assertNotIn("owner_uart_write", body)
        self.assertIn("switch (query_id)", source)
        query_map = function_body(source, "usb_query_command")
        for command in (
            '"ATI"', '"AT+CPIN?"', '"AT+CEREG?"', '"AT+COPS?"',
            '"AT+CGATT?"', '"AT+CGACT?"', '"AT+CGPADDR"', '"AT+ICCID"',
            '"AT+CSQ"', '"AT+CESQ"', '"AT+CFUN?"', '"AT+CREG?"',
            '"AT+CGREG?"', '"AT+CEER"', '"AT+CIMI"', '"AT+CPOL?"',
            '"AT+CGDCONT?"', '"AT+MSSLCIPHER=?"',
        ):
            self.assertEqual(query_map.count(command), 1, command)
        header = (SOURCE.parent / "include" / "idf_modem.h").read_text()
        self.assertIn("IDF_MODEM_USB_QUERY_MSSLCIPHER = 0x12", header)
        self.assertIn("case IDF_MODEM_USB_QUERY_MSSLCIPHER", query_map)
        response_map = function_body(source, "usb_query_response_prefix")
        self.assertIn(
            'case IDF_MODEM_USB_QUERY_MSSLCIPHER: return "+MSSLCIPHER:";',
            response_map,
        )
        self.assertIn("IDF_MODEM_ERR_BUSY", body)
        self.assertIn("IDF_MODEM_USB_QUERY_TIMEOUT_MS", body)
        self.assertIn("s_runtime_queue_ready", body)
        self.assertIn("atReady", body)
        self.assertNotIn("modemReady", body)
        self.assertIn("idf_modem_usb_query_admission", body)
        self.assertNotIn("idf_modem_at_idle", body)
        self.assertIn("filter_urcs", source)
        self.assertIn("response_prefix", source)

    def test_usb_query_submits_busy_owner_to_bounded_queue(self):
        source = SOURCE.read_text()
        body = function_body(source, "idf_modem_usb_query")
        submit = function_body(source, "submit_owner_command")
        self.assertIn("submit_owner_command", body)
        self.assertIn("xSemaphoreTake(s_command_mutex", submit)
        self.assertIn("slot_index < 0", submit)
        self.assertIn("xQueueSend(queue, &slot_index, 0)", submit)
        self.assertIn("result = ESP_ERR_TIMEOUT", submit)

    def test_usb_query_busy_reason_is_captured_at_owner_boundary(self):
        source = SOURCE.read_text()
        body = function_body(source, "idf_modem_usb_query")
        submit = function_body(source, "submit_owner_command")
        self.assertIn("busy_reason", body)
        self.assertIn("IdfModemUsbQueryBusyReason::gate_closed", body)
        for reason in ("gate_closed", "mutex_timeout", "slots_full", "queue_full"):
            self.assertIn(
                f"IdfModemUsbQueryBusyReason::{reason}", submit
            )

    def test_msslcipher_has_a_bounded_extended_response_without_changing_legacy_limit(self):
        source = SOURCE.read_text()
        header = (SOURCE.parent / "include" / "idf_modem.h").read_text()
        body = function_body(source, "idf_modem_usb_query")
        self.assertIn("IDF_MODEM_USB_QUERY_MAX_RESPONSE = 96", header)
        self.assertIn("IDF_MODEM_USB_QUERY_MSSLCIPHER_MAX_RESPONSE = 192", header)
        self.assertIn("IDF_MODEM_USB_QUERY_MSSLCIPHER_MAX_RESPONSE", body)
        self.assertIn("request.response_limit", body)
        self.assertIn("request.capture_other_line = query_id == IDF_MODEM_USB_QUERY_MSSLCIPHER", body)
        self.assertIn("slot.request.capture_other_line ? &slot.other_line_present", source)
        self.assertIn("response_limit", function_body(source, "owner_send_at"))
        self.assertIn("response_limit", function_body(source, "execute_owner_command"))

    def test_cpol_has_only_a_bounded_longer_owner_timeout(self):
        source = SOURCE.read_text()
        header = (SOURCE.parent / "include" / "idf_modem.h").read_text()
        body = function_body(source, "idf_modem_usb_query")
        self.assertIn("IDF_MODEM_USB_QUERY_CPOL_TIMEOUT_MS = 5000", header)
        self.assertIn("IDF_MODEM_USB_QUERY_TIMEOUT_MS = 1500", header)
        self.assertIn("query_id == IDF_MODEM_USB_QUERY_CPOL", body)
        self.assertIn("IDF_MODEM_USB_QUERY_CPOL_TIMEOUT_MS", body)
        self.assertIn("IDF_MODEM_USB_QUERY_TIMEOUT_MS", body)
        submit = function_body(source, "submit_owner_command")
        self.assertIn("request.timeout_ms + wait_margin_ms", submit)
        self.assertIn("wait_margin_ms = request.kind == OwnerCommandKind::pdu ? 7000UL : 1000UL", submit)

    def test_oversized_dev_query_logs_only_bounded_metadata_before_clearing(self):
        source = SOURCE.read_text()
        body = function_body(source, "idf_modem_usb_query")
        oversize = body[body.index("response.size() > output_limit"):]
        log = oversize[:oversize.index("response.clear()")]
        self.assertIn("idf_logf", log)
        self.assertIn("query_id", log)
        self.assertIn("response.size()", log)
        self.assertIn("static_cast<unsigned>(response.size())", log)
        self.assertNotIn("bounded_actual_length", log)
        self.assertNotIn("std::min", log)
        self.assertNotIn("IDF_MODEM_USB_QUERY_MAX_RESPONSE + 1", log)
        self.assertIn("output_limit", log)
        self.assertNotIn("response.c_str()", log)
        self.assertNotIn("response.data()", log)
        for forbidden in ("command", "operator", "apn", "plmn"):
            self.assertNotIn(forbidden, log.lower())

    def test_cpol_query_returns_compact_summary_before_generic_size_guard(self):
        source = SOURCE.read_text()
        body = function_body(source, "idf_modem_usb_query")
        summary = body.index("idf_modem_cpol_compact_summary")
        generic_limit = body.index("response.size() > output_limit")
        self.assertIn("query_id == IDF_MODEM_USB_QUERY_CPOL", body[:summary])
        self.assertLess(summary, generic_limit)
        self.assertIn("response = idf_modem_cpol_compact_summary(response)", body)
        self.assertIn('"idf_modem_cpol_summary.h"', source)

    def test_owner_submit_uses_one_absolute_deadline_for_all_waits(self):
        source = SOURCE.read_text()
        submit = function_body(source, "submit_owner_command")
        self.assertIn("TickDeadline deadline(wait_ms)", submit)
        self.assertGreaterEqual(submit.count("deadline.remaining_ticks()"), 3)
        self.assertIn("timeout_ticks_ceil", source)
        self.assertNotIn("xSemaphoreTake(s_command_mutex, portMAX_DELAY)", submit)

    def test_usb_query_readiness_covers_locked_unregistered_and_reset_lifecycle(self):
        source = SOURCE.read_text()
        body = function_body(source, "idf_modem_usb_query")
        self.assertIn("status.atReady", body)
        self.assertIn("s_runtime_queue_ready.load", body)
        self.assertIn("s_reset_request", body)
        owner_loop = function_body(source, "modem_task")
        startup_queries = owner_loop.index("while (sim_ready && check_count++ < 30)")
        queue_ready = owner_loop.index("s_runtime_queue_ready.store(true", 0, startup_queries)
        self.assertLess(queue_ready, startup_queries)
        registration = owner_loop.split("while (sim_ready && check_count++ < 30)", 1)[1].split(
            "bool registered", 1
        )[0]
        self.assertLess(
            registration.index("owner_process_one_command(false)"),
            registration.index('send_ok("AT+CEREG?"'),
        )
        self.assertIn("s_runtime_queue_ready.store(false", source)
        for lifecycle in ("handle_reset_request_if_any", "run_pending_reinit_if_recovered"):
            body = function_body(source, lifecycle)
            self.assertIn("s_runtime_queue_ready.store(true", body)

    def test_dev_usb_query_is_compile_time_excluded_from_release(self):
        source = SOURCE.read_text()
        start = source.index("static const char* usb_query_command")
        self.assertGreater(source.rfind("#if SMS_USB_RECOVERY", 0, start), 0)
        self.assertIn("#endif", source[start:])
        cmake = SOURCE.parent / "CMakeLists.txt"
        self.assertIn("SMS_USB_RECOVERY", cmake.read_text())

    def test_interleaved_urc_fixture_is_executable_and_keeps_urc_out_of_query(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "the host URC fixture requires g++")
        fixture = SOURCE.parent / "test" / "query_filter_fixture.cpp"
        self.assertTrue(fixture.exists(), "missing executable query filter fixture")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "query_filter_fixture"
            compile_result = subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror", "-pthread",
                 "-I", str(SOURCE.parent / "include"), str(fixture), "-o", str(binary)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run([str(binary)], check=False, capture_output=True, text=True)
            self.assertEqual(run_result.returncode, 0, run_result.stderr)
            self.assertEqual(
                set(run_result.stdout.splitlines()),
                {
                    "query=runtime-gate outcome=busy-runtime-gate reason=gate_closed submit-calls=0",
                    "query=not-ready outcome=not-ready reason=unknown submit-calls=0",
                    "query=idle-collision outcome=submitted reason=unknown submit-calls=1",
                    "query=mutex outcome=busy-command-mutex reason=mutex_timeout submit-calls=1",
                    "query=slots outcome=busy-slots reason=slots_full submit-calls=1",
                    "query=queue outcome=busy-queue reason=queue_full submit-calls=1",
                    "query=owner outcome=timeout-owner reason=unknown submit-calls=1",
                },
            )

    def test_reset_cancels_queued_normal_owner_slot_before_uart(self):
        source = SOURCE.read_text()
        body = function_body(source, "owner_process_one_command")
        self.assertIn("idf_modem_owner_command_allowed", body)
        self.assertIn("s_reset_request.load", body)
        self.assertIn("s_runtime_queue_ready.load", body)
        self.assertIn("slot.result = ESP_ERR_INVALID_STATE", body)
        self.assertIn("slot.state = OwnerCommandState::done", body)
        self.assertIn("xSemaphoreGive(slot.completed)", body)
        self.assertLess(
            body.index("idf_modem_owner_command_allowed"),
            body.index("slot.state = OwnerCommandState::running"),
        )

    def test_identity_change_logs_are_masked(self):
        source = SOURCE.read_text()
        self.assertIn("mask_identity", source)
        identity = function_body(source, "sample_identity_once")
        self.assertNotIn("after.imei.c_str()", identity)
        self.assertNotIn("after.iccid.c_str()", identity)
        self.assertNotIn("after.imsi.c_str()", identity)

    def test_cellular_ip_log_does_not_disclose_address(self):
        source = SOURCE.read_text()
        sample = function_body(source, "sample_cell_ip_once")
        self.assertNotIn("ip.c_str()", sample)
        self.assertIn('idf_log_line("cellular IP acquired")', sample)

    def test_registration_state_gates_data_and_rlos_recovery(self):
        source = SOURCE.read_text()
        data_mode = function_body(source, "apply_configured_data_mode_once")
        self.assertIn("idf_modem_data_activation_allowed", data_mode)
        self.assertLess(data_mode.index("idf_modem_data_activation_allowed"),
                        data_mode.index('"AT+CGACT=1,1"'))
        startup = function_body(source, "apply_startup_data_mode")
        self.assertIn("idf_modem_data_activation_allowed", startup)
        owner_loop = function_body(source, "modem_task")
        first_cereg = owner_loop.index('send_ok("AT+CEREG?"')
        first_data_setup = owner_loop.index("apply_startup_data_mode(stat)")
        self.assertLess(first_cereg, first_data_setup)
        self.assertIn("stat == 11", owner_loop)
        self.assertIn("rlos_only_seen", owner_loop)
        self.assertIn("Continuing read-only registration probes", owner_loop)
        self.assertIn("reg_patch.modemReady = (stat == 1 || stat == 5)", owner_loop)
        self.assertIn("bool now_ready = (stat == 1 || stat == 5)", owner_loop)

    def test_sms_health_keeps_rlos_restricted_without_reset(self):
        source = SOURCE.read_text()
        health = function_body(source, "idf_modem_sms_health_check")
        self.assertIn("idf_modem_health_reset_required", health)
        self.assertIn("request_health_reset_with_backoff", health)
        self.assertIn('stat == 11 ? "restricted-rlos"', health)
        self.assertIn("Registration unavailable; modem reset not requested", health)
        self.assertIn("cereg_query_ok", health)

    def test_identity_sampling_is_home_only_at_shared_entrypoint(self):
        source = SOURCE.read_text()
        identity = function_body(source, "sample_identity_once")
        self.assertIn("idf_modem_identity_sampling_allowed", identity)
        self.assertLess(identity.index("idf_modem_identity_sampling_allowed"),
                        identity.index('"AT+COPS=3,0"'))
        self.assertGreaterEqual(source.count("sample_identity_once(false, true)"), 3)

    def test_reset_publishes_gate_before_recovery_side_effect(self):
        source = SOURCE.read_text()
        invalidate = function_body(source, "invalidate_registration_state")
        self.assertIn("idf_modem_invalidate_registration_stat", invalidate)
        self.assertIn("s_data_mode_retry_pending.store(false", invalidate)
        self.assertIn("s_status.cellIp.clear()", invalidate)
        reset = function_body(source, "idf_modem_request_reset")
        self.assertIn("xSemaphoreTake(s_command_mutex, portMAX_DELAY)", reset)
        self.assertIn("xSemaphoreGive(s_command_mutex)", reset)
        self.assertIn("wake_owner_task", reset)
        lock = reset.index("xSemaphoreTake(s_command_mutex, portMAX_DELAY)")
        unlock = reset.index("xSemaphoreGive(s_command_mutex)", lock)
        self.assertLess(lock, reset.index("s_runtime_queue_ready.store(false"))
        self.assertLess(reset.index("s_runtime_queue_ready.store(false"), reset.index("s_reset_request.store"))
        self.assertLess(reset.index("s_reset_request.store"), unlock)
        self.assertLess(unlock, reset.index("invalidate_registration_state"))
        self.assertLess(unlock, reset.index("set_phase"))
        self.assertLess(unlock, reset.index("wake_owner_task"))
        critical = reset[lock:unlock]
        for forbidden in ("s_session_mutex", "submit_owner_command", "xQueue", "xSemaphoreTake(slot"):
            self.assertNotIn(forbidden, critical)
        for lifecycle in ("handle_reset_request_if_any", "run_pending_reinit_if_recovered", "modem_task"):
            self.assertIn("invalidate_registration_state", function_body(source, lifecycle))
        retry = function_body(source, "process_data_mode_retry")
        self.assertIn("s_reset_request.load", retry)
        self.assertIn("ceregStat < 0", retry)
        operator = function_body(source, "apply_operator_if_configured")
        self.assertIn("idf_modem_identity_sampling_allowed", operator)

    def test_successful_sim_unlock_invalidates_before_sms_reopen(self):
        source = SOURCE.read_text()
        for lifecycle in ("handle_reset_request_if_any", "run_pending_reinit_if_recovered"):
            body = function_body(source, lifecycle)
            unlock = body.index("if (try_unlock_sim")
            self.assertLess(
                body.index("invalidate_registration_state", unlock),
                body.index("configure_sms_and_registration", unlock),
            )

        owner = function_body(source, "modem_task")
        startup = owner.index("if (sim_ready)")
        self.assertLess(
            owner.index("invalidate_registration_state", startup),
            owner.index("configure_sms_and_registration", startup),
        )
        runtime_unlock = owner.split("if (unlock_request != 0)", 1)[1]
        self.assertLess(
            runtime_unlock.index("invalidate_registration_state"),
            runtime_unlock.index("configure_sms_and_registration"),
        )

    def test_only_owner_checked_wrappers_read_or_write_uart(self):
        source = SOURCE.read_text()

        # All byte I/O must stay visible behind the two owner-checked choke points.
        self.assertNotRegex(source, r"\buart_(?:write_chars|read_pattern)\s*\(")
        self.assertEqual(source.count("uart_read_bytes("), 1)
        self.assertEqual(source.count("uart_write_bytes("), 1)
        self.assertEqual(source.count("uart_flush_input("), 1)
        self.assertEqual(source.count("uart_get_buffered_data_len("), 1)

        read = function_body(source, "owner_uart_read")
        write = function_body(source, "owner_uart_write")
        flush = function_body(source, "owner_uart_flush")
        buffered = function_body(source, "capture_pending_uart_locked")
        for body in (read, write, flush, buffered):
            self.assertIn("assert_owner_task();", body)

        self.assertIn("uart_read_bytes(", read)
        self.assertIn("uart_write_bytes(", write)

        for api in (
            "idf_modem_send_at",
            "idf_modem_send_at_until",
            "idf_modem_send_pdu",
            "idf_modem_cellular_http_get",
        ):
            body = function_body(source, api)
            self.assertNotIn("owner_uart_read(", body)
            self.assertNotIn("owner_uart_write(", body)
            if api == "idf_modem_cellular_http_get":
                self.assertIn("ESP_ERR_NOT_SUPPORTED", body)
                self.assertNotIn("submit_owner_command", body)
            else:
                self.assertIn("submit_owner_command", body)

        send_at = function_body(source, "owner_send_at_deadline")
        send_until = function_body(source, "owner_send_at_until")
        send_pdu = function_body(source, "owner_send_pdu")
        self.assertIn("MAX_RESPONSE = 8192", send_at)
        self.assertIn("MAX_RESPONSE = 4096", send_until)
        self.assertIn("MAX_RESPONSE = 4096", send_pdu)

        public_send_at = function_body(source, "idf_modem_send_at")
        self.assertIn('cmd.rfind("AT+CNMA", 0)', public_send_at)
        self.assertIn('request.filter_urcs = cmd == "AT+CEREG?"', public_send_at)
        self.assertIn('request.response_prefix = "+CEREG:"', public_send_at)
        self.assertIn("if (!priority) owner_drain_priority_commands();", public_send_at)
        submit = function_body(source, "submit_owner_command")
        self.assertIn("!priority && !s_runtime_queue_ready.load", submit)
        owner_loop = function_body(source, "modem_task")
        self.assertIn("s_runtime_queue_ready.store(true", owner_loop)
        self.assertLess(
            owner_loop.index("owner_process_one_command(true)"),
            owner_loop.index("owner_process_one_command(false)"),
        )

    def test_cellular_http_public_entry_fails_closed_before_owner_or_uart(self):
        source = SOURCE.read_text()
        body = function_body(source, "idf_modem_cellular_http_get")
        self.assertIn("result = IdfCellularHttpResult();", body)
        self.assertIn('result.message = "Cellular HTTP is not supported";', body)
        self.assertIn("return ESP_ERR_NOT_SUPPORTED;", body)
        unsupported = body[:body.index("return ESP_ERR_NOT_SUPPORTED;")]
        for forbidden in (
            "submit_owner_command", "xTaskGetCurrentTaskHandle", "idf_modem_get_status",
            "owner_cellular_http_get", "send_at_locked", "owner_uart_write", "idf_log",
            "CEREG", "CGATT", "CGACT", "MHTTP", "url.c_str()",
        ):
            self.assertNotIn(forbidden, unsupported)

    def test_cellular_http_has_no_unapproved_production_callers_repo_wide(self):
        # The public shape remains for a future secure implementation, but no
        # production caller is currently allowed to reach this unsupported API.
        allowed_terminal_callers = frozenset()
        call_sites = production_cellular_http_call_sites()
        unexpected = sorted(set(call_sites) - allowed_terminal_callers)
        self.assertEqual(
            unexpected,
            [],
            "new cellular HTTP production caller requires an explicit terminal allowlist entry: "
            + ", ".join(unexpected),
        )

    def test_https_post_wire_fixture_is_executable(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "the host HTTPS fixture requires g++")
        fixture = SOURCE.parent / "test" / "https_post_fixture.cpp"
        implementation = SOURCE.parent / "idf_modem_https_wire.cpp"
        self.assertTrue(fixture.exists(), "missing executable HTTPS POST fixture")
        self.assertTrue(implementation.exists(), "missing HTTPS POST wire implementation")
        with tempfile.TemporaryDirectory() as directory:
            stub_root = Path(directory) / "stubs"
            mbedtls = stub_root / "mbedtls"
            freertos = stub_root / "freertos"
            mbedtls.mkdir(parents=True)
            freertos.mkdir(parents=True)
            (stub_root / "mbedtls_stub.h").write_text(r'''
#pragma once
#include <cstddef>
#include <cstdint>
#include <cstring>

struct mbedtls_ctr_drbg_context {};
struct mbedtls_entropy_context {};
struct mbedtls_ssl_config {};
struct mbedtls_ssl_context {
    void* bio_context = nullptr;
    int (*bio_send)(void*, const unsigned char*, size_t) = nullptr;
    int (*bio_recv)(void*, unsigned char*, size_t) = nullptr;
};
struct mbedtls_x509_crt {};

extern int fixture_tls_setup_result;
extern int fixture_tls_handshake_result;

inline constexpr int MBEDTLS_ERR_NET_RECV_FAILED = -1;
inline constexpr int MBEDTLS_ERR_NET_SEND_FAILED = -2;
inline constexpr int MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY = -3;
inline constexpr int MBEDTLS_ERR_SSL_TIMEOUT = -4;
inline constexpr int MBEDTLS_ERR_SSL_WANT_READ = -5;
inline constexpr int MBEDTLS_ERR_SSL_WANT_WRITE = -6;
inline constexpr int MBEDTLS_SSL_IS_CLIENT = 0;
inline constexpr int MBEDTLS_SSL_PRESET_DEFAULT = 0;
inline constexpr int MBEDTLS_SSL_TRANSPORT_STREAM = 0;
inline constexpr int MBEDTLS_SSL_VERIFY_REQUIRED = 0;
inline constexpr int MBEDTLS_SSL_VERSION_TLS1_2 = 0;
inline constexpr unsigned int MBEDTLS_X509_KU_KEY_CERT_SIGN = 1;

inline void mbedtls_ctr_drbg_init(mbedtls_ctr_drbg_context*) {}
inline void mbedtls_ctr_drbg_free(mbedtls_ctr_drbg_context*) {}
inline int mbedtls_ctr_drbg_random(void*, unsigned char*, size_t) { return 0; }
inline int mbedtls_ctr_drbg_seed(mbedtls_ctr_drbg_context*,
                                 int (*)(void*, unsigned char*, size_t), void*,
                                 const unsigned char*, size_t) { return 0; }
inline void mbedtls_entropy_init(mbedtls_entropy_context*) {}
inline void mbedtls_entropy_free(mbedtls_entropy_context*) {}
inline int mbedtls_entropy_func(void*, unsigned char*, size_t) { return 0; }
inline int mbedtls_sha256(const unsigned char*, size_t, unsigned char* output, int) {
    std::memset(output, 0xab, 32);
    return 0;
}
inline void mbedtls_ssl_config_init(mbedtls_ssl_config*) {}
inline void mbedtls_ssl_config_free(mbedtls_ssl_config*) {}
inline int mbedtls_ssl_config_defaults(mbedtls_ssl_config*, int, int, int) { return 0; }
inline void mbedtls_ssl_conf_rng(mbedtls_ssl_config*,
                                 int (*)(void*, unsigned char*, size_t), void*) {}
inline void mbedtls_ssl_conf_authmode(mbedtls_ssl_config*, int) {}
inline void mbedtls_ssl_conf_min_tls_version(mbedtls_ssl_config*, int) {}
inline void mbedtls_ssl_conf_max_tls_version(mbedtls_ssl_config*, int) {}
inline void mbedtls_ssl_conf_ca_chain(mbedtls_ssl_config*, mbedtls_x509_crt*, void*) {}
inline void mbedtls_ssl_init(mbedtls_ssl_context*) {}
inline void mbedtls_ssl_free(mbedtls_ssl_context*) {}
inline int mbedtls_ssl_setup(mbedtls_ssl_context*, const mbedtls_ssl_config*) {
    return fixture_tls_setup_result;
}
inline int mbedtls_ssl_set_hostname(mbedtls_ssl_context*, const char*) { return 0; }
inline void mbedtls_ssl_set_bio(
    mbedtls_ssl_context* ssl, void* context,
    int (*send)(void*, const unsigned char*, size_t),
    int (*recv)(void*, unsigned char*, size_t),
    int (*)(void*, unsigned char*, size_t, uint32_t)) {
    ssl->bio_context = context;
    ssl->bio_send = send;
    ssl->bio_recv = recv;
}
inline int mbedtls_ssl_handshake(mbedtls_ssl_context*) {
    return fixture_tls_handshake_result;
}
inline uint32_t mbedtls_ssl_get_verify_result(const mbedtls_ssl_context*) { return 0; }
inline int mbedtls_ssl_write(mbedtls_ssl_context* ssl, const unsigned char* bytes,
                             size_t length) {
    return ssl->bio_send ? ssl->bio_send(ssl->bio_context, bytes, length) : -2;
}
inline int mbedtls_ssl_read(mbedtls_ssl_context* ssl, unsigned char* bytes, size_t length) {
    const size_t bounded = length < 7 ? length : 7;
    return ssl->bio_recv ? ssl->bio_recv(ssl->bio_context, bytes, bounded) : -1;
}
inline void mbedtls_x509_crt_init(mbedtls_x509_crt*) {}
inline void mbedtls_x509_crt_free(mbedtls_x509_crt*) {}
inline int mbedtls_x509_crt_parse_der(mbedtls_x509_crt*, const unsigned char*, size_t) { return 0; }
inline int mbedtls_x509_crt_get_ca_istrue(const mbedtls_x509_crt*) { return 1; }
inline int mbedtls_x509_crt_check_key_usage(const mbedtls_x509_crt*, unsigned int) { return 0; }
''')
            for header in (
                "ctr_drbg.h", "entropy.h", "net_sockets.h", "sha256.h", "ssl.h", "x509_crt.h"
            ):
                (mbedtls / header).write_text('#include "../mbedtls_stub.h"\n')
            (freertos / "FreeRTOS.h").write_text(r'''
#pragma once
#include <cstdint>
using TickType_t = uint32_t;
#define pdMS_TO_TICKS(milliseconds) static_cast<TickType_t>(milliseconds)
''')
            (freertos / "task.h").write_text(r'''
#pragma once
#include "FreeRTOS.h"
inline void vTaskDelay(TickType_t) {}
''')
            binary = Path(directory) / "https_post_fixture"
            compile_result = subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                 "-fsanitize=address,undefined", "-fno-omit-frame-pointer",
                 "-I", str(stub_root), "-I", str(SOURCE.parent),
                 "-I", str(SOURCE.parent / "include"),
                 str(implementation), str(SOURCE.parent / "idf_modem_https.cpp"),
                 str(fixture), "-o", str(binary)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True,
                env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1",
                     "UBSAN_OPTIONS": "halt_on_error=1"},
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

            implementation_source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
            mutations = {
                "reason_removal": implementation_source.replace(
                    "if (disposition == MipStateDisposition::invalid) {\n"
                    "                record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);",
                    "if (disposition == MipStateDisposition::invalid) {",
                    1,
                ),
                "reason_inversion": implementation_source.replace(
                    "record_failure_reason(deadline_.expired()\n"
                    "                                  ? IdfModemHttpsDiagnosticReason::timeout\n"
                    "                                  : IdfModemHttpsDiagnosticReason::poll_timeout);",
                    "record_failure_reason(deadline_.expired()\n"
                    "                                  ? IdfModemHttpsDiagnosticReason::poll_timeout\n"
                    "                                  : IdfModemHttpsDiagnosticReason::timeout);",
                    1,
                ),
                "reason_collapse": implementation_source.replace(
                    "IdfModemHttpsDiagnosticReason::result_nonzero",
                    "IdfModemHttpsDiagnosticReason::response_invalid",
                    1,
                ),
            }
            for name, mutated in mutations.items():
                self.assertNotEqual(mutated, implementation_source, name)
                mutated_source = Path(directory) / f"{name}.cpp"
                mutated_binary = Path(directory) / name
                mutated_source.write_text(mutated)
                mutated_compile = subprocess.run(
                    [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                     "-I", str(stub_root), "-I", str(SOURCE.parent),
                     "-I", str(SOURCE.parent / "include"),
                     str(implementation), str(mutated_source), str(fixture),
                     "-o", str(mutated_binary)],
                    check=False, capture_output=True, text=True,
                )
                self.assertEqual(mutated_compile.returncode, 0, mutated_compile.stderr)
                mutated_run = subprocess.run(
                    [str(mutated_binary)], check=False, capture_output=True, text=True,
                )
                self.assertNotEqual(mutated_run.returncode, 0, name)

    def test_https_owner_routes_mip_commands_through_uart_without_prompt_requeue(self):
        source = SOURCE.read_text()
        adapter = function_body(source, "owner_https_send_command")
        self.assertIn("owner_send_mip_deadline", adapter)
        self.assertIn("TickDeadline cleanup_deadline(HTTPS_CLEANUP_TIMEOUT_MS)", adapter)
        self.assertIn("owner_uart_write_all", source)
        self.assertIn("preserve_uart_urcs", source)
        self.assertNotIn("submit_owner_command", adapter)
        self.assertNotIn("raw_payload", adapter)
        self.assertNotIn("owner_send_raw_prompt_payload", source)
        self.assertNotIn("MHTTP", (SOURCE.parent / "idf_modem_https.cpp").read_text())

    def test_https_owner_callback_is_concrete_mip_command_adapter(self):
        source = SOURCE.read_text()
        adapter = function_body(source, "owner_https_send_command")
        self.assertIn("const std::string command_text(command)", adapter)
        self.assertIn("owner_send_mip_deadline", adapter)
        self.assertIn("cleanup", adapter)
        self.assertNotIn("CCLK", adapter)
        self.assertNotIn("filter_urcs", adapter)

    def test_https_queue_wait_covers_both_cleanup_attempts_and_propagates_deadline(self):
        source = SOURCE.read_text()
        submit = function_body(source, "submit_owner_command")
        self.assertIn("HTTPS_CLEANUP_WAIT_MARGIN_MS", submit)
        self.assertIn("HTTPS_CLEANUP_COMMANDS_MAX", source)
        self.assertIn("HTTPS_CLEANUP_CLOSE_COMMANDS_MAX", source)
        self.assertIn("HTTPS_CLEANUP_CONFIGS_MAX * HTTPS_CLEANUP_CONFIG_COMMANDS_MAX", source)
        self.assertIn("HTTPS_CLEANUP_PDP_COMMANDS_MAX", source)
        self.assertNotIn("3UL * HTTPS_CLEANUP_TIMEOUT_MS", submit)
        self.assertIn("operation_deadline(deadline.start", submit)
        self.assertIn("slot.request.deadline_start = operation_deadline.start", submit)
        self.assertIn("slot.request.deadline_span = operation_deadline.span", submit)
        adapter = function_body(source, "owner_https_send_command")
        self.assertIn("cleanup", adapter)
        self.assertIn("TickDeadline cleanup_deadline(HTTPS_CLEANUP_TIMEOUT_MS)", adapter)
        self.assertIn("static constexpr size_t OWNER_COMMAND_SLOTS = 4;", source)
        self.assertIn("slot.state = OwnerCommandState::abandoned", submit)
        reclaim = function_body(source, "owner_process_one_command")
        self.assertIn("slot.state == OwnerCommandState::abandoned", reclaim)
        self.assertIn("reset_owner_slot(slot)", reclaim)

    def test_https_der_bound_rejects_before_owner_copy_or_submit(self):
        source = SOURCE.read_text()
        submit = function_body(source, "submit_owner_command")
        bounded = function_body(source, "owner_request_bounded")
        self.assertIn("if (request.kind != OwnerCommandKind::https_post)", bounded)
        self.assertIn("return true;", bounded)
        self.assertIn("rootCertificateDer.empty()", bounded)
        self.assertIn("rootCertificateDer.size() <= IDF_MODEM_HTTPS_ROOT_DER_MAX", bounded)
        self.assertIn("rootCertificateSha256.size() == 32", bounded)
        self.assertLess(submit.index("owner_request_bounded(request)"),
                        submit.index("slot.request = request"))

        https_source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        validate = function_body(https_source, "idf_modem_https_validate_request")
        self.assertIn("rootCertificateDer.empty()", validate)
        self.assertIn("rootCertificateDer.size() > IDF_MODEM_HTTPS_ROOT_DER_MAX", validate)
        self.assertIn("rootCertificateSha256.size() != 32", validate)
        post = function_body(source, "idf_modem_https_post")
        self.assertLess(post.index("idf_modem_https_validate_request"),
                        post.index("owner_request.https_post_request = request"))
        self.assertLess(post.index("idf_modem_https_validate_request"),
                        post.index("submit_owner_command"))

    def test_https_cleanup_budget_includes_apn_restore(self):
        source = SOURCE.read_text()
        submit = function_body(source, "submit_owner_command")
        self.assertIn("HTTPS_CLEANUP_PDP_PROFILE_RESTORE_COMMANDS_MAX", source)
        self.assertIn("HTTPS_CLEANUP_COMMANDS_MAX", source)
        self.assertIn("HTTPS_CLEANUP_CONFIGS_MAX * HTTPS_CLEANUP_CONFIG_COMMANDS_MAX", source)
        self.assertIn("HTTPS_CLEANUP_PDP_COMMANDS_MAX", source)
        self.assertIn("HTTPS_CLEANUP_WAIT_MARGIN_MS", submit)
        self.assertNotIn("3UL * HTTPS_CLEANUP_TIMEOUT_MS", submit)

    def test_https_mip_state_open_close_and_cgact_parsers_are_strict(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        wire = (SOURCE.parent / "idf_modem_https_wire.cpp").read_text()
        self.assertIn("parse_mip_open", source)
        self.assertIn("result != 0", source)
        self.assertIn("parse_mip_open", wire)
        self.assertIn("std::array<bool, 256> seen", wire)
        self.assertIn("return found", wire)
        self.assertIn('expected == "INITIAL"', wire)
        self.assertIn('expected == "CONNECTED"', wire)

    def test_https_open_accepts_terminal_and_parses_optional_result_strictly(self):
        source = SOURCE.read_text()
        wire = (SOURCE.parent / "idf_modem_https_wire.cpp").read_text()
        fixture = (SOURCE.parent / "test" / "https_post_fixture.cpp").read_text()
        adapter = function_body(source, "owner_send_mip_deadline")
        self.assertIn("await_mip_open", adapter)
        self.assertIn("terminal_seen", adapter)
        self.assertIn("open_seen", adapter)
        self.assertIn("line_carry", adapter)
        self.assertIn("known_mip_urc", adapter)
        self.assertIn("if (line == command)", adapter)
        self.assertIn("parse_mip_open", adapter)
        self.assertIn("terminal_seen && line_carry.empty()", adapter)
        self.assertNotIn("terminal_seen && open_seen &&", adapter)
        self.assertIn("owner_send_mip_deadline(command_text, active_deadline, response,", source)
        self.assertIn("open_latch->feed", adapter)
        self.assertIn("open_latch->feed", function_body(source, "capture_pending_uart_locked"))
        confirm = function_body(source, "owner_https_confirm_open")
        self.assertIn("capture_pending_uart_locked", confirm)
        self.assertIn("open_latch.finish()", confirm)
        self.assertNotIn("open_latch.reset()", confirm)
        self.assertIn("!open_latch->connected()", adapter)
        self.assertIn("if (cleanup) context.open_latch.reset()", source)
        self.assertIn("context.open_latch.reset()", function_body(source, "owner_https_post"))
        self.assertIn("parse_mip_urc", wire)
        self.assertNotIn('"+MIPURC:"', wire.split("bool is_known_urc", 1)[1].split("}", 1)[0])
        self.assertIn("open_after_ok_response", fixture)
        self.assertIn("no_open_present", fixture)
        self.assertIn("duplicate_open", fixture)
        self.assertIn("+UNKNOWN: 1", fixture)
        self.assertIn('\\"disconn\\",0,2', fixture)

    def test_https_failure_stages_are_fixed_sanitized_messages(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        owner = SOURCE.read_text()
        self.assertIn("enum class HttpsFailureStage", source)
        expected = (
            "HTTPS modem initial-state check failed",
            "HTTPS modem runtime snapshot failed",
            "HTTPS modem PDP/APN setup failed",
            "HTTPS modem runtime configuration failed",
            "HTTPS modem socket open failed",
            "HTTPS modem connected-state poll failed",
            "HTTPS TLS setup failed",
            "HTTPS TLS handshake failed",
            "HTTPS request write failed",
            "HTTPS response failed",
            "HTTPS cleanup failed",
        )
        for message in expected:
            self.assertEqual(source.count(f'"{message}"'), 1)
            self.assertNotIn("AT+", message)
            self.assertNotIn("fixture", message)
        for message in (
            "HTTPS modem initial query command failed",
            "HTTPS modem initial query response invalid",
            "HTTPS modem stale socket close command failed",
            "HTTPS modem stale socket close response invalid",
            "HTTPS modem post-close query command failed",
            "HTTPS modem post-close query response invalid",
        ):
            self.assertEqual(source.count(f'"{message}"'), 1)
            self.assertLess(len(message.encode("ascii")), 96)
            for forbidden in ("AT+", "INITIAL", "CONNECTED", "CLOSED", "TCP", "fixture"):
                self.assertNotIn(forbidden, message)
        for message in (
            "HTTPS cleanup socket close failed",
            "HTTPS cleanup SSL config restore failed",
            "HTTPS cleanup autofree config restore failed",
            "HTTPS cleanup encoding config restore failed",
            "HTTPS cleanup PDP deactivate failed",
            "HTTPS cleanup PDP profile restore failed",
        ):
            self.assertEqual(source.count(f'"{message}"'), 1)
            self.assertLess(len(message.encode("ascii")), 96)
            for forbidden in ("AT+", "fixture", "request-apn", "INITIAL", "CONNECTED", "TCP"):
                self.assertNotIn(forbidden, message)
        result_header = (SOURCE.parent / "include" / "idf_modem_https.h").read_text()
        self.assertIn("MAX_CLEANUP_MESSAGE = 96", result_header)
        self.assertIn("std::string cleanupMessage", result_header)
        self.assertIn("enum class IdfModemHttpsDiagnosticReason", result_header)
        for reason in (
            "command_failure", "timeout", "response_invalid", "terminal_failure",
            "poll_timeout", "result_nonzero", "unknown",
        ):
            self.assertIn(f"{reason} =", result_header)
        self.assertIn("IdfModemHttpsDiagnosticReason failureReason", result_header)
        self.assertIn("IdfModemHttpsDiagnosticReason cleanupReason", result_header)
        self.assertIn("bool cleanupRequiresReset", result_header)
        submit = function_body(owner, "submit_owner_command")
        self.assertEqual(submit.count("*https_result = slot.https_post_result"), 2)
        run = function_body(source, "run")
        for stage in (
            "initial_state", "runtime_snapshot", "pdp_apn", "runtime_config",
            "socket_open", "connected_state", "tls_setup", "tls_handshake",
            "request_write", "response_read",
        ):
            self.assertIn(f"HttpsFailureStage::{stage}", run)
        post = function_body(owner, "idf_modem_https_post")
        self.assertIn("err == ESP_ERR_TIMEOUT && result.message.empty()", post)
        self.assertNotIn("Test push failed; see the log", source)

    def test_https_diagnostic_reasons_are_fixed_and_cleanup_close_is_reset_sensitive(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        header = (SOURCE.parent / "include" / "idf_modem_https.h").read_text()
        for reason in (
            "command_failure", "timeout", "response_invalid", "terminal_failure",
            "poll_timeout", "result_nonzero", "unknown",
        ):
            self.assertIn(f'"{reason}"', header)
        wait = source.split("bool wait_for_connected()", 1)[1].split(
            "bool query_config", 1
        )[0]
        self.assertIn("IdfModemHttpsDiagnosticReason::command_failure", wait)
        self.assertIn("IdfModemHttpsDiagnosticReason::timeout", wait)
        self.assertIn("IdfModemHttpsDiagnosticReason::response_invalid", wait)
        self.assertIn("IdfModemHttpsDiagnosticReason::terminal_failure", wait)
        self.assertIn("IdfModemHttpsDiagnosticReason::poll_timeout", wait)
        cleanup = source.split("void cleanup()", 1)[1].split(
            "const IdfModemHttpsPostRequest& request_", 1
        )[0]
        self.assertIn("IdfModemHttpsDiagnosticReason::result_nonzero", cleanup)
        self.assertIn("IdfModemHttpsDiagnosticReason::response_invalid", cleanup)
        self.assertIn("IdfModemHttpsDiagnosticReason::timeout", cleanup)
        self.assertIn("true);", cleanup)
        self.assertIn("cleanupRequiresReset", source)
        self.assertNotIn("response.c_str()", cleanup)
        self.assertNotIn("response.data()", cleanup)

    def test_https_initial_state_failure_labels_cover_each_branch(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        ensure_initial = function_body(source, "ensure_initial_state")
        query_state = function_body(source, "query_state")
        for label in (
            "kInitialQueryCommandFailure",
            "kInitialQueryResponseInvalid",
            "kStaleCloseCommandFailure",
            "kStaleCloseResponseInvalid",
            "kPostCloseQueryCommandFailure",
            "kPostCloseQueryResponseInvalid",
        ):
            self.assertIn(label, ensure_initial + query_state)
        self.assertIn("query_state(\"INITIAL\", kPostCloseQueryCommandFailure", ensure_initial)
        self.assertIn("post_close_state_failed", (SOURCE.parent / "test" / "https_post_fixture.cpp").read_text())

    def test_https_uart_drain_uses_operation_deadline_and_bounded_cap(self):
        source = SOURCE.read_text()
        drain = function_body(source, "capture_pending_uart_locked")
        self.assertIn("TickDeadline& deadline", source[source.index("capture_pending_uart_locked"):])
        self.assertIn("HTTPS_UART_DRAIN_MAX_MS", source)
        self.assertNotIn("std::max<uint32_t>(max_ms, 1000)", drain)
        self.assertIn("deadline.expired()", drain)
        cleanup = function_body(source, "submit_owner_command")
        self.assertIn("HTTPS_CLEANUP_WAIT_MARGIN_MS", cleanup)
        self.assertIn("OWNER_SLOT_RECLAIM_MUTEX_TIMEOUT_MS", cleanup)

    def test_https_cgdcont_rejects_duplicate_and_out_of_range_rows(self):
        wire = (SOURCE.parent / "idf_modem_https_wire.cpp").read_text()
        self.assertIn("std::array<bool, 256> seen", wire)
        self.assertIn("seen[context]", wire)
        self.assertIn("context == 0 || context > 16", wire)

    def test_https_mip_slot_timeout_path_reclaims_abandoned_slots(self):
        source = SOURCE.read_text()
        submit = function_body(source, "submit_owner_command")
        self.assertIn("slot.state = OwnerCommandState::abandoned", submit)
        self.assertIn("xSemaphoreTake(s_command_mutex", submit)
        self.assertIn("caller_abandoned", submit)
        self.assertIn("OWNER_SLOT_RECLAIM_MUTEX_TIMEOUT_MS", submit)
        self.assertIn("wake_owner_task()", submit)
        self.assertIn("owner_reclaim_expired_done_slots", source)
        self.assertIn("reset_owner_slot(slot)", source)
        self.assertIn("for (size_t i = 0; i < OWNER_COMMAND_SLOTS; ++i)", source)

    def test_https_mbedtls_contexts_free_only_after_initialization(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        destructor_match = re.search(r"~MipTlsSession\s*\(\)\s*\{", source)
        self.assertIsNotNone(destructor_match)
        destructor_start = destructor_match.end()
        destructor = source[destructor_start:source.index("\n    }", destructor_start)]
        init = function_body(source, "init")
        for name in ("ssl", "config", "certificate", "drbg", "entropy"):
            self.assertIn(f"{name}_initialized_", destructor)
            self.assertIn(f"{name}_initialized_ = true", init)
        self.assertIn("if (!ssl_)", init)
        self.assertIn("if (!config_)", init)
        self.assertIn("if (!certificate_)", init)
        self.assertIn("if (!drbg_)", init)
        self.assertIn("if (!entropy_)", init)

    def test_https_remote_close_keeps_slot_owned_until_explicit_cleanup(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        receive = function_body(source, "receive_mip_bytes")
        cleanup = function_body(source, "cleanup")
        self.assertIn("bool remote_closed_ = false;", source)
        self.assertNotIn("maybe_open_", receive)
        self.assertIn("if (cleanup_done_) return;", cleanup)
        self.assertIn("if (maybe_open_)", cleanup)
        self.assertIn('"AT+MIPCLOSE=0"', cleanup)

    def test_https_stale_slot_cleanup_is_one_shot_before_config_snapshot(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        run = function_body(source, "run")
        ensure_initial = function_body(source, "ensure_initial_state")
        self.assertLess(run.index("ensure_initial_state"), run.index("snapshot_config"))
        self.assertEqual(ensure_initial.count('"AT+MIPCLOSE=0"'), 1)
        self.assertEqual(ensure_initial.count('query_state("INITIAL",'), 1)
        self.assertIn("classify_mip_state", ensure_initial)
        self.assertIn("MipStateDisposition::invalid", ensure_initial)
        self.assertIn("command(close, response, true,", ensure_initial)
        self.assertNotIn("while", ensure_initial)
        self.assertNotIn("MIPOPEN", ensure_initial)
        wait_connected = function_body(
            source[source.index("bool wait_for_connected()"):], "wait_for_connected"
        )
        self.assertIn("kConnectedPollWindowMs", wait_connected)
        self.assertIn("kConnectedPollCadenceMs", wait_connected)
        self.assertIn("kConnectedPollMaxQueries", wait_connected)
        self.assertIn("vTaskDelay", wait_connected)

    def test_https_http_parser_requires_eof_without_length_and_rejects_chunked(self):
        source = (SOURCE.parent / "idf_modem_https_wire.cpp").read_text()
        header = (SOURCE.parent / "idf_modem_https_wire.h").read_text()
        implementation = source + header
        self.assertIn("finish_eof", source)
        self.assertIn("finish_eof", header)
        self.assertIn("Content-Length", implementation)
        self.assertIn("content_length", implementation)
        self.assertIn("Transfer-Encoding", implementation)
        self.assertIn("transfer_encoding", implementation)
        self.assertIn("complete_ = false", implementation)

    def test_https_tls_plaintext_scratch_stays_within_task_stack_budget(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        read_http = function_body(source, "read_http")
        scratch = re.search(
            r"constexpr\s+size_t\s+([A-Za-z_]\w*)\s*=\s*(\d+)\s*;", read_http
        )
        self.assertIsNotNone(scratch, "read_http needs an explicit local scratch budget")
        name, size = scratch.groups()
        self.assertGreater(int(size), 0)
        self.assertLessEqual(int(size), 1024)
        self.assertIn(f"std::array<uint8_t, {name}> bytes{{}};", read_http)
        self.assertNotIn("kReadMax", read_http)

    def test_https_post_uses_private_mip_runner_and_wire_seam(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        runner = function_body(source, "idf_modem_https_run_post")
        self.assertIn("using namespace idf_modem_https_wire;", source)
        self.assertIn("class MipPostSession", source)
        self.assertIn("MipPostSession session", runner)
        self.assertIn("AT+MIPOPEN", source)
        self.assertIn("AT+MIPSEND", source)
        self.assertIn("AT+MIPRD", source)
        self.assertIn("AT+MIPCLOSE", source)
        self.assertNotIn("MHTTP", source)

    def test_https_apn_is_targeted_validated_verified_before_activation(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        prepare = function_body(source, "prepare_pdp")
        run = function_body(source, "run")
        self.assertIn("trim_spaces(request_.apn)", prepare)
        self.assertIn("build_cgdccont_command", prepare)
        self.assertIn("requested_apn != current_apn", prepare)
        self.assertIn("if (active || current_profile.empty()) return false;", prepare)
        self.assertIn("pdp_profile_changed_ = true", prepare)
        self.assertIn("configured_apn != requested_apn", prepare)
        first_query = prepare.index("command(context_query")
        set_apn = prepare.index("command(configure")
        verify_query = prepare.index("command(context_query", set_apn)
        activate = prepare.index("command(activate")
        self.assertLess(first_query, set_apn)
        self.assertLess(set_apn, verify_query)
        self.assertLess(verify_query, activate)
        self.assertNotIn("MIPOPEN", prepare)
        self.assertLess(run.index("prepare_pdp"), run.index("open_socket"))


if __name__ == "__main__":
    unittest.main()
