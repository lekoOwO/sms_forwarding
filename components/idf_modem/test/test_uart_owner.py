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
            '"AT+CGDCONT?"',
        ):
            self.assertEqual(query_map.count(command), 1, command)
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
        oversize = body[body.index("response.size() > IDF_MODEM_USB_QUERY_MAX_RESPONSE"):]
        log = oversize[:oversize.index("response.clear()")]
        self.assertIn("idf_logf", log)
        self.assertIn("query_id", log)
        self.assertIn("response.size()", log)
        self.assertIn("static_cast<unsigned>(response.size())", log)
        self.assertNotIn("bounded_actual_length", log)
        self.assertNotIn("std::min", log)
        self.assertNotIn("IDF_MODEM_USB_QUERY_MAX_RESPONSE + 1", log)
        self.assertIn("IDF_MODEM_USB_QUERY_MAX_RESPONSE", log)
        self.assertNotIn("response.c_str()", log)
        self.assertNotIn("response.data()", log)
        for forbidden in ("command", "operator", "apn", "plmn"):
            self.assertNotIn(forbidden, log.lower())

    def test_cpol_query_returns_compact_summary_before_generic_size_guard(self):
        source = SOURCE.read_text()
        body = function_body(source, "idf_modem_usb_query")
        summary = body.index("idf_modem_cpol_compact_summary")
        generic_limit = body.index("response.size() > IDF_MODEM_USB_QUERY_MAX_RESPONSE")
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
        implementation = SOURCE.parent / "idf_modem_https.cpp"
        self.assertTrue(fixture.exists(), "missing executable HTTPS POST fixture")
        self.assertTrue(implementation.exists(), "missing HTTPS POST protocol implementation")
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "https_post_fixture"
            compile_result = subprocess.run(
                [compiler, "-std=c++17", "-Wall", "-Wextra", "-Werror",
                 "-I", str(SOURCE.parent / "include"), str(implementation),
                 str(fixture), "-o", str(binary)],
                check=False, capture_output=True, text=True,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

    def test_https_owner_routes_each_nonempty_raw_payload_through_prompt_transport(self):
        source = SOURCE.read_text()
        adapter = function_body(source, "owner_https_send_command")
        self.assertIn("if (!raw_payload.empty())", adapter)
        self.assertNotIn('command.rfind("AT+MHTTPCONTENT=", 0)', adapter)
        self.assertIn("owner_send_raw_prompt_payload", adapter)
        prompt = function_body(source, "owner_send_raw_prompt_payload")
        self.assertIn("scan.find('>') == std::string::npos", prompt)
        self.assertIn("return ESP_ERR_TIMEOUT", prompt)
        self.assertIn("owner_uart_write(payload.data(), payload.size())", prompt)
        self.assertIn("!= static_cast<int>(payload.size())", prompt)

    def test_https_clock_query_uses_owner_urc_filter_with_clock_prefix(self):
        source = SOURCE.read_text()
        adapter = function_body(source, "owner_https_send_command")
        self.assertIn('const bool filter_urcs = command == "AT+CCLK?";', adapter)
        self.assertIn('const char* response_prefix = filter_urcs ? "+CCLK:" : nullptr;', adapter)
        self.assertIn("filter_urcs, response_prefix, &modem_error", adapter)

    def test_https_queue_wait_covers_both_cleanup_attempts_and_propagates_deadline(self):
        source = SOURCE.read_text()
        submit = function_body(source, "submit_owner_command")
        self.assertIn("wait_margin_ms += 3UL * HTTPS_CLEANUP_TIMEOUT_MS", submit)
        self.assertIn("operation_deadline(deadline.start", submit)
        self.assertIn("slot.request.deadline_start = operation_deadline.start", submit)
        self.assertIn("slot.request.deadline_span = operation_deadline.span", submit)
        adapter = function_body(source, "owner_https_send_command")
        self.assertIn("cleanup", adapter)
        self.assertIn("TickDeadline cleanup_deadline(HTTPS_CLEANUP_TIMEOUT_MS)", adapter)

    def test_https_owner_trims_apn_before_cgdc_cont(self):
        source = (SOURCE.parent / "idf_modem_https.cpp").read_text()
        runner = function_body(source, "idf_modem_https_run_post")
        trim = runner.index("const std::string apn = trim_spaces(request.apn);")
        cgdc_cont = runner.index('"AT+CGDCONT=1')
        self.assertLess(trim, cgdc_cont)


if __name__ == "__main__":
    unittest.main()
