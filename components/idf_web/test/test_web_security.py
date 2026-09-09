#!/usr/bin/env python3
import json
import subprocess
import tempfile
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "components/idf_web"


def scheduler_keepalive_baseline_model(ka_enabled, ka_action, ka_last_valid):
    """Model the scheduler's baseline write branch for a small executable matrix."""
    writes = []
    if ka_enabled and not ka_last_valid:
        writes.append("keepalive-last")
    return writes


def restore_restart_idle_model(local_owner, ota_restart_pending, other_cellular_job,
                               allow_local_owner):
    """The restore restart may ignore only its own local restart claim."""
    cellular_busy = ((local_owner and not allow_local_owner) or
                     ota_restart_pending or other_cellular_job)
    return not cellular_busy


def function_body(source: str, name: str) -> str:
    search = 0
    while True:
        start = source.index(f" {name}(", search)
        brace = source.index("{", start)
        declaration_end = source.find(";", start, brace)
        if declaration_end < 0:
            break
        search = brace + 1
    start = brace + 1
    depth = 1
    for index in range(start, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[start:index]
    raise AssertionError(f"unterminated function: {name}")


def definition_body(source: str, declaration: str) -> str:
    declaration_start = source.index(declaration)
    brace = source.index("{", declaration_start)
    depth = 1
    for index in range(brace + 1, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return source[brace + 1:index]
    raise AssertionError(f"unterminated definition: {declaration}")


def assert_idf6_crypto_contract(source: str) -> None:
    assert '"psa/crypto.h"' in source
    assert '"mbedtls/gcm.h"' not in source
    assert '"mbedtls/pkcs5.h"' not in source
    assert "PSA_ALG_PBKDF2_HMAC(PSA_ALG_SHA_256)" in source
    assert "PSA_KEY_DERIVATION_INPUT_COST, BACKUP_KDF_ITERATIONS);" in source
    assert "PSA_KEY_DERIVATION_INPUT_SALT, salt, BACKUP_SALT_BYTES" in source
    assert "PSA_KEY_DERIVATION_INPUT_PASSWORD" in source
    assert "reinterpret_cast<const uint8_t*>(passphrase.data()), passphrase.size()" in source
    assert "psa_key_derivation_output_bytes(&operation, key, 32)" in source
    assert "psa_key_derivation_abort(&operation)" in source
    assert "PSA_ALG_AEAD_WITH_SHORTENED_TAG(PSA_ALG_GCM, BACKUP_TAG_BYTES)" in source
    assert source.count("psa_set_key_type(&attributes, PSA_KEY_TYPE_AES)") == 2
    assert source.count("psa_set_key_bits(&attributes, 256)") == 2
    assert "psa_aead_encrypt(key_id, algorithm, iv, BACKUP_IV_BYTES" in source
    assert "out, BACKUP_AAD_BYTES, plaintext, plaintext_size" in source
    assert "out + BACKUP_HEADER_BYTES, plaintext_size + BACKUP_TAG_BYTES" in source
    assert "psa_aead_decrypt(key_id, algorithm, encrypted + 32, BACKUP_IV_BYTES" in source
    assert "encrypted, BACKUP_AAD_BYTES, encrypted + BACKUP_HEADER_BYTES" in source
    assert "length + BACKUP_TAG_BYTES, output.data.get(), length" in source
    assert source.count("destroy_status == PSA_SUCCESS") == 2
    assert source.count("rc = crypto_ok ? 0 : -1;") == 2


def run_idf6_crypto_contract(source: str) -> bool:
    try:
        assert_idf6_crypto_contract(source)
    except AssertionError:
        return False
    return True


def run_imei_job_seam(source: str):
    util = (ROOT / "components/idf_logbuf/idf_util.cpp").read_text()
    harness = r'''
#include <cassert>
#include <cstdint>
#include <cstdio>
#include <iostream>
#include <string>
using esp_err_t = int;
constexpr int ESP_OK = 0;
static bool available = true;
static int getter_calls = 0;
static int idf_modem_get_imei(std::string& out, uint32_t timeout) {
    assert(timeout == 3000);
    ++getter_calls;
    out = available ? "860000000000001" : "";
    return available ? ESP_OK : -1;
}
static int idf_modem_send_at(const std::string&, uint32_t, std::string& out) {
    out = "private raw modem response";
    return -1;
}
static int idf_modem_request_reset(bool) { return -1; }
static bool parse_csq_line(const std::string&, int&, int&) { return false; }
static std::string first_line_containing(const std::string&, const char*) { return {}; }
'''
    for declaration, text in (
        ("void idf_util_json_escape_append(std::string& out, const std::string& value)", util),
        ("static void json_prop(std::string& out, const char* key, const std::string& value)", source),
        ("static std::string action_result(bool success, const char* code, const std::string& data = {}, const std::string& detail = {})", source),
        ("static std::string run_modem_job(const std::string& action)", source),
    ):
        name = declaration.split("(", 1)[0].rsplit(" ", 1)[1]
        harness += declaration + " {" + function_body(text.replace(" = {}", ""), name) + "}\n"
    harness += r'''
int main() {
    std::cout << run_modem_job("imei") << '\n';
    available = false;
    std::cout << run_modem_job("imei") << '\n';
    assert(getter_calls == 2);
}
'''
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "imei_job.cpp"
        path.write_text(harness)
        binary = Path(directory) / "imei_job"
        subprocess.run(["g++", "-std=c++17", "-Wall", "-Wextra", "-Werror", str(path),
                        "-o", str(binary)], check=True, capture_output=True, text=True)
        result = subprocess.run([str(binary)], check=False, capture_output=True, text=True)
        assert result.returncode == 0, result.stderr
        return [json.loads(line) for line in result.stdout.splitlines()]


def run_guard_seam(source: str, mutate_idle=None, mutate_cellular=None):
    def guard_body(name):
        for declaration in (
            f"static bool {name}(bool allow_device_restart, bool allow_current_ota)",
            f"static bool {name}(bool allow_device_restart)",
        ):
            if declaration in source:
                return definition_body(source, declaration)
        raise AssertionError(f"missing guard definition: {name}")

    cellular_locked = guard_body("cellular_job_active_locked")
    cellular_active = guard_body("cellular_job_active")
    if mutate_cellular:
        cellular_locked = mutate_cellular(cellular_locked)
    idle = definition_body(source, "static bool system_idle_for_maintenance(bool include_done = false,")
    if mutate_idle:
        idle = mutate_idle(idle)
    harness = f'''
#include <atomic>
#include <cassert>

using TickType_t = unsigned;
struct WebAsyncJob {{ bool running = false; bool queued = false; }};

static std::atomic<bool> s_device_restart_pending{{false}};
static std::atomic<bool> s_push_test_admission_active{{false}};
static std::atomic<bool> s_shared_admission_active{{false}};
static WebAsyncJob s_keepalive_job;
static WebAsyncJob s_esim_job;
static WebAsyncJob s_sched_job;
static bool s_modem_apply_running = false;
static bool s_web_modem_action_running = false;

static bool g_lock_available = true;
static bool g_backup_transfer = false;
static bool g_ota_active = false;
static unsigned g_ota_active_calls = 0;
static bool g_ota_restart_pending = false;
static bool g_restore_restart_pending = false;
static bool g_api_jobs_active = false;
static bool g_api_jobs_visible = false;
static bool g_push_busy = false;
static bool g_push_test_active = false;
static unsigned g_forward_queue = 0;
static unsigned g_retry_queue = 0;
static unsigned g_sms_queue = 0;
static unsigned g_email_queue = 0;

static bool cell_job_lock(TickType_t = 0) {{ return g_lock_available; }}
static void cell_job_unlock() {{}}
static bool backup_transfer_active() {{ return g_backup_transfer; }}
static bool ota_active() {{ ++g_ota_active_calls; return g_ota_active; }}
static bool idf_web_ota_restart_pending() {{ return g_ota_restart_pending; }}
static bool restore_restart_pending() {{ return g_restore_restart_pending; }}
static bool api_jobs_active() {{ return g_api_jobs_active; }}
static bool api_jobs_visible() {{ return g_api_jobs_visible; }}
static bool idf_push_busy() {{ return g_push_busy; }}
static bool idf_push_test_active() {{ return g_push_test_active; }}
static unsigned idf_push_forward_queue_depth() {{ return g_forward_queue; }}
static unsigned idf_push_retry_queue_depth() {{ return g_retry_queue; }}
static unsigned idf_sms_outgoing_queue_depth() {{ return g_sms_queue; }}
static unsigned idf_push_email_queue_depth() {{ return g_email_queue; }}
[[maybe_unused]] static bool shared_admission_active() {{
    return s_shared_admission_active.load(std::memory_order_acquire) ||
           s_push_test_admission_active.load(std::memory_order_acquire);
}}

static bool cellular_job_active_locked(bool allow_device_restart, bool allow_current_ota = false)
{{
    (void)allow_current_ota;
{cellular_locked}
}}

static bool cellular_job_active(bool allow_device_restart, bool allow_current_ota = false)
{{
    (void)allow_current_ota;
{cellular_active}
}}

static bool system_idle_for_maintenance(bool include_done = false,
                                         bool allow_restore_restart = false,
                                         bool allow_device_restart = false)
{{{idle}}}

static void reset_state()
{{
    g_lock_available = true;
    g_backup_transfer = false;
    g_ota_active = false;
    g_ota_active_calls = 0;
    g_ota_restart_pending = false;
    g_restore_restart_pending = false;
    g_api_jobs_active = false;
    g_api_jobs_visible = false;
    g_push_busy = false;
    g_push_test_active = false;
    g_forward_queue = 0;
    g_retry_queue = 0;
    g_sms_queue = 0;
    g_email_queue = 0;
    s_device_restart_pending.store(false);
    s_push_test_admission_active.store(false);
    s_shared_admission_active.store(false);
    s_keepalive_job = WebAsyncJob{{}};
    s_esim_job = WebAsyncJob{{}};
    s_sched_job = WebAsyncJob{{}};
    s_modem_apply_running = false;
    s_web_modem_action_running = false;
}}

static void expect_idle(bool expected, bool allow_device_restart = true,
                        bool allow_restore_restart = true, bool include_done = false)
{{
    assert(system_idle_for_maintenance(include_done, allow_restore_restart, allow_device_restart) == expected);
}}

static void expect_busy_with_current_ota()
{{
    g_ota_active = true;
    assert(cellular_job_active(false, true));
    reset_state();
}}

int main()
{{
    reset_state();
    g_ota_active = true;
    const bool current_ota_busy = cellular_job_active(false, true);
    assert(g_ota_active_calls == 1);  // OTA expiry must still be evaluated.
    assert(!current_ota_busy);         // The chunk owner may continue its session.

    reset_state();
    g_ota_active = true;
    assert(cellular_job_active(false, false));  // Default callers remain blocked.

    reset_state();
    s_device_restart_pending.store(true);
    expect_busy_with_current_ota();
    g_ota_restart_pending = true;
    expect_busy_with_current_ota();
    s_keepalive_job.running = true;
    expect_busy_with_current_ota();
    s_keepalive_job.queued = true;
    expect_busy_with_current_ota();
    s_esim_job.running = true;
    expect_busy_with_current_ota();
    s_esim_job.queued = true;
    expect_busy_with_current_ota();
    s_sched_job.running = true;
    expect_busy_with_current_ota();
    s_sched_job.queued = true;
    expect_busy_with_current_ota();
    s_modem_apply_running = true;
    expect_busy_with_current_ota();
    s_web_modem_action_running = true;
    expect_busy_with_current_ota();
    g_lock_available = false;
    g_ota_active = false;
    assert(cellular_job_active(false, true));  // Lock failure stays fail-safe busy.

    reset_state();
    expect_idle(true);

    s_device_restart_pending.store(true);
    expect_idle(true);  // The scheduler owns this local claim.
    expect_idle(false, false);
    g_ota_restart_pending = true;
    expect_idle(false);  // An OTA restart is an external owner.
    reset_state();

    g_restore_restart_pending = true;
    expect_idle(true);  // The restore scheduler explicitly allows its own pending state.
    expect_idle(false, true, false);
    reset_state();

    g_backup_transfer = true; expect_idle(false); reset_state();
    g_ota_active = true; expect_idle(false); reset_state();
    g_api_jobs_active = true; expect_idle(false); reset_state();
    g_api_jobs_visible = true; expect_idle(false, true, false, true); reset_state();
    s_push_test_admission_active.store(true); expect_idle(false); reset_state();
    g_push_busy = true; expect_idle(false); reset_state();
    g_push_test_active = true; expect_idle(false); reset_state();
    g_forward_queue = 1; expect_idle(false); reset_state();
    g_retry_queue = 1; expect_idle(false); reset_state();
    g_sms_queue = 1; expect_idle(false); reset_state();
    g_email_queue = 1; expect_idle(false); reset_state();

    s_keepalive_job.running = true; expect_idle(false); reset_state();
    s_keepalive_job.queued = true; expect_idle(false); reset_state();
    s_esim_job.running = true; expect_idle(false); reset_state();
    s_esim_job.queued = true; expect_idle(false); reset_state();
    s_sched_job.running = true; expect_idle(false); reset_state();
    s_sched_job.queued = true; expect_idle(false); reset_state();
    s_modem_apply_running = true; expect_idle(false); reset_state();
    s_web_modem_action_running = true; expect_idle(false); reset_state();
    g_lock_available = false; expect_idle(false);

    reset_state();
    s_device_restart_pending.store(true);
    s_esim_job.running = true;
    expect_idle(false);  // Ignoring the owner must not skip other cellular work.
    return 0;
}}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        harness_path = Path(temp_dir) / "guard_seam_test.cpp"
        binary_path = Path(temp_dir) / "guard_seam_test"
        harness_path.write_text(harness)
        subprocess.run(
            ["g++", "-std=c++17", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
             str(harness_path), "-o", str(binary_path)],
            check=True,
        )
        return subprocess.run([str(binary_path)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_admission_seam(source: str, mutate_try=None):
    if "static bool try_shared_admission(" not in source:
        return None
    try_body = function_body(source, "try_shared_admission")
    release_body = function_body(source, "release_shared_admission")
    active_body = function_body(source, "shared_admission_active")
    if mutate_try:
        try_body = mutate_try(try_body)
    harness = f'''
#include <atomic>
#include <cassert>
#include <thread>

static std::atomic<bool> s_shared_admission_active{{false}};
static std::atomic<bool> s_push_test_admission_active{{false}};

static bool try_shared_admission(bool push_test_owner)
{{{try_body}}}

static void release_shared_admission()
{{{release_body}}}

static bool shared_admission_active()
{{{active_body}}}

static bool admit_push_test()
{{
    if (s_push_test_admission_active.exchange(true, std::memory_order_acq_rel)) return false;
    if (!try_shared_admission(true)) {{
        s_push_test_admission_active.store(false, std::memory_order_release);
        return false;
    }}
    return true;
}}

static void release_push_test()
{{
    release_shared_admission();
    s_push_test_admission_active.store(false, std::memory_order_release);
}}

int main()
{{
    assert(try_shared_admission(false));
    assert(shared_admission_active());
    assert(!try_shared_admission(false));
    release_shared_admission();
    assert(!shared_admission_active());

    s_push_test_admission_active.store(true, std::memory_order_release);
    assert(!try_shared_admission(false));
    s_push_test_admission_active.store(false, std::memory_order_release);

    constexpr unsigned rounds = 200;
    for (unsigned round = 0; round < rounds; ++round) {{
        s_shared_admission_active.store(false, std::memory_order_release);
        s_push_test_admission_active.store(false, std::memory_order_release);
        std::atomic<bool> go{{false}};
        bool esim_won = false;
        bool push_won = false;
        std::thread esim([&]() {{
            while (!go.load(std::memory_order_acquire)) {{}}
            esim_won = try_shared_admission(false);
        }});
        std::thread push([&]() {{
            while (!go.load(std::memory_order_acquire)) {{}}
            push_won = admit_push_test();
        }});
        go.store(true, std::memory_order_release);
        esim.join();
        push.join();
        assert(static_cast<unsigned>(esim_won) + static_cast<unsigned>(push_won) == 1);
        if (push_won) release_push_test();
        else release_shared_admission();
        assert(!shared_admission_active());
    }}
    return 0;
}}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        harness_path = Path(temp_dir) / "admission_seam_test.cpp"
        binary_path = Path(temp_dir) / "admission_seam_test"
        harness_path.write_text(harness)
        subprocess.run(
            ["g++", "-std=c++17", "-pthread", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
             str(harness_path), "-o", str(binary_path)],
            check=True,
        )
        return subprocess.run([str(binary_path)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_esim_transition_seam(source: str):
    if "static bool wait_esim_modem_ready_and_idle(" not in source or \
            "static bool esim_transition_can_succeed(" not in source:
        return None
    wait_body = function_body(source, "wait_esim_modem_ready_and_idle")
    result_body = function_body(source, "esim_transition_can_succeed")
    harness = f'''
#include <cassert>
#include <cstdint>

using esp_err_t = int;
static constexpr esp_err_t ESP_OK = 0;
static constexpr esp_err_t ESP_FAIL = -1;
struct IdfModemStatus {{ bool atReady = false; bool modemReady = false; }};
static IdfModemStatus g_status;
static bool g_at_idle = false;
static uint64_t g_now_us = 0;
static IdfModemStatus idf_modem_get_status() {{ return g_status; }}
static bool idf_modem_at_idle() {{ return g_at_idle; }}
static uint64_t esp_timer_get_time() {{ return g_now_us; }}
static unsigned pdMS_TO_TICKS(unsigned milliseconds) {{ return milliseconds; }}
static void vTaskDelay(unsigned ticks) {{ g_now_us += static_cast<uint64_t>(ticks) * 1000ULL; }}

static bool wait_esim_modem_ready_and_idle(unsigned timeout_ms)
{{{wait_body}}}

static bool esim_transition_can_succeed(bool operation_ok, bool modem_ready, esp_err_t refresh_err)
{{{result_body}}}

int main()
{{
    g_status = {{true, true}}; g_at_idle = true; g_now_us = 0;
    assert(wait_esim_modem_ready_and_idle(1000));
    g_status = {{false, true}}; g_at_idle = true; g_now_us = 0;
    assert(!wait_esim_modem_ready_and_idle(1000));
    g_status = {{true, false}}; g_at_idle = true; g_now_us = 0;
    assert(!wait_esim_modem_ready_and_idle(1000));
    g_status = {{true, true}}; g_at_idle = false; g_now_us = 0;
    assert(!wait_esim_modem_ready_and_idle(1000));
    assert(esim_transition_can_succeed(true, true, ESP_OK));
    assert(!esim_transition_can_succeed(true, false, ESP_OK));
    assert(!esim_transition_can_succeed(true, true, ESP_FAIL));
    assert(!esim_transition_can_succeed(false, true, ESP_OK));
    return 0;
}}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        harness_path = Path(temp_dir) / "esim_transition_seam_test.cpp"
        binary_path = Path(temp_dir) / "esim_transition_seam_test"
        harness_path.write_text(harness)
        subprocess.run(
            ["g++", "-std=c++17", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
             str(harness_path), "-o", str(binary_path)],
            check=True,
        )
        return subprocess.run([str(binary_path)], check=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def run_esim_status_json_seam(source: str, mutate_body=None):
    job_start = source.index("struct WebAsyncJob {")
    job_struct = source[job_start:source.index("\n};", job_start) + 3]
    json_prop = function_body(source, "json_prop")
    modern_state = function_body(source, "modern_esim_state")
    modern_class = function_body(source, "modern_esim_class")
    profile_json = function_body(source, "append_modern_esim_profile_json")
    job_code = function_body(source, "modern_esim_job_code")
    status_start = source.index('        std::string body = "{\\"eid\\":{"')
    status_end = source.index("        set_json_no_cache(req);", status_start)
    status_body = source[status_start:status_end]
    if mutate_body:
        mutated = mutate_body(status_body)
        assert mutated != status_body
        status_body = mutated
    harness = f'''
#include <cassert>
#include <iostream>
#include <string>
#include <vector>

#include "idf_util.h"

{job_struct}

struct IdfEsimProfile {{
    std::string state;
    std::string nickname;
    std::string profileClass;
}};

static void json_prop(std::string& out, const char* key, const std::string& value)
{{{json_prop}}}

static const char* modern_esim_state(const std::string& state)
{{{modern_state}}}

static const char* modern_esim_class(const std::string& profile_class)
{{{modern_class}}}

static void append_modern_esim_profile_json(std::string& body,
                                            const IdfEsimProfile& p,
                                            const std::string& handle)
{{{profile_json}}}

static const char* modern_esim_job_code(const WebAsyncJob& job)
{{{job_code}}}

static std::string build_esim_status(const WebAsyncJob& job,
                                     const std::string& eid,
                                     const std::vector<IdfEsimProfile>& profiles,
                                     const std::vector<std::string>& handles)
{{
{status_body}
    return body;
}}

int main()
{{
    struct Case {{ unsigned id; bool queued; bool running; bool done; bool success; const char* action; const char* state; }};
    const Case cases[] = {{
        {{0, false, false, false, false, "", "disabled"}},
        {{7, true, false, false, false, "refresh", "enabled"}},
        {{8, false, true, false, false, "info", "disabled"}},
        {{9, false, false, true, true, "nickname", "enabled"}},
        {{10, false, false, true, false, "delete", "disabled"}},
    }};
    for (const Case& item : cases) {{
        WebAsyncJob job;
        job.id = item.id;
        job.queued = item.queued;
        job.running = item.running;
        job.done = item.done;
        job.success = item.success;
        job.action = item.action;
        const std::vector<IdfEsimProfile> profiles = {{{{item.state,
            R"(carrier "quoted" \\ path)", "operational"}}}};
        const std::vector<std::string> handles = {{"p0123456789abcdef"}};
        std::cout << build_esim_status(job, item.id == 0 ? "" : "89012345678901234567890123456789",
                                       profiles, handles) << '\\n';
    }}
    return 0;
}}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        harness_path = Path(temp_dir) / "esim_status_json_seam_test.cpp"
        binary_path = Path(temp_dir) / "esim_status_json_seam_test"
        harness_path.write_text(harness)
        subprocess.run(
            [
                "g++", "-std=c++17", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
                f"-I{ROOT / 'components' / 'idf_logbuf' / 'include'}",
                str(ROOT / "components" / "idf_logbuf" / "idf_util.cpp"),
                str(harness_path), "-o", str(binary_path),
            ],
            check=True,
        )
        output = subprocess.run([str(binary_path)], check=True, stdout=subprocess.PIPE, text=True)
        return output.stdout.splitlines()


def parse_esim_status_json(lines):
    parsed = []
    for index, line in enumerate(lines):
        try:
            parsed.append(json.loads(line))
        except json.JSONDecodeError as error:
            raise AssertionError(f"eSIM status response {index} is invalid JSON: {error}") from error
    return parsed


def main() -> None:
    harness = r'''
#include <cassert>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

#include "idf_web_core.h"
#include "idf_web_crypto.h"

static uint8_t* reject_allocation(size_t) { return nullptr; }
static bool reject_derivation(const std::string&, const uint8_t*, uint8_t key[32]) {
    std::memset(key, 0xa5, 32);
    return false;
}

int main() {
    const std::string token = "0123456789abcdef0123456789abcdef";
    assert(idf_web_constant_time_equal(token.data(), token.size(), token));
    assert(!idf_web_constant_time_equal("", 0, token));
    assert(!idf_web_constant_time_equal("0123456789abcdef0123456789abcdee", token.size(), token));
    assert(!idf_web_constant_time_equal("0123456789abcdef0123456789abcdefx", token.size() + 1, token));

    const char* ap_routes[] = {"/wifiscan", "/wificonfig", "/apstatus"};
    for (const char* route : ap_routes) {
        assert(idf_web_ap_auth_bypass(true, true, route));
        assert(!idf_web_ap_auth_bypass(true, false, route));
        assert(!idf_web_ap_auth_bypass(false, true, route));
    }
    assert(idf_web_ap_auth_bypass(true, true, "/wifiscan?fresh=1"));
    assert(!idf_web_ap_auth_bypass(true, true, "/"));
    assert(!idf_web_ap_auth_bypass(true, true, "/api/config"));
    assert(!idf_web_ap_auth_bypass(true, true, "/wificonfig/extra"));
    assert(idf_web_ap_csrf_bypass(true, true, "/wificonfig", "1"));
    assert(!idf_web_ap_csrf_bypass(true, false, "/wificonfig", "1"));
    assert(!idf_web_ap_csrf_bypass(false, true, "/wificonfig", "1"));
    assert(!idf_web_ap_csrf_bypass(true, true, "/wificonfig?x=1", "1"));
    assert(!idf_web_ap_csrf_bypass(true, true, "/wifiscan", "1"));
    assert(!idf_web_ap_csrf_bypass(true, true, "/wificonfig", "anything-else"));

    for (const char* command : {"AT", "ATI", "AT+CSQ", "  at+cops?  "}) {
        assert(idf_web_at_command_allowed(command));
    }
    for (const char* command : {"ATD123", "ATO", "AT+CMGS=1", "AT+CMGW=1",
                                "AT+CGDATA", "AT+CMUX=0", "AT+CIPSEND=1",
                                "AT+QISEND=1", "AT+CASEND=1", "AT\r+CSQ"}) {
        assert(!idf_web_at_command_allowed(command));
    }

    IdfWebFormDecodeResult decoded = idf_web_decode_form(
        "phone=%2B886900000000&content=%E7%95%8C+ok", 48);
    assert(decoded.valid && decoded.fields.size() == 2);
    assert(decoded.fields[0].second == "+886900000000");
    assert(decoded.fields[1].second == "界 ok");
    assert(!idf_web_decode_form("x=%ZZ", 48).valid);
    assert(!idf_web_decode_form("x=%00", 48).valid);
    std::string too_many;
    for (int i = 0; i < 49; ++i) too_many += (i ? "&" : "") + std::string("x") + std::to_string(i) + "=1";
    assert(!idf_web_decode_form(too_many, 48).valid);
    std::string config_update;
    for (int i = 0; i < 51; ++i) config_update += (i ? "&" : "") + std::string("x") + std::to_string(i) + "=1";
    const IdfWebFormDecodeResult max_config_update = idf_web_decode_form(config_update, 51);
    assert(max_config_update.valid && !max_config_update.too_many_fields && max_config_update.fields.size() == 51);
    config_update += "&x51=1";
    const IdfWebFormDecodeResult oversized_config_update = idf_web_decode_form(config_update, 51);
    assert(!oversized_config_update.valid && oversized_config_update.too_many_fields);

    IdfWebPushTestQuery push_query;
    assert(idf_web_parse_push_test_query("channel=0", 3, push_query));
    assert(push_query.channel == 0 && !push_query.includeCleanup);
    assert(idf_web_parse_push_test_query("channel=2&detail=1", 3, push_query));
    assert(push_query.channel == 2 && push_query.includeCleanup);
    assert(idf_web_parse_push_test_query("detail=1&channel=1", 3, push_query));
    assert(push_query.channel == 1 && push_query.includeCleanup);
    assert(idf_web_parse_push_test_query("channel=+0", 3, push_query));
    assert(push_query.channel == 0 && !push_query.includeCleanup);
    assert(idf_web_parse_push_test_query("channel=%2B0", 3, push_query));
    assert(push_query.channel == 0 && !push_query.includeCleanup);
    for (const char* invalid : {
             "", "detail=1", "channel=3", "channel=-1", "channel=0&detail=",
             "channel=0&detail=0", "channel=0&detail=2", "channel=0&unknown=1",
             "channel=0&channel=1", "channel=0&detail=1&detail=1",
             "channel=0&detail=1&unknown=1", "channel=%ZZ", "channel=0&&detail=1",
             "channel=0&=1",
         }) {
        assert(!idf_web_parse_push_test_query(invalid, 3, push_query));
    }
    assert(!idf_web_parse_push_test_query("channel=" + std::string(56, ' ') + "0",
                                          3, push_query));

    char request_body[] = "content=before";
    IdfWebOwnedJobInput owned = idf_web_own_job_input("sms", request_body,
                                                       sizeof(request_body) - 1);
    std::memcpy(request_body, "content=after!", sizeof(request_body) - 1);
    assert(owned.type == "sms");
    assert(owned.payload == "content=before");

    IdfWebJobSlotMeta slots[6] = {};
    slots[0] = {1, IdfWebJobState::Running, 0};
    slots[1] = {2, IdfWebJobState::Done, 100};
    assert(idf_web_count_active_jobs(slots, 6) == 1);
    slots[2] = {3, IdfWebJobState::Queued, 0};
    assert(idf_web_count_active_jobs(slots, 6) == 2);
    slots[0] = {1, IdfWebJobState::Done, 100};
    slots[2] = {3, IdfWebJobState::Done, 100};
    assert(idf_web_count_active_jobs(slots, 6) == 0);
    slots[0] = {1, IdfWebJobState::Running, 0};
    slots[2] = {};
    assert(idf_web_select_job_slot(slots, 6, 200, 1000) == 2);
    for (int i = 2; i < 6; ++i) slots[i] = {uint32_t(i + 1), IdfWebJobState::Running, 0};
    // An unexpired terminal result, including a restore result, must not be evicted.
    assert(idf_web_select_job_slot(slots, 6, 200, 1000) == -1);
    assert(idf_web_select_job_slot(slots, 6, 1099, 1000) == -1);
    assert(idf_web_select_job_slot(slots, 6, 1100, 1000) == 1);
    slots[1] = {2, IdfWebJobState::Running, 0};
    slots[4] = {5, IdfWebJobState::Done, 0xfffffff0U};
    assert(idf_web_select_job_slot(slots, 6, 0x20U, 0x20U) == 4);

    IdfWebJobSlotMeta visible[6] = {};
    visible[0] = {11, IdfWebJobState::Done, 1000};
    visible[1] = {12, IdfWebJobState::Queued, 0};
    assert(idf_web_count_visible_jobs(visible, 6, 1059, 60) == 2);
    assert(idf_web_count_visible_jobs(visible, 6, 1060, 60) == 1);
    visible[1] = {13, IdfWebJobState::Running, 0};
    assert(idf_web_count_visible_jobs(visible, 6, 1060, 60) == 1);

    IdfWebJobSlotMeta lifecycle[6] = {};
    lifecycle[0] = {42, IdfWebJobState::Queued, 0};
    assert(idf_web_count_visible_jobs(lifecycle, 6, 1000, 60) == 1);
    lifecycle[0].state = IdfWebJobState::Running;
    assert(idf_web_count_visible_jobs(lifecycle, 6, 1000, 60) == 1);
    lifecycle[0] = {42, IdfWebJobState::Done, 1000};
    assert(idf_web_count_visible_jobs(lifecycle, 6, 1059, 60) == 1);
    assert(idf_web_count_visible_jobs(lifecycle, 6, 1060, 60) == 0);
    // The firmware uses esp_timer milliseconds and a 60-second TTL. A delayed
    // first poll at 32 seconds must still see the completed result.
    lifecycle[0] = {42, IdfWebJobState::Done, 100000};
    assert(idf_web_count_visible_jobs(lifecycle, 6, 132000, 60000) == 1);
    assert(idf_web_count_visible_jobs(lifecycle, 6, 159999, 60000) == 1);
    assert(idf_web_count_visible_jobs(lifecycle, 6, 160000, 60000) == 0);
    lifecycle[0] = {42, IdfWebJobState::Done, 0xfffffff0U};
    assert(idf_web_count_visible_jobs(lifecycle, 6, 0x2bU, 60) == 1);
    assert(idf_web_count_visible_jobs(lifecycle, 6, 0x2cU, 60) == 0);

    IdfWebJobSlotMeta query_churn[6] = {};
    query_churn[0] = {42, IdfWebJobState::Done, 1000};
    for (uint32_t now = 1100; now < 10000; now += 100) {
        query_churn[1] = {now, IdfWebJobState::Done, now};
        assert(idf_web_count_active_jobs(query_churn, 6) == 0);
        assert(idf_web_count_visible_jobs(query_churn, 6, now, 60000) >= 1);
    }

    const std::string log_snapshot =
        R"({"seq":5,"lines":["one","two","three","four","fi\"ve"]})";
    assert(idf_web_paginate_log_json(log_snapshot, false, 0, 2) ==
        R"({"entries":[{"id":4,"message":"four"},{"id":5,"message":"fi\"ve"}],"nextCursor":4,"hasMore":true})");
    assert(idf_web_paginate_log_json(log_snapshot, true, 0, 2) ==
        R"({"entries":[{"id":4,"message":"four"},{"id":5,"message":"fi\"ve"}],"nextCursor":4,"hasMore":true})");
    assert(idf_web_paginate_log_json(log_snapshot, true, 4, 2) ==
        R"({"entries":[{"id":2,"message":"two"},{"id":3,"message":"three"}],"nextCursor":2,"hasMore":true})");
    assert(idf_web_paginate_log_json(log_snapshot, true, 2, 50) ==
        R"({"entries":[{"id":1,"message":"one"}],"nextCursor":null,"hasMore":false})");
    assert(idf_web_paginate_log_json("not-json", false, 0, 50) ==
        R"({"entries":[],"nextCursor":null,"hasMore":false})");

    const uint8_t salt[16] = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const uint8_t iv[12] = {16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27};
    const std::vector<uint8_t> plain = {'p','o','r','t','a','b','l','e','-','c','o','n','f','i','g'};
    IdfWebOwnedBytes encrypted;
    assert(idf_web_encrypt_backup(plain.data(), plain.size(), "correct horse battery", salt, iv, encrypted) ==
           IdfWebCryptoResult::Ok);
    const std::string expected_hex =
        "534d5343464730310100010150340300000102030405060708090a0b0c0d0e0f"
        "101112131415161718191a1b0ac0d13428afd55452d0070dfe478b4a1f0fd073"
        "713ed962a6ff04fb268941";
    assert(idf_web_hex(encrypted.data.get(), encrypted.size) == expected_hex);
    IdfWebOwnedBytes decrypted;
    assert(idf_web_decrypt_backup(encrypted.data.get(), encrypted.size, "correct horse battery", decrypted) ==
           IdfWebCryptoResult::Ok && decrypted.size == plain.size() &&
           std::memcmp(decrypted.data.get(), plain.data(), plain.size()) == 0);
    assert(idf_web_decrypt_backup(encrypted.data.get(), encrypted.size, "wrong passphrase", decrypted) ==
           IdfWebCryptoResult::AuthenticationFailed && !decrypted.data);
    IdfWebOwnedBytes allocation_failed;
    assert(idf_web_encrypt_backup(plain.data(), plain.size(), "correct horse battery", salt, iv,
                                  allocation_failed, reject_allocation) == IdfWebCryptoResult::Failed);
    assert(!allocation_failed.data);
    assert(idf_web_decrypt_backup(encrypted.data.get(), encrypted.size, "correct horse battery",
                                  allocation_failed, reject_allocation) == IdfWebCryptoResult::Failed);
    assert(!allocation_failed.data);
    assert(idf_web_encrypt_backup(plain.data(), plain.size(), "correct horse battery", salt, iv,
                                  allocation_failed, nullptr, reject_derivation) == IdfWebCryptoResult::Failed);
    assert(!allocation_failed.data);
    assert(idf_web_decrypt_backup(encrypted.data.get(), encrypted.size, "correct horse battery",
                                  allocation_failed, nullptr, reject_derivation) == IdfWebCryptoResult::Failed);
    assert(!allocation_failed.data);
    encrypted.data[20] ^= 1;
    assert(idf_web_decrypt_backup(encrypted.data.get(), encrypted.size, "correct horse battery", decrypted) ==
           IdfWebCryptoResult::AuthenticationFailed && !decrypted.data);
    encrypted.data[20] ^= 1;
    encrypted.data[8] = 2;
    assert(idf_web_decrypt_backup(encrypted.data.get(), encrypted.size, "correct horse battery", decrypted) ==
           IdfWebCryptoResult::InvalidEnvelope && !decrypted.data);
    idf_web_secure_clear(encrypted);
    const std::vector<uint8_t> too_large_plain(32769, 1);
    assert(idf_web_encrypt_backup(too_large_plain.data(), too_large_plain.size(), "correct horse battery",
                                  salt, iv, encrypted) == IdfWebCryptoResult::TooLarge);
    assert(!encrypted.data);
    assert(idf_web_valid_backup_passphrase("123456789012"));
    assert(!idf_web_valid_backup_passphrase("12345678901"));
    assert(!idf_web_valid_backup_passphrase(std::string(129, 'x')));

    IdfWebTransfer transfer;
    auto append_transfer = [](IdfWebTransfer& item, uint32_t id, size_t offset,
                              const std::vector<uint8_t>& chunk, size_t max_chunk) {
        return idf_web_transfer_append(item, id, offset, chunk.data(), chunk.size(), max_chunk);
    };
    assert(idf_web_transfer_start(transfer, IdfWebTransferMode::Restore, 7, 100, 10));
    assert(!append_transfer(transfer, 7, 1, std::vector<uint8_t>(60, 1), 8192));
    assert(!transfer.bytes.data);
    assert(idf_web_transfer_start(transfer, IdfWebTransferMode::Restore, 8, 100, 20));
    assert(!append_transfer(transfer, 99, 0, std::vector<uint8_t>(10, 1), 8192));
    assert(transfer.mode == IdfWebTransferMode::Restore && transfer.id == 8 && transfer.bytes.size == 0);
    assert(!idf_web_transfer_cancel_upload(transfer, 99));
    assert(transfer.mode == IdfWebTransferMode::Restore && transfer.id == 8);
    assert(!idf_web_transfer_start(transfer, IdfWebTransferMode::Restore, 13, 100, 25));
    assert(append_transfer(transfer, 8, 0, std::vector<uint8_t>(60, 1), 8192));
    IdfWebOwnedBytes uploaded;
    assert(!idf_web_transfer_take_complete(transfer, 8, uploaded));
    assert(append_transfer(transfer, 8, 60, std::vector<uint8_t>(40, 2), 8192));
    assert(idf_web_transfer_take_complete(transfer, 8, uploaded));
    assert(uploaded.size == 100 && transfer.mode == IdfWebTransferMode::Restore);
    assert(!idf_web_transfer_start(transfer, IdfWebTransferMode::Restore, 14, 100, 30));
    assert(!append_transfer(transfer, 8, 0, std::vector<uint8_t>(10, 1), 8192));
    assert(transfer.mode == IdfWebTransferMode::Restore && transfer.id == 8);
    assert(!idf_web_transfer_cancel_upload(transfer, 8));
    assert(transfer.mode == IdfWebTransferMode::Restore && transfer.id == 8);
    assert(!idf_web_transfer_expire(transfer, 1000, 100));
    assert(transfer.mode == IdfWebTransferMode::Restore && transfer.id == 8);
    idf_web_secure_clear(uploaded);
    assert(!uploaded.data);
    idf_web_transfer_clear(transfer);
    assert(idf_web_transfer_start(transfer, IdfWebTransferMode::Restore, 9, 100, 0xfffffff0U));
    assert(idf_web_transfer_expire(transfer, 0x20U, 0x20U));
    assert(transfer.mode == IdfWebTransferMode::None && !transfer.bytes.data);
    assert(idf_web_transfer_start(transfer, IdfWebTransferMode::Restore, 10, 9000, 30));
    assert(!append_transfer(transfer, 10, 0, std::vector<uint8_t>(8193, 1), 8192));
    assert(transfer.mode == IdfWebTransferMode::None && !transfer.bytes.data);
    assert(!idf_web_transfer_start(transfer, IdfWebTransferMode::Restore, 11,
                                   std::numeric_limits<size_t>::max(), 40));
    assert(transfer.mode == IdfWebTransferMode::None && !transfer.bytes.data);
    assert(!idf_web_transfer_start(transfer, IdfWebTransferMode::Restore, 12, 100, 50,
                                   reject_allocation));
    assert(transfer.mode == IdfWebTransferMode::None && !transfer.bytes.data);

    IdfWebOwnedBytes raw_export;
    assert(idf_web_allocate_owned_bytes(raw_export, 32));
    std::memset(raw_export.data.get(), 0xa5, raw_export.capacity);
    assert(idf_web_finalize_owned_bytes(raw_export, 12, 32) && raw_export.size == 12);
    assert(!idf_web_finalize_owned_bytes(raw_export, 0, 32) && !raw_export.data);
    assert(idf_web_allocate_owned_bytes(raw_export, 32));
    assert(!idf_web_finalize_owned_bytes(raw_export, 33, 32) && !raw_export.data);
}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        harness_path = Path(temp_dir) / "web_security_test.cpp"
        binary_path = Path(temp_dir) / "web_security_test"
        harness_path.write_text(harness)
        subprocess.run(
            [
                "g++", "-std=c++17", "-fno-exceptions", "-Wall", "-Wextra", "-Werror",
                f"-I{WEB / 'include'}", f"-I{ROOT / 'components' / 'idf_config' / 'include'}",
                str(WEB / "idf_web_core.cpp"),
                str(WEB / "idf_web_crypto.cpp"), str(harness_path), "-lcrypto",
                "-o", str(binary_path),
            ],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True)

    crypto_source = (WEB / "idf_web_crypto.cpp").read_text()
    assert run_idf6_crypto_contract(crypto_source)
    assert not run_idf6_crypto_contract(crypto_source.replace(
        "PSA_KEY_DERIVATION_INPUT_COST, BACKUP_KDF_ITERATIONS",
        "PSA_KEY_DERIVATION_INPUT_COST, BACKUP_KDF_ITERATIONS + 1", 1))
    assert not run_idf6_crypto_contract(crypto_source.replace(
        "out, BACKUP_AAD_BYTES, plaintext, plaintext_size",
        "out, BACKUP_AAD_BYTES - 1, plaintext, plaintext_size", 1))
    assert not run_idf6_crypto_contract(crypto_source.replace(
        "destroy_status == PSA_SUCCESS", "true", 1))
    assert not run_idf6_crypto_contract(crypto_source.replace(
        "psa_key_derivation_abort(&operation)", "psa_key_derivation_setup(&operation, 0)", 1))

    source = (WEB / "idf_web.cpp").read_text()
    assert run_imei_job_seam(source) == [
        {"success": True, "code": "ACTION_MODEM_OK",
         "data": {"imei": "860000000000001"}, "detail": ""},
        {"success": False, "code": "ACTION_MODEM_FAILED",
         "data": {"imei": ""}, "detail": ""},
    ]
    assert run_guard_seam(source).returncode == 0
    mutated_ota_guard = run_guard_seam(source, mutate_cellular=lambda body: body.replace(
        "(!allow_current_ota && ota_busy)", "ota_busy", 1))
    assert mutated_ota_guard.returncode != 0
    mutated_guard = run_guard_seam(source, lambda body: body.replace(
        "!s_push_test_admission_active.load(std::memory_order_acquire) &&", "true &&", 1).replace(
        "!shared_admission_active() &&", "true &&", 1))
    assert mutated_guard.returncode != 0
    admission = run_admission_seam(source)
    assert admission is not None and admission.returncode == 0
    transition = run_esim_transition_seam(source)
    assert transition is not None and transition.returncode == 0
    status = parse_esim_status_json(run_esim_status_json_seam(source))
    assert [item["job"]["state"] for item in status] == [
        "idle", "queued", "running", "succeeded", "failed"
    ]
    assert status[1]["profiles"][0]["nickname"] == 'carrier "quoted" \\ path'
    mutated_status = run_esim_status_json_seam(source, lambda body: body.replace(
        'body += "\\\",";', 'body += ",";', 1))
    try:
        parse_esim_status_json(mutated_status)
    except AssertionError:
        pass
    else:
        raise AssertionError("eSIM status mutation remained valid JSON")
    sdkconfig_defaults = (ROOT / "sdkconfig.defaults").read_text()
    assert "CONFIG_HTTPD_MAX_URI_LEN=2048" in sdkconfig_defaults
    assert "CONFIG_HTTPD_MAX_REQ_HDR_LEN=8192" in sdkconfig_defaults
    assert "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y" in sdkconfig_defaults
    assert '"X-CSRF-Token"' in source
    assert source.count('"X-SMS-CSRF"') == 1
    assert "colon == decoded_text" in source
    assert 'register_handler(s_server, "/api/config", HTTP_GET, handle_api_config)' in source
    assert 'register_handler(s_server, "/api/esim", HTTP_ANY, handle_api_esim)' in source
    assert 'register_handler(s_server, "/api/ota/state", HTTP_GET, handle_ota_state)' in source
    assert 'register_handler(s_server, "/query", HTTP_GET, handle_query)' in source
    assert 'register_handler(s_server, "/tools", HTTP_GET, handle_root)' in source
    assert 'register_handler(s_server, "/sms", HTTP_GET, handle_root)' in source
    assert 'register_handler(s_server, "/export"' not in source
    assert 'register_handler(s_server, "/config.json"' not in source
    assert 'register_handler(s_server, "/import"' not in source
    assert 'register_handler(s_server, "/update"' not in source
    assert 'register_handler(s_server, "/api/jobs", HTTP_GET, handle_api_job)' in source
    assert 'register_handler(s_server, "/api/device/restart", HTTP_ANY, handle_reboot)' in source
    assert 'register_handler(s_server, "/reboot"' not in source
    assert "handle_import_config" not in source
    assert "handle_ota_update" not in source
    registered = set(re.findall(r'register_handler\(s_server, "([^"]+)"', source))
    assert registered == {
        "/", "/tools", "/sms", "/assets/*", "/api/config", "/api/esim", "/api/jobs", "/query", "/save", "/wifi",
        "/wifiscan", "/wificonfig", "/apstatus", "/log", "/at", "/ping", "/flight",
        "/modem", "/sendsms", "/api/config/export", "/api/config/restore/start",
        "/api/config/restore/chunk", "/api/config/restore/finish", "/api/ota/start",
        "/api/ota/chunk", "/api/ota/finish", "/api/ota/state", "/api/push/test", "/api/device/restart", "/*",
        "/api/push/ca/probe", "/api/push/ca/install", "/api/push/ca/status",
        "/api/keepalive", "/api/keepalive/ca/probe", "/api/keepalive/ca/install", "/api/keepalive/ca/status",
        "/api/rules/preview",
    }
    assert 'register_handler(s_server, "/ping", HTTP_POST, handle_ping)' in source
    assert 'register_handler(s_server, "/api/push/test", HTTP_ANY, handle_test_push)' in source
    for route, handler in (
        ("/api/push/ca/probe", "handle_push_ca_probe"),
        ("/api/push/ca/install", "handle_push_ca_install"),
        ("/api/push/ca/status", "handle_push_ca_status"),
    ):
        assert f'register_handler(s_server, "{route}", HTTP_ANY, {handler})' in source
    ca_method = function_body(source, "send_ca_method_error")
    assert 'httpd_resp_set_status(req, "405 Method Not Allowed")' in ca_method
    assert 'httpd_resp_set_hdr(req, "Allow", allow)' in ca_method
    assert 'action_result(false, "ACTION_INPUT_INVALID", {}, "method")' in ca_method
    esim = function_body(source, "handle_api_esim")
    assert esim.index("reject_oversized_body(req)") < esim.index("check_auth_strict(req)")
    assert esim.index("check_auth_strict(req)") < esim.index("req->method != HTTP_GET")
    assert esim.index("req->method != HTTP_GET") < esim.index("check_csrf(req)")
    assert 'httpd_resp_set_hdr(req, "Allow", "GET, POST")' in esim
    assert "ACTION_ESIM_HANDLE_STALE" in esim
    assert 'json_prop(body, "displayId", "••••")' in source
    assert "idf_esim_list_profiles(current" in source
    restart = function_body(source, "handle_reboot")
    assert restart.index("reject_oversized_body(req)") < restart.index("check_auth(req)")
    assert restart.index("check_auth(req)") < restart.index("req->method != HTTP_POST")
    assert restart.index("req->method != HTTP_POST") < restart.index("check_csrf(req)")
    assert restart.index("check_csrf(req)") < restart.index("req->content_len != 0")
    assert 'httpd_resp_set_hdr(req, "Allow", "POST")' in restart
    assert "ACTION_DEVICE_RESTARTING" in restart
    assert 'httpd_resp_set_status(req, "200 OK")' in restart
    assert "claim_restart_owner()" in restart
    assert "idf_web_ota_restart_pending()" in restart
    assert 'schedule_restart_or_now("web_restart", true)' in restart
    for guard in (
        "backup_transfer_active()", "ota_active()", "restore_restart_pending()",
        "api_jobs_active()", "s_push_test_admission_active.load", "idf_push_test_active()",
    ):
        assert guard in restart
    assert 'register_handler(s_server, "/testpush"' not in source
    push_test = function_body(source, "handle_test_push")
    assert push_test.index("reject_oversized_body(req)") < push_test.index("check_auth(req)")
    assert push_test.index("check_auth(req)") < push_test.index("req->method != HTTP_GET")
    assert push_test.index("req->method != HTTP_GET") < push_test.index("check_csrf(req)")
    assert push_test.index("check_csrf(req)") < push_test.index("req->content_len != 0")
    assert push_test.index("idf_push_test_channel_active") < push_test.index("api_jobs_active()")
    assert "push_test_parse_query(req, channel, include_cleanup)" in push_test
    assert push_test.count("idf_push_test_status_json(channel, include_cleanup)") == 3
    assert "get_query_param(req, \"channel\"" not in push_test
    for guard in (
        "backup_transfer_active()", "ota_active()", "device_restart_pending()",
        "restore_restart_pending()", "api_jobs_active()",
    ):
        assert guard in push_test
    for handler in ("handle_save", "handle_config_restore_start", "handle_ota_start"):
        assert "idf_push_test_active()" in function_body(source, handler)
    assert "idf_push_test_active()" in function_body(source, "reject_restart_while_backup_active")
    assert "!idf_push_test_active()" in function_body(source, "system_idle_for_maintenance")
    claim = function_body(source, "claim_restart_owner")
    assert "compare_exchange_strong" in claim
    schedule = function_body(source, "schedule_restart_or_now")
    assert "static bool schedule_restart_or_now" in source
    assert "return false;" in schedule
    assert "return true;" in schedule
    assert "if (!already_claimed && !claim_restart_owner()) return false;" in schedule
    assert "xTaskCreate(restart_task, task_name" in schedule
    factory = function_body(source, "handle_factory_reset")
    assert factory.index("claim_restart_owner()") < factory.index("idf_config_factory_reset()")
    assert 'schedule_restart_or_now("factory_restart", true)' in factory
    wifi = function_body(source, "handle_wifi_config")
    assert wifi.index("claim_restart_owner()") < wifi.index("idf_config_save_wifi_profile")
    assert 'schedule_restart_or_now("wifi_restart", true)' in wifi
    scheduler = function_body(source, "scheduler_task")
    for marker, end in (
        ("Free heap below threshold", "const uint32_t maintenance_now_ms"),
        ("Daily scheduled restart", "vTaskDelay(pdMS_TO_TICKS(5000))"),
    ):
        guarded_restart = scheduler.split(marker, 1)[1].split(end, 1)[0]
        assert "s_device_restart_pending.compare_exchange_strong" in guarded_restart
        assert "system_idle_for_maintenance" in guarded_restart
        assert "s_device_restart_pending.store(false" in guarded_restart
    export = function_body(source, "handle_config_export")
    export_post = export.split("if (req->method != HTTP_POST)", 1)[1]
    assert export_post.index("idf_push_test_active()") < export_post.index("read_body(req, body")
    for route in (
        'register_handler(s_server, "/api/config/export", HTTP_ANY, handle_config_export)',
        'register_handler(s_server, "/api/config/restore/start", HTTP_POST, handle_config_restore_start)',
        'register_handler(s_server, "/api/config/restore/chunk", HTTP_POST, handle_config_restore_chunk)',
        'register_handler(s_server, "/api/config/restore/finish", HTTP_POST, handle_config_restore_finish)',
    ):
        assert route in source
    for handler in (
        "handle_config_export", "handle_config_restore_start",
        "handle_config_restore_chunk", "handle_config_restore_finish",
        "handle_ota_start", "handle_ota_chunk", "handle_ota_finish",
    ):
        body = function_body(source, handler)
        assert body.index("check_auth(req)") < body.index("check_csrf(req)")
    ota_state = function_body(source, "handle_ota_state")
    assert ota_state.index("reject_oversized_body(req)") < ota_state.index("check_auth(req)")
    assert "check_csrf(req)" not in ota_state
    assert ota_state.index("check_auth(req)") < ota_state.index("req->content_len != 0")
    assert "idf_web_ota_get_state(&state)" in ota_state
    assert "idf_web_ota_get_public_key_sha256(public_key_sha256)" in ota_state
    assert "state.active_offset != 0x10000U && state.active_offset != 0x1F0000U" in ota_state
    for offset_check in (
        "state.pending_address != 0",
        "state.pending_address != 0x10000U",
        "state.pending_address != 0x1F0000U",
    ):
        assert offset_check in ota_state
    assert "state.pending_verify != (state.image_state == IdfWebOtaImageState::PendingVerify)" in ota_state
    for field in (
        "activeOffset", "imageState", "pendingVerify", "accepted",
        "pending", "pendingAddress", "publicKeySha256",
    ):
        assert f'\\"{field}\\"' in ota_state
    assert "crypto_job ? 8192 : 6144" in source
    assert "uxTaskGetStackHighWaterMark(nullptr)" in source
    assert "uint8_t chunk[8192]" not in source
    assert source.count("reject_restart_while_backup_active(req)") == 2
    snapshot = function_body(source, "handle_api_config")
    for redacted in ("smtpPass", "password", "url", "key1", "key2", "customBody"):
        assert f'json_prop(body, "{redacted}", "")' in snapshot
    for secret in (
        "cfg.smtpPass", "cfg.webPass", "channel.url", "channel.key1",
        "channel.key2", "channel.customBody",
    ):
        assert secret not in snapshot
    for flag in ("pushUrlSet", "pushKey1Set", "pushKey2Set", "pushCustomBodySet"):
        assert flag in snapshot
    for flag in ("cfg.emailEnabled", "cfg.pushEnabled"):
        assert flag in snapshot
    assert 'json_prop(body, "forwardRules", cfg.forwardRules)' in snapshot

    scheduler = function_body(source, "scheduler_task")
    assert "idf_push_heartbeat_tick();" in scheduler
    assert "hb_last_day" not in scheduler
    assert "cfg.hbEnabled" not in scheduler
    assert "system_idle_for_maintenance())" in scheduler
    assert "system_idle_for_maintenance(true)" in scheduler
    assert "restore_restart_due(maintenance_now_ms)" in scheduler
    assert 'system_idle_for_maintenance(false, true, true)' in scheduler
    assert 'restore_restart_due(maintenance_now_ms) && claim_restart_owner()' in scheduler
    assert 'if (schedule_restart_or_now("restore_restart", true))' in scheduler
    assert "s_restore_restart_pending.store(false" in scheduler
    restore_restart = scheduler.split("if (restore_restart_due(maintenance_now_ms)", 1)[1].split(
        "uint32_t now", 1)[0]
    assert restore_restart.index("claim_restart_owner()") < restore_restart.index(
        "system_idle_for_maintenance(false, true, true)")
    assert restore_restart.index("system_idle_for_maintenance(false, true, true)") < restore_restart.index(
        'schedule_restart_or_now("restore_restart", true)')
    assert restore_restart.count("release_restart_owner()") == 2
    maintenance = function_body(source, "system_idle_for_maintenance")
    cellular = function_body(source, "cellular_job_active_locked")
    assert "static bool cellular_job_active_locked(bool allow_device_restart = false," in source
    assert "bool allow_current_ota = false);" in source
    assert "(!allow_device_restart && s_device_restart_pending.load" in cellular
    assert "idf_web_ota_restart_pending()" in cellular
    assert "const bool ota_busy = ota_active();" in cellular
    assert "(!allow_current_ota && ota_busy)" in cellular
    assert "s_keepalive_job.running" in cellular
    assert "s_esim_job.running" in cellular
    assert "cellular_job_active(allow_device_restart)" in maintenance
    assert "(!allow_device_restart && s_device_restart_pending.load" in maintenance
    assert "idf_web_ota_restart_pending()" in maintenance
    assert "api_jobs_active()" in maintenance
    assert "api_jobs_visible()" in maintenance
    assert "include_done" in maintenance
    assert "backup_transfer_active()" in maintenance
    ota_chunk = function_body(source, "handle_ota_chunk")
    assert "cellular_job_active(false, true)" in ota_chunk
    assert "ota_active()" in maintenance
    assert "restore_restart_pending()" in maintenance
    restore_due = function_body(source, "restore_restart_due")
    assert "now_ms - s_restore_restart_completed_ms.load" in restore_due
    assert "API_JOB_TTL_MS" in restore_due
    enqueue = source[source.rindex("static esp_err_t enqueue_api_job("):]
    busy = enqueue[enqueue.index("if ((ota_active()") : enqueue.index("if (!s_api_job_mutex")]
    assert "if (backup_job) backup_clear_claim();" in busy
    assert "if (slot_index < 0)" in enqueue
    assert "ACTION_JOB_QUEUE_FULL" in enqueue
    restore_start = function_body(source, "handle_config_restore_start")
    assert "restore_restart_pending()" in restore_start
    restart_guard = function_body(source, "reject_restart_while_backup_active")
    assert "api_jobs_active()" in restart_guard
    assert "ota_active()" in restart_guard
    assert "restore_restart_pending()" in restart_guard
    assert "system_idle_for_maintenance(true)" in source

    query = function_body(source, "run_query_job")
    assert '"sinr"' not in query
    assert '"connected"' not in query
    for key in ("wifiStatus", "rssiDbm", "gateway", "netmask", "dns", "mac", "bssid", "channel"):
        assert key in query

    auth = function_body(source, "check_auth")
    assert "request_is_on_ap_interface(req)" in auth
    ap_csrf = function_body(source, "check_csrf")
    assert '"X-SMS-CSRF"' in ap_csrf
    assert 'idf_wifi_is_ap_mode()' in ap_csrf
    assert "idf_web_ap_csrf_bypass(true, ap_local, req->uri, ap_token)" in ap_csrf

    for handler in ("handle_at", "handle_flight", "handle_modem_api", "handle_wifi"):
        body = function_body(source, handler)
        assert body.index("check_auth(req)") < body.index("check_csrf(req)")
    for handler in ("handle_at", "handle_flight", "handle_modem_api"):
        assert "enqueue_api_job" in function_body(source, handler)
    assert "check_csrf(req)" not in function_body(source, "handle_query")
    modern_save = function_body(source, "handle_modern_save")
    save_family = function_body(source, "modern_save_field_family")
    save = function_body(source, "handle_save")
    run_save = function_body(source, "run_save_job")
    assert save.index("reject_oversized_body(req)") < save.index("check_auth(req)")
    assert 'enqueue_api_job(req, "save", body)' in save
    assert re.search(r"idf_web_decode_form\(body,\s*51\)", run_save)
    assert re.search(r"idf_web_decode_form\(body,\s*51\)", save)
    assert "idf_config_get()" not in source
    assert "idf_config_save_accounts(accounts, true)" in modern_save
    assert 'key == "emailEnabled"' in save_family
    assert 'key == "pushEnabled"' in save_family
    assert 'key == "forwardRules"' in save_family
    save_limits = function_body(source, "modern_field_limit")
    assert re.search(r'key == "forwardRules"\)\s+return MAX_FORWARD_RULES_BYTES;', save_limits)
    assert "idf_config_save_forward_rules" in modern_save
    for field in ("emailEnabled", "pushEnabled"):
        assert f'const std::string {field} = field_text(fields, "{field}")' in modern_save
        assert f'{field} != "0" && {field} != "1"' in modern_save
    assert "idf_config_save_email(enabled," in modern_save
    assert "idf_config_save_push(enabled," in modern_save
    for api in (
        "idf_config_save_identity", "idf_config_save_notification_locale",
        "idf_config_save_network_mode", "idf_config_save_heartbeat",
    ):
        assert api in source
    assert '"account%duser", i' in modern_save
    assert '"account%dpass", i' in modern_save
    for field in (
        "deviceName", "hostname", "notificationLocale", "smtpServer", "smtpPort",
        "smtpUser", "smtpPass", "smtpSendTo", "adminPhone", "numberBlackList",
        "networkMode", "heartbeatEnable", "heartbeatInterval",
    ):
        assert f'"{field}"' in source
    api_job = function_body(source, "handle_api_job")
    assert "API_JOB_TTL_MS" in api_job
    assert "now_ms - slot.meta.completed_ms" in api_job
    restore_finish = function_body(source, "handle_config_restore_finish")
    assert 'enqueue_api_job(req, "backup_restore", passphrase, std::move(encrypted), true)' in restore_finish
    restore_job = function_body(source, "run_backup_restore_job")
    assert "backup_clear_claim()" not in restore_job
    backup_clear = function_body(source, "backup_clear_claim")
    assert "idf_web_transfer_clear(s_backup_transfer)" in backup_clear
    assert "s_api_jobs" not in backup_clear
    task = function_body(source, "api_job_task")
    assert "slot.meta.id == job.meta.id" in task
    assert "slot.meta.state = IdfWebJobState::Done" in task
    assert 'job.input.type == "backup_restore" && completion_success' in task
    assert "s_restore_restart_completed_ms.store(slot.meta.completed_ms" in task
    assert "s_restore_restart_pending.store(true" in task
    assert '"API job start id=%u restore=%u"' in task
    assert '"API job done id=%u ok=%u completed_ms=%u stack_hwm=%u"' in task
    assert '"API job completion mismatch id=%u slot_id=%u slot_state=%u"' in task
    assert '"API restore decrypt id=%u result=%u"' in restore_job
    assert '"API restore config id=%u err=%d status=%u"' in restore_job
    assert '"API job accepted id=%u restore=%u"' in source
    assert 'if (job.input.type == "backup_restore") backup_clear_claim();' in task
    assert task.index("xSemaphoreGive(s_api_job_mutex);") < task.index(
        'if (job.input.type == "backup_restore") backup_clear_claim();')
    assert '"API job lookup miss id=%u state=%u age_ms=%u expired=%u"' in api_job
    scan_lock = api_job.split("xSemaphoreTake(s_api_job_mutex, portMAX_DELAY);", 1)[1].split(
        "xSemaphoreGive(s_api_job_mutex);", 1)[0]
    assert "s_last_restore_job.job_id == id && !s_last_restore_job.lookup_logged" in scan_lock
    assert "restore_lifecycle_miss = s_last_restore_job" in scan_lock
    assert "xSemaphoreTake(s_api_job_mutex" not in api_job[api_job.index("if (!found) {"):]
    assert "struct ApiRestoreLifecycleSnapshot" in source
    for field in (
        "job_id", "phases", "decrypt_result", "config_err", "config_status",
        "done_id", "done_state", "completed_ms", "stack_hwm", "mismatch_id",
        "mismatch_state", "lookup_logged",
    ):
        assert field in source
    assert "RESTORE_PHASE_ACCEPTED" in source
    assert "RESTORE_PHASE_STARTED" in source
    assert "RESTORE_PHASE_DECRYPT" in source
    assert "RESTORE_PHASE_CONFIG" in source
    assert "RESTORE_PHASE_DONE" in source
    assert "RESTORE_PHASE_MISMATCH" in source
    assert '"API restore lifecycle miss id=%u p=%u d=%u ce=%d cs=%u di=%u ds=%u "' in api_job
    assert "s_last_restore_job = ApiRestoreLifecycleSnapshot();" in source
    log = function_body(source, "handle_empty_log")
    assert 'get_query_param(req, "cursor"' in log
    assert 'get_query_param(req, "limit"' in log
    assert "idf_web_paginate_log_json" in log
    assert "parsed > 50" in log
    sendsms = function_body(source, "handle_send_sms")
    assert sendsms.index("reject_oversized_body(req)") < sendsms.index("check_auth(req)")
    assert 'enqueue_api_job(req, "sms", raw)' in sendsms
    ping = function_body(source, "handle_ping")
    assert ping.index("reject_oversized_body(req)") < ping.index("check_auth(req)")
    assert 'enqueue_api_job(req, "ping", "")' in ping
    wifi = function_body(source, "handle_wifi")
    assert 'enqueue_api_job(req, "wifi", action)' in wifi
    wifi_scan = function_body(source, "handle_wifi_scan")
    assert 'get_query_param(req, "poll"' in wifi_scan
    assert '"X-WiFi-Scan-Busy"' in wifi_scan
    assert '"X-WiFi-Scan-Ready"' in wifi_scan
    wifi_config = function_body(source, "handle_wifi_config")
    assert wifi_config.index("reject_oversized_body(req)") < wifi_config.index("check_auth(req)")
    assert "connect_err = idf_wifi_provision_connect" in wifi_config
    assert wifi_config.index("idf_config_save_wifi") < wifi_config.index("idf_wifi_provision_connect")
    assert '"400 Bad Request"' in wifi_config
    assert '"409 Conflict"' in wifi_config
    assert '"500 Internal Server Error"' in wifi_config

    restore_start = function_body(source, "handle_config_restore_start")
    assert "backup_transfer_active()" in restore_start

    web_start = function_body(source, "idf_web_start")
    scheduler = web_start[web_start.index("if (!s_scheduler_started)"):]
    assert "httpd_stop(s_server);" in scheduler
    assert "s_server = nullptr;" in scheduler
    assert "return ESP_ERR_NO_MEM;" in scheduler
    assert scheduler.index("httpd_stop(s_server);") < scheduler.index("return ESP_ERR_NO_MEM;")

    assert "static bool keepalive_traffic_preflight" in source
    keepalive = function_body(source, "keepalive_task")
    assert keepalive.index("keepalive_traffic_preflight") < keepalive.index("keepalive_prepare_esim")
    traffic_preflight = function_body(source, "keepalive_traffic_preflight")
    assert "IDF_MODEM_KEEPALIVE_MAX_RUNTIME_KB" in traffic_preflight
    assert "cfg.kaTrafficKB > static_cast<int>(IDF_MODEM_KEEPALIVE_MAX_RUNTIME_KB)" in traffic_preflight
    assert "Keepalive traffic exceeds the safe 512 KB UART runtime limit" in traffic_preflight

    keepalive = function_body(source, "keepalive_task")
    assert "idf_modem_cellular_http_get" in keepalive
    assert "enqueue_maintenance_notice" in keepalive

    sched_action = function_body(source, "sched_run_action")
    assert "idf_modem_cellular_http_get" not in sched_action
    assert "Cellular HTTP scheduled tasks are not supported" in sched_action
    scheduler = function_body(source, "scheduler_task")
    assert "t.action == 1" in scheduler
    assert scheduler.index("t.action == 1") < scheduler.index("start_sched_job")
    assert "if (cfg.kaEnabled && !epoch_valid(cfg.kaLastTime))" in scheduler
    for ka_enabled, ka_action, ka_last_valid, expected_writes in (
        (True, 1, False, ["keepalive-last"]),
        (True, 1, True, []),
        (True, 2, False, ["keepalive-last"]),
        (False, 1, False, []),
    ):
        assert scheduler_keepalive_baseline_model(ka_enabled, ka_action, ka_last_valid) == expected_writes
    assert restore_restart_idle_model(True, False, False, True)
    assert not restore_restart_idle_model(True, True, False, True)
    assert not restore_restart_idle_model(True, False, True, True)
    assert not restore_restart_idle_model(True, False, False, False)
    sched_worker = function_body(source, "sched_task_worker")
    assert "epoch_valid(now) && t.action != 1" in sched_worker
    assert sched_worker.index("if (t.action == 1)") < sched_worker.index("esim_prepare_profile")
    assert "t.action != 1 && (t.action != 0 || !ok)" in sched_worker
    assert sched_worker.index("t.action != 1 && (t.action != 0 || !ok)") < sched_worker.index(
        "enqueue_maintenance_notice"
    )
    sched_handler = function_body(source, "handle_schedtask")
    assert "run_cfg.valid && run_cfg.task.action == 1" in sched_handler
    assert sched_handler.index("run_cfg.valid && run_cfg.task.action == 1") < sched_handler.index("start_sched_job")
    keepalive_handler = function_body(source, "handle_keepalive")
    keepalive_reset = keepalive_handler.split('if (action == "reset")', 1)[1].split(
        'if (action == "run")', 1
    )[0]
    assert keepalive_reset.index("now < 1700000000u") < keepalive_reset.index(
        "idf_config_set_keepalive_last"
    )
    sched_reset = sched_handler.split('if (action == "reset")', 1)[1].split(
        "std::string message;", 1
    )[0]
    assert "IdfSchedRunView reset_cfg = idf_config_get_sched_run_view(index);" in sched_reset
    assert "reset_cfg.valid && reset_cfg.task.action == 1" in sched_reset
    assert sched_reset.index("reset_cfg.valid && reset_cfg.task.action == 1") < sched_reset.index(
        "idf_config_set_sched_last"
    )

    ping_job = function_body(source, "run_ping_job")
    assert "ACTION_PING_UNSUPPORTED" in ping_job
    for forbidden in ("idf_modem_send_at", "AT+CGACT", "AT+MPING"):
        assert forbidden not in ping_job
    needs_modem = function_body(source, "api_job_task").split("const bool needs_modem", 1)[1].split(";", 1)[0]
    assert 'job.input.type == "ping"' not in needs_modem


if __name__ == "__main__":
    main()
