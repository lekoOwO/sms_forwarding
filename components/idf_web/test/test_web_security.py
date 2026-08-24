#!/usr/bin/env python3
import subprocess
import tempfile
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "components/idf_web"


def scheduler_keepalive_baseline_model(ka_enabled, ka_action, ka_last_valid):
    """Model the scheduler's baseline write branch for a small executable matrix."""
    writes = []
    if ka_enabled and ka_action != 1 and not ka_last_valid:
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


def run_guard_seam(source: str, mutate_idle=None):
    cellular_locked = definition_body(source, "static bool cellular_job_active_locked(bool allow_device_restart)")
    cellular_active = definition_body(source, "static bool cellular_job_active(bool allow_device_restart)")
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
static WebAsyncJob s_keepalive_job;
static WebAsyncJob s_esim_job;
static WebAsyncJob s_sched_job;
static bool s_modem_apply_running = false;
static bool s_web_modem_action_running = false;

static bool g_lock_available = true;
static bool g_backup_transfer = false;
static bool g_ota_active = false;
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
static bool ota_active() {{ return g_ota_active; }}
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

static bool cellular_job_active_locked(bool allow_device_restart)
{{{cellular_locked}}}

static bool cellular_job_active(bool allow_device_restart)
{{{cellular_active}}}

static bool system_idle_for_maintenance(bool include_done = false,
                                         bool allow_restore_restart = false,
                                         bool allow_device_restart = false)
{{{idle}}}

static void reset_state()
{{
    g_lock_available = true;
    g_backup_transfer = false;
    g_ota_active = false;
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

int main()
{{
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

    source = (WEB / "idf_web.cpp").read_text()
    assert run_guard_seam(source).returncode == 0
    mutated_guard = run_guard_seam(source, lambda body: body.replace(
        "!s_push_test_admission_active.load(std::memory_order_acquire) &&", "true &&", 1))
    assert mutated_guard.returncode != 0
    sdkconfig_defaults = (ROOT / "sdkconfig.defaults").read_text()
    assert "CONFIG_HTTPD_MAX_URI_LEN=2048" in sdkconfig_defaults
    assert "CONFIG_HTTPD_MAX_REQ_HDR_LEN=8192" in sdkconfig_defaults
    assert "CONFIG_BOOTLOADER_APP_ROLLBACK_ENABLE=y" in sdkconfig_defaults
    assert '"X-CSRF-Token"' in source
    assert source.count('"X-SMS-CSRF"') == 1
    assert "colon == decoded_text" in source
    assert 'register_handler(s_server, "/api/config", HTTP_GET, handle_api_config)' in source
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
        "/", "/tools", "/sms", "/assets/*", "/api/config", "/api/jobs", "/query", "/save", "/wifi",
        "/wifiscan", "/wificonfig", "/apstatus", "/log", "/at", "/ping", "/flight",
        "/modem", "/sendsms", "/api/config/export", "/api/config/restore/start",
        "/api/config/restore/chunk", "/api/config/restore/finish", "/api/ota/start",
        "/api/ota/chunk", "/api/ota/finish", "/api/push/test", "/api/device/restart", "/*",
    }
    assert 'register_handler(s_server, "/ping", HTTP_POST, handle_ping)' in source
    assert 'register_handler(s_server, "/api/push/test", HTTP_ANY, handle_test_push)' in source
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
    assert "static bool cellular_job_active_locked(bool allow_device_restart)" in source
    assert "(!allow_device_restart && s_device_restart_pending.load" in cellular
    assert "idf_web_ota_restart_pending()" in cellular
    assert "s_keepalive_job.running" in cellular
    assert "s_esim_job.running" in cellular
    assert "cellular_job_active(allow_device_restart)" in maintenance
    assert "(!allow_device_restart && s_device_restart_pending.load" in maintenance
    assert "idf_web_ota_restart_pending()" in maintenance
    assert "api_jobs_active()" in maintenance
    assert "api_jobs_visible()" in maintenance
    assert "include_done" in maintenance
    assert "backup_transfer_active()" in maintenance
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
    assert 'enqueue_api_job(req, "backup_restore", passphrase, std::move(encrypted))' in restore_finish
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
    unsupported_keepalive = keepalive[keepalive.index("if (cfg.kaAction == 1)"):]
    assert "Cellular HTTP keepalive is not supported" in unsupported_keepalive
    assert unsupported_keepalive.index("Cellular HTTP keepalive is not supported") < unsupported_keepalive.index("keepalive_prepare_esim")
    assert "idf_modem_cellular_http_get" not in keepalive

    sched_action = function_body(source, "sched_run_action")
    assert "idf_modem_cellular_http_get" not in sched_action
    assert "Cellular HTTP scheduled tasks are not supported" in sched_action
    scheduler = function_body(source, "scheduler_task")
    assert "t.action == 1" in scheduler
    assert scheduler.index("t.action == 1") < scheduler.index("start_sched_job")
    assert "cfg.kaAction != 1" in scheduler
    assert "if (cfg.kaEnabled && cfg.kaAction != 1 && !epoch_valid(cfg.kaLastTime))" in scheduler
    for ka_enabled, ka_action, ka_last_valid, expected_writes in (
        (True, 1, False, []),
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
    assert "IdfKeepaliveRunView reset_cfg = idf_config_get_keepalive_run_view();" in keepalive_reset
    assert "reset_cfg.kaAction == 1" in keepalive_reset
    assert keepalive_reset.index("reset_cfg.kaAction == 1") < keepalive_reset.index(
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
