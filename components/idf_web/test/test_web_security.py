#!/usr/bin/env python3
import subprocess
import tempfile
import re
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WEB = ROOT / "components/idf_web"


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
    assert(idf_web_select_job_slot(slots, 6, 200, 1000) == 2);
    for (int i = 2; i < 6; ++i) slots[i] = {uint32_t(i + 1), IdfWebJobState::Running, 0};
    // When all six slots are occupied, finished results yield to new work even
    // before their normal TTL. Otherwise six quick reads stall the API for a minute.
    assert(idf_web_select_job_slot(slots, 6, 200, 1000) == 1);
    slots[1] = {2, IdfWebJobState::Running, 0};
    slots[4] = {5, IdfWebJobState::Done, 0xfffffff0U};
    assert(idf_web_select_job_slot(slots, 6, 0x20U, 0x20U) == 4);

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
    assert(append_transfer(transfer, 8, 0, std::vector<uint8_t>(60, 1), 8192));
    IdfWebOwnedBytes uploaded;
    assert(!idf_web_transfer_take_complete(transfer, 8, uploaded));
    assert(append_transfer(transfer, 8, 60, std::vector<uint8_t>(40, 2), 8192));
    assert(idf_web_transfer_take_complete(transfer, 8, uploaded));
    assert(uploaded.size == 100 && transfer.mode == IdfWebTransferMode::Restore);
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
    assert "handle_import_config" not in source
    assert "handle_ota_update" not in source
    registered = set(re.findall(r'register_handler\(s_server, "([^"]+)"', source))
    assert registered == {
        "/", "/tools", "/sms", "/assets/*", "/api/config", "/api/jobs", "/query", "/save", "/wifi",
        "/wifiscan", "/wificonfig", "/apstatus", "/log", "/at", "/ping", "/flight",
        "/modem", "/sendsms", "/api/config/export", "/api/config/restore/start",
        "/api/config/restore/chunk", "/api/config/restore/finish", "/api/ota/start",
        "/api/ota/chunk", "/api/ota/finish", "/*",
    }
    assert 'register_handler(s_server, "/ping", HTTP_POST, handle_ping)' in source
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
    assert source.count("reject_restart_while_backup_active(req)") == 3
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

    scheduler = function_body(source, "scheduler_task")
    assert "idf_push_heartbeat_tick();" in scheduler
    assert "hb_last_day" not in scheduler
    assert "cfg.hbEnabled" not in scheduler

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
    save = function_body(source, "handle_save")
    run_save = function_body(source, "run_save_job")
    assert save.index("reject_oversized_body(req)") < save.index("check_auth(req)")
    assert 'enqueue_api_job(req, "save", body)' in save
    assert re.search(r"idf_web_decode_form\(body,\s*51\)", run_save)
    assert re.search(r"idf_web_decode_form\(body,\s*51\)", save)
    assert "idf_config_get()" not in source
    assert "idf_config_save_accounts(accounts, true)" in modern_save
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
    assert wifi_config.index("idf_wifi_provision_connect") < wifi_config.index("idf_config_save_wifi")
    assert '"400 Bad Request"' in wifi_config
    assert '"409 Conflict"' in wifi_config
    assert '"500 Internal Server Error"' in wifi_config

    assert "static bool keepalive_traffic_preflight" in source
    keepalive = function_body(source, "keepalive_task")
    assert keepalive.index("keepalive_traffic_preflight") < keepalive.index("keepalive_prepare_esim")
    traffic_preflight = function_body(source, "keepalive_traffic_preflight")
    assert "IDF_MODEM_KEEPALIVE_MAX_RUNTIME_KB" in traffic_preflight
    assert "cfg.kaTrafficKB > static_cast<int>(IDF_MODEM_KEEPALIVE_MAX_RUNTIME_KB)" in traffic_preflight
    assert "Keepalive traffic exceeds the safe 512 KB UART runtime limit" in traffic_preflight


if __name__ == "__main__":
    main()
