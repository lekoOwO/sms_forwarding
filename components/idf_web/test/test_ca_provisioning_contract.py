#!/usr/bin/env python3
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
WEB = (ROOT / "components/idf_web/idf_web.cpp").read_text()
PUSH = (ROOT / "components/idf_push/idf_push_ca.cpp").read_text()
MODEM = (ROOT / "components/idf_modem/idf_modem_https.cpp").read_text()


def body(source: str, name: str, next_name: str) -> str:
    return source.split(f"static esp_err_t {name}", 1)[1].split(
        f"static {next_name}", 1
    )[0]


for route, method in (
    ("/api/push/ca/probe", "HTTP_ANY"),
    ("/api/push/ca/install", "HTTP_ANY"),
    ("/api/push/ca/status", "HTTP_ANY"),
):
    assert f'register_handler(s_server, "{route}", {method}' in WEB

probe = body(WEB, "handle_push_ca_probe", "bool exact_pkix_content_type")
assert probe.index("check_auth(req)") < probe.index("check_csrf(req)")
assert probe.index('ca_require_method(req, HTTP_POST, "POST")') < probe.index("check_csrf(req)")
assert "ca_has_transfer_encoding(req)" in probe
assert "ca_parse_query(req, false, channel, nullptr)" in probe
assert "req->content_len != 0" in probe
assert 'enqueue_api_job(req, "push_ca_probe"' in probe

install = body(WEB, "handle_push_ca_install", "esp_err_t handle_push_ca_status")
assert install.index("check_auth(req)") < install.index("check_csrf(req)")
assert install.index('ca_require_method(req, HTTP_POST, "POST")') < install.index("check_csrf(req)")
assert "ca_parse_query(req, true, channel, &nonce)" in install
assert "ca_has_transfer_encoding(req)" in install
assert "ca_content_length_matches(req)" in install
assert "IDF_CONFIG_CA_MAX_DER_BYTES" in install
assert '"application/pkix-cert"' in WEB
assert 'enqueue_api_job(req, "push_ca_install"' in install

status = body(WEB, "handle_push_ca_status", "bool cell_job_lock")
assert "check_csrf(req)" not in status
assert status.index("check_auth(req)") < status.index('ca_require_method(req, HTTP_GET, "GET")')
assert "ca_has_transfer_encoding(req)" in status
assert "ca_parse_query(req, false, channel, nullptr)" in status

method_guard = body(WEB, "send_ca_method_error", "bool ca_require_method")
assert 'httpd_resp_set_status(req, "405 Method Not Allowed")' in method_guard
assert 'httpd_resp_set_hdr(req, "Allow", allow)' in method_guard
assert 'action_result(false, "ACTION_INPUT_INVALID", {}, "method")' in method_guard

for key in ("cellularEnabled", "cellularUrl", "cellularUrlClear"):
    assert key in WEB
assert 'value != "0" && value != "1"' in WEB
assert "cellular_clear && !cellular_url.empty()" in WEB
assert 'json_prop(body, "cellularUrl"' not in WEB
assert '\\"cellularUrlSet\\"' in WEB

probe_job = WEB.split("static std::string run_push_ca_probe_job", 1)[1].split(
    "static std::string run_push_ca_install_job", 1
)[0]
assert "result.size() <= 1800" in probe_job
for field in ("nonce", "expiresInMs", "chain", "certSha256", "issuerDer", "aki"):
    assert f'\\"{field}\\"' in probe_job
for forbidden in ('"origin"', '"hostname"', '"certificateDer"'):
    assert forbidden not in probe_job

assert "clear_session(sessions[channel])" in PUSH
assert "retained.nonce != nonce" in PUSH
assert "retained = {}" in PUSH
assert PUSH.count("session.generation != idf_config_generation()") >= 2
for requirement in (
    "IDF_PUSH_CA_ALLOWLIST", "mbedtls_x509_crt_get_ca_istrue",
    "mbedtls_x509_crt_check_key_usage",
    "MBEDTLS_X509_KU_KEY_CERT_SIGN", "mbedtls_x509_time_is_future",
    "mbedtls_x509_time_is_past", "mbedtls_x509_crt_verify_with_profile",
    "session.hostname.c_str()",
):
    assert requirement in PUSH

for requirement in (
    "mbedtls_x509_crt_parse_der",
    "mbedtls_ssl_conf_ca_chain",
    "mbedtls_ssl_set_hostname",
    "MBEDTLS_SSL_VERIFY_REQUIRED",
):
    assert requirement in MODEM

for forbidden in (
    "AT+MSSLLIST=",
    "AT+MSSLCERTWR",
    "AT+MSSLCERTRD",
    'AT+MSSLCFG=\"cert\"',
    'AT+MSSLCFG=\"ignoreverify\"',
):
    assert forbidden not in MODEM
