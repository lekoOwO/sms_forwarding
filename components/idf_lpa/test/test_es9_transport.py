import subprocess
import tempfile
import unittest
from pathlib import Path


COMPONENT = Path(__file__).resolve().parents[1]
HEADER = COMPONENT / "include" / "idf_lpa_es9_transport.h"
SOURCE = COMPONENT / "idf_lpa_es9_transport.cpp"


ESP_ERR_H = r'''
#pragma once
using esp_err_t = int;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_NO_MEM 0x103
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_TIMEOUT 0x105
#define ESP_ERR_HTTP_EAGAIN 0x7007
#define ESP_ERR_HTTP_WRITE_DATA 0x7003
#define ESP_ERR_HTTP_FETCH_HEADER 0x7004
#define ESP_ERR_HTTP_INCOMPLETE_DATA 0x700c
'''


HTTP_CLIENT_H = r'''
#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

typedef struct FakeClient* esp_http_client_handle_t;

enum esp_http_client_event_id_t {
    HTTP_EVENT_ERROR = 0,
    HTTP_EVENT_ON_CONNECTED,
    HTTP_EVENT_HEADERS_SENT,
    HTTP_EVENT_ON_HEADER,
    HTTP_EVENT_ON_HEADERS_COMPLETE,
    HTTP_EVENT_ON_STATUS_CODE,
    HTTP_EVENT_ON_DATA,
    HTTP_EVENT_ON_FINISH,
    HTTP_EVENT_DISCONNECTED,
    HTTP_EVENT_REDIRECT,
};

typedef struct esp_http_client_event {
    esp_http_client_event_id_t event_id;
    esp_http_client_handle_t client;
    void* data;
    int data_len;
    void* user_data;
    char* header_key;
    char* header_value;
} esp_http_client_event_t;

typedef esp_err_t (*http_event_handle_cb)(esp_http_client_event_t* event);

enum esp_http_client_method_t {
    HTTP_METHOD_GET = 0,
    HTTP_METHOD_POST = 1,
};

typedef struct esp_http_client_config {
    const char* url;
    const char* user_agent;
    int timeout_ms;
    bool disable_auto_redirect;
    int max_redirection_count;
    int max_authorization_retries;
    bool keep_alive_enable;
    bool skip_cert_common_name_check;
    bool is_async;
    int buffer_size;
    int buffer_size_tx;
    esp_http_client_method_t method;
    esp_err_t (*crt_bundle_attach)(void*);
    http_event_handle_cb event_handler;
    void* user_data;
} esp_http_client_config_t;

#ifdef __cplusplus
extern "C" {
#endif
esp_http_client_handle_t esp_http_client_init(const esp_http_client_config_t* config);
esp_err_t esp_http_client_set_method(esp_http_client_handle_t client,
                                     esp_http_client_method_t method);
esp_err_t esp_http_client_set_header(esp_http_client_handle_t client,
                                     const char* key, const char* value);
esp_err_t esp_http_client_set_timeout_ms(esp_http_client_handle_t client, int timeout_ms);
esp_err_t esp_http_client_open(esp_http_client_handle_t client, int write_len);
int esp_http_client_write(esp_http_client_handle_t client, const char* buffer, int len);
int64_t esp_http_client_fetch_headers(esp_http_client_handle_t client);
int esp_http_client_read(esp_http_client_handle_t client, char* buffer, int len);
int esp_http_client_get_status_code(esp_http_client_handle_t client);
esp_err_t esp_http_client_close(esp_http_client_handle_t client);
esp_err_t esp_http_client_cleanup(esp_http_client_handle_t client);
bool esp_http_client_is_complete_data_received(esp_http_client_handle_t client);
#ifdef __cplusplus
}
#endif
'''


FAKE_CPP = r'''
#include "idf_lpa_es9_transport.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>

#include "esp_crt_bundle.h"
#include "esp_http_client.h"

enum class Scenario {
    success,
    notify_success,
    missing_protocol,
    duplicate_protocol,
    wrong_status,
    redirect,
    notify_body,
    oversized,
    open_eagain,
    open_header_eagain,
    write_eagain,
    write_zero_permanent,
    write_short,
    fetch_eagain,
    read_eagain,
    read_failure,
    timeout_open,
    init_failure,
    config_failure,
};

struct FakeClient {};

struct FakeState {
    Scenario scenario = Scenario::success;
    FakeClient client;
    esp_http_client_config_t config = {};
    std::string url;
    std::string user_agent;
    std::string protocol = "gsma/rsp/v2.6.0";
    std::string request;
    std::string response = R"({"ok":true})";
    std::array<std::string, 2> header_keys = {};
    std::array<std::string, 2> header_values = {};
    int init_calls = 0;
    int method_calls = 0;
    int header_calls = 0;
    int timeout_calls = 0;
    int open_calls = 0;
    int write_calls = 0;
    int fetch_calls = 0;
    int read_calls = 0;
    int close_calls = 0;
    int cleanup_calls = 0;
    int delay_calls = 0;
    int status = 200;
    int64_t content_length = 0;
    size_t response_offset = 0;
    bool opened = false;
    bool complete = false;
    bool headers_sent = false;
    int64_t now_us = 0;
    int64_t now_step_us = 1000;
};

FakeState g;

static void reset(Scenario scenario, const char* protocol = "gsma/rsp/v2.6.0")
{
    g = {};
    g.scenario = scenario;
    g.protocol = protocol;
    g.response = R"({"ok":true})";
    g.status = scenario == Scenario::notify_success || scenario == Scenario::notify_body ? 204 : 200;
    if (scenario == Scenario::wrong_status) g.status = 500;
    if (scenario == Scenario::redirect) g.status = 302;
    if (scenario == Scenario::notify_success) g.response.clear();
    g.content_length = scenario == Scenario::notify_body ? 1 : 0;
    if (scenario == Scenario::oversized) {
        g.content_length = static_cast<int64_t>(IDF_LPA_ES9_MAX_JSON_BYTES + 1U);
    }
    if (scenario == Scenario::timeout_open) g.now_step_us = 30000000;
}

static void emit(int id, void* data = nullptr, int length = 0,
                 char* key = nullptr, char* value = nullptr)
{
    esp_http_client_event_t event = {};
    event.event_id = static_cast<esp_http_client_event_id_t>(id);
    event.client = &g.client;
    event.data = data;
    event.data_len = length;
    event.user_data = g.config.user_data;
    event.header_key = key;
    event.header_value = value;
    assert(g.config.event_handler);
    assert(g.config.event_handler(&event) == ESP_OK);
}

extern "C" int64_t esp_timer_get_time()
{
    const int64_t value = g.now_us;
    g.now_us += g.now_step_us;
    return value;
}

extern "C" void vTaskDelay(unsigned int ticks)
{
    ++g.delay_calls;
    g.now_us += static_cast<int64_t>(ticks) * 1000;
}

extern "C" esp_err_t esp_crt_bundle_attach(void*)
{
    return ESP_OK;
}

extern "C" esp_http_client_handle_t esp_http_client_init(
    const esp_http_client_config_t* config)
{
    ++g.init_calls;
    assert(config);
    g.config = *config;
    g.url = config->url ? config->url : "";
    g.user_agent = config->user_agent ? config->user_agent : "";
    if (g.scenario == Scenario::init_failure) return nullptr;
    return &g.client;
}

extern "C" esp_err_t esp_http_client_set_method(esp_http_client_handle_t, esp_http_client_method_t method)
{
    ++g.method_calls;
    assert(method == HTTP_METHOD_POST);
    return g.scenario == Scenario::config_failure ? ESP_FAIL : ESP_OK;
}

extern "C" esp_err_t esp_http_client_set_header(esp_http_client_handle_t,
                                                  const char* key, const char* value)
{
    ++g.header_calls;
    assert(key && value);
    assert(g.header_calls <= static_cast<int>(g.header_keys.size()));
    g.header_keys[static_cast<size_t>(g.header_calls - 1)] = key;
    g.header_values[static_cast<size_t>(g.header_calls - 1)] = value;
    return g.scenario == Scenario::config_failure ? ESP_FAIL : ESP_OK;
}

extern "C" esp_err_t esp_http_client_set_timeout_ms(esp_http_client_handle_t,
                                                      int timeout_ms)
{
    ++g.timeout_calls;
    assert(timeout_ms > 0 && timeout_ms <= 15000);
    return g.scenario == Scenario::config_failure ? ESP_FAIL : ESP_OK;
}

extern "C" esp_err_t esp_http_client_open(esp_http_client_handle_t,
                                            int write_len)
{
    ++g.open_calls;
    assert(write_len > 0);
    if (g.scenario == Scenario::timeout_open) return ESP_ERR_HTTP_EAGAIN;
    if (g.scenario == Scenario::open_header_eagain && g.open_calls == 1) {
        emit(HTTP_EVENT_ON_CONNECTED);
        return ESP_ERR_HTTP_EAGAIN;
    }
    if (g.scenario == Scenario::open_eagain && g.open_calls < 3) {
        return ESP_ERR_HTTP_EAGAIN;
    }
    g.opened = true;
    return ESP_OK;
}

extern "C" int esp_http_client_write(esp_http_client_handle_t,
                                      const char* buffer, int length)
{
    ++g.write_calls;
    assert(buffer && length > 0);
    if (g.scenario == Scenario::write_eagain && g.write_calls < 3) {
        return -ESP_ERR_HTTP_EAGAIN;
    }
    if (g.scenario == Scenario::write_zero_permanent) return 0;
    if (g.scenario == Scenario::write_short && g.write_calls == 1) {
        g.request.append(buffer, static_cast<size_t>(length / 2));
        return length / 2;
    }
    g.request.append(buffer, static_cast<size_t>(length));
    return length;
}

extern "C" int64_t esp_http_client_fetch_headers(esp_http_client_handle_t)
{
    ++g.fetch_calls;
    if (g.scenario == Scenario::fetch_eagain && g.fetch_calls < 3) {
        return -ESP_ERR_HTTP_EAGAIN;
    }
    if (g.scenario == Scenario::read_failure) return -ESP_ERR_HTTP_FETCH_HEADER;
    if (!g.headers_sent) {
        g.headers_sent = true;
        char key[] = "X-Admin-Protocol";
        if (g.scenario != Scenario::missing_protocol) {
            emit(HTTP_EVENT_ON_HEADER, nullptr, 0, key, g.protocol.data());
            if (g.scenario == Scenario::duplicate_protocol) {
                emit(HTTP_EVENT_ON_HEADER, nullptr, 0, key, g.protocol.data());
            }
        }
        if (g.scenario == Scenario::redirect) emit(HTTP_EVENT_REDIRECT);
    }
    return g.content_length;
}

extern "C" int esp_http_client_read(esp_http_client_handle_t,
                                     char* buffer, int length)
{
    ++g.read_calls;
    assert(buffer && length > 0);
    if (g.scenario == Scenario::read_eagain && g.read_calls < 3) {
        return -ESP_ERR_HTTP_EAGAIN;
    }
    if (g.scenario == Scenario::read_failure) return -ESP_FAIL;
    if (g.scenario == Scenario::notify_body) {
        char body = 'x';
        emit(HTTP_EVENT_ON_DATA, &body, 1);
        g.complete = true;
        return 1;
    }
    if (g.scenario == Scenario::oversized) {
        static char chunk = 'x';
        emit(HTTP_EVENT_ON_DATA, &chunk, static_cast<int>(IDF_LPA_ES9_MAX_JSON_BYTES + 1U));
        g.complete = true;
        return static_cast<int>(IDF_LPA_ES9_MAX_JSON_BYTES + 1U);
    }
    if (g.response_offset == 0U && !g.response.empty()) {
        const size_t count = std::min<size_t>(g.response.size(), static_cast<size_t>(length));
        emit(HTTP_EVENT_ON_DATA, g.response.data(), static_cast<int>(count));
        std::memcpy(buffer, g.response.data(), count);
        g.response_offset = count;
        if (g.response_offset == g.response.size()) g.complete = true;
        return static_cast<int>(count);
    }
    g.complete = true;
    return 0;
}

extern "C" int esp_http_client_get_status_code(esp_http_client_handle_t)
{
    return g.status;
}

extern "C" esp_err_t esp_http_client_close(esp_http_client_handle_t)
{
    ++g.close_calls;
    return ESP_OK;
}

extern "C" esp_err_t esp_http_client_cleanup(esp_http_client_handle_t)
{
    ++g.cleanup_calls;
    return ESP_OK;
}

extern "C" bool esp_http_client_is_complete_data_received(esp_http_client_handle_t)
{
    return g.complete;
}

static void assert_cleaned()
{
    assert(g.close_calls == 1);
    assert(g.cleanup_calls == 1);
}

static void assert_rejected(Scenario scenario, IdfLpaEs9Operation operation,
                            IdfLpaEs9TransportError expected,
                            const char* protocol = "gsma/rsp/v2.6.0")
{
    reset(scenario, protocol);
    std::string response = "server-secret";
    IdfLpaEs9TransportError error = IdfLpaEs9TransportError::none;
    assert(!idf_lpa_es9_post_json(operation, "edge.example", R"({"request":true})",
                                  response, error));
    assert(response.empty());
    assert(error == expected);
    if (scenario == Scenario::init_failure) {
        assert(g.close_calls == 0 && g.cleanup_calls == 0);
    } else {
        assert_cleaned();
    }
    assert(std::string(idf_lpa_es9_transport_error_name(error)).find("server-secret") ==
           std::string::npos);
}

int main()
{
    reset(Scenario::success);
    std::string response;
    IdfLpaEs9TransportError error = IdfLpaEs9TransportError::unknown;
    assert(idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                 "edge.example", R"({"request":true})", response, error));
    assert(response == R"({"ok":true})");
    assert(error == IdfLpaEs9TransportError::none);
    assert(g.url == "https://edge.example/gsma/rsp2/es9plus/initiateAuthentication");
    assert(g.config.disable_auto_redirect && !g.config.keep_alive_enable);
    assert(!g.config.skip_cert_common_name_check && g.config.crt_bundle_attach);
    assert(g.config.is_async && g.config.timeout_ms == 15000);
    assert(g.config.method == HTTP_METHOD_POST && g.method_calls == 1);
    assert(g.user_agent == "gsma-rsp-lpad");
    assert(g.header_calls == 2 && g.open_calls == 1 && g.close_calls == 1 &&
           g.cleanup_calls == 1);
    assert(g.header_keys[0] == "Content-Type");
    assert(g.header_values[0] == "application/json");
    assert(g.header_keys[1] == "X-Admin-Protocol");
    assert(g.header_values[1] == "gsma/rsp/v2.6.0");

    reset(Scenario::success);
    assert(idf_lpa_es9_post_json(IdfLpaEs9Operation::authenticate_client,
                                 "edge.example", R"({"request":true})", response, error));
    assert(g.url == "https://edge.example/gsma/rsp2/es9plus/authenticateClient");
    assert(g.user_agent == "gsma-rsp-lpad");

    reset(Scenario::notify_success);
    response = "stale";
    assert(idf_lpa_es9_post_json(IdfLpaEs9Operation::handle_notification,
                                 "edge.example", R"({"request":true})", response, error));
    assert(response.empty() && error == IdfLpaEs9TransportError::none);
    assert(g.url == "https://edge.example/gsma/rsp2/es9plus/handleNotification");
    assert(g.user_agent == "gsma-rsp-lpad");

    for (Scenario scenario : {Scenario::open_eagain, Scenario::write_short,
                              Scenario::fetch_eagain,
                              Scenario::read_eagain}) {
        reset(scenario);
        assert(idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                     "edge.example", R"({"request":true})", response, error));
        assert(error == IdfLpaEs9TransportError::none);
        if (scenario == Scenario::write_short) {
            assert(g.write_calls > 1);
        } else {
            assert(g.delay_calls > 0);
        }
    }
    assert_rejected(Scenario::open_header_eagain,
                    IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::transport);
    assert(g.open_calls == 1 && g.write_calls == 0 && g.delay_calls == 0);
    assert_rejected(Scenario::write_zero_permanent,
                    IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::request_write);
    assert(g.write_calls == 1 && g.delay_calls == 0 && g.request.empty());
    assert_rejected(Scenario::write_eagain,
                    IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::request_write);
    assert(g.write_calls == 1 && g.delay_calls == 0 && g.request.empty());

    assert_rejected(Scenario::missing_protocol, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::response_protocol);
    assert_rejected(Scenario::duplicate_protocol, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::response_protocol);
    for (const char* protocol : {
             "gsma/rsp/v2.0.0", "gsma/rsp/v2.6.0", "gsma/rsp/v2.12.34"}) {
        reset(Scenario::success, protocol);
        assert(idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                     "edge.example", R"({"request":true})", response, error));
        assert(error == IdfLpaEs9TransportError::none);
    }
    for (const char* protocol : {
             "http/1.1", "GSMA/rsp/v2.6.0", "gsma/rsp/v2", "gsma/rsp/v2.",
             "gsma/rsp/v2.6",
             "gsma/rsp/v2..0", "gsma/rsp/v2.6.", "gsma/rsp/v2.6.0.1",
             "gsma/rsp/v2.a.0", "gsma/rsp/v2.6,a", "gsma/rsp/v2.6.0x",
             "gsma/rsp/v2.6.0 ", "gsma/rsp/v2.6.0\n", "gsma/rsp/v2.42949672960.0",
             "gsma/rsp/v2.6.4294967296",
             "gsma/rsp/v2.123456789012345678901234567890"}) {
        assert_rejected(Scenario::success, IdfLpaEs9Operation::initiate_authentication,
                        IdfLpaEs9TransportError::response_protocol, protocol);
    }
    assert_rejected(Scenario::wrong_status, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::response_status);
    assert_rejected(Scenario::redirect, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::redirect);
    assert_rejected(Scenario::notify_body, IdfLpaEs9Operation::handle_notification,
                    IdfLpaEs9TransportError::response_body);
    assert_rejected(Scenario::oversized, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::response_too_large);
    assert_rejected(Scenario::read_failure, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::transport);
    assert_rejected(Scenario::timeout_open, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::timeout);
    assert_rejected(Scenario::config_failure, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::config);
    assert_rejected(Scenario::init_failure, IdfLpaEs9Operation::initiate_authentication,
                    IdfLpaEs9TransportError::client_init);

    reset(Scenario::success);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  "https://edge.example", R"({"request":true})", response, error));
    assert(error == IdfLpaEs9TransportError::invalid_host && g.init_calls == 0);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  "127.0.0.1", R"({"request":true})", response, error));
    assert(error == IdfLpaEs9TransportError::invalid_host && g.init_calls == 0);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  "edge", R"({"request":true})", response, error));
    assert(error == IdfLpaEs9TransportError::invalid_host && g.init_calls == 0);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  "edge.example", "", response, error));
    assert(error == IdfLpaEs9TransportError::invalid_request && g.init_calls == 0);
    std::string exact_alias = R"({"request":true})";
    reset(Scenario::success);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  "edge.example", exact_alias, exact_alias, error));
    assert(error == IdfLpaEs9TransportError::invalid_request && exact_alias.empty() &&
           g.init_calls == 0);
    std::string partial_alias = "xx{";
    partial_alias += R"("request":true})";
    partial_alias += "yy";
    const std::string_view partial_request(partial_alias.data() + 2,
                                            partial_alias.size() - 4);
    reset(Scenario::success);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  "edge.example", partial_request, partial_alias, error));
    assert(error == IdfLpaEs9TransportError::invalid_request && partial_alias.empty() &&
           g.init_calls == 0);
    std::string host_exact_alias = "edge.example";
    reset(Scenario::success);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  host_exact_alias, R"({"request":true})", host_exact_alias,
                                  error));
    assert(error == IdfLpaEs9TransportError::invalid_request && host_exact_alias.empty() &&
           g.init_calls == 0);
    std::string host_partial_alias = "xxedge.exampleyy";
    const std::string_view partial_host(host_partial_alias.data() + 2,
                                        host_partial_alias.size() - 4);
    reset(Scenario::success);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  partial_host, R"({"request":true})", host_partial_alias,
                                  error));
    assert(error == IdfLpaEs9TransportError::invalid_request && host_partial_alias.empty() &&
           g.init_calls == 0);
    std::string max_request(IDF_LPA_ES9_MAX_JSON_BYTES, 'x');
    reset(Scenario::success);
    assert(idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                 "edge.123", max_request, response, error));
    assert(g.request.size() == IDF_LPA_ES9_MAX_JSON_BYTES);
    max_request.push_back('x');
    reset(Scenario::success);
    assert(!idf_lpa_es9_post_json(IdfLpaEs9Operation::initiate_authentication,
                                  "edge.123", max_request, response, error));
    assert(error == IdfLpaEs9TransportError::invalid_request && g.init_calls == 0);
}
'''


class Es9TransportTest(unittest.TestCase):
    def test_es9_transport_host_contract(self):
        self.assertTrue(HEADER.exists(), "transport header is missing")
        self.assertTrue(SOURCE.exists(), "transport source is missing")
        self.assertRegex(
            SOURCE.read_text(),
            r"esp_http_client_handle_t client = esp_http_client_init\(&config\);\s*"
            r"if \(!client\) \{\s*secure_clear\(url\);\s*"
            r"return fail\(error, IdfLpaEs9TransportError::client_init\);",
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            include = Path(temp_dir) / "include"
            (include / "freertos").mkdir(parents=True)
            include.mkdir(exist_ok=True)
            (include / "esp_err.h").write_text(ESP_ERR_H)
            (include / "esp_http_client.h").write_text(HTTP_CLIENT_H)
            (include / "esp_crt_bundle.h").write_text(
                '#pragma once\n#include "esp_err.h"\nextern "C" esp_err_t esp_crt_bundle_attach(void*);\n'
            )
            (include / "esp_timer.h").write_text(
                '#pragma once\n#include <stdint.h>\nextern "C" int64_t esp_timer_get_time();\n'
            )
            (include / "freertos" / "FreeRTOS.h").write_text(
                '#pragma once\n#define pdMS_TO_TICKS(value) (value)\n'
            )
            (include / "freertos" / "task.h").write_text(
                '#pragma once\n#ifdef __cplusplus\nextern "C" {\n#endif\nvoid vTaskDelay(unsigned int ticks);\n#ifdef __cplusplus\n}\n#endif\n'
            )
            (include / "esp_tls_errors.h").write_text(
                '#pragma once\n#define ESP_TLS_ERR_SSL_WANT_READ 0x7001\n#define ESP_TLS_ERR_SSL_WANT_WRITE 0x7002\n'
            )
            harness = Path(temp_dir) / "es9_transport_fixture.cpp"
            binary = Path(temp_dir) / "es9_transport_fixture"
            harness.write_text(FAKE_CPP)
            result = subprocess.run(
                [
                    "g++", "-std=c++17", "-DESP_PLATFORM", "-fno-exceptions", "-fno-rtti",
                    "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-I", str(include), "-I", str(COMPONENT / "include"),
                    str(SOURCE), str(harness), "-o", str(binary),
                ],
                check=False, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True, timeout=30,
            )
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
