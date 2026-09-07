import subprocess
import tempfile
import unittest
from pathlib import Path


COMPONENT = Path(__file__).resolve().parents[1]
HEADER = COMPONENT / "include" / "idf_lpa_es9_transport.h"
SOURCE = COMPONENT / "idf_lpa_es9_transport.cpp"
BPP_SOURCE = COMPONENT / "idf_lpa_bpp.cpp"


ESP_ERR_H = r'''
#pragma once
using esp_err_t = int;
#define ESP_OK 0
#define ESP_FAIL -1
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NO_MEM 0x103
#define ESP_ERR_INVALID_SIZE 0x104
#define ESP_ERR_INVALID_RESPONSE 0x106
#define ESP_ERR_TIMEOUT 0x105
#define ESP_ERR_HTTP_EAGAIN 0x7007
#define ESP_ERR_HTTP_WRITE_DATA 0x7003
#define ESP_ERR_HTTP_FETCH_HEADER 0x7004
#define ESP_ERR_HTTP_READ_TIMEOUT 0x700B
#define ESP_ERR_HTTP_INCOMPLETE_DATA 0x700C
#define ESP_ERR_HTTP_CONNECTION_CLOSED 0x7008
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

enum esp_http_state_t {
    HTTP_STATE_UNINIT = 0,
    HTTP_STATE_INIT,
    HTTP_STATE_CONNECTING,
    HTTP_STATE_CONNECTED,
    HTTP_STATE_REQ_COMPLETE_HEADER,
    HTTP_STATE_REQ_COMPLETE_DATA,
    HTTP_STATE_RES_COMPLETE_HEADER,
    HTTP_STATE_RES_ON_DATA_START,
    HTTP_STATE_RES_COMPLETE_DATA,
    HTTP_STATE_CLOSE,
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
esp_err_t esp_http_client_perform(esp_http_client_handle_t client);
esp_err_t esp_http_client_set_method(esp_http_client_handle_t client,
                                     esp_http_client_method_t method);
esp_err_t esp_http_client_set_header(esp_http_client_handle_t client,
                                     const char* key, const char* value);
esp_err_t esp_http_client_set_post_field(esp_http_client_handle_t client,
                                         const char* data, int len);
esp_err_t esp_http_client_set_timeout_ms(esp_http_client_handle_t client, int timeout_ms);
esp_err_t esp_http_client_open(esp_http_client_handle_t client, int write_len);
int esp_http_client_write(esp_http_client_handle_t client, const char* buffer, int len);
int64_t esp_http_client_fetch_headers(esp_http_client_handle_t client);
int esp_http_client_read(esp_http_client_handle_t client, char* buffer, int len);
int esp_http_client_get_status_code(esp_http_client_handle_t client);
int64_t esp_http_client_get_content_length(esp_http_client_handle_t client);
esp_http_state_t esp_http_client_get_state(esp_http_client_handle_t client);
esp_err_t esp_http_client_close(esp_http_client_handle_t client);
esp_err_t esp_http_client_cleanup(esp_http_client_handle_t client);
bool esp_http_client_is_complete_data_received(esp_http_client_handle_t client);
#ifdef __cplusplus
}
#endif
'''


BPP_CARD_H = r'''
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "esp_err.h"

class IdfEsimLpaBppSession {
public:
    IdfEsimLpaBppSession() = default;
    IdfEsimLpaBppSession(const IdfEsimLpaBppSession&) = delete;
    IdfEsimLpaBppSession& operator=(const IdfEsimLpaBppSession&) = delete;
    IdfEsimLpaBppSession(IdfEsimLpaBppSession&&) noexcept = default;
    IdfEsimLpaBppSession& operator=(IdfEsimLpaBppSession&&) noexcept = default;
    ~IdfEsimLpaBppSession() = default;

    esp_err_t begin_segment(std::string& safe_message);
    esp_err_t write_block(const std::uint8_t* data,
                          std::size_t length,
                          bool last,
                          std::uint16_t block_number,
                          std::vector<std::uint8_t>& response,
                          std::string& safe_message);
    void close();
};

struct FakeCardState {
    int begin_calls = 0;
    int close_calls = 0;
    int write_calls = 0;
    int fail_write_call = 0;
    std::vector<std::uint16_t> block_numbers;
};

extern FakeCardState fake_card;
'''


FAKE_CPP = r'''
#include "idf_lpa_es9_transport.h"
#include "idf_lpa_bpp.h"
#include "idf_esim_lpa.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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
    open_eagain_long,
    open_header_eagain,
    write_eagain,
    write_zero_permanent,
    write_short,
    fetch_eagain,
    read_eagain,
    response_eagain_forever,
    eof_truncated,
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
    const char* post_field = nullptr;
    int post_length = 0;
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
    int perform_calls = 0;
    int post_field_calls = 0;
    int body_event_calls = 0;
    int close_body_event_calls = -1;
    int close_calls = 0;
    int cleanup_calls = 0;
    int delay_calls = 0;
    int status = 200;
    int64_t content_length = 0;
    size_t response_offset = 0;
    size_t body_event_bytes = 0;
    bool opened = false;
    bool complete = false;
    bool request_sent = false;
    bool headers_sent = false;
    esp_http_state_t http_state = HTTP_STATE_INIT;
    bool bpp_mode = false;
    bool body_eagain_after_progress = false;
    bool body_eagain_sent = false;
    bool headers_complete_emitted = false;
    bool redirect_emitted = false;
    bool redirect_before_headers = false;
    std::vector<std::size_t> response_chunks;
    std::size_t response_chunk_index = 0;
    int64_t now_us = 0;
    int64_t now_step_us = 1000;
};

FakeState g;
FakeCardState fake_card;

esp_err_t IdfEsimLpaBppSession::begin_segment(std::string& message)
{
    ++fake_card.begin_calls;
    (void)message;
    return ESP_OK;
}

esp_err_t IdfEsimLpaBppSession::write_block(const std::uint8_t* data,
                                            std::size_t length,
                                            bool last,
                                            std::uint16_t block_number,
                                            std::vector<std::uint8_t>& response,
                                            std::string& message)
{
    ++fake_card.write_calls;
    fake_card.block_numbers.push_back(block_number);
    if (fake_card.fail_write_call != 0 &&
        fake_card.write_calls == fake_card.fail_write_call) {
        message = "card payload sentinel";
        return ESP_FAIL;
    }
    assert(data != nullptr && length <= IDF_LPA_BPP_BLOCK_BYTES);
    response.clear();
    if (last && fake_card.begin_calls == 7) response = {0x90U, 0x00U};
    (void)message;
    return ESP_OK;
}

void IdfEsimLpaBppSession::close()
{
    ++fake_card.close_calls;
}

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

static void reset_bpp(std::string body,
                      Scenario scenario = Scenario::success,
                      const char* protocol = "gsma/rsp/v2.6.0",
                      std::int64_t content_length = -1)
{
    reset(scenario, protocol);
    g.bpp_mode = true;
    g.response = std::move(body);
    g.content_length = content_length >= 0 ? content_length :
        static_cast<std::int64_t>(g.response.size());
    g.response_chunks = {1U, 7U, 3U, 11U, 2U, 17U};
    g.response_chunk_index = 0U;
    g.body_eagain_after_progress = scenario == Scenario::read_eagain;
    if (scenario == Scenario::response_eagain_forever) g.now_step_us = 1000000;
    fake_card = {};
}

static void assert_session_closed_once()
{
    assert(fake_card.close_calls == (fake_card.begin_calls == 0 ? 0 : 1));
}

static esp_err_t emit(int id, void* data = nullptr, int length = 0,
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
    if (id == HTTP_EVENT_ON_HEADERS_COMPLETE) g.headers_complete_emitted = true;
    if (id == HTTP_EVENT_REDIRECT) {
        g.redirect_emitted = true;
        g.redirect_before_headers = !g.headers_complete_emitted;
    }
    assert(g.config.event_handler);
    return g.config.event_handler(&event);
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
    g.http_state = HTTP_STATE_INIT;
    if (g.scenario == Scenario::init_failure) return nullptr;
    return &g.client;
}

static esp_err_t emit_bpp_response_headers()
{
    int status_data = g.status;
    esp_err_t result = emit(
        HTTP_EVENT_ON_STATUS_CODE, &status_data, static_cast<int>(sizeof(status_data)));
    if (result != ESP_OK) return result;
    char content_key[] = "Content-Length";
    std::string content_value = std::to_string(g.content_length);
    result = emit(HTTP_EVENT_ON_HEADER, nullptr, 0, content_key, content_value.data());
    if (result != ESP_OK) return result;
    char protocol_key[] = "X-Admin-Protocol";
    if (g.scenario != Scenario::missing_protocol) {
        result = emit(HTTP_EVENT_ON_HEADER, nullptr, 0, protocol_key, g.protocol.data());
        if (result != ESP_OK) return result;
        if (g.scenario == Scenario::duplicate_protocol) {
            result = emit(HTTP_EVENT_ON_HEADER, nullptr, 0,
                          protocol_key, g.protocol.data());
            if (result != ESP_OK) return result;
        }
    }
    result = emit(HTTP_EVENT_ON_HEADERS_COMPLETE);
    if (g.scenario == Scenario::redirect) {
        const esp_err_t redirect_result = emit(HTTP_EVENT_REDIRECT);
        if (result != ESP_OK) return result;
        return redirect_result;
    }
    return result;
}

extern "C" esp_err_t esp_http_client_perform(esp_http_client_handle_t)
{
    ++g.perform_calls;
    if (g.http_state == HTTP_STATE_INIT || g.http_state == HTTP_STATE_CONNECTING) {
        if (g.scenario == Scenario::timeout_open) {
            g.http_state = HTTP_STATE_CONNECTING;
            return ESP_ERR_HTTP_EAGAIN;
        }
        if ((g.scenario == Scenario::open_eagain && g.perform_calls < 3) ||
            (g.scenario == Scenario::open_eagain_long && g.perform_calls < 6)) {
            g.http_state = HTTP_STATE_CONNECTING;
            return ESP_ERR_HTTP_EAGAIN;
        }
        g.http_state = HTTP_STATE_CONNECTED;
        emit(HTTP_EVENT_ON_CONNECTED);
    }
    if (!g.request_sent) {
        emit(HTTP_EVENT_HEADERS_SENT);
        g.http_state = HTTP_STATE_REQ_COMPLETE_HEADER;
        g.request_sent = true;
        assert(g.post_field && g.post_length > 0);
        const int written = esp_http_client_write(&g.client, g.post_field, g.post_length);
        if (written != g.post_length) {
            g.http_state = HTTP_STATE_REQ_COMPLETE_HEADER;
            return written < 0 ? ESP_ERR_HTTP_EAGAIN : ESP_ERR_HTTP_WRITE_DATA;
        }
        g.http_state = HTTP_STATE_REQ_COMPLETE_DATA;
    }
    if (!g.headers_sent) {
        if (g.scenario == Scenario::fetch_eagain && g.perform_calls < 6) {
            g.http_state = HTTP_STATE_REQ_COMPLETE_DATA;
            return ESP_ERR_HTTP_EAGAIN;
        }
        const esp_err_t header_result = emit_bpp_response_headers();
        g.headers_sent = true;
        g.http_state = HTTP_STATE_RES_ON_DATA_START;
        if (header_result != ESP_OK) return header_result;
    }
    if (g.scenario == Scenario::response_eagain_forever) {
        g.http_state = HTTP_STATE_RES_ON_DATA_START;
        return ESP_ERR_HTTP_EAGAIN;
    }
    if (g.scenario == Scenario::eof_truncated && g.response_offset == 0U) {
        const std::size_t count = g.response.size() / 2U;
        assert(count != 0U);
        ++g.body_event_calls;
        g.body_event_bytes += count;
        const esp_err_t data_result = emit(
            HTTP_EVENT_ON_DATA, g.response.data(), static_cast<int>(count));
        g.response_offset = count;
        if (data_result != ESP_OK) return data_result;
        g.http_state = HTTP_STATE_RES_ON_DATA_START;
        return ESP_ERR_HTTP_INCOMPLETE_DATA;
    }
    if (g.scenario == Scenario::read_failure) {
        g.http_state = HTTP_STATE_RES_ON_DATA_START;
        return ESP_FAIL;
    }
    if (g.bpp_mode) {
        if (g.body_eagain_after_progress && g.response_offset != 0U &&
            !g.body_eagain_sent) {
            g.body_eagain_sent = true;
            g.http_state = HTTP_STATE_RES_ON_DATA_START;
            return ESP_ERR_HTTP_EAGAIN;
        }
        while (g.response_offset < g.response.size()) {
            std::size_t count = std::min<std::size_t>(
                g.response.size() - g.response_offset, 2048U);
            if (g.response_chunk_index < g.response_chunks.size()) {
                count = std::min(count, g.response_chunks[g.response_chunk_index++]);
            }
            assert(count != 0U);
            ++g.body_event_calls;
            g.body_event_bytes += count;
            const esp_err_t data_result = emit(
                HTTP_EVENT_ON_DATA, g.response.data() + g.response_offset,
                static_cast<int>(count));
            g.response_offset += count;
            if (data_result != ESP_OK) return data_result;
            if (g.body_eagain_after_progress && g.response_offset != 0U &&
                !g.body_eagain_sent) {
                g.body_eagain_sent = true;
                g.http_state = HTTP_STATE_RES_ON_DATA_START;
                return ESP_ERR_HTTP_EAGAIN;
            }
        }
        g.complete = true;
        g.http_state = HTTP_STATE_RES_COMPLETE_DATA;
        emit(HTTP_EVENT_ON_FINISH);
        return ESP_OK;
    }
    g.complete = true;
    g.http_state = HTTP_STATE_RES_COMPLETE_DATA;
    emit(HTTP_EVENT_ON_FINISH);
    return ESP_OK;
}

extern "C" esp_http_state_t esp_http_client_get_state(esp_http_client_handle_t)
{
    return g.http_state;
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

extern "C" esp_err_t esp_http_client_set_post_field(esp_http_client_handle_t,
                                                       const char* data, int length)
{
    ++g.post_field_calls;
    assert(data && length > 0);
    g.post_field = data;
    g.post_length = length;
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
    if (g.scenario == Scenario::response_eagain_forever) return -ESP_ERR_HTTP_EAGAIN;
    if (g.scenario == Scenario::read_failure) return -ESP_FAIL;
    if (g.bpp_mode) {
        if (g.body_eagain_after_progress && g.response_offset != 0U &&
            !g.body_eagain_sent) {
            g.body_eagain_sent = true;
            return -ESP_ERR_HTTP_EAGAIN;
        }
        if (g.response_offset == g.response.size()) {
            g.complete = true;
            return 0;
        }
        std::size_t count = std::min<std::size_t>(
            g.response.size() - g.response_offset, static_cast<std::size_t>(length));
        if (g.response_chunk_index < g.response_chunks.size()) {
            count = std::min(count, g.response_chunks[g.response_chunk_index++]);
        }
        assert(count != 0U);
        std::memcpy(buffer, g.response.data() + g.response_offset, count);
        g.response_offset += count;
        if (g.response_offset == g.response.size()) g.complete = true;
        return static_cast<int>(count);
    }
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

extern "C" int64_t esp_http_client_get_content_length(esp_http_client_handle_t)
{
    return g.content_length;
}

extern "C" esp_err_t esp_http_client_close(esp_http_client_handle_t)
{
    ++g.close_calls;
    if (g.close_body_event_calls < 0) g.close_body_event_calls = g.body_event_calls;
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

static std::vector<std::uint8_t> bpp_tlv(std::initializer_list<std::uint8_t> tag,
                                         std::initializer_list<std::uint8_t> value)
{
    std::vector<std::uint8_t> result(tag);
    assert(value.size() < 128U);
    result.push_back(static_cast<std::uint8_t>(value.size()));
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

static std::vector<std::uint8_t> bpp_tlv(std::initializer_list<std::uint8_t> tag,
                                         const std::vector<std::uint8_t>& value)
{
    std::vector<std::uint8_t> result(tag);
    assert(value.size() < 128U);
    result.push_back(static_cast<std::uint8_t>(value.size()));
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

static std::vector<std::uint8_t> valid_bpp()
{
    const auto init = bpp_tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = bpp_tlv({0xA0U}, bpp_tlv({0x87U}, {0x02U}));
    auto metadata_payload = bpp_tlv({0xBF,0x25}, {
        0x5A,10,0x98,0x88,0x12,0x32,0x54,0x76,0x98,0x10,0x32,0xF4,
        0x91,7,'C','a','r','r','i','e','r',0x92,6,'T','r','a','v','e','l'});
    metadata_payload.insert(metadata_payload.end(), {0xAA,0xBB,0xCC,0xDD,1,2,3,4});
    const auto metadata = bpp_tlv({0xA1U}, bpp_tlv({0x88U}, metadata_payload));
    const auto second = bpp_tlv({0xA2U}, bpp_tlv({0x87U}, {0x04U}));
    const auto profile = bpp_tlv({0xA3U}, bpp_tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, second, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return bpp_tlv({0xBFU, 0x36U}, content);
}

static std::string bpp_base64(const std::vector<std::uint8_t>& bytes)
{
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (std::size_t i = 0U; i < bytes.size(); i += 3U) {
        const std::size_t remaining = bytes.size() - i;
        const std::uint32_t first = bytes[i];
        const std::uint32_t second = remaining > 1U ? bytes[i + 1U] : 0U;
        const std::uint32_t third = remaining > 2U ? bytes[i + 2U] : 0U;
        const std::uint32_t value = (first << 16U) | (second << 8U) | third;
        result.push_back(alphabet[(value >> 18U) & 0x3FU]);
        result.push_back(alphabet[(value >> 12U) & 0x3FU]);
        result.push_back(remaining > 1U ? alphabet[(value >> 6U) & 0x3FU] : '=');
        result.push_back(remaining > 2U ? alphabet[value & 0x3FU] : '=');
    }
    return result;
}

static std::string bpp_response(std::string_view encoded)
{
    return std::string(
               R"json({"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"001122","boundProfilePackage":")json") +
           std::string(encoded) + "\"}";
}

static LpaRspProfileMetadata expected_metadata() { return {"Carrier", "Travel", false}; }

static void assert_bpp_rejected(Scenario scenario,
                                std::string_view body,
                                IdfLpaEs9TransportError expected,
                                const char* protocol = "gsma/rsp/v2.6.0")
{
    reset_bpp(std::string(body), scenario, protocol);
    std::vector<std::uint8_t> pir = {0xA5U};
    std::string message = "response sentinel";
    IdfLpaEs9TransportError error = IdfLpaEs9TransportError::none;
    assert(!idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(error == expected);
    assert(pir.empty());
    assert(message.find("sentinel") == std::string::npos);
    assert(std::string(idf_lpa_es9_transport_error_name(error)).find("sentinel") ==
           std::string::npos);
    assert(g.close_calls == 1 && g.cleanup_calls == 1);
    assert_session_closed_once();
}

static void assert_bpp_pir_alias(std::size_t offset, std::size_t length,
                                 int input_kind)
{
    reset_bpp("not-used");
    std::vector<std::uint8_t> pir(64U, 0xA5U);
    const std::string_view alias(
        reinterpret_cast<const char*>(pir.data() + offset), length);
    std::string_view host = "edge.example";
    std::string_view request = R"({"request":true})";
    std::string_view transaction = "001122";
    if (input_kind == 0) host = alias;
    if (input_kind == 1) request = alias;
    if (input_kind == 2) transaction = alias;
    std::string message = "alias sentinel";
    IdfLpaEs9TransportError error = IdfLpaEs9TransportError::none;
    assert(!idf_lpa_es9_get_bound_profile_package(
        host, request, transaction, expected_metadata(), pir, message, error));
    assert(error == IdfLpaEs9TransportError::invalid_request);
    assert(pir.empty() && message.empty() && g.init_calls == 0);
}

static void test_bpp_transport()
{
    const std::string encoded = bpp_base64(valid_bpp());
    const std::string body = bpp_response(encoded);
    std::vector<std::uint8_t> pir = {0xA5U};
    std::string message = "request sentinel";
    IdfLpaEs9TransportError error = IdfLpaEs9TransportError::unknown;

    reset_bpp(body);
    assert(idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(error == IdfLpaEs9TransportError::none);
    assert(pir == std::vector<std::uint8_t>({0x90U, 0x00U}));
    assert(message.empty());
    assert(g.url == "https://edge.example/gsma/rsp2/es9plus/getBoundProfilePackage");
    assert(g.user_agent == "gsma-rsp-lpad");
    assert(g.config.disable_auto_redirect && !g.config.keep_alive_enable);
    assert(!g.config.skip_cert_common_name_check && g.config.crt_bundle_attach);
    assert(g.config.method == HTTP_METHOD_POST && g.header_calls == 2);
    assert(g.header_keys[0] == "Content-Type" &&
           g.header_values[0] == "application/json");
    assert(g.header_keys[1] == "X-Admin-Protocol" &&
           g.header_values[1] == "gsma/rsp/v2.6.0");
    assert(g.post_field_calls == 1 && g.post_length == 16 &&
           std::string(g.post_field, static_cast<std::size_t>(g.post_length)) ==
               R"({"request":true})");
    assert(g.request == R"({"request":true})");
    assert(g.open_calls == 0 && g.perform_calls == 1 && g.write_calls == 1 &&
           g.read_calls == 0 && g.close_calls == 1 && g.cleanup_calls == 1 &&
           g.body_event_calls > 0 && g.body_event_bytes == body.size() &&
           fake_card.close_calls == 1);

    reset_bpp(body);
    auto consent = expected_metadata();
    consent.profile_name = "Different";
    assert(!idf_lpa_es9_get_bound_profile_package("edge.example", R"({"request":true})",
        "001122", consent, pir, message, error));
    assert(error == IdfLpaEs9TransportError::response_body && pir.empty());
    assert(fake_card.begin_calls == 2 && fake_card.close_calls == 1);
    reset_bpp(body);
    consent = expected_metadata();
    consent.has_policy_rules = true;
    assert(!idf_lpa_es9_get_bound_profile_package("edge.example", R"({"request":true})",
        "001122", consent, pir, message, error));
    assert(error == IdfLpaEs9TransportError::invalid_request && pir.empty());
    assert(g.init_calls == 0 && fake_card.begin_calls == 0);

    reset_bpp(body);
    const std::string oversized_request(IDF_LPA_ES9_MAX_JSON_BYTES + 1U, 'x');
    pir = {0xA5U};
    message = "request limit sentinel";
    assert(!idf_lpa_es9_get_bound_profile_package(
        "edge.example", oversized_request, "001122", expected_metadata(), pir, message, error));
    assert(error == IdfLpaEs9TransportError::invalid_request && pir.empty());
    assert(g.init_calls == 0 && fake_card.begin_calls == 0);

    for (int input_kind = 0; input_kind < 3; ++input_kind) {
        assert_bpp_pir_alias(0U, 64U, input_kind);
        assert_bpp_pir_alias(1U, 63U, input_kind);
    }

    for (const std::size_t chunk : {1U, 2U, 3U, 5U, 17U, 64U}) {
        reset_bpp(body);
        g.response_chunks = {chunk};
        pir = {0xA5U};
        message = "chunk sentinel";
        assert(idf_lpa_es9_get_bound_profile_package(
            "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
        assert(pir == std::vector<std::uint8_t>({0x90U, 0x00U}));
        assert(message.empty());
        assert(g.request == R"({"request":true})");
    }

    assert_bpp_rejected(Scenario::missing_protocol, body,
                        IdfLpaEs9TransportError::response_protocol);
    assert(g.read_calls == 0 && g.body_event_calls == 0 && fake_card.begin_calls == 0);
    assert_bpp_rejected(Scenario::duplicate_protocol, body,
                        IdfLpaEs9TransportError::response_protocol);
    assert(g.read_calls == 0 && g.body_event_calls == 0 && fake_card.begin_calls == 0);
    assert_bpp_rejected(Scenario::success, body,
                        IdfLpaEs9TransportError::response_protocol, "gsma/rsp/v2.6.0 ");
    assert(g.read_calls == 0 && g.body_event_calls == 0 && fake_card.begin_calls == 0);
    assert_bpp_rejected(Scenario::success, body,
                        IdfLpaEs9TransportError::response_protocol,
                        "gsma/rsp/v2.1234567890.1234567890");
    assert(g.read_calls == 0 && g.body_event_calls == 0 && fake_card.begin_calls == 0);
    assert_bpp_rejected(Scenario::wrong_status, body,
                        IdfLpaEs9TransportError::response_status);
    assert(g.read_calls == 0 && g.body_event_calls == 0 && fake_card.begin_calls == 0);
    assert_bpp_rejected(Scenario::redirect, body,
                        IdfLpaEs9TransportError::redirect);
    assert(g.read_calls == 0 && g.body_event_calls == 0 && fake_card.begin_calls == 0);
    assert(g.headers_complete_emitted && g.redirect_emitted && !g.redirect_before_headers);

    const auto exact_cap = static_cast<std::int64_t>(IDF_LPA_BPP_MAX_ENCODED_BYTES + 64U * 1024U);
    assert_bpp_rejected(Scenario::success, "x",
                        IdfLpaEs9TransportError::response_body);
    reset_bpp("x", Scenario::success, "gsma/rsp/v2.6.0", exact_cap);
    pir = {0xA5U};
    message = "exact cap sentinel";
    assert(!idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(error == IdfLpaEs9TransportError::response_body && g.perform_calls == 1);
    assert(pir.empty() && message.find("sentinel") == std::string::npos);
    reset_bpp("x", Scenario::success, "gsma/rsp/v2.6.0", exact_cap + 1);
    pir = {0xA5U};
    message = "wire cap sentinel";
    assert(!idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(error == IdfLpaEs9TransportError::response_too_large && g.perform_calls == 1);
    assert(pir.empty() && message.find("sentinel") == std::string::npos &&
           g.body_event_calls == 0 && fake_card.begin_calls == 0);

    reset_bpp(body, Scenario::read_eagain);
    pir = {0xA5U};
    message.clear();
    assert(idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(pir == std::vector<std::uint8_t>({0x90U, 0x00U}) && g.delay_calls >= 1);
    reset_bpp(body, Scenario::fetch_eagain);
    pir = {0xA5U};
    message.clear();
    assert(idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(pir == std::vector<std::uint8_t>({0x90U, 0x00U}) &&
           g.perform_calls == 6 && g.delay_calls >= 5 && g.write_calls == 1);
    assert_bpp_rejected(Scenario::response_eagain_forever, body,
                        IdfLpaEs9TransportError::timeout);
    assert(g.perform_calls > 4 && g.perform_calls < 1000 && g.delay_calls > 0);
    assert_bpp_rejected(Scenario::write_eagain, body,
                        IdfLpaEs9TransportError::request_write);
    assert(g.perform_calls == 1 && g.write_calls == 1 && fake_card.begin_calls == 0);

    reset_bpp(body, Scenario::open_eagain);
    pir = {0xA5U};
    message.clear();
    assert(idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(pir == std::vector<std::uint8_t>({0x90U, 0x00U}) && g.perform_calls == 3);
    reset_bpp(body, Scenario::open_eagain_long);
    pir = {0xA5U};
    message.clear();
    assert(idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(pir == std::vector<std::uint8_t>({0x90U, 0x00U}) &&
           g.perform_calls == 6 && g.delay_calls >= 5);

    reset_bpp(body, Scenario::timeout_open);
    g.now_step_us = 30LL * 60LL * 1000000LL;
    pir = {0xA5U};
    message = "deadline sentinel";
    assert(!idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(error == IdfLpaEs9TransportError::timeout && pir.empty());

    std::string truncated = body.substr(0, body.size() - 1U);
    assert_bpp_rejected(Scenario::success, truncated,
                        IdfLpaEs9TransportError::response_body);
    assert_bpp_rejected(Scenario::success, "not-json",
                        IdfLpaEs9TransportError::response_body);
    assert(g.perform_calls == 1 && g.body_event_calls == 1 && g.body_event_bytes == 1U &&
           g.close_body_event_calls == g.body_event_calls);
    reset_bpp(body);
    fake_card.fail_write_call = 1;
    pir = {0xA5U};
    message = "card sentinel";
    assert(!idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(error == IdfLpaEs9TransportError::response_body && pir.empty());
    assert(message.find("sentinel") == std::string::npos);
    assert(g.perform_calls == 1 && g.body_event_calls > 0 &&
           g.close_body_event_calls == g.body_event_calls &&
           fake_card.close_calls == 1);

    assert_bpp_rejected(Scenario::eof_truncated, body,
                        IdfLpaEs9TransportError::response_body);
    assert(g.perform_calls == 1 && g.body_event_calls == 1 &&
           g.body_event_bytes == body.size() / 2U && g.response_offset == body.size() / 2U);

    reset_bpp(body);
    g.body_eagain_after_progress = true;
    pir = {0xA5U};
    message.clear();
    assert(idf_lpa_es9_get_bound_profile_package(
        "edge.example", R"({"request":true})", "001122", expected_metadata(), pir, message, error));
    assert(pir == std::vector<std::uint8_t>({0x90U, 0x00U}));
    assert(g.open_calls == 0 && g.perform_calls == 2 && g.write_calls == 1 &&
           g.response_offset == body.size() && g.request == R"({"request":true})");
}

int main()
{
    reset(Scenario::success);
    std::string cancelled;
    IdfLpaEs9TransportError cancel_error = IdfLpaEs9TransportError::unknown;
    assert(idf_lpa_es9_post_json(IdfLpaEs9Operation::cancel_session,
        "edge.example", R"({"transactionId":"0102","cancelSessionResponse":"vwEA"})",
        cancelled, cancel_error));
    assert(g.url == "https://edge.example/gsma/rsp2/es9plus/cancelSession" &&
        cancelled == R"({"ok":true})" && cancel_error == IdfLpaEs9TransportError::none);
    assert(g.request == R"({"transactionId":"0102","cancelSessionResponse":"vwEA"})");
    assert_rejected(Scenario::notify_success, IdfLpaEs9Operation::cancel_session,
        IdfLpaEs9TransportError::response_status);

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
            assert(g.request == R"({"request":true})");
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
             "gsma/rsp/v2.1234567890.1234567890",
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

    test_bpp_transport();
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
            (include / "idf_esim_lpa.h").write_text(BPP_CARD_H)
            harness = Path(temp_dir) / "es9_transport_fixture.cpp"
            binary = Path(temp_dir) / "es9_transport_fixture"
            harness.write_text(FAKE_CPP)
            # Use the real RSP parser; only its host crypto backend is built without ESP_PLATFORM.
            rsp_object = Path(temp_dir) / "rsp.o"
            subprocess.run([
                "g++", "-std=c++17", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra",
                "-Werror", "-pedantic", "-I", str(COMPONENT / "include"),
                "-I", str(COMPONENT.parent / "idf_esim" / "include"),
                "-c", str(COMPONENT / "idf_lpa_rsp.cpp"), "-o", str(rsp_object),
            ], check=True, capture_output=True, text=True, timeout=30)
            result = subprocess.run(
                [
                    "g++", "-std=c++17", "-DESP_PLATFORM", "-fno-exceptions", "-fno-rtti",
                    "-Wall", "-Wextra", "-Werror", "-pedantic",
                    "-DIDF_LPA_BPP_TESTING",
                    "-I", str(include), "-I", str(COMPONENT / "include"),
                    "-I", str(COMPONENT.parent / "idf_esim" / "include"),
                    str(SOURCE), str(BPP_SOURCE), str(rsp_object),
                    str(COMPONENT / "idf_lpa_activation_code.cpp"),
                    str(COMPONENT.parent / "idf_esim" / "idf_esim_codec.cpp"),
                    str(harness), "-lcrypto", "-o", str(binary),
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
