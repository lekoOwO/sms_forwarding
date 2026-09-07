#include "idf_lpa_es9_transport.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef ESP_PLATFORM
#include "idf_lpa_bpp.h"
#include "esp_crt_bundle.h"
#include "esp_http_client.h"
#include "esp_timer.h"
#include "esp_tls_errors.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#endif

namespace {

void secure_zero(void* address, std::size_t size) noexcept
{
    volatile auto* bytes = static_cast<volatile std::uint8_t*>(address);
    while (size != 0U) {
        *bytes = 0U;
        ++bytes;
        --size;
    }
}

void secure_clear(std::string& value) noexcept
{
    const std::size_t capacity = value.capacity();
    if (capacity > value.size()) value.resize(capacity, '\0');
    if (!value.empty()) secure_zero(value.data(), value.size());
    value.clear();
    std::string().swap(value);
}

void secure_clear(std::vector<std::uint8_t>& value) noexcept
{
    if (value.capacity() != 0U && value.data() != nullptr) {
        secure_zero(value.data(), value.capacity());
    }
    value.clear();
    std::vector<std::uint8_t>().swap(value);
}

bool input_overlaps_buffer(std::string_view input,
                           const void* output_data,
                           std::size_t output_capacity) noexcept
{
    if (input.empty() || output_capacity == 0U) return false;
    const std::uintptr_t input_begin = reinterpret_cast<std::uintptr_t>(input.data());
    const std::uintptr_t output_begin = reinterpret_cast<std::uintptr_t>(output_data);
    const std::uintptr_t max_address = std::numeric_limits<std::uintptr_t>::max();
    if (input_begin == 0U || output_begin == 0U ||
        input.size() > max_address - input_begin ||
        output_capacity > max_address - output_begin) {
        return true;
    }
    const std::uintptr_t input_end = input_begin + input.size();
    const std::uintptr_t output_end = output_begin + output_capacity;
    return input_begin < output_end && output_begin < input_end;
}

bool input_overlaps_output(std::string_view input,
                           const std::string& output) noexcept
{
    return input_overlaps_buffer(input, output.data(), output.capacity());
}

bool input_overlaps_output(std::string_view input,
                           const std::vector<std::uint8_t>& output) noexcept
{
    return input_overlaps_buffer(input, output.data(), output.capacity());
}

bool fail(IdfLpaEs9TransportError& error, IdfLpaEs9TransportError value) noexcept
{
    error = value;
    return false;
}

bool equal_ascii_ci(std::string_view left, std::string_view right) noexcept
{
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0U; i < left.size(); ++i) {
        unsigned char lhs = static_cast<unsigned char>(left[i]);
        unsigned char rhs = static_cast<unsigned char>(right[i]);
        if (lhs >= static_cast<unsigned char>('a') &&
            lhs <= static_cast<unsigned char>('z')) {
            lhs = static_cast<unsigned char>(lhs - static_cast<unsigned char>('a') +
                                             static_cast<unsigned char>('A'));
        }
        if (rhs >= static_cast<unsigned char>('a') &&
            rhs <= static_cast<unsigned char>('z')) {
            rhs = static_cast<unsigned char>(rhs - static_cast<unsigned char>('a') +
                                             static_cast<unsigned char>('A'));
        }
        if (lhs != rhs) return false;
    }
    return true;
}

bool equal_ascii_ci_cstr(const char* left, std::string_view right) noexcept
{
    if (!left) return false;
    for (std::size_t i = 0U; i < right.size(); ++i) {
        if (left[i] == '\0') return false;
    }
    if (left[right.size()] != '\0') return false;
    return equal_ascii_ci(std::string_view(left, right.size()), right);
}

bool valid_smdp_host(std::string_view host) noexcept
{
    if (host.empty() || host.size() > 253U) return false;
    std::size_t label_start = 0U;
    std::size_t label_count = 0U;
    bool all_numeric = true;
    while (label_start <= host.size()) {
        const std::size_t dot = host.find('.', label_start);
        const std::size_t label_end = dot == std::string_view::npos ? host.size() : dot;
        const std::size_t label_size = label_end - label_start;
        if (label_size == 0U || label_size > 63U) return false;
        if (host[label_start] == '-' || host[label_end - 1U] == '-') return false;
        bool numeric_label = true;
        for (std::size_t i = label_start; i < label_end; ++i) {
            const unsigned char value = static_cast<unsigned char>(host[i]);
            const bool alpha = (value >= static_cast<unsigned char>('A') &&
                                value <= static_cast<unsigned char>('Z')) ||
                               (value >= static_cast<unsigned char>('a') &&
                                value <= static_cast<unsigned char>('z'));
            const bool digit = value >= static_cast<unsigned char>('0') &&
                               value <= static_cast<unsigned char>('9');
            if (!alpha && !digit && value != static_cast<unsigned char>('-')) return false;
            if (!digit) numeric_label = false;
        }
        all_numeric = all_numeric && numeric_label;
        ++label_count;
        if (dot == std::string_view::npos) break;
        label_start = dot + 1U;
    }
    return label_count >= 2U && !all_numeric;
}

struct OperationSpec {
    std::string_view path;
    bool empty_response;
};

bool operation_spec(IdfLpaEs9Operation operation, OperationSpec& spec) noexcept
{
    switch (operation) {
    case IdfLpaEs9Operation::initiate_authentication:
        spec = {"/gsma/rsp2/es9plus/initiateAuthentication", false};
        return true;
    case IdfLpaEs9Operation::authenticate_client:
        spec = {"/gsma/rsp2/es9plus/authenticateClient", false};
        return true;
    case IdfLpaEs9Operation::handle_notification:
        spec = {"/gsma/rsp2/es9plus/handleNotification", true};
        return true;
    case IdfLpaEs9Operation::cancel_session:
        spec = {"/gsma/rsp2/es9plus/cancelSession", false};
        return true;
    }
    return false;
}

#ifdef ESP_PLATFORM

constexpr std::string_view kAdminProtocolPrefix = "gsma/rsp/v2.";

bool valid_admin_protocol_component(std::string_view component) noexcept
{
    if (component.empty() || component.size() > 10U) return false;
    std::uint32_t value = 0U;
    for (const char character : component) {
        const unsigned char digit = static_cast<unsigned char>(character);
        if (digit < static_cast<unsigned char>('0') ||
            digit > static_cast<unsigned char>('9')) {
            return false;
        }
        const std::uint32_t number = static_cast<std::uint32_t>(
            digit - static_cast<unsigned char>('0'));
        if (value > (std::numeric_limits<std::uint32_t>::max() - number) / 10U) {
            return false;
        }
        value = value * 10U + number;
    }
    return true;
}

bool valid_admin_protocol(std::string_view protocol) noexcept
{
    if (protocol.size() <= kAdminProtocolPrefix.size() || protocol.size() > 32U ||
        protocol.compare(0U, kAdminProtocolPrefix.size(), kAdminProtocolPrefix) != 0) {
        return false;
    }
    const std::string_view version = protocol.substr(kAdminProtocolPrefix.size());
    const std::size_t separator = version.find('.');
    if (separator == std::string_view::npos ||
        version.find('.', separator + 1U) != std::string_view::npos) {
        return false;
    }
    return valid_admin_protocol_component(version.substr(0U, separator)) &&
           valid_admin_protocol_component(version.substr(separator + 1U));
}

enum class CaptureError : std::uint8_t {
    none,
    timeout,
    response_too_large,
    response_status,
    response_protocol,
    response_body,
    redirect,
};

struct ResponseCapture {
    std::string protocol;
    std::string body;
    std::size_t response_bytes = 0U;
    std::int64_t content_length = -1;
    int status_code = -1;
    bool connected = false;
    bool headers_sent = false;
    bool headers_complete = false;
    bool protocol_seen = false;
    bool protocol_duplicate = false;
    bool protocol_overlong = false;
    bool redirected = false;
    bool stream_body = false;
    std::int64_t deadline_us = 0;
    IdfLpaBppStream* bpp = nullptr;
    std::string* bpp_message = nullptr;
    bool http_closed = false;
    bool http_closing = false;
    esp_err_t http_close_result = ESP_OK;
    esp_err_t callback_error = ESP_OK;
    CaptureError error = CaptureError::none;

    ~ResponseCapture() noexcept
    {
        secure_clear(protocol);
        secure_clear(body);
    }
};

bool valid_protocol_header(const ResponseCapture& capture) noexcept
{
    return capture.protocol_seen && !capture.protocol_duplicate &&
           !capture.protocol_overlong && valid_admin_protocol(capture.protocol);
}

void capture_error(ResponseCapture& capture, CaptureError error) noexcept
{
    if (capture.error == CaptureError::none) capture.error = error;
}

esp_err_t close_http_once(esp_http_client_handle_t client,
                          ResponseCapture& capture) noexcept
{
    if (capture.http_closed) return capture.http_close_result;
    capture.http_closed = true;
    capture.http_closing = true;
    capture.http_close_result = esp_http_client_close(client);
    capture.http_closing = false;
    return capture.http_close_result;
}

esp_err_t capture_error_code(CaptureError error) noexcept
{
    switch (error) {
    case CaptureError::timeout: return ESP_ERR_TIMEOUT;
    case CaptureError::response_too_large: return ESP_ERR_INVALID_SIZE;
    case CaptureError::response_status:
    case CaptureError::response_protocol:
    case CaptureError::response_body:
    case CaptureError::redirect: return ESP_ERR_INVALID_RESPONSE;
    case CaptureError::none: return ESP_OK;
    }
    return ESP_FAIL;
}

esp_err_t abort_http_event(ResponseCapture& capture,
                           esp_http_client_event_t* event,
                           CaptureError error,
                           esp_err_t callback_error) noexcept
{
    capture_error(capture, error);
    if (capture.callback_error == ESP_OK) capture.callback_error = callback_error;
    if (event && event->client) (void)close_http_once(event->client, capture);
    return capture.callback_error;
}

bool parse_content_length(const char* value, std::int64_t& result) noexcept
{
    if (!value) return false;
    std::size_t offset = 0U;
    while (value[offset] == ' ' || value[offset] == '\t') ++offset;
    if (value[offset] == '\0') return false;
    std::uint64_t parsed = 0U;
    constexpr std::uint64_t kMax =
        static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max());
    std::size_t digit_count = 0U;
    while (value[offset] >= '0' && value[offset] <= '9') {
        const std::uint64_t digit = static_cast<std::uint64_t>(value[offset] - '0');
        if (parsed > (kMax - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
        ++offset;
        ++digit_count;
        if (digit_count > 19U) return false;
    }
    while (value[offset] == ' ' || value[offset] == '\t') ++offset;
    if (digit_count == 0U || value[offset] != '\0') return false;
    result = static_cast<std::int64_t>(parsed);
    return true;
}

CaptureError stream_preflight_error(const ResponseCapture& capture) noexcept
{
    if (capture.redirected ||
        (capture.status_code >= 300 && capture.status_code < 400)) {
        return CaptureError::redirect;
    }
    if (capture.status_code != 200) return CaptureError::response_status;
    if (!valid_protocol_header(capture)) {
        return CaptureError::response_protocol;
    }
    if (capture.content_length == -2) return CaptureError::response_body;
    if (capture.content_length > static_cast<std::int64_t>(IDF_LPA_ES9_BPP_MAX_WIRE_BYTES)) {
        return CaptureError::response_too_large;
    }
    return CaptureError::none;
}

esp_err_t on_http_event(esp_http_client_event_t* event)
{
    if (!event || !event->user_data) return ESP_OK;
    auto* capture = static_cast<ResponseCapture*>(event->user_data);
    if (event->event_id == HTTP_EVENT_DISCONNECTED && capture->http_closing) {
        return ESP_OK;
    }
    if (capture->stream_body && capture->deadline_us > 0 &&
        esp_timer_get_time() >= capture->deadline_us) {
        return abort_http_event(*capture, event, CaptureError::timeout, ESP_ERR_TIMEOUT);
    }
    if (capture->stream_body && capture->error != CaptureError::none) {
        return capture->callback_error == ESP_OK ? ESP_FAIL : capture->callback_error;
    }
    if (event->event_id == HTTP_EVENT_ON_CONNECTED) {
        capture->connected = true;
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_HEADERS_SENT) {
        capture->headers_sent = true;
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_REDIRECT) {
        capture->redirected = true;
        if (capture->stream_body) {
            return abort_http_event(*capture, event, CaptureError::redirect,
                                    ESP_ERR_INVALID_RESPONSE);
        }
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_ON_STATUS_CODE) {
        if (event->data && event->data_len >= static_cast<int>(sizeof(int))) {
            capture->status_code = *static_cast<const int*>(event->data);
        }
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_ON_HEADER && event->header_key &&
        equal_ascii_ci_cstr(event->header_key, "X-Admin-Protocol")) {
        if (capture->protocol_seen) {
            capture->protocol_duplicate = true;
        } else {
            capture->protocol_seen = true;
            const char* value = event->header_value;
            std::size_t value_size = 0U;
            while (value && value_size <= 32U && value[value_size] != '\0') {
                ++value_size;
            }
            capture->protocol_overlong = value_size > 32U;
            capture->protocol.assign(value ? value : "", std::min<std::size_t>(value_size, 32U));
        }
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_ON_HEADER && event->header_key &&
        equal_ascii_ci_cstr(event->header_key, "Content-Length")) {
        std::int64_t content_length = -1;
        if (!parse_content_length(event->header_value, content_length) ||
            capture->content_length != -1) {
            capture->content_length = -2;
        } else {
            capture->content_length = content_length;
        }
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_ON_HEADERS_COMPLETE) {
        capture->headers_complete = true;
        if (capture->stream_body && capture->error == CaptureError::none) {
            const CaptureError preflight = stream_preflight_error(*capture);
            if (preflight != CaptureError::none) {
                return abort_http_event(*capture, event, preflight,
                                        capture_error_code(preflight));
            }
        }
        return ESP_OK;
    }
    if (event->event_id != HTTP_EVENT_ON_DATA) return ESP_OK;
    if (event->data_len < 0 || (event->data_len != 0 && !event->data)) {
        if (capture->stream_body) {
            return abort_http_event(*capture, event, CaptureError::response_body,
                                    ESP_ERR_INVALID_RESPONSE);
        }
        capture_error(*capture, CaptureError::response_body);
        return ESP_OK;
    }
    const std::size_t data_size = static_cast<std::size_t>(event->data_len);
    if (capture->stream_body) {
        if (capture->error != CaptureError::none) {
            return capture->callback_error == ESP_OK ? ESP_FAIL : capture->callback_error;
        }
        if (data_size == 0U) return ESP_OK;
        const CaptureError preflight = stream_preflight_error(*capture);
        if (preflight != CaptureError::none) {
            return abort_http_event(*capture, event, preflight,
                                    capture_error_code(preflight));
        }
        if (capture->response_bytes > IDF_LPA_ES9_BPP_MAX_WIRE_BYTES ||
            data_size > IDF_LPA_ES9_BPP_MAX_WIRE_BYTES - capture->response_bytes) {
            capture->response_bytes = IDF_LPA_ES9_BPP_MAX_WIRE_BYTES + 1U;
            return abort_http_event(*capture, event, CaptureError::response_too_large,
                                    ESP_ERR_INVALID_SIZE);
        }
        capture->response_bytes += data_size;
        if (!capture->bpp || !capture->bpp_message) {
            return abort_http_event(*capture, event, CaptureError::response_body,
                                    ESP_ERR_INVALID_STATE);
        }
        const char* data = static_cast<const char*>(event->data);
        std::size_t offset = 0U;
        while (offset < data_size) {
            if (capture->deadline_us > 0 && esp_timer_get_time() >= capture->deadline_us) {
                return abort_http_event(*capture, event, CaptureError::timeout,
                                        ESP_ERR_TIMEOUT);
            }
            const std::size_t chunk = std::min<std::size_t>(1024U, data_size - offset);
            const esp_err_t feed_error =
                capture->bpp->feed(data + offset, chunk, *capture->bpp_message);
            if (feed_error != ESP_OK) {
                return abort_http_event(*capture, event, CaptureError::response_body,
                                        feed_error);
            }
            offset += chunk;
            if (capture->deadline_us > 0 && esp_timer_get_time() >= capture->deadline_us) {
                return abort_http_event(*capture, event, CaptureError::timeout,
                                        ESP_ERR_TIMEOUT);
            }
        }
        return ESP_OK;
    }
    if (data_size > IDF_LPA_ES9_MAX_JSON_BYTES ||
        capture->response_bytes > IDF_LPA_ES9_MAX_JSON_BYTES - data_size) {
        capture->response_bytes = IDF_LPA_ES9_MAX_JSON_BYTES + 1U;
        capture_error(*capture, CaptureError::response_too_large);
        return ESP_OK;
    }
    if (data_size == 0U) return ESP_OK;
    capture->response_bytes += data_size;
    capture->body.append(static_cast<const char*>(event->data), data_size);
    return ESP_OK;
}

class Deadline {
public:
    explicit Deadline(std::uint32_t timeout_ms)
        : deadline_us_(esp_timer_get_time() +
                       static_cast<std::int64_t>(timeout_ms) *
                           1000LL) {}

    bool expired() const noexcept
    {
        return esp_timer_get_time() >= deadline_us_;
    }

    std::int64_t deadline_us() const noexcept { return deadline_us_; }

    bool apply(esp_http_client_handle_t client) const
    {
        if (!client) return false;
        const std::int64_t now = esp_timer_get_time();
        if (now >= deadline_us_) return false;
        const std::int64_t remaining_us = deadline_us_ - now;
        const std::int64_t remaining_ms = (remaining_us + 999LL) / 1000LL;
        const int timeout_ms = static_cast<int>(std::max<std::int64_t>(
            1LL, std::min<std::int64_t>(IDF_LPA_ES9_IO_TIMEOUT_MS, remaining_ms)));
        return esp_http_client_set_timeout_ms(client, timeout_ms) == ESP_OK;
    }

private:
    std::int64_t deadline_us_;
};

void wait_again(std::uint32_t delay_ms = 1U) noexcept
{
    const auto ticks = pdMS_TO_TICKS(delay_ms);
    vTaskDelay(ticks == 0U ? 1U : ticks);
}

void wait_backoff(std::uint32_t& delay_ms) noexcept
{
    wait_again(delay_ms);
    delay_ms = std::min<std::uint32_t>(delay_ms > 125U ? 250U : delay_ms * 2U,
                                       250U);
}

bool retryable_io(int result, int saved_errno) noexcept
{
    return result == -ESP_ERR_HTTP_EAGAIN ||
           result == ESP_TLS_ERR_SSL_WANT_READ ||
           result == ESP_TLS_ERR_SSL_WANT_WRITE ||
           saved_errno == EAGAIN || saved_errno == EWOULDBLOCK;
}

void configure_post_client(esp_http_client_config_t& config,
                           const char* url,
                           std::size_t request_size,
                           ResponseCapture& capture)
{
    config.url = url;
    config.user_agent = "gsma-rsp-lpad";
    config.method = HTTP_METHOD_POST;
    config.timeout_ms = static_cast<int>(IDF_LPA_ES9_IO_TIMEOUT_MS);
    config.disable_auto_redirect = true;
    config.max_redirection_count = 0;
    config.max_authorization_retries = -1;
    config.keep_alive_enable = false;
    config.skip_cert_common_name_check = false;
    config.is_async = true;
    config.buffer_size = 2048;
    config.buffer_size_tx = static_cast<int>(std::min<std::size_t>(
        32768U, std::max<std::size_t>(2048U, request_size + 512U)));
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.event_handler = on_http_event;
    config.user_data = &capture;
}

IdfLpaEs9TransportError request_headers(esp_http_client_handle_t client,
                                        std::string_view request,
                                        ResponseCapture& capture,
                                        Deadline& deadline,
                                        std::int64_t& content_length)
{
    std::uint32_t retry_delay_ms = 1U;
    while (true) {
        if (!deadline.apply(client)) return deadline.expired()
            ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        const esp_err_t open_result = esp_http_client_open(
            client, static_cast<int>(request.size()));
        if (open_result == ESP_OK) break;
        // ESP-IDF 會將非同步連線進度與請求標頭傳輸 EAGAIN 映射為
        // ESP_ERR_HTTP_EAGAIN。只有在 connected event 之前重試，因為此時尚未
        // 傳送請求標頭；一旦連線完成，可能已有前綴資料，必須 fail closed。
        if (open_result != ESP_ERR_HTTP_EAGAIN || capture.connected) {
            return deadline.expired()
                ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        }
        wait_backoff(retry_delay_ms);
    }

    std::size_t written = 0U;
    while (written < request.size()) {
        if (!deadline.apply(client)) return deadline.expired()
            ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        const std::size_t chunk = std::min<std::size_t>(1024U, request.size() - written);
        const int result = esp_http_client_write(
            client, request.data() + written, static_cast<int>(chunk));
        if (result > 0) {
            if (static_cast<std::size_t>(result) > chunk) {
                return IdfLpaEs9TransportError::request_write;
            }
            written += static_cast<std::size_t>(result);
            continue;
        }
        // esp_http_client_write() 可能在內部請求標頭已送達傳輸層後仍回報無進度。
        // 回傳值與 errno 都不能證明重播 ES9+ body 是安全的，因此每個非正值
        // 只呼叫一次並 fail closed。
        return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                  : IdfLpaEs9TransportError::request_write;
    }

    content_length = -1;
    while (true) {
        if (!deadline.apply(client)) return deadline.expired()
            ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        errno = 0;
        content_length = esp_http_client_fetch_headers(client);
        const int saved_errno = errno;
        if (content_length >= 0) break;
        if (content_length == -ESP_ERR_HTTP_EAGAIN ||
            saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
            wait_backoff(retry_delay_ms);
            continue;
        }
        return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                  : IdfLpaEs9TransportError::transport;
    }
    return IdfLpaEs9TransportError::none;
}

IdfLpaEs9TransportError stream_request(esp_http_client_handle_t client,
                                       std::string_view request,
                                       ResponseCapture& capture,
                                       Deadline& deadline)
{
    std::int64_t content_length = -1;
    const IdfLpaEs9TransportError headers_result = request_headers(
        client, request, capture, deadline, content_length);
    if (headers_result != IdfLpaEs9TransportError::none) return headers_result;
    if (content_length > static_cast<std::int64_t>(IDF_LPA_ES9_MAX_JSON_BYTES)) {
        return IdfLpaEs9TransportError::response_too_large;
    }

    std::array<char, 1024> buffer = {};
    std::uint32_t retry_delay_ms = 1U;
    while (!esp_http_client_is_complete_data_received(client)) {
        if (!deadline.apply(client)) return deadline.expired()
            ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        errno = 0;
        const int result = esp_http_client_read(client, buffer.data(), buffer.size());
        const int saved_errno = errno;
        if (retryable_io(result, saved_errno)) {
            wait_backoff(retry_delay_ms);
            continue;
        }
        if (result < 0) return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                                  : IdfLpaEs9TransportError::transport;
        if (result == 0) {
            if (esp_http_client_is_complete_data_received(client)) break;
            return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                      : IdfLpaEs9TransportError::transport;
        }
        retry_delay_ms = 1U;
        if (capture.error != CaptureError::none) {
            if (capture.error == CaptureError::response_too_large) {
                return IdfLpaEs9TransportError::response_too_large;
            }
            return IdfLpaEs9TransportError::response_body;
        }
    }
    if (capture.error == CaptureError::response_too_large) {
        return IdfLpaEs9TransportError::response_too_large;
    }
    if (capture.error == CaptureError::response_body) {
        return IdfLpaEs9TransportError::response_body;
    }
    return IdfLpaEs9TransportError::none;
}

IdfLpaEs9TransportError capture_error_result(const ResponseCapture& capture) noexcept
{
    switch (capture.error) {
    case CaptureError::none: return IdfLpaEs9TransportError::none;
    case CaptureError::timeout:
        return IdfLpaEs9TransportError::timeout;
    case CaptureError::response_too_large:
        return IdfLpaEs9TransportError::response_too_large;
    case CaptureError::response_status:
        return IdfLpaEs9TransportError::response_status;
    case CaptureError::response_protocol:
        return IdfLpaEs9TransportError::response_protocol;
    case CaptureError::response_body:
        return IdfLpaEs9TransportError::response_body;
    case CaptureError::redirect:
        return IdfLpaEs9TransportError::redirect;
    }
    return IdfLpaEs9TransportError::transport;
}

IdfLpaEs9TransportError perform_bpp_response(esp_http_client_handle_t client,
                                             ResponseCapture& capture,
                                             IdfLpaBppStream& bpp,
                                             std::string& safe_message,
                                             Deadline& deadline)
{
    capture.bpp = &bpp;
    capture.bpp_message = &safe_message;
    capture.deadline_us = deadline.deadline_us();
    std::uint32_t retry_delay_ms = 1U;
    while (true) {
        if (!deadline.apply(client)) return deadline.expired()
            ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        errno = 0;
        const esp_err_t result = esp_http_client_perform(client);
        const int saved_errno = errno;
        if (deadline.expired()) return IdfLpaEs9TransportError::timeout;
        if (capture.headers_complete) {
            if (capture.status_code < 0) {
                capture.status_code = esp_http_client_get_status_code(client);
            }
            if (capture.content_length == -1) {
                capture.content_length = esp_http_client_get_content_length(client);
            }
        }
        const IdfLpaEs9TransportError captured = capture_error_result(capture);
        if (captured != IdfLpaEs9TransportError::none) return captured;
        if (result == ESP_OK) break;

        const esp_http_state_t state = esp_http_client_get_state(client);
        const bool response_phase = state >= HTTP_STATE_REQ_COMPLETE_DATA;
        const bool eagain = result == ESP_ERR_HTTP_EAGAIN ||
                            result == -ESP_ERR_HTTP_EAGAIN ||
                            saved_errno == EAGAIN || saved_errno == EWOULDBLOCK;
        if (eagain) {
            if (!response_phase) {
                // 連線或標頭已有進度後不可重播請求 body；只有尚在進行中的
                // TLS 連線可以重試。
                if (state != HTTP_STATE_CONNECTING || capture.connected) {
                    return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                              : IdfLpaEs9TransportError::request_write;
                }
                wait_backoff(retry_delay_ms);
                continue;
            }
            wait_backoff(retry_delay_ms);
            continue;
        }
        if (deadline.expired()) return IdfLpaEs9TransportError::timeout;
        if (!response_phase) return IdfLpaEs9TransportError::request_write;
        if (result == ESP_ERR_HTTP_READ_TIMEOUT ||
            result == ESP_ERR_HTTP_INCOMPLETE_DATA ||
            result == ESP_ERR_HTTP_CONNECTION_CLOSED) {
            return IdfLpaEs9TransportError::response_body;
        }
        return IdfLpaEs9TransportError::transport;
    }

    const IdfLpaEs9TransportError captured = capture_error_result(capture);
    if (captured != IdfLpaEs9TransportError::none) return captured;
    if (capture.status_code < 0) {
        capture.status_code = esp_http_client_get_status_code(client);
    }
    if (capture.content_length == -1) {
        capture.content_length = esp_http_client_get_content_length(client);
    }
    if (capture.redirected) return IdfLpaEs9TransportError::redirect;
    if (capture.status_code != 200) return IdfLpaEs9TransportError::response_status;
    if (!valid_protocol_header(capture)) {
        return IdfLpaEs9TransportError::response_protocol;
    }
    if (capture.content_length == -2 ||
        (capture.content_length >= 0 &&
         capture.response_bytes != static_cast<std::size_t>(capture.content_length))) {
        return IdfLpaEs9TransportError::response_body;
    }
    return IdfLpaEs9TransportError::none;
}

#endif  // ESP_PLATFORM

}  // namespace

const char* idf_lpa_es9_transport_error_name(IdfLpaEs9TransportError error) noexcept
{
    switch (error) {
    case IdfLpaEs9TransportError::none: return "none";
    case IdfLpaEs9TransportError::invalid_operation: return "invalid-operation";
    case IdfLpaEs9TransportError::invalid_host: return "invalid-host";
    case IdfLpaEs9TransportError::invalid_request: return "invalid-request";
    case IdfLpaEs9TransportError::client_init: return "client-init";
    case IdfLpaEs9TransportError::config: return "config";
    case IdfLpaEs9TransportError::redirect: return "redirect";
    case IdfLpaEs9TransportError::request_write: return "request-write";
    case IdfLpaEs9TransportError::timeout: return "timeout";
    case IdfLpaEs9TransportError::transport: return "transport";
    case IdfLpaEs9TransportError::response_too_large: return "response-too-large";
    case IdfLpaEs9TransportError::response_status: return "response-status";
    case IdfLpaEs9TransportError::response_protocol: return "response-protocol";
    case IdfLpaEs9TransportError::response_body: return "response-body";
    case IdfLpaEs9TransportError::unknown: return "unknown";
    }
    return "unknown";
}

bool idf_lpa_es9_post_json(IdfLpaEs9Operation operation,
                           std::string_view smdp_host,
                           std::string_view request_json,
                           std::string& response_body,
                           IdfLpaEs9TransportError& error)
{
    const bool host_output_overlap = input_overlaps_output(smdp_host, response_body);
    const bool request_output_overlap = input_overlaps_output(request_json, response_body);
    secure_clear(response_body);
    error = IdfLpaEs9TransportError::none;
    if (host_output_overlap || request_output_overlap) return fail(
        error, IdfLpaEs9TransportError::invalid_request);
    OperationSpec spec = {};
    if (!operation_spec(operation, spec)) return fail(
        error, IdfLpaEs9TransportError::invalid_operation);
    if (!valid_smdp_host(smdp_host)) return fail(
        error, IdfLpaEs9TransportError::invalid_host);
    if (request_json.empty() || request_json.size() > IDF_LPA_ES9_MAX_JSON_BYTES ||
        request_json.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return fail(error, IdfLpaEs9TransportError::invalid_request);
    }

#ifndef ESP_PLATFORM
    (void)spec;
    (void)smdp_host;
    (void)request_json;
    return fail(error, IdfLpaEs9TransportError::transport);
#else
    std::string url;
    url.reserve(8U + smdp_host.size() + spec.path.size());
    url = "https://";
    url.append(smdp_host.data(), smdp_host.size());
    url.append(spec.path.data(), spec.path.size());

    ResponseCapture capture;
    esp_http_client_config_t config = {};
    configure_post_client(config, url.c_str(), request_json.size(), capture);

    Deadline deadline(IDF_LPA_ES9_TRANSACTION_TIMEOUT_MS);
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        secure_clear(url);
        return fail(error, IdfLpaEs9TransportError::client_init);
    }

    IdfLpaEs9TransportError result = IdfLpaEs9TransportError::none;
    int status_code;
    do {
        if (esp_http_client_set_method(client, HTTP_METHOD_POST) != ESP_OK ||
            esp_http_client_set_header(client, "Content-Type", "application/json") != ESP_OK ||
            esp_http_client_set_header(client, "X-Admin-Protocol", "gsma/rsp/v2.6.0") != ESP_OK) {
            result = IdfLpaEs9TransportError::config;
            break;
        }
        result = stream_request(client, request_json, capture, deadline);
        status_code = esp_http_client_get_status_code(client);
        if (result != IdfLpaEs9TransportError::none) break;
        if (capture.redirected) {
            result = IdfLpaEs9TransportError::redirect;
            break;
        }
        if (!valid_protocol_header(capture)) {
            result = IdfLpaEs9TransportError::response_protocol;
            break;
        }
        if ((!spec.empty_response && status_code != 200) ||
            (spec.empty_response && status_code != 204)) {
            result = IdfLpaEs9TransportError::response_status;
            break;
        }
        if (spec.empty_response) {
            if (capture.response_bytes != 0U || !capture.body.empty()) {
                result = IdfLpaEs9TransportError::response_body;
                break;
            }
        } else if (capture.response_bytes == 0U || capture.body.empty()) {
            result = IdfLpaEs9TransportError::response_body;
            break;
        }
        response_body = std::move(capture.body);
    } while (false);

    const esp_err_t close_result = close_http_once(client, capture);
    const esp_err_t cleanup_result = esp_http_client_cleanup(client);
    secure_clear(url);
    if (result == IdfLpaEs9TransportError::none &&
        (close_result != ESP_OK || cleanup_result != ESP_OK)) {
        result = IdfLpaEs9TransportError::transport;
    }
    if (result != IdfLpaEs9TransportError::none) {
        secure_clear(response_body);
        return fail(error, result);
    }
    error = IdfLpaEs9TransportError::none;
    return true;
#endif
}

bool idf_lpa_es9_get_bound_profile_package(
    std::string_view smdp_host,
    std::string_view request_json,
    std::string_view expected_transaction_id,
    const LpaRspProfileMetadata& expected_metadata,
    std::vector<std::uint8_t>& profile_installation_result,
    std::string& safe_message,
    IdfLpaEs9TransportError& error)
{
    const bool host_pir_overlap = input_overlaps_output(smdp_host,
                                                        profile_installation_result);
    const bool request_pir_overlap = input_overlaps_output(request_json,
                                                           profile_installation_result);
    const bool transaction_pir_overlap =
        input_overlaps_output(expected_transaction_id, profile_installation_result);
    const bool host_message_overlap = input_overlaps_output(smdp_host, safe_message);
    const bool request_message_overlap = input_overlaps_output(request_json, safe_message);
    const bool transaction_message_overlap =
        input_overlaps_output(expected_transaction_id, safe_message);
    const bool metadata_overlap =
        input_overlaps_output(expected_metadata.profile_name, profile_installation_result) ||
        input_overlaps_output(expected_metadata.service_provider_name, profile_installation_result) ||
        input_overlaps_output(expected_metadata.profile_name, safe_message) ||
        input_overlaps_output(expected_metadata.service_provider_name, safe_message);
    secure_clear(profile_installation_result);
    secure_clear(safe_message);
    error = IdfLpaEs9TransportError::none;
    if (host_pir_overlap || request_pir_overlap || transaction_pir_overlap ||
        host_message_overlap || request_message_overlap || transaction_message_overlap || metadata_overlap) {
        return fail(error, IdfLpaEs9TransportError::invalid_request);
    }
    if (!valid_smdp_host(smdp_host)) {
        return fail(error, IdfLpaEs9TransportError::invalid_host);
    }
    if (request_json.empty() ||
        expected_metadata.has_policy_rules ||
        expected_metadata.profile_name.size() > IDF_LPA_RSP_MAX_PROFILE_NAME_BYTES ||
        expected_metadata.service_provider_name.size() > IDF_LPA_RSP_MAX_PROVIDER_NAME_BYTES ||
        request_json.size() > IDF_LPA_ES9_MAX_JSON_BYTES ||
        request_json.size() > static_cast<std::size_t>(std::numeric_limits<int>::max())) {
        return fail(error, IdfLpaEs9TransportError::invalid_request);
    }

#ifndef ESP_PLATFORM
    (void)expected_transaction_id;
    (void)expected_metadata;
    (void)smdp_host;
    (void)request_json;
    return fail(error, IdfLpaEs9TransportError::transport);
#else
    Deadline deadline(IDF_LPA_ES9_BPP_TRANSACTION_TIMEOUT_MS);
    IdfLpaBppStream bpp(expected_transaction_id, expected_metadata);
    std::string url;
    url.reserve(8U + smdp_host.size() +
                std::string_view("/gsma/rsp2/es9plus/getBoundProfilePackage").size());
    url = "https://";
    url.append(smdp_host.data(), smdp_host.size());
    url.append("/gsma/rsp2/es9plus/getBoundProfilePackage");

    ResponseCapture capture;
    capture.stream_body = true;
    esp_http_client_config_t config = {};
    configure_post_client(config, url.c_str(), request_json.size(), capture);

    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        bpp.abort();
        secure_clear(url);
        return fail(error, IdfLpaEs9TransportError::client_init);
    }

    IdfLpaEs9TransportError result;
    if (esp_http_client_set_method(client, HTTP_METHOD_POST) != ESP_OK ||
        esp_http_client_set_header(client, "Content-Type", "application/json") != ESP_OK ||
        esp_http_client_set_header(client, "X-Admin-Protocol", "gsma/rsp/v2.6.0") != ESP_OK ||
        esp_http_client_set_post_field(client, request_json.data(),
                                       static_cast<int>(request_json.size())) != ESP_OK) {
        result = IdfLpaEs9TransportError::config;
    } else {
        result = perform_bpp_response(client, capture, bpp, safe_message, deadline);
    }

    const esp_err_t close_result = close_http_once(client, capture);
    const esp_err_t cleanup_result = esp_http_client_cleanup(client);
    secure_clear(url);
    if (result == IdfLpaEs9TransportError::none &&
        (close_result != ESP_OK || cleanup_result != ESP_OK)) {
        result = IdfLpaEs9TransportError::transport;
    }
    if (result == IdfLpaEs9TransportError::none) {
        if (deadline.expired()) {
            result = IdfLpaEs9TransportError::timeout;
        } else {
            const esp_err_t finish_result =
                bpp.finish(profile_installation_result, safe_message);
            const bool finish_expired = deadline.expired();
            if (finish_result != ESP_OK) {
                result = IdfLpaEs9TransportError::response_body;
            } else if (finish_expired) {
                result = IdfLpaEs9TransportError::timeout;
            }
        }
    }
    if (result != IdfLpaEs9TransportError::none) {
        bpp.abort();
        secure_clear(profile_installation_result);
        secure_clear(safe_message);
        return fail(error, result);
    }
    error = IdfLpaEs9TransportError::none;
    return true;
#endif
}
