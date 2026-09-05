#include "idf_lpa_es9_transport.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

#ifdef ESP_PLATFORM
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

bool input_overlaps_output(std::string_view input,
                           const std::string& output) noexcept
{
    if (input.empty() || output.capacity() == 0U) return false;
    const std::uintptr_t input_begin = reinterpret_cast<std::uintptr_t>(input.data());
    const std::uintptr_t output_begin = reinterpret_cast<std::uintptr_t>(output.data());
    const std::uintptr_t max_address = std::numeric_limits<std::uintptr_t>::max();
    if (input_begin == 0U || output_begin == 0U ||
        input.size() > max_address - input_begin ||
        output.capacity() > max_address - output_begin) {
        return true;
    }
    const std::uintptr_t input_end = input_begin + input.size();
    const std::uintptr_t output_end = output_begin + output.capacity();
    return input_begin < output_end && output_begin < input_end;
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
    response_too_large,
    response_body,
};

struct ResponseCapture {
    std::string protocol;
    std::string body;
    std::size_t response_bytes = 0U;
    bool connected = false;
    bool protocol_seen = false;
    bool protocol_duplicate = false;
    bool redirected = false;
    CaptureError error = CaptureError::none;

    ~ResponseCapture() noexcept
    {
        secure_clear(protocol);
        secure_clear(body);
    }
};

void capture_error(ResponseCapture& capture, CaptureError error) noexcept
{
    if (capture.error == CaptureError::none) capture.error = error;
}

esp_err_t on_http_event(esp_http_client_event_t* event)
{
    if (!event || !event->user_data) return ESP_OK;
    auto* capture = static_cast<ResponseCapture*>(event->user_data);
    if (event->event_id == HTTP_EVENT_ON_CONNECTED) {
        capture->connected = true;
        return ESP_OK;
    }
    if (event->event_id == HTTP_EVENT_REDIRECT) {
        capture->redirected = true;
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
            capture->protocol.assign(value ? value : "", value_size);
        }
        return ESP_OK;
    }
    if (event->event_id != HTTP_EVENT_ON_DATA) return ESP_OK;
    if (event->data_len < 0 || (event->data_len != 0 && !event->data)) {
        capture_error(*capture, CaptureError::response_body);
        return ESP_OK;
    }
    const std::size_t data_size = static_cast<std::size_t>(event->data_len);
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
    Deadline()
        : deadline_us_(esp_timer_get_time() +
                       static_cast<std::int64_t>(IDF_LPA_ES9_TRANSACTION_TIMEOUT_MS) *
                           1000LL) {}

    bool expired() const noexcept
    {
        return esp_timer_get_time() >= deadline_us_;
    }

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

void wait_again() noexcept
{
    vTaskDelay(pdMS_TO_TICKS(1U));
}

bool retryable_io(int result, int saved_errno) noexcept
{
    return result == -ESP_ERR_HTTP_EAGAIN ||
           result == ESP_TLS_ERR_SSL_WANT_READ ||
           result == ESP_TLS_ERR_SSL_WANT_WRITE ||
           saved_errno == EAGAIN || saved_errno == EWOULDBLOCK;
}

IdfLpaEs9TransportError stream_request(esp_http_client_handle_t client,
                                       std::string_view request,
                                       ResponseCapture& capture,
                                       Deadline& deadline)
{
    while (true) {
        if (!deadline.apply(client)) return deadline.expired()
            ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        const esp_err_t open_result = esp_http_client_open(
            client, static_cast<int>(request.size()));
        if (open_result == ESP_OK) break;
        // ESP-IDF maps asynchronous connect progress and request-header
        // transport EAGAIN to ESP_ERR_HTTP_EAGAIN.  Retry only before the
        // connected event, when no request header can have been sent; once
        // connected, fail closed rather than replaying a possible prefix.
        if (open_result != ESP_ERR_HTTP_EAGAIN || capture.connected) {
            return deadline.expired()
                ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        }
        wait_again();
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
        // esp_http_client_write() can report no progress after its internal
        // request headers have already reached the transport.  Its return
        // value and errno do not prove that replaying this ES9+ body is safe,
        // so every non-positive result fails closed after one call.
        return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                  : IdfLpaEs9TransportError::request_write;
    }

    std::int64_t content_length = -1;
    while (true) {
        if (!deadline.apply(client)) return deadline.expired()
            ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        errno = 0;
        content_length = esp_http_client_fetch_headers(client);
        const int saved_errno = errno;
        if (content_length >= 0) break;
        if (content_length == -ESP_ERR_HTTP_EAGAIN ||
            saved_errno == EAGAIN || saved_errno == EWOULDBLOCK) {
            wait_again();
            continue;
        }
        return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                  : IdfLpaEs9TransportError::transport;
    }
    if (content_length > static_cast<std::int64_t>(IDF_LPA_ES9_MAX_JSON_BYTES)) {
        return IdfLpaEs9TransportError::response_too_large;
    }

    std::array<char, 1024> buffer = {};
    while (!esp_http_client_is_complete_data_received(client)) {
        if (!deadline.apply(client)) return deadline.expired()
            ? IdfLpaEs9TransportError::timeout : IdfLpaEs9TransportError::transport;
        errno = 0;
        const int result = esp_http_client_read(client, buffer.data(), buffer.size());
        const int saved_errno = errno;
        if (retryable_io(result, saved_errno)) {
            wait_again();
            continue;
        }
        if (result < 0) return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                                  : IdfLpaEs9TransportError::transport;
        if (result == 0) {
            if (esp_http_client_is_complete_data_received(client)) break;
            return deadline.expired() ? IdfLpaEs9TransportError::timeout
                                      : IdfLpaEs9TransportError::transport;
        }
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
    config.url = url.c_str();
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
        32768U, std::max<std::size_t>(2048U, request_json.size() + 512U)));
    config.crt_bundle_attach = esp_crt_bundle_attach;
    config.event_handler = on_http_event;
    config.user_data = &capture;

    Deadline deadline;
    esp_http_client_handle_t client = esp_http_client_init(&config);
    if (!client) {
        secure_clear(url);
        return fail(error, IdfLpaEs9TransportError::client_init);
    }

    IdfLpaEs9TransportError result = IdfLpaEs9TransportError::none;
    int status_code = 0;
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
        if (!capture.protocol_seen || capture.protocol_duplicate ||
            !valid_admin_protocol(capture.protocol)) {
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

    const esp_err_t close_result = esp_http_client_close(client);
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
