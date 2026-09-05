#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

constexpr std::size_t IDF_LPA_ES9_MAX_JSON_BYTES = 24U * 1024U;
constexpr std::uint32_t IDF_LPA_ES9_IO_TIMEOUT_MS = 15000U;
constexpr std::uint32_t IDF_LPA_ES9_TRANSACTION_TIMEOUT_MS = 60000U;

enum class IdfLpaEs9Operation : std::uint8_t {
    initiate_authentication,
    authenticate_client,
    handle_notification,
};

enum class IdfLpaEs9TransportError : std::uint8_t {
    none,
    invalid_operation,
    invalid_host,
    invalid_request,
    client_init,
    config,
    redirect,
    request_write,
    timeout,
    transport,
    response_too_large,
    response_status,
    response_protocol,
    response_body,
    unknown,
};

const char* idf_lpa_es9_transport_error_name(IdfLpaEs9TransportError error) noexcept;

// Sends one fixed ES9+ JSON operation over HTTPS.  The caller owns the response body.
// On every failure, response_body is securely cleared and error contains only a closed enum.
// smdp_host 與 request_json 不得與 response_body 的儲存區重疊；重疊輸入會 fail closed。
bool idf_lpa_es9_post_json(IdfLpaEs9Operation operation,
                           std::string_view smdp_host,
                           std::string_view request_json,
                           std::string& response_body,
                           IdfLpaEs9TransportError& error);
