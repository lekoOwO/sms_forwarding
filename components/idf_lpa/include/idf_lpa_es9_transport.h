#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "idf_lpa_rsp.h"

constexpr std::size_t IDF_LPA_ES9_MAX_JSON_BYTES = 24U * 1024U;
constexpr std::uint32_t IDF_LPA_ES9_IO_TIMEOUT_MS = 15000U;
constexpr std::uint32_t IDF_LPA_ES9_TRANSACTION_TIMEOUT_MS = 60000U;
constexpr std::uint32_t IDF_LPA_ES9_BPP_TRANSACTION_TIMEOUT_MS = 30U * 60U * 1000U;
constexpr std::size_t IDF_LPA_ES9_BPP_MAX_WIRE_BYTES =
    1536U * 1024U + 64U * 1024U;

enum class IdfLpaEs9Operation : std::uint8_t {
    initiate_authentication,
    authenticate_client,
    handle_notification,
    cancel_session,
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

// 以固定 GetBoundProfilePackage 路徑串流 BPP response；不快取伺服器 body。
// 只有 HTTP preflight 通過後才會將 body 餵給 BPP，成功只回傳單一 PIR，交由上層驗證。
// expected_metadata 必須是已同意且無 PPR 的 metadata；串流器會在送出 A1/88 前比對。
// 失敗時清除 PIR 與安全訊息，且不會通知、移除或啟用 profile。
bool idf_lpa_es9_get_bound_profile_package(
    std::string_view smdp_host,
    std::string_view request_json,
    std::string_view expected_transaction_id,
    const LpaRspProfileMetadata& expected_metadata,
    std::vector<std::uint8_t>& profile_installation_result,
    std::string& safe_message,
    IdfLpaEs9TransportError& error);
