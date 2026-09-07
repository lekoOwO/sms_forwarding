#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

// ES9+ response bodies are bounded before any parser or allocation is used.
constexpr std::size_t IDF_LPA_RSP_MAX_JSON_BYTES = 24U * 1024U;
constexpr std::size_t IDF_LPA_RSP_MAX_OBJECT_BYTES = 8U * 1024U;
constexpr std::size_t IDF_LPA_RSP_MAX_CONFIRMATION_BYTES = 128U;
constexpr std::size_t IDF_LPA_RSP_MAX_PROVIDER_NAME_BYTES = 128U;
constexpr std::size_t IDF_LPA_RSP_MAX_PROFILE_NAME_BYTES = 256U;

enum class LpaRspError {
    none,
    input_too_large,
    json_malformed,
    json_duplicate,
    json_missing,
    json_type,
    server_error,
    base64_malformed,
    base64_noncanonical,
    object_too_large,
    der_malformed,
    der_root,
    field_missing,
    der_duplicate,
    transaction_mismatch,
    challenge_mismatch,
    address_mismatch,
    confirmation_malformed,
    matching_id,
    crypto_input,
    transaction_malformed,
    crypto_failure,
    unknown,
};

const char* idf_lpa_rsp_error_name(LpaRspError error) noexcept;

bool idf_lpa_rsp_parse_status(std::string_view json,
                              bool& success,
                              LpaRspError& error);

bool idf_lpa_rsp_json_get_string(std::string_view json,
                                 std::string_view key,
                                 std::string& out,
                                 LpaRspError& error);

bool idf_lpa_rsp_base64_encode(const std::uint8_t* input,
                               std::size_t input_size,
                               std::string& out,
                               LpaRspError& error);

bool idf_lpa_rsp_base64_decode(std::string_view input,
                               std::vector<std::uint8_t>& out,
                               LpaRspError& error);

bool idf_lpa_rsp_decode_transaction_id(std::string_view input,
                                       std::array<std::uint8_t, 16>& out,
                                       std::size_t& out_size,
                                       LpaRspError& error);

bool idf_lpa_rsp_transaction_id_matches(std::string_view input,
                                        const std::uint8_t* expected,
                                        std::size_t expected_size,
                                        LpaRspError& error);

bool idf_lpa_rsp_validate_matching_id(std::string_view matching_id,
                                      LpaRspError& error);

enum class LpaRspDerObject {
    server_signed1,
    smdp_signed2,
    authenticate_server_response,
    prepare_download_response,
    profile_metadata,
    notification_metadata,
    profile_installation_result,
    signature,
    ci_key,
    server_signature1 = signature,
    ci_key_id = ci_key,
};

// Validates only one bounded, canonical DER root and its expected tag.  It
// deliberately does not claim to validate the child schema for that object;
// specialized functions below perform their own required-field checks.
bool idf_lpa_rsp_validate_der_structure(const std::uint8_t* object,
                                        std::size_t object_size,
                                        LpaRspDerObject kind,
                                        LpaRspError& error);

bool idf_lpa_rsp_validate_server_signed1(const std::uint8_t* object,
                                         std::size_t object_size,
                                         const std::uint8_t* transaction_id,
                                         std::size_t transaction_size,
                                         const std::array<std::uint8_t, 16>& euicc_challenge,
                                         std::string_view expected_address,
                                         LpaRspError& error);

bool idf_lpa_rsp_parse_smdp_signed2(const std::uint8_t* object,
                                    std::size_t object_size,
                                    const std::uint8_t* transaction_id,
                                    std::size_t transaction_size,
                                    bool& confirmation_required,
                                    LpaRspError& error);

bool idf_lpa_rsp_compute_hash_cc(std::string_view confirmation_code,
                                 const std::uint8_t* transaction_id,
                                 std::size_t transaction_size,
                                 std::array<std::uint8_t, 32>& hash_cc,
                                 LpaRspError& error);

// 输入为已解码的 DER 对象；会话挑战及 SM-DP+ 地址须先由调用者绑定验证。
bool idf_lpa_rsp_build_authenticate_server_request(
    const std::vector<std::uint8_t>& server_signed1,
    const std::vector<std::uint8_t>& server_signature1,
    const std::vector<std::uint8_t>& ci_key_id,
    const std::vector<std::uint8_t>& server_certificate,
    std::string_view matching_id,
    std::string_view imei,
    const std::vector<std::uint8_t>& device_capabilities,
    std::vector<std::uint8_t>& request,
    LpaRspError& error);

// 校验卡片回应与原 BF38 请求的交易、地址、serverChallenge 和完整 context；
// 返回完整 BF38。仅验证结构和绑定，不替代 eUICC/服务器的密码签章验证。
bool idf_lpa_rsp_parse_authenticate_server_response(
    const std::uint8_t* object,
    std::size_t object_size,
    const std::vector<std::uint8_t>& expected_request,
    std::vector<std::uint8_t>& authenticate_client_response,
    LpaRspError& error);

bool idf_lpa_rsp_build_prepare_download_request(
    const std::vector<std::uint8_t>& smdp_signed2,
    const std::vector<std::uint8_t>& smdp_signature2,
    const std::vector<std::uint8_t>& smdp_certificate,
    const std::array<std::uint8_t, 32>* hash_cc,
    std::vector<std::uint8_t>& request,
    LpaRspError& error);

struct LpaRspProfileMetadata {
    std::string service_provider_name;
    std::string profile_name;
    bool has_policy_rules = false;
};

// 僅匯出有界、可顯示的名稱及 PPR 存在旗標，不執行 RAT/PPR 授權。
bool idf_lpa_rsp_parse_profile_metadata(const std::uint8_t* object,
                                         std::size_t object_size,
                                         LpaRspProfileMetadata& metadata,
                                         LpaRspError& error);

enum class LpaRspCancelReason : std::uint8_t {
    end_user_rejection = 0,
    postponed = 1,
    timeout = 2,
    ppr_not_allowed = 3,
    metadata_mismatch = 4,
    load_bpp_execution_error = 5,
    undefined_reason = 127,
};

bool idf_lpa_rsp_build_cancel_session_request(
    const std::uint8_t* transaction, std::size_t transaction_size,
    LpaRspCancelReason reason, std::vector<std::uint8_t>& request, LpaRspError& error);

// 回傳完整 BF41；驗證交易、原因及結構，OID/簽章密碼驗證仍由 eUICC/伺服器負責。
bool idf_lpa_rsp_parse_cancel_session_response(
    const std::uint8_t* object, std::size_t object_size,
    const std::uint8_t* transaction, std::size_t transaction_size,
    LpaRspCancelReason reason, std::vector<std::uint8_t>& response, LpaRspError& error);

// 驗證 PrepareDownloadResponse，僅回傳後續 GetBPP 所需的有界 response body；
// 不驗證密碼簽章，也不宣稱可證明實際 eUICC 行為。
bool idf_lpa_rsp_parse_prepare_download_response(
    const std::uint8_t* object,
    std::size_t object_size,
    const std::uint8_t* expected_transaction,
    std::size_t expected_transaction_size,
    std::vector<std::uint8_t>& get_bpp_response,
    LpaRspError& error);

// 驗證 ProfileInstallationResult，僅回傳移除待處理通知所需的 metadata；
// 不驗證密碼簽章，也不宣稱可證明實際 eUICC 行為。
bool idf_lpa_rsp_parse_profile_installation_result(
    const std::uint8_t* object,
    std::size_t object_size,
    const std::uint8_t* expected_transaction,
    std::size_t expected_transaction_size,
    std::string_view expected_activation_host,
    std::uint32_t& sequence_number,
    std::string& notification_address,
    LpaRspError& error);

// true 只表示通知结构及会话绑定有效；installed 单独表示安装结果。
bool idf_lpa_rsp_parse_profile_installation_notification(
    const std::uint8_t* object,
    std::size_t object_size,
    const std::uint8_t* expected_transaction,
    std::size_t expected_transaction_size,
    std::string_view expected_activation_host,
    bool& installed,
    std::uint32_t& sequence_number,
    std::string& notification_address,
    LpaRspError& error);

// 仅接受同一 SM-DP+ 的历史安装通知，不借用新交易 ID，也不处理其他通知类别。
bool idf_lpa_rsp_parse_pending_installation_notification(
    const std::uint8_t* object,
    std::size_t object_size,
    std::string_view expected_activation_host,
    bool& installed,
    std::uint32_t& sequence_number,
    std::string& notification_address,
    LpaRspError& error);
