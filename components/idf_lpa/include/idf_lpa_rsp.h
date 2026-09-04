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
