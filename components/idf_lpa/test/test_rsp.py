import subprocess
import shutil
import tempfile
import unittest
from pathlib import Path


COMPONENT = Path(__file__).resolve().parents[1]
HEADER = COMPONENT / "include" / "idf_lpa_rsp.h"
SOURCE = COMPONENT / "idf_lpa_rsp.cpp"
ACTIVATION_SOURCE = COMPONENT / "idf_lpa_activation_code.cpp"
CODEC_SOURCE = COMPONENT.parent / "idf_esim" / "idf_esim_codec.cpp"
CODEC_INCLUDE = COMPONENT.parent / "idf_esim" / "include"


HOST_CPP = r'''
#include "idf_lpa_rsp.h"

#include <array>
#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using Error = LpaRspError;

static std::vector<uint8_t> tlv(std::initializer_list<uint8_t> tag,
                                const std::vector<uint8_t>& value)
{
    std::vector<uint8_t> out(tag);
    if (value.size() < 128U) {
        out.push_back(static_cast<uint8_t>(value.size()));
    } else if (value.size() <= 0xFFU) {
        out.push_back(0x81U);
        out.push_back(static_cast<uint8_t>(value.size()));
    } else {
        assert(value.size() <= 0xFFFFU);
        out.push_back(0x82U);
        out.push_back(static_cast<uint8_t>(value.size() >> 8U));
        out.push_back(static_cast<uint8_t>(value.size()));
    }
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

static std::vector<uint8_t> joined(const std::vector<std::vector<uint8_t>>& parts)
{
    std::vector<uint8_t> out;
    for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

static std::vector<uint8_t> sequence(const std::vector<std::vector<uint8_t>>& children)
{
    return tlv({0x30}, joined(children));
}

static std::vector<uint8_t> prepare_download_success(
    const std::vector<uint8_t>& transaction,
    std::vector<uint8_t> hash_cc = std::vector<uint8_t>(32U, 0xCCU))
{
    const auto signed_data = sequence({
        tlv({0x80}, transaction),
        tlv({0x5F, 0x49}, {0x01, 0x02, 0x03}),
        hash_cc.empty() ? std::vector<uint8_t>() : tlv({0x04}, hash_cc),
    });
    return tlv({0xBF, 0x21}, tlv({0xA0}, joined({
        signed_data,
        tlv({0x5F, 0x37}, {0xAA, 0xBB}),
    })));
}

static std::vector<uint8_t> prepare_download_error(const std::vector<uint8_t>& transaction,
                                                   const std::vector<uint8_t>& code = {0x01})
{
    return tlv({0xBF, 0x21}, tlv({0xA1}, joined({
        tlv({0x80}, transaction),
        tlv({0x02}, code),
    })));
}

static std::vector<uint8_t> notification_metadata(
    std::vector<uint8_t> sequence = {0x01},
    std::vector<uint8_t> operation = {0x07, 0x80},
    std::vector<uint8_t> address = {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'},
    std::vector<uint8_t> iccid = {0x98, 0x88, 0x12, 0x32, 0x54,
                                  0x76, 0x98, 0x10, 0x32, 0xF4})
{
    std::vector<std::vector<uint8_t>> fields = {
        tlv({0x80}, sequence),
        tlv({0x81}, operation),
        tlv({0x0C}, address),
    };
    if (!iccid.empty()) fields.push_back(tlv({0x5A}, iccid));
    return tlv({0xBF, 0x2F}, joined(fields));
}

static std::vector<uint8_t> pir_error_result(uint8_t command_id = 0x05U,
                                             uint8_t reason = 0x01U,
                                             std::vector<uint8_t> sima_response = {})
{
    std::vector<std::vector<uint8_t>> fields = {
        tlv({0x02}, {command_id}),
        tlv({0x02}, {reason}),
    };
    if (!sima_response.empty()) fields.push_back(tlv({0x04}, sima_response));
    return tlv({0xA2}, tlv({0xA1}, joined(fields)));
}

static std::vector<uint8_t> profile_installation_result(
    const std::vector<uint8_t>& transaction,
    std::vector<uint8_t> metadata = notification_metadata(),
    std::vector<uint8_t> final_result = tlv({0xA2}, tlv({0xA0}, joined({
        tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}),
        tlv({0x04}, {0x90, 0x00}),
    }))),
    std::vector<uint8_t> oid = {0x2B, 0x06, 0x01, 0x04, 0x01})
{
    const auto signed_data = tlv({0xBF, 0x27}, joined({
        tlv({0x80}, transaction),
        metadata,
        tlv({0x06}, oid),
        final_result,
    }));
    return tlv({0xBF, 0x37}, joined({
        signed_data,
        tlv({0x5F, 0x37}, {0xCC, 0xDD}),
    }));
}

static void expect_der_kind(LpaRspDerObject kind,
                            const std::vector<uint8_t>& value)
{
    Error error = Error::unknown;
    assert(idf_lpa_rsp_validate_der_structure(value.data(), value.size(), kind, error));
    assert(error == Error::none);
}

static void profile_metadata_consent_contract()
{
    Error error = Error::unknown;
    LpaRspProfileMetadata metadata;
    const auto iccid = tlv({0x5A}, {0x98,0x88,0x12,0x32,0x54,0x76,0x98,0x10,0x32,0xF4});
    const auto provider = tlv({0x91}, {'T','e','s','t',' ','M','o','b','i','l','e'});
    const auto name = tlv({0x92}, {0xE6,0x97,0x85,0xE8,0xA1,0x8C}); // 旅行
    const auto normal = tlv({0xBF, 0x25}, joined({iccid, provider, name}));
    assert(idf_lpa_rsp_parse_profile_metadata(normal.data(), normal.size(), metadata, error));
    assert(metadata.service_provider_name == "Test Mobile" && metadata.profile_name == "旅行" &&
        !metadata.has_policy_rules && error == Error::none);
    const auto with_policy = tlv({0xBF,0x25}, joined({iccid, provider, name,
        tlv({0xB7}, tlv({0x80}, {0x42,0xF6,0x18})), tlv({0x99}, {0x06,0x40})}));
    assert(idf_lpa_rsp_parse_profile_metadata(with_policy.data(), with_policy.size(), metadata, error));
    assert(metadata.has_policy_rules && metadata.profile_name == "旅行");
    for (const auto& malformed : {
        tlv({0xBF,0x25}, joined({iccid, name})),
        tlv({0xBF,0x25}, joined({iccid, name, provider})),
        tlv({0xBF,0x25}, joined({iccid, provider, name, name})),
        tlv({0xBF,0x25}, joined({iccid, provider, tlv({0x92}, {0xC0,0xAF})})),
        tlv({0xBF,0x25}, joined({iccid, provider, tlv({0x92}, {'b',0,'d'})})),
        tlv({0xBF,0x25}, joined({iccid, provider, tlv({0x92}, std::vector<uint8_t>(65,'x'))})),
        tlv({0xBF,0x25}, joined({iccid, provider, name, tlv({0x94}, {1})})),
        tlv({0xBF,0x25}, joined({iccid, provider, name, tlv({0x99}, {8,0x40})})),
        tlv({0xBF,0x2F}, joined({iccid, provider, name}))}) {
        metadata = {"stale", "stale", true};
        assert(!idf_lpa_rsp_parse_profile_metadata(malformed.data(), malformed.size(), metadata, error));
        assert(metadata.service_provider_name.empty() && metadata.profile_name.empty() &&
            !metadata.has_policy_rules);
    }
    // UTF8String SIZE counts characters, not bytes (SGP.22 2.8.2).
    std::vector<uint8_t> wide_name;
    for (unsigned i = 0; i < 64; ++i) wide_name.insert(wide_name.end(), {0xE6,0x97,0x85});
    const auto wide = tlv({0xBF,0x25}, joined({iccid, provider, tlv({0x92}, wide_name)}));
    assert(idf_lpa_rsp_parse_profile_metadata(wide.data(), wide.size(), metadata, error));
    assert(metadata.profile_name.size() == 192U);
}

static void cancel_session_wire_and_binding_contract()
{
    Error error = Error::unknown;
    const std::array<uint8_t,2> transaction = {1,2};
    std::vector<uint8_t> request;
    assert(idf_lpa_rsp_build_cancel_session_request(transaction.data(), transaction.size(),
        LpaRspCancelReason::postponed, request, error));
    assert(request == (std::vector<uint8_t>{0xBF,0x41,7,0x80,2,1,2,0x81,1,1}));
    const auto response = [&](std::vector<uint8_t> tx, std::vector<uint8_t> reason,
                              std::vector<uint8_t> oid = {0x2B,0x06,0x01,0x04,0x01}) {
        return tlv({0xBF,0x41}, tlv({0xA0}, joined({sequence({tlv({0x80},tx),
            tlv({0x81},oid), tlv({0x82},reason)}), tlv({0x5F,0x37},{0xAA,0xBB})})));
    };
    const auto accepted = response({1,2},{1});
    std::vector<uint8_t> forwarded;
    assert(idf_lpa_rsp_parse_cancel_session_response(accepted.data(), accepted.size(),
        transaction.data(), transaction.size(), LpaRspCancelReason::postponed, forwarded, error));
    assert(forwarded == accepted && error == Error::none);
    for (const auto& wrong : {response({1,3},{1}), response({1,2},{0}),
                              response({1,2},{1},{0x80}),
                              tlv({0xBF,0x41}, tlv({0x81},{5}))}) {
        forwarded = {0xEE};
        assert(!idf_lpa_rsp_parse_cancel_session_response(wrong.data(), wrong.size(),
            transaction.data(), transaction.size(), LpaRspCancelReason::postponed, forwarded, error));
        assert(forwarded.empty());
    }
    assert(!idf_lpa_rsp_build_cancel_session_request(transaction.data(), transaction.size(),
        static_cast<LpaRspCancelReason>(6), request, error));
    assert(request.empty());
    assert(!idf_lpa_rsp_build_cancel_session_request(nullptr, 0,
        LpaRspCancelReason::postponed, request, error));
    assert(request.empty());
    forwarded = accepted;
    assert(!idf_lpa_rsp_parse_cancel_session_response(forwarded.data(), forwarded.size(),
        transaction.data(), transaction.size(), LpaRspCancelReason::postponed, forwarded, error));
    assert(forwarded.empty());
}

static void install_request_wire_and_binding_contract()
{
    Error error = Error::unknown;
    const std::vector<uint8_t> transaction = {0x01, 0x02};
    const std::vector<uint8_t> host = {'e','d','g','e','.','e','x','a','m','p','l','e'};
    const std::vector<uint8_t> challenge(16U, 0xBBU);
    const auto signed1 = sequence({tlv({0x80}, transaction),
        tlv({0x81}, std::vector<uint8_t>(16U, 0xAAU)), tlv({0x83}, host),
        tlv({0x84}, challenge)});
    const auto signature = tlv({0x5F, 0x37}, {0xAA, 0xBB});
    const auto key = tlv({0x04}, {0xCC});
    // Structurally complete synthetic certificates; cryptography belongs to the card/server.
    const auto certificate = sequence({tlv({0x02}, {0x01})});
    const std::vector<uint8_t> capabilities = {0x30, 0x00};
    // Independent SGP.22 4.2/5.7.13 wire oracle. IMEI check digit is HIGH, filler F LOW.
    const std::vector<uint8_t> context = {
        0xA0, 0x1B, 0x80, 0x05, 'T','O','K','E','N', 0xA1, 0x12,
        0x80, 0x04, 0x68, 0x00, 0x00, 0x00, 0xA1, 0x00,
        0x82, 0x08, 0x68, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1F};
    std::vector<uint8_t> request = {0xEE};
    assert(idf_lpa_rsp_build_authenticate_server_request(signed1, signature, key,
        certificate, "TOKEN", "860000000000001", capabilities, request, error));
    assert(request == tlv({0xBF, 0x38}, joined({signed1, signature, key, certificate, context})));
    const auto original_request = request;
    const auto response = [&](const std::vector<uint8_t>& tx,
                              const std::vector<uint8_t>& address,
                              const std::vector<uint8_t>& nonce,
                              const std::vector<uint8_t>& ctx) {
        const auto euicc_signed1 = sequence({tlv({0x80}, tx), tlv({0x83}, address),
            tlv({0x84}, nonce), tlv({0xBF, 0x22}, tlv({0x80}, {0x01})), ctx});
        return tlv({0xBF, 0x38}, tlv({0xA0}, joined({euicc_signed1, signature,
                                                     certificate, certificate})));
    };
    const auto accepted = response(transaction, host, challenge, context);
    std::vector<uint8_t> extracted = {0xEE};
    assert(idf_lpa_rsp_parse_authenticate_server_response(accepted.data(), accepted.size(),
        request, extracted, error));
    assert(extracted == accepted && error == Error::none);
    const auto reject_response = [&](const std::vector<uint8_t>& changed, Error reason) {
        extracted = {0xEE};
        assert(!idf_lpa_rsp_parse_authenticate_server_response(changed.data(), changed.size(),
            request, extracted, error));
        assert(extracted.empty() && error == reason);
    };
    reject_response(response({0x01, 0x03}, host, challenge, context), Error::transaction_mismatch);
    reject_response(response(transaction, {'e','v','i','l','.','e','x','a','m','p','l','e'},
        challenge, context), Error::address_mismatch);
    reject_response(response(transaction, host, std::vector<uint8_t>(16U, 0xBCU), context),
        Error::challenge_mismatch);
    auto changed_context = context;
    changed_context.back() = 0x2F;
    reject_response(response(transaction, host, challenge, changed_context), Error::der_malformed);
    reject_response(tlv({0xBF, 0x38}, tlv({0xA1}, joined({tlv({0x80}, transaction),
        tlv({0x02}, {0x02})}))), Error::server_error);
    reject_response(tlv({0xBF, 0x38}, tlv({0xA1}, joined({tlv({0x80}, {0x03}),
        tlv({0x02}, {0x02})}))), Error::transaction_mismatch);
    assert(!idf_lpa_rsp_build_authenticate_server_request(signed1, signature, key,
        certificate, "TOKEN", "86000000000000X", capabilities, request, error));
    assert(request.empty());
    assert(!idf_lpa_rsp_build_authenticate_server_request(signed1, signature, key,
        {0x30, 0x00}, "TOKEN", "860000000000001", capabilities, request, error));
    assert(request.empty());
    const auto large_certificate = sequence({tlv({0x04}, std::vector<uint8_t>(8100U, 0xAAU))});
    assert(!idf_lpa_rsp_build_authenticate_server_request(signed1, signature, key,
        large_certificate, "TOKEN", "860000000000001", capabilities, request, error));
    assert(request.empty() && error == Error::object_too_large);
    auto alias = signed1;
    assert(!idf_lpa_rsp_build_authenticate_server_request(alias, signature, key,
        certificate, "TOKEN", "860000000000001", capabilities, alias, error));
    assert(alias.empty());
    extracted = accepted;
    assert(!idf_lpa_rsp_parse_authenticate_server_response(extracted.data(), extracted.size(),
        original_request, extracted, error));
    assert(extracted.empty());

    const auto signed2 = sequence({tlv({0x80}, transaction), tlv({0x01}, {0xFF})});
    std::array<uint8_t, 32> hash_cc{};
    hash_cc.fill(0xCC);
    assert(idf_lpa_rsp_build_prepare_download_request(signed2, signature, certificate,
        &hash_cc, request, error));
    assert(request == tlv({0xBF, 0x21}, joined({signed2, signature,
        tlv({0x04}, std::vector<uint8_t>(32U, 0xCC)), certificate})));
    assert(!idf_lpa_rsp_build_prepare_download_request(signed2, signature, certificate,
        nullptr, request, error));
    assert(request.empty() && error == Error::confirmation_malformed);
    const auto no_confirmation = sequence({tlv({0x80}, transaction), tlv({0x01}, {0x00})});
    assert(idf_lpa_rsp_build_prepare_download_request(no_confirmation, signature, certificate,
        nullptr, request, error));
    assert(request == tlv({0xBF, 0x21}, joined({no_confirmation, signature, certificate})));
    const auto malformed_signed2 = sequence({tlv({0x80}, transaction), tlv({0x01}, {0x01})});
    assert(!idf_lpa_rsp_build_prepare_download_request(malformed_signed2, signature, certificate,
        nullptr, request, error));
    assert(request.empty());
    const auto large_signature = tlv({0x5F, 0x37}, std::vector<uint8_t>(128U, 0xAAU));
    assert(!idf_lpa_rsp_build_prepare_download_request(signed2, large_signature,
        large_certificate, &hash_cc, request, error));
    assert(request.empty() && error == Error::object_too_large);
    alias = signed2;
    assert(!idf_lpa_rsp_build_prepare_download_request(alias, signature, certificate,
        &hash_cc, alias, error));
    assert(alias.empty());
}

int main()
{
    profile_metadata_consent_contract();
    install_request_wire_and_binding_contract();
    {
        Error retry_error = Error::unknown;
        bool cc = true;
        const std::vector<uint8_t> transaction = {1,2};
        const auto otpk = tlv({0x5F,0x49}, std::vector<uint8_t>(65U, 0x04U));
        const auto retry = sequence({tlv({0x80}, transaction), tlv({0x01}, {0}), otpk});
        assert(idf_lpa_rsp_parse_smdp_signed2(retry.data(), retry.size(), transaction.data(),
            transaction.size(), cc, retry_error));
        assert(!cc && retry_error == Error::none);
        const auto signature = tlv({0x5F,0x37}, {0xAA,0xBB});
        const auto certificate = sequence({tlv({0x02},{1})});
        std::vector<uint8_t> prepare;
        assert(idf_lpa_rsp_build_prepare_download_request(retry, signature, certificate,
            nullptr, prepare, retry_error));
        assert(prepare == tlv({0xBF,0x21}, joined({retry, signature, certificate})));
        for (const auto& bad : {
            sequence({tlv({0x80}, transaction), tlv({0x01}, {0}), tlv({0x5F,0x49}, {})}),
            sequence({tlv({0x80}, transaction), tlv({0x01}, {0}), otpk, otpk}),
            sequence({tlv({0x80}, transaction), otpk, tlv({0x01}, {0})}),
            sequence({tlv({0x80}, transaction), tlv({0x01}, {0}),
                tlv({0x5F,0x49}, std::vector<uint8_t>(129U, 0x04U))})}) {
            assert(!idf_lpa_rsp_parse_smdp_signed2(bad.data(), bad.size(), transaction.data(),
                transaction.size(), cc, retry_error));
            assert(!cc);
        }
    }
    cancel_session_wire_and_binding_contract();
    Error error = Error::unknown;
    const auto failure_notification = profile_installation_result(
        {0x01, 0x02}, notification_metadata(), pir_error_result());
    bool installed = true;
    uint32_t notification_sequence = 99;
    std::string notification_host = "sentinel";
    const std::array<uint8_t, 2> notification_transaction = {0x01, 0x02};
    assert(idf_lpa_rsp_parse_profile_installation_notification(
        failure_notification.data(), failure_notification.size(),
        notification_transaction.data(), notification_transaction.size(), "edge.example",
        installed, notification_sequence, notification_host, error));
    assert(!installed && notification_sequence == 1 && notification_host == "edge.example");
    const auto historical_success = profile_installation_result({0x76});
    assert(idf_lpa_rsp_parse_pending_installation_notification(historical_success.data(),
        historical_success.size(), "edge.example", installed, notification_sequence,
        notification_host, error));
    assert(installed && notification_sequence == 1 && notification_host == "edge.example");
    // Pending recovery validates its historical transaction, not the current transaction.
    const auto historical = profile_installation_result({0x77}, notification_metadata(),
        pir_error_result());
    assert(idf_lpa_rsp_parse_pending_installation_notification(historical.data(), historical.size(),
        "EDGE.EXAMPLE", installed, notification_sequence, notification_host, error));
    assert(!installed && notification_sequence == 1 && notification_host == "edge.example");
    assert(!idf_lpa_rsp_parse_profile_installation_notification(historical.data(), historical.size(),
        notification_transaction.data(), notification_transaction.size(), "edge.example",
        installed, notification_sequence, notification_host, error));
    assert(!installed && notification_sequence == 0 && notification_host.empty() &&
        error == Error::transaction_mismatch);
    assert(!idf_lpa_rsp_parse_pending_installation_notification(historical.data(), historical.size(),
        "other.example", installed, notification_sequence, notification_host, error));
    assert(!installed && notification_sequence == 0 && notification_host.empty() &&
        error == Error::address_mismatch);
    const auto no_transaction = profile_installation_result({});
    assert(!idf_lpa_rsp_parse_pending_installation_notification(no_transaction.data(),
        no_transaction.size(), "edge.example", installed, notification_sequence,
        notification_host, error));
    assert(!installed && notification_sequence == 0 && notification_host.empty());
    bool success = false;
    assert(idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"transactionId":"0102"})",
               success, error));
    assert(success && error == Error::none);
    assert(!idf_lpa_rsp_parse_status(
               R"({"functionExecutionStatus":{"status":"Executed-Success"}})",
               success, error));
    assert(!success && error == Error::json_missing);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"decoy":{"functionExecutionStatus":{"status":"Executed-Success"}}}})",
               success, error));
    assert(!success && error == Error::json_missing);
    assert(!idf_lpa_rsp_parse_status(
               R"({"status":"Executed-Success","header":{"functionExecutionStatus":{"status":"Failed"}}})",
               success, error));
    assert(error == Error::server_error);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":false}})", success, error));
    assert(error == Error::json_type);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"status":false}}})",
               success, error));
    assert(error == Error::json_type);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"message":"Executed-Success"}}})",
               success, error));
    assert(error == Error::json_missing);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"status":"Executed-Success","status":"Failed"}}})",
               success, error));
    assert(error == Error::json_duplicate);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"status":"Executed-Success"},"functionExecutionStatus":{"status":"Failed"}}})",
               success, error));
    assert(error == Error::json_duplicate);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"status":"Executed-Success"}},"header":{"functionExecutionStatus":{"status":"Failed"}}})",
               success, error));
    assert(error == Error::json_duplicate);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"status":"Executed-Success"},"x":1,"x":2}})",
               success, error));
    assert(error == Error::json_duplicate);
    assert(!idf_lpa_rsp_parse_status(
               R"({"x":1,"x":2,"header":{"functionExecutionStatus":{"status":"Executed-Success"}}})",
               success, error));
    assert(error == Error::json_duplicate);
    std::string field;
    assert(idf_lpa_rsp_json_get_string(
               R"({"transactionId":"0102"})", "transactionId", field, error));
    assert(field == "0102");
    assert(!idf_lpa_rsp_json_get_string(
               R"({"transactionId":"one","transactionId":"two"})",
               "transactionId", field, error));
    assert(error == Error::json_duplicate && field.empty());
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"status":"Failed","statusCodeData":{"subjectCode":"server-secret","reasonCode":"server-secret"}}}})",
               success, error));
    assert(error == Error::server_error);
    assert(std::string(idf_lpa_rsp_error_name(error)).find("server-secret") == std::string::npos);
    assert(!idf_lpa_rsp_parse_status("{}", success, error));
    assert(error == Error::json_missing);
    assert(!idf_lpa_rsp_parse_status("{}trailing", success, error));
    assert(error == Error::json_malformed);
    assert(!idf_lpa_rsp_parse_status(
               R"({"header":{"functionExecutionStatus":{"status":"Executed-Success",}}})",
               success, error));
    assert(error == Error::json_malformed);
    assert(!idf_lpa_rsp_parse_status(
               R"({"unknown":{"a":1,"a":2},"functionExecutionStatus":{"status":"Executed-Success"}})",
               success, error));
    assert(error == Error::json_duplicate);
    assert(!idf_lpa_rsp_parse_status(std::string(24U * 1024U + 1U, 'x'), success, error));
    assert(error == Error::input_too_large);

    const std::array<uint8_t, 3> foo = {0x66, 0x6F, 0x6F};
    std::string encoded;
    assert(idf_lpa_rsp_base64_encode(foo.data(), foo.size(), encoded, error));
    assert(encoded == "Zm9v");
    std::vector<uint8_t> decoded;
    assert(idf_lpa_rsp_base64_decode("Zg==", decoded, error));
    assert(decoded == std::vector<uint8_t>({0x66}));
    assert(!idf_lpa_rsp_base64_decode("Zh==", decoded, error));
    assert(error == Error::base64_noncanonical && decoded.empty());
    for (std::string_view bad : {"Zg=", "Zg===", "Z g=", "ZgA=extra", "!!!!"}) {
        assert(!idf_lpa_rsp_base64_decode(bad, decoded, error));
        assert(decoded.empty());
    }
    assert(!idf_lpa_rsp_base64_decode("Zm9v!!!!", decoded, error));
    assert(error == Error::base64_malformed && decoded.empty());
    assert(!idf_lpa_rsp_base64_decode(
               std::string((8U * 1024U + 2U) / 3U * 4U + 4U, 'A'), decoded, error));
    assert(error == Error::object_too_large);

    std::array<uint8_t, 16> transaction = {};
    size_t transaction_size = 0U;
    assert(idf_lpa_rsp_decode_transaction_id(
               "00112233445566778899AABBCCDDEEFF", transaction,
               transaction_size, error));
    assert(transaction_size == 16U && transaction[0] == 0x00U && transaction[15] == 0xFFU);
    assert(idf_lpa_rsp_transaction_id_matches(
               "00112233445566778899AABBCCDDEEFF", transaction.data(), transaction_size, error));
    assert(!idf_lpa_rsp_transaction_id_matches("001122", transaction.data(), transaction_size, error));
    assert(error == Error::transaction_mismatch);
    std::array<uint8_t, 16> invalid_transaction = {};
    size_t invalid_transaction_size = 0U;
    assert(!idf_lpa_rsp_decode_transaction_id(
               "0011G2", invalid_transaction, invalid_transaction_size, error));
    assert(error == Error::transaction_malformed && invalid_transaction_size == 0U);
    assert(idf_lpa_rsp_validate_matching_id("ABC-012", error));
    assert(!idf_lpa_rsp_validate_matching_id("abc-012", error));
    assert(error == Error::matching_id);
    assert(!idf_lpa_rsp_validate_matching_id("", error));
    assert(error == Error::matching_id);

    const std::array<uint8_t, 16> challenge = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F};
    const std::vector<uint8_t> tx(transaction.begin(), transaction.begin() + transaction_size);
    const std::vector<uint8_t> signed1 = sequence({
        tlv({0x80}, tx),
        tlv({0x81}, std::vector<uint8_t>(challenge.begin(), challenge.end())),
        tlv({0x83}, {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}),
        tlv({0x84}, std::vector<uint8_t>(16U, 0xA5U)),
    });
    const bool signed1_ok = idf_lpa_rsp_validate_server_signed1(
        signed1.data(), signed1.size(), transaction.data(), transaction.size(),
        challenge, "EDGE.EXAMPLE", error);
    assert(signed1_ok);
    std::vector<uint8_t> signed1_extra = signed1;
    const auto unexpected_signed1 = tlv({0x85}, {0x00});
    signed1_extra.insert(signed1_extra.end(), unexpected_signed1.begin(), unexpected_signed1.end());
    signed1_extra[1] = static_cast<uint8_t>(signed1_extra.size() - 2U);
    assert(!idf_lpa_rsp_validate_server_signed1(
               signed1_extra.data(), signed1_extra.size(), transaction.data(), transaction.size(),
               challenge, "edge.example", error));
    assert(error == Error::der_malformed);
    std::vector<uint8_t> duplicate = signed1;
    const auto duplicate_tx = tlv({0x80}, tx);
    duplicate.insert(duplicate.end(), duplicate_tx.begin(), duplicate_tx.end());
    duplicate[1] = static_cast<uint8_t>(duplicate.size() - 2U);
    assert(!idf_lpa_rsp_validate_server_signed1(
               duplicate.data(), duplicate.size(), transaction.data(), transaction.size(),
               challenge, "edge.example", error));
    assert(error == Error::der_duplicate);
    assert(!idf_lpa_rsp_validate_server_signed1(
               signed1.data(), signed1.size() - 1U, transaction.data(), transaction.size(),
               challenge, "edge.example", error));
    assert(error == Error::der_malformed || error == Error::der_root);
    assert(!idf_lpa_rsp_validate_server_signed1(
               signed1.data(), signed1.size(), transaction.data(), transaction.size() - 1U,
               challenge, "edge.example", error));
    assert(error == Error::transaction_mismatch);
    assert(!idf_lpa_rsp_validate_server_signed1(
               signed1.data(), signed1.size(), transaction.data(), transaction.size(),
               challenge, "other.example", error));
    assert(error == Error::address_mismatch);
    std::vector<uint8_t> wrong_challenge = signed1;
    wrong_challenge[22] = 0xFFU;
    assert(!idf_lpa_rsp_validate_server_signed1(
               wrong_challenge.data(), wrong_challenge.size(), transaction.data(),
               transaction.size(), challenge, "edge.example", error));
    assert(error == Error::challenge_mismatch);
    std::vector<uint8_t> bad_server_challenge = signed1;
    bad_server_challenge.pop_back();
    assert(!idf_lpa_rsp_validate_server_signed1(
               bad_server_challenge.data(), bad_server_challenge.size(), transaction.data(),
               transaction.size(), challenge, "edge.example", error));
    assert(error == Error::der_malformed || error == Error::der_root);

    const std::vector<uint8_t> signed2 = sequence({
        tlv({0x80}, tx),
        tlv({0x01}, {0xFF}),
    });
    bool confirmation_required = false;
    assert(idf_lpa_rsp_parse_smdp_signed2(
               signed2.data(), signed2.size(), transaction.data(), transaction.size(),
               confirmation_required, error));
    assert(confirmation_required);
    const std::vector<uint8_t> signed2_duplicate = sequence({
        tlv({0x80}, tx), tlv({0x01}, {0x01}), tlv({0x01}, {0x00})});
    assert(!idf_lpa_rsp_parse_smdp_signed2(
               signed2_duplicate.data(), signed2_duplicate.size(), transaction.data(),
               transaction.size(), confirmation_required, error));
    assert(error == Error::der_duplicate);
    const std::vector<uint8_t> signed2_missing = sequence({tlv({0x80}, tx)});
    assert(!idf_lpa_rsp_parse_smdp_signed2(
               signed2_missing.data(), signed2_missing.size(), transaction.data(),
               transaction.size(), confirmation_required, error));
    assert(error == Error::field_missing);
    const std::vector<uint8_t> signed2_bad_flag = sequence({
        tlv({0x80}, tx), tlv({0x01}, {0x01, 0x00})});
    assert(!idf_lpa_rsp_parse_smdp_signed2(
               signed2_bad_flag.data(), signed2_bad_flag.size(), transaction.data(),
               transaction.size(), confirmation_required, error));
    assert(error == Error::confirmation_malformed);
    const std::vector<uint8_t> signed2_false = sequence({
        tlv({0x80}, tx), tlv({0x01}, {0x00})});
    assert(idf_lpa_rsp_parse_smdp_signed2(
               signed2_false.data(), signed2_false.size(), transaction.data(),
               transaction.size(), confirmation_required, error));
    assert(!confirmation_required);
    const std::vector<uint8_t> signed2_noncanonical_true = sequence({
        tlv({0x80}, tx), tlv({0x01}, {0x01})});
    assert(!idf_lpa_rsp_parse_smdp_signed2(
               signed2_noncanonical_true.data(), signed2_noncanonical_true.size(),
               transaction.data(), transaction.size(), confirmation_required, error));
    assert(error == Error::confirmation_malformed);
    std::vector<uint8_t> signed2_wrong_transaction = signed2;
    signed2_wrong_transaction[4] = 0xFFU;
    assert(!idf_lpa_rsp_parse_smdp_signed2(
               signed2_wrong_transaction.data(), signed2_wrong_transaction.size(),
               transaction.data(), transaction.size(), confirmation_required, error));
    assert(error == Error::transaction_mismatch);
    const std::vector<uint8_t> signed2_extra = sequence({
        tlv({0x80}, tx), tlv({0x01}, {0xFF}), tlv({0x82}, {0x00})});
    assert(!idf_lpa_rsp_parse_smdp_signed2(
               signed2_extra.data(), signed2_extra.size(), transaction.data(), transaction.size(),
               confirmation_required, error));
    assert(error == Error::der_malformed);

    expect_der_kind(LpaRspDerObject::authenticate_server_response,
                    tlv({0xBF, 0x38}, {}));
    expect_der_kind(LpaRspDerObject::prepare_download_response, tlv({0xBF, 0x21}, {}));
    expect_der_kind(LpaRspDerObject::profile_metadata, tlv({0xBF, 0x25}, {}));
    const auto notification_not_profile = notification_metadata();
    assert(!idf_lpa_rsp_validate_der_structure(notification_not_profile.data(),
        notification_not_profile.size(), LpaRspDerObject::profile_metadata, error));
    assert(error == Error::der_root);
    expect_der_kind(LpaRspDerObject::notification_metadata, tlv({0xBF, 0x2F}, {}));
    expect_der_kind(LpaRspDerObject::profile_installation_result, tlv({0xBF, 0x37}, {}));
    expect_der_kind(LpaRspDerObject::signature, tlv({0x5F, 0x37}, {0xAA}));
    expect_der_kind(LpaRspDerObject::ci_key, tlv({0x04}, {0x04, 0x05}));
    const auto wrong_signature_root = tlv({0x04}, {0xAA});
    assert(!idf_lpa_rsp_validate_der_structure(
               wrong_signature_root.data(), wrong_signature_root.size(),
               LpaRspDerObject::signature, error));
    assert(error == Error::der_root);
    const auto signature_trailing = joined({tlv({0x5F, 0x37}, {0xAA}), tlv({0x04}, {})});
    assert(!idf_lpa_rsp_validate_der_structure(
               signature_trailing.data(), signature_trailing.size(),
               LpaRspDerObject::signature, error));
    assert(error == Error::der_malformed);
    const auto oversized_signature = tlv({0x5F, 0x37}, std::vector<uint8_t>(1019U, 0xAA));
    assert(idf_lpa_rsp_validate_der_structure(
               oversized_signature.data(), oversized_signature.size(),
               LpaRspDerObject::signature, error));
    const auto oversized_ci_key = tlv({0x04}, std::vector<uint8_t>(128U, 0xAA));
    assert(!idf_lpa_rsp_validate_der_structure(
               oversized_ci_key.data(), oversized_ci_key.size(), LpaRspDerObject::ci_key, error));
    assert(error == Error::object_too_large);
    assert(!idf_lpa_rsp_validate_der_structure(
               signed1.data(), signed1.size(), LpaRspDerObject::prepare_download_response, error));
    assert(error == Error::der_root);
    std::vector<uint8_t> oversized(8U * 1024U + 1U, 0U);
    assert(!idf_lpa_rsp_validate_der_structure(
               oversized.data(), oversized.size(), LpaRspDerObject::smdp_signed2, error));
    assert(error == Error::object_too_large);
    assert(!idf_lpa_rsp_validate_der_structure(
               std::vector<uint8_t>{0x30U, 0x81U, 0x01U, 0x00U}.data(), 4U,
               LpaRspDerObject::smdp_signed2, error));
    assert(error == Error::der_malformed);
    const std::vector<uint8_t> trailing = {0xBFU, 0x21U, 0x00U, 0x00U};
    assert(!idf_lpa_rsp_validate_der_structure(
               trailing.data(), trailing.size(), LpaRspDerObject::prepare_download_response,
               error));
    assert(error == Error::der_malformed);
    std::vector<uint8_t> long_prepare = {0xBFU, 0x21U, 0x81U, 0x80U};
    for (size_t index = 0U; index < 64U; ++index) {
        long_prepare.push_back(0x04U);
        long_prepare.push_back(0x00U);
    }
    expect_der_kind(LpaRspDerObject::prepare_download_response, long_prepare);
    std::vector<uint8_t> deep = {0x04U, 0x00U};
    for (size_t depth = 0U; depth < 10U; ++depth) deep = tlv({0x30U}, deep);
    assert(!idf_lpa_rsp_validate_der_structure(
               deep.data(), deep.size(), LpaRspDerObject::smdp_signed2, error));
    assert(error == Error::der_malformed);

    const auto prepare = prepare_download_success(tx);
    std::vector<uint8_t> get_bpp_response = {0x53, 0x45, 0x4E, 0x54, 0x49, 0x4E, 0x45, 0x4C};
    assert(idf_lpa_rsp_parse_prepare_download_response(
               prepare.data(), prepare.size(), transaction.data(), transaction.size(),
               get_bpp_response, error));
    assert(get_bpp_response == prepare && error == Error::none);
    const auto prepare_error = prepare_download_error(tx);
    get_bpp_response = {0x53, 0x45, 0x4E, 0x54, 0x49, 0x4E, 0x45, 0x4C};
    assert(!idf_lpa_rsp_parse_prepare_download_response(
               prepare_error.data(), prepare_error.size(), transaction.data(), transaction.size(),
               get_bpp_response, error));
    assert(error == Error::server_error);
    assert(get_bpp_response.empty());
    const auto pir = profile_installation_result(tx);
    std::uint32_t sequence_number = 0xDEADBEEFU;
    std::string notification_address = "secret-address";
    assert(idf_lpa_rsp_parse_profile_installation_result(
               pir.data(), pir.size(), transaction.data(), transaction.size(), "EDGE.EXAMPLE",
               sequence_number, notification_address, error));
    assert(sequence_number == 1U && notification_address == "edge.example" &&
           error == Error::none);
    const auto pir_failed = profile_installation_result(
        tx, notification_metadata(), pir_error_result());
    sequence_number = 0xDEADBEEFU;
    notification_address = "secret-address";
    assert(!idf_lpa_rsp_parse_profile_installation_result(
               pir_failed.data(), pir_failed.size(), transaction.data(), transaction.size(),
               "edge.example", sequence_number, notification_address, error));
    assert(error == Error::server_error && sequence_number == 0U && notification_address.empty());

    const auto prepare_without_hash = prepare_download_success(tx, {});
    get_bpp_response = {0x53, 0x45, 0x4E, 0x54, 0x49, 0x4E, 0x45, 0x4C};
    assert(idf_lpa_rsp_parse_prepare_download_response(
               prepare_without_hash.data(), prepare_without_hash.size(), transaction.data(),
               transaction.size(), get_bpp_response, error));
    assert(get_bpp_response == prepare_without_hash && error == Error::none);

    auto reject_prepare = [&](const std::vector<uint8_t>& value, Error expected) {
        get_bpp_response = {0x53, 0x45, 0x4E, 0x54, 0x49, 0x4E, 0x45, 0x4C};
        assert(!idf_lpa_rsp_parse_prepare_download_response(
                   value.data(), value.size(), transaction.data(), transaction.size(),
                   get_bpp_response, error));
        assert(error == expected && get_bpp_response.empty());
        assert(std::string(idf_lpa_rsp_error_name(error)).find("EDGE") == std::string::npos);
    };
    const auto prepare_signed_data = sequence({
        tlv({0x80}, tx),
        tlv({0x5F, 0x49}, {0x01, 0x02, 0x03}),
    });
    const auto prepare_success_child = tlv({0xA0}, joined({
        prepare_signed_data,
        tlv({0x5F, 0x37}, {0xAA, 0xBB}),
    }));
    const auto prepare_error_child = tlv({0xA1}, joined({
        tlv({0x80}, tx),
        tlv({0x02}, {0x01}),
    }));
    for (uint8_t code : {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x7FU}) {
        get_bpp_response = {0x53, 0x45, 0x4E, 0x54, 0x49, 0x4E, 0x45, 0x4C};
        const auto valid_error = prepare_download_error(tx, {code});
        assert(!idf_lpa_rsp_parse_prepare_download_response(
                   valid_error.data(), valid_error.size(), transaction.data(), transaction.size(),
                   get_bpp_response, error));
        assert(error == Error::server_error && get_bpp_response.empty());
    }
    for (const auto& code : {std::vector<uint8_t>{0x00U}, std::vector<uint8_t>{0x06U},
                              std::vector<uint8_t>{0x7EU}, std::vector<uint8_t>{0x00U, 0x80U}}) {
        reject_prepare(prepare_download_error(tx, code), Error::der_malformed);
    }
    reject_prepare(tlv({0xBF, 0x22}, {}), Error::der_root);
    auto prepare_trailing = prepare;
    prepare_trailing.push_back(0x00);
    reject_prepare(prepare_trailing, Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, {}), Error::field_missing);
    reject_prepare(tlv({0xBF, 0x21}, joined({prepare_success_child, prepare_success_child})),
                   Error::der_duplicate);
    reject_prepare(tlv({0xBF, 0x21}, joined({prepare_error_child, prepare_error_child})),
                   Error::der_duplicate);
    reject_prepare(tlv({0xBF, 0x21}, joined({prepare_success_child, prepare_error_child})),
                   Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       prepare_signed_data,
                   }))), Error::field_missing);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       sequence({tlv({0x80}, tx), tlv({0x5F, 0x49}, {0x01}),
                                 tlv({0x04}, std::vector<uint8_t>(31U, 0xCC))}),
                       tlv({0x5F, 0x37}, {0xAA}),
                   }))), Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       sequence({tlv({0x80}, tx), tlv({0x5F, 0x49}, {0x01}),
                                 tlv({0x04}, {0xCC}), tlv({0x04}, {0xDD})}),
                       tlv({0x5F, 0x37}, {0xAA}),
                   }))), Error::der_duplicate);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       sequence({tlv({0x80}, tx), tlv({0x04}, {0xCC}),
                                 tlv({0x5F, 0x49}, {0x01})}),
                       tlv({0x5F, 0x37}, {0xAA}),
                   }))), Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       prepare_signed_data,
                       tlv({0x5F, 0x37}, {}),
                   }))), Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       sequence({tlv({0x80}, tx)}),
                       tlv({0x5F, 0x37}, {0xAA}),
                   }))), Error::field_missing);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       sequence({tlv({0x5F, 0x49}, {0x01, 0x02, 0x03})}),
                       tlv({0x5F, 0x37}, {0xAA}),
                   }))), Error::field_missing);
    reject_prepare(tlv({0xBF, 0x21}, joined({
                       prepare_success_child,
                       tlv({0xBF, 0x22}, {}),
                   })), Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       prepare_signed_data,
                       tlv({0x5F, 0x37}, {0xAA}),
                       tlv({0x5F, 0x37}, {0xBB}),
                   }))), Error::der_duplicate);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       tlv({0x5F, 0x37}, {0xAA}), prepare_signed_data,
                   }))), Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       sequence({tlv({0x5F, 0x49}, {0x01}), tlv({0x80}, tx),
                                 tlv({0x82}, {0x01})}),
                       tlv({0x5F, 0x37}, {0xAA}),
                   }))), Error::der_malformed);
    auto wrong_prepare_transaction = prepare_download_success({0xFF, 0xEE});
    reject_prepare(wrong_prepare_transaction, Error::transaction_mismatch);
    reject_prepare(prepare_download_error({0xFF, 0xEE}), Error::transaction_mismatch);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA1}, tlv({0x80}, tx))),
                   Error::field_missing);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA1}, tlv({0x02}, {0x01}))),
                   Error::field_missing);
    reject_prepare(prepare_download_error(tx, {0x00, 0x01}), Error::der_malformed);
    reject_prepare(prepare_download_error(tx, {0x01, 0x02, 0x03, 0x04, 0x05}),
                   Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA1}, joined({
                       tlv({0x02}, {0x01}), tlv({0x80}, tx),
                   }))), Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA1}, joined({
                       tlv({0x80}, tx), tlv({0x02}, {0x01}), tlv({0x82}, {0x01}),
                   }))), Error::der_malformed);
    auto prepare_noncanonical_length = prepare;
    const std::uint8_t prepare_root_length = prepare_noncanonical_length[2];
    prepare_noncanonical_length[2] = 0x81;
    prepare_noncanonical_length.insert(prepare_noncanonical_length.begin() + 3,
                                       prepare_root_length);
    reject_prepare(prepare_noncanonical_length, Error::der_malformed);
    reject_prepare(std::vector<uint8_t>(8U * 1024U + 1U, 0x00), Error::object_too_large);
    std::vector<uint8_t> prepare_deep = {0x04, 0x00};
    for (std::size_t depth = 0U; depth < 10U; ++depth) prepare_deep = tlv({0x30}, prepare_deep);
    reject_prepare(prepare_deep, Error::der_malformed);
    const auto prepare_large = tlv({0xBF, 0x21}, tlv({0xA0}, joined({
        sequence({tlv({0x80}, tx), tlv({0x5F, 0x49}, std::vector<uint8_t>(128U, 0x01))}),
        tlv({0x5F, 0x37}, std::vector<uint8_t>(130U, 0xAA)),
    })));
    get_bpp_response.clear();
    assert(idf_lpa_rsp_parse_prepare_download_response(
               prepare_large.data(), prepare_large.size(), transaction.data(), transaction.size(),
               get_bpp_response, error));
    assert(get_bpp_response == prepare_large);
    const std::size_t prepare_success_capacity = get_bpp_response.capacity();
    reject_prepare(tlv({0xBF, 0x21}, {}), Error::field_missing);
    assert(prepare_success_capacity > 0U && get_bpp_response.capacity() == 0U);
    get_bpp_response = prepare;
    const std::size_t aliased_prepare_size = get_bpp_response.size();
    assert(!idf_lpa_rsp_parse_prepare_download_response(
               get_bpp_response.data(), aliased_prepare_size, transaction.data(),
               transaction.size(), get_bpp_response, error));
    assert(error == Error::der_malformed && get_bpp_response.empty() &&
           get_bpp_response.capacity() == 0U);
    get_bpp_response = tx;
    assert(!idf_lpa_rsp_parse_prepare_download_response(
               prepare.data(), prepare.size(), get_bpp_response.data(), tx.size(),
               get_bpp_response, error));
    assert(error == Error::der_malformed && get_bpp_response.empty() &&
           get_bpp_response.capacity() == 0U);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       sequence({tlv({0x5F, 0x49}, std::vector<uint8_t>(129U, 0x01)),
                                 tlv({0x80}, tx)}),
                       tlv({0x5F, 0x37}, {0xAA}),
                   }))), Error::der_malformed);
    reject_prepare(tlv({0xBF, 0x21}, tlv({0xA0}, joined({
                       sequence({tlv({0x5F, 0x49}, {0x01}), tlv({0x80}, tx)}),
                       tlv({0x5F, 0x37}, std::vector<uint8_t>(1025U, 0xAA)),
                   }))), Error::der_malformed);

    auto reject_pir = [&](const std::vector<uint8_t>& value, Error expected) {
        sequence_number = 0xDEADBEEFU;
        notification_address = "notification-secret";
        assert(!idf_lpa_rsp_parse_profile_installation_result(
                   value.data(), value.size(), transaction.data(), transaction.size(),
                   "EDGE.EXAMPLE", sequence_number, notification_address, error));
        assert(error == expected && sequence_number == 0U && notification_address.empty());
        assert(std::string(idf_lpa_rsp_error_name(error)).find("EDGE") == std::string::npos);
    };
    reject_pir(tlv({0xBF, 0x36}, {}), Error::der_root);
    auto pir_trailing = pir;
    pir_trailing.push_back(0x00);
    reject_pir(pir_trailing, Error::der_malformed);
    reject_pir(tlv({0xBF, 0x37}, {}), Error::field_missing);
    reject_pir(tlv({0xBF, 0x37}, joined({
                  tlv({0xBF, 0x27}, {}), tlv({0x5F, 0x37}, {0xAA}),
                  tlv({0x5F, 0x37}, {0xBB}),
              })), Error::der_duplicate);
    reject_pir(tlv({0xBF, 0x37}, joined({
                  tlv({0xBF, 0x27}, {}), tlv({0x5F, 0x37}, {0xAA}),
                  tlv({0xBF, 0x26}, {}),
              })), Error::der_malformed);
    reject_pir(tlv({0xBF, 0x37}, tlv({0x5F, 0x37}, {0xAA})), Error::field_missing);
    const auto pir_data = tlv({0xBF, 0x27}, joined({
        tlv({0x80}, tx),
        notification_metadata(),
        tlv({0x06}, {0x2B, 0x06, 0x01, 0x04, 0x01}),
        tlv({0xA2}, tlv({0xA0}, joined({
            tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}),
            tlv({0x04}, {0x90, 0x00}),
        }))),
    }));
    const auto pir_signature = tlv({0x5F, 0x37}, {0xCC});
    const auto pir_error_valid = profile_installation_result(
        tx, notification_metadata(), pir_error_result(0x05U, 0x01U));
    assert(!idf_lpa_rsp_parse_profile_installation_result(
               pir_error_valid.data(), pir_error_valid.size(),
               transaction.data(), transaction.size(), "edge.example", sequence_number,
               notification_address, error));
    assert(error == Error::server_error && sequence_number == 0U && notification_address.empty());
    const auto pir_error_with_response = profile_installation_result(
        tx, notification_metadata(), pir_error_result(0x05U, 0x01U, {0x90U, 0x00U}));
    assert(!idf_lpa_rsp_parse_profile_installation_result(
               pir_error_with_response.data(), pir_error_with_response.size(), transaction.data(),
               transaction.size(), "edge.example", sequence_number, notification_address, error));
    assert(error == Error::server_error && sequence_number == 0U && notification_address.empty());
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA1}, {}))), Error::field_missing);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA1}, tlv({0x02}, {0x05})))),
               Error::field_missing);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA1}, joined({
                                               tlv({0x02}, {0x05}), tlv({0x02}, {0x01}),
                                               tlv({0x02}, {0x02}),
                                           })))), Error::der_duplicate);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA1}, joined({
                                               tlv({0x02}, {0x05}), tlv({0x82}, {0x01}),
                                               tlv({0x02}, {0x01}),
                                           })))), Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA1}, joined({
                                               tlv({0x02}, {0x0D}), tlv({0x02}, {0x00}),
                                           })))), Error::der_malformed);
    for (uint8_t command_id : {0x00U, 0x01U, 0x02U, 0x03U, 0x04U, 0x05U}) {
        const auto valid_error = profile_installation_result(
            tx, notification_metadata(), pir_error_result(command_id, 0x01U));
        assert(!idf_lpa_rsp_parse_profile_installation_result(
                   valid_error.data(), valid_error.size(), transaction.data(), transaction.size(),
                   "edge.example", sequence_number, notification_address, error));
        assert(error == Error::server_error);
    }
    for (uint8_t reason : {0x01U, 0x02U, 0x03U, 0x04U, 0x05U, 0x06U, 0x07U, 0x08U,
                           0x09U, 0x0AU, 0x0BU, 0x0CU, 0x0DU, 0x0EU, 0x0FU, 0x7FU}) {
        const auto valid_error = profile_installation_result(
            tx, notification_metadata(), pir_error_result(0x05U, reason));
        assert(!idf_lpa_rsp_parse_profile_installation_result(
                   valid_error.data(), valid_error.size(), transaction.data(), transaction.size(),
                   "edge.example", sequence_number, notification_address, error));
        assert(error == Error::server_error);
    }
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           pir_error_result(0x06U, 0x01U)), Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           pir_error_result(0x05U, 0x00U)), Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           pir_error_result(0x05U, 0x10U)), Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           pir_error_result(0x05U, 0x80U)), Error::der_malformed);
    reject_pir(tlv({0xBF, 0x37}, joined({pir_data, pir_signature, pir_data})),
               Error::der_duplicate);
    reject_pir(tlv({0xBF, 0x37}, joined({pir_data, pir_signature, tlv({0x5F, 0x36}, {0x01})})),
               Error::der_malformed);
    reject_pir(profile_installation_result({0xFF, 0xEE}), Error::transaction_mismatch);
    reject_pir(profile_installation_result(tx, notification_metadata({0x00, 0x01})),
               Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata({0x01, 0x00, 0x00, 0x00, 0x01})),
               Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata({0x01}, {0x06, 0x40})),
               Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata({0x01}, {0x07, 0x81})),
               Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata({0x01}, {0x07, 0x80},
                                                                      {'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'n', 'e', 't'})),
               Error::address_mismatch);
    reject_pir(profile_installation_result(tx, notification_metadata({0x01}, {0x07, 0x80},
                                                                      {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x01})),
               Error::address_mismatch);
    reject_pir(profile_installation_result(tx, notification_metadata({0x01}, {0x07, 0x80},
                                                                      {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}),
                                           tlv({0xA2}, tlv({0xA1}, {}))), Error::field_missing);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA3}, {0x01}))), Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, joined({tlv({0xA0}, {}), tlv({0xA1}, {})}))),
               Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA0}, tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05})))),
               Error::field_missing);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA0}, tlv({0x04}, {0x90, 0x00})))),
               Error::field_missing);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA0}, joined({
                                               tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}),
                                               tlv({0x04}, {0x90, 0x00}), tlv({0x82}, {0x01}),
                                           })))), Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA0}, joined({
                                               tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}),
                                               tlv({0x4F}, {0x06, 0x07, 0x08, 0x09, 0x0A}),
                                               tlv({0x04}, {0x90, 0x00}),
                                           })))), Error::der_duplicate);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA0}, joined({
                                               tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}),
                                               tlv({0x04}, {0x90, 0x00}), tlv({0x04}, {0x91, 0x00}),
                                           })))), Error::der_duplicate);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA0}, joined({
                                               tlv({0x4F}, {0x01, 0x02, 0x03, 0x04}),
                                               tlv({0x04}, {0x90, 0x00}),
                                           })))), Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA0}, joined({
                                               tlv({0x4F}, std::vector<uint8_t>(17U, 0x01)),
                                               tlv({0x04}, {0x90, 0x00}),
                                           })))), Error::der_malformed);
    reject_pir(profile_installation_result(tx, notification_metadata(),
                                           tlv({0xA2}, tlv({0xA0}, joined({
                                               tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}),
                                               tlv({0x04}, {}),
                                           })))), Error::der_malformed);
    const auto pir_oversized_oid_data = tlv({0xBF, 0x27}, joined({
        tlv({0x80}, tx), notification_metadata(),
        tlv({0x06}, std::vector<uint8_t>(65U, 0x2B)),
        tlv({0xA2}, tlv({0xA0}, joined({
            tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}), tlv({0x04}, {0x90}),
        }))),
    }));
    reject_pir(tlv({0xBF, 0x37}, joined({pir_oversized_oid_data, pir_signature})),
               Error::der_malformed);
    const auto pir_oversized_signature = tlv({0xBF, 0x37}, joined({
        pir_data, tlv({0x5F, 0x37}, std::vector<uint8_t>(1025U, 0xCC)),
    }));
    reject_pir(pir_oversized_signature, Error::der_malformed);
    const auto pir_data_extra = tlv({0xBF, 0x27}, joined({
        tlv({0x80}, tx), notification_metadata(), tlv({0x06}, {0x2B}),
        tlv({0xA2}, tlv({0xA0}, joined({
            tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}), tlv({0x04}, {0x90}),
        }))), tlv({0x82}, {0x01}),
    }));
    reject_pir(tlv({0xBF, 0x37}, joined({pir_data_extra, pir_signature})),
               Error::der_malformed);
    const auto metadata_with_extra = tlv({0xBF, 0x2F}, joined({
        tlv({0x80}, {0x01}), tlv({0x81}, {0x07, 0x80}),
        tlv({0x0C}, {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}),
        tlv({0x82}, {0x01}),
    }));
    reject_pir(profile_installation_result(tx, metadata_with_extra), Error::der_malformed);
    const std::vector<uint8_t> iccid_20 = {
        0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54};
    const auto pir_iccid_20 = profile_installation_result(
        tx, notification_metadata({0x01}, {0x07, 0x80},
                                   {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'},
                                   iccid_20));
    assert(idf_lpa_rsp_parse_profile_installation_result(
               pir_iccid_20.data(), pir_iccid_20.size(),
               transaction.data(), transaction.size(), "edge.example", sequence_number,
               notification_address, error));
    assert(sequence_number == 1U && notification_address == "edge.example" &&
           error == Error::none);
    const auto pir_long = profile_installation_result(
        tx, notification_metadata({0x01}, {0x07, 0x80},
                                   {'v', 'e', 'r', 'y', '-', 'l', 'o', 'n', 'g', '.', 'e', 'x',
                                    'a', 'm', 'p', 'l', 'e'}));
    assert(idf_lpa_rsp_parse_profile_installation_result(
               pir_long.data(), pir_long.size(), transaction.data(), transaction.size(),
               "very-long.example", sequence_number, notification_address, error));
    const std::size_t pir_success_capacity = notification_address.capacity();
    assert(notification_address == "very-long.example");
    reject_pir(tlv({0xBF, 0x37}, {}), Error::field_missing);
    assert(pir_success_capacity > notification_address.capacity());
    notification_address = "edge.example";
    const std::string_view aliased_host(notification_address);
    assert(!idf_lpa_rsp_parse_profile_installation_result(
               pir.data(), pir.size(), transaction.data(), transaction.size(), aliased_host,
               sequence_number, notification_address, error));
    assert(error == Error::der_malformed && sequence_number == 0U &&
           notification_address.empty());
    const auto pir_without_iccid = profile_installation_result(
        tx, notification_metadata({0x01}, {0x07, 0x80},
                                   {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'},
                                   {}));
    assert(idf_lpa_rsp_parse_profile_installation_result(
               pir_without_iccid.data(), pir_without_iccid.size(),
               transaction.data(), transaction.size(), "edge.example", sequence_number,
               notification_address, error));
    const auto metadata_iccid_before_address = tlv({0xBF, 0x2F}, joined({
        tlv({0x80}, {0x01}), tlv({0x81}, {0x07, 0x80}),
        tlv({0x5A}, {0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0xF4}),
        tlv({0x0C}, {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}),
    }));
    reject_pir(profile_installation_result(tx, metadata_iccid_before_address),
               Error::der_malformed);
    for (const auto& bad_iccid : {
             std::vector<uint8_t>{0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32},
             std::vector<uint8_t>{0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0x54,
                                  0x76},
             std::vector<uint8_t>{0xF8, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0xF4},
             std::vector<uint8_t>{0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0xFF},
         }) {
        reject_pir(profile_installation_result(
                       tx, notification_metadata({0x01}, {0x07, 0x80},
                                                  {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm',
                                                   'p', 'l', 'e'},
                                                  bad_iccid)),
                   Error::der_malformed);
    }
    for (const auto& bad_oid : {
             std::vector<uint8_t>{}, std::vector<uint8_t>{0x2B, 0x86},
             std::vector<uint8_t>{0x2B, 0x80, 0x00},
             std::vector<uint8_t>{0x2B, 0x86, 0x80},
             std::vector<uint8_t>{0x2B, 0x82, 0xFF, 0xFF, 0xFF, 0xFF,
                                  0xFF, 0xFF, 0xFF, 0xFF, 0x7F},
         }) {
        reject_pir(profile_installation_result(tx, notification_metadata(),
                                               tlv({0xA2}, tlv({0xA0}, joined({
                                                   tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}),
                                                   tlv({0x04}, {0x90, 0x00}),
                                               }))),
                                               bad_oid),
                   Error::der_malformed);
    }
    const auto pir_root_out_of_order = tlv({0xBF, 0x37}, joined({
        pir_signature, pir_data,
    }));
    reject_pir(pir_root_out_of_order, Error::der_malformed);
    const auto pir_data_out_of_order = tlv({0xBF, 0x27}, joined({
        notification_metadata(), tlv({0x80}, tx), tlv({0x06}, {0x2B, 0x06, 0x01, 0x04, 0x01}),
        tlv({0xA2}, tlv({0xA0}, joined({
            tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}), tlv({0x04}, {0x90, 0x00}),
        }))),
    }));
    reject_pir(tlv({0xBF, 0x37}, joined({pir_data_out_of_order, pir_signature})),
               Error::der_malformed);
    const auto pir_success_out_of_order = tlv({0xBF, 0x27}, joined({
        tlv({0x80}, tx), notification_metadata(), tlv({0x06}, {0x2B, 0x06, 0x01, 0x04, 0x01}),
        tlv({0xA2}, tlv({0xA0}, joined({
            tlv({0x04}, {0x90, 0x00}), tlv({0x4F}, {0x01, 0x02, 0x03, 0x04, 0x05}),
        }))),
    }));
    reject_pir(tlv({0xBF, 0x37}, joined({pir_success_out_of_order, pir_signature})),
               Error::der_malformed);
    const auto metadata_duplicate = tlv({0xBF, 0x2F}, joined({
        tlv({0x80}, {0x01}), tlv({0x80}, {0x02}), tlv({0x81}, {0x07, 0x80}),
        tlv({0x0C}, {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}),
    }));
    reject_pir(profile_installation_result(tx, metadata_duplicate), Error::der_duplicate);
    const auto metadata_iccid_duplicate = tlv({0xBF, 0x2F}, joined({
        tlv({0x80}, {0x01}), tlv({0x81}, {0x07, 0x80}),
        tlv({0x0C}, {'e', 'd', 'g', 'e', '.', 'e', 'x', 'a', 'm', 'p', 'l', 'e'}),
        tlv({0x5A}, {0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0xF4}),
        tlv({0x5A}, {0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0xF4}),
    }));
    reject_pir(profile_installation_result(tx, metadata_iccid_duplicate), Error::der_duplicate);
    auto pir_noncanonical_length = pir;
    const std::uint8_t pir_root_length = pir_noncanonical_length[2];
    pir_noncanonical_length[2] = 0x81;
    pir_noncanonical_length.insert(pir_noncanonical_length.begin() + 3, pir_root_length);
    reject_pir(pir_noncanonical_length, Error::der_malformed);
    std::vector<uint8_t> pir_deep = {0x04, 0x00};
    for (std::size_t depth = 0U; depth < 10U; ++depth) pir_deep = tlv({0x30}, pir_deep);
    reject_pir(pir_deep, Error::der_malformed);
    auto pir_signature_empty = pir;
    pir_signature_empty[pir_signature_empty.size() - 3U] = 0U;
    reject_pir(pir_signature_empty, Error::der_malformed);

    std::array<uint8_t, 32> hash = {};
    assert(idf_lpa_rsp_compute_hash_cc("1234", transaction.data(), 4U, hash, error));
    const std::array<uint8_t, 32> expected_hash = {
        0x48, 0x02, 0xC6, 0x24, 0x29, 0x27, 0x1F, 0x35,
        0x14, 0xC9, 0x86, 0xE9, 0xA0, 0x4D, 0x4E, 0xF5,
        0x31, 0xAE, 0x8E, 0x3E, 0x10, 0xFD, 0xC4, 0xEF,
        0x4C, 0x58, 0xA6, 0x6B, 0x9E, 0xA8, 0xE4, 0x0C};
    assert(hash == expected_hash);
    assert(!idf_lpa_rsp_compute_hash_cc("", transaction.data(), 4U, hash, error));
    const std::array<uint8_t, 32> zero_hash = {};
    assert(error == Error::crypto_input && hash == zero_hash);
    assert(!idf_lpa_rsp_compute_hash_cc("1234", nullptr, 4U, hash, error));
    assert(error == Error::crypto_input && hash == zero_hash);
    return 0;
}
'''


class RspProtocolTest(unittest.TestCase):
    def test_rsp_protocol_and_crypto_contract(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "g++ is required for the RSP host check")
        self.assertTrue(HEADER.exists(), "missing RSP public header")
        self.assertTrue(SOURCE.exists(), "missing RSP implementation")
        self.assertTrue(ACTIVATION_SOURCE.exists(), "missing activation parser")
        self.assertTrue(CODEC_SOURCE.exists(), "missing shared TLV codec")

        with tempfile.TemporaryDirectory(prefix="idf-lpa-rsp-") as directory:
            root = Path(directory)
            harness = root / "rsp_fixture.cpp"
            binary = root / "rsp_fixture"
            harness.write_text(HOST_CPP, encoding="utf-8")
            compile_result = subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    "-fno-exceptions",
                    "-fno-rtti",
                    "-I",
                    str(COMPONENT / "include"),
                    "-I",
                    str(CODEC_INCLUDE),
                    str(SOURCE),
                    str(ACTIVATION_SOURCE),
                    str(CODEC_SOURCE),
                    str(harness),
                    "-lcrypto",
                    "-o",
                    str(binary),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            run_result = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(run_result.returncode, 0, run_result.stderr)

        source_text = SOURCE.read_text(encoding="utf-8")
        self.assertIn("psa_hash_setup", source_text)
        self.assertIn("psa_hash_abort", source_text)
        self.assertIn("PSA_ALG_SHA_256", source_text)
        self.assertIn("secure_zero", source_text)
        self.assertNotIn("server-secret", source_text)


if __name__ == "__main__":
    unittest.main()
