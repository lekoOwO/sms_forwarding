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
    assert(value.size() < 128U);
    out.push_back(static_cast<uint8_t>(value.size()));
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

static std::vector<uint8_t> sequence(const std::vector<std::vector<uint8_t>>& children)
{
    std::vector<uint8_t> value;
    for (const auto& child : children) value.insert(value.end(), child.begin(), child.end());
    return tlv({0x30}, value);
}

static void expect_der_kind(LpaRspDerObject kind,
                            const std::vector<uint8_t>& value)
{
    Error error = Error::unknown;
    assert(idf_lpa_rsp_validate_der_structure(value.data(), value.size(), kind, error));
    assert(error == Error::none);
}

int main()
{
    Error error = Error::unknown;
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
    expect_der_kind(LpaRspDerObject::profile_metadata, tlv({0xBF, 0x2F}, {}));
    expect_der_kind(LpaRspDerObject::notification_metadata, tlv({0xBF, 0x2F}, {}));
    expect_der_kind(LpaRspDerObject::profile_installation_result, tlv({0xBF, 0x37}, {}));
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
