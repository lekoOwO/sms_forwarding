#include "idf_esim_codec.h"
#include "idf_esim.h"
#include "idf_esim_lpa.h"
#include "idf_modem.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace {

enum class ResponseMode {
    normal,
    auth_material,
    notifications,
    notification_status,
    terminal_capability_error,
    ccho_retry,
    ccho_bare,
    ccho_out_of_range,
    ccho_out_of_range_malformed,
    ccho_final_failure,
    profile_interleaved,
    profile_unknown_line,
    cgl_interleaved,
    cgl_duplicate,
    cgl_wrong_echo,
    cgl_duplicate_echo,
    cgl_unknown_line,
    cgl_missing_ok,
    cgl_error,
    cgl_bad_hex,
    cgl_bad_length,
    cgl_unquoted,
    cgl_after_ok,
    chain_61,
    chain_91,
    chain_too_long,
    chain_too_large,
    chain_overflow_nonempty,
    get_response_failure,
    bad_sw,
};

struct FakeModem {
    ResponseMode mode = ResponseMode::normal;
    uint8_t notification_status = 0;
    size_t ccho_calls = 0;
    size_t cgl_calls = 0;
    size_t cchc_calls = 0;
    size_t owner_begin_calls = 0;
    size_t owner_end_calls = 0;
    std::vector<std::string> commands;
};

FakeModem fake;

std::string cgl_response(std::string_view hex)
{
    std::string response = "\r\n+CGLA: ";
    response += std::to_string(hex.size());
    response += ",\"";
    response.append(hex.data(), hex.size());
    response += "\"\r\nOK\r\n";
    return response;
}

std::string cgl_profile_response(std::string_view command, std::string_view hex)
{
    std::string response = "\r\n";
    response.append(command.data(), command.size());
    response += "\r\nRING\r\n+CMTI: \"SM\",1\r\n+CMT: \r\n";
    response.append(32U, 'A');
    response += "\r\n+CGLA: ";
    response += std::to_string(hex.size());
    response += ",\"";
    response.append(hex.data(), hex.size());
    response += "\"\r\n+CEREG: 1,1\r\nOK\r\n";
    return response;
}

std::string terminal_capability_response()
{
    return "\r\nAT+CSIM=20,\"80AA000005A903830107\"\r\n+CSIM: 4,\"9000\"\r\nOK\r\n";
}

std::string auth_material_hex(size_t call)
{
    if (call == 1U) return "BF20098203010203A900AA009000";
    if (call == 2U) return "BF221B8103010203820301020383030102038406820101830102880200809000";
    return "BF2E12801000112233445566778899AABBCCDDEEFF9000";
}

std::string malformed_cgl_response(ResponseMode mode)
{
    switch (mode) {
        case ResponseMode::cgl_duplicate:
            return cgl_response("9000") + "\r\n+CGLA: 4,\"9000\"\r\n";
        case ResponseMode::cgl_wrong_echo:
            return "\r\nAT+CGLA=wrong\r\n+CGLA: 4,\"9000\"\r\nOK\r\n";
        case ResponseMode::cgl_duplicate_echo:
            return "";
        case ResponseMode::cgl_unknown_line:
            return "\r\n+CGLA: 4,\"9000\"\r\nSENTINEL\r\nOK\r\n";
        case ResponseMode::cgl_missing_ok:
            return "\r\n+CGLA: 4,\"9000\"\r\n";
        case ResponseMode::cgl_error:
            return "\r\n+CGLA: 4,\"9000\"\r\nERROR\r\n";
        case ResponseMode::cgl_bad_hex:
            return "\r\n+CGLA: 4,\"90G0\"\r\nOK\r\n";
        case ResponseMode::cgl_bad_length:
            return "\r\n+CGLA: 6,\"9000\"\r\nOK\r\n";
        case ResponseMode::cgl_unquoted:
            return "\r\n+CGLA: 4,9000\r\nOK\r\n";
        case ResponseMode::cgl_after_ok:
            return "\r\n+CGLA: 4,\"9000\"\r\nOK\r\nAT+CGLA=\r\n";
        default:
            return cgl_response("9000");
    }
}

std::string next_cgl_response()
{
    ++fake.cgl_calls;
    const std::string command = fake.commands.empty() ? std::string() : fake.commands.back();
    if (fake.mode == ResponseMode::auth_material) {
        return cgl_response(auth_material_hex(fake.cgl_calls));
    }
    if (fake.mode == ResponseMode::notifications) {
        return cgl_response("BF2B05A0030102039000");
    }
    if (fake.mode == ResponseMode::notification_status) {
        const char* status_hex[] = {"00", "01", "7F", "02"};
        return cgl_response(std::string("BF30038001") + status_hex[fake.notification_status] + "9000");
    }
    if (fake.mode == ResponseMode::profile_interleaved) {
        if (command.find("BF3E") != std::string::npos) {
            return cgl_profile_response(command, "BF3E035A01019000");
        }
        if (command.find("BF2D") != std::string::npos) {
            return cgl_profile_response(command, "BF2D05E3035A01019000");
        }
    }
    if (fake.mode == ResponseMode::profile_unknown_line) {
        return "\r\n" + command + "\r\n+CGLA: 4,\"9000\"\r\nSENTINEL\r\nOK\r\n";
    }
    if (fake.mode == ResponseMode::cgl_interleaved) {
        return cgl_profile_response(command, "9000");
    }
    const int mode = static_cast<int>(fake.mode);
    if (mode >= static_cast<int>(ResponseMode::cgl_duplicate) &&
        mode <= static_cast<int>(ResponseMode::cgl_after_ok)) {
        if (fake.mode == ResponseMode::cgl_duplicate_echo) {
            return "\r\n" + command + "\r\n" + command + "\r\n+CGLA: 4,\"9000\"\r\nOK\r\n";
        }
        return malformed_cgl_response(fake.mode);
    }
    if (fake.mode == ResponseMode::chain_61) {
        if (fake.cgl_calls == 1U) return cgl_response("01026102");
        return cgl_response("AABB9000");
    }
    if (fake.mode == ResponseMode::chain_91) return cgl_response("01029102");
    if (fake.mode == ResponseMode::chain_too_long) return cgl_response("6101");
    if (fake.mode == ResponseMode::chain_too_large) {
        std::string data(510U, 'A');
        return cgl_response(data + "6101");
    }
    if (fake.mode == ResponseMode::chain_overflow_nonempty) {
        return cgl_response("AABB6101");
    }
    if (fake.mode == ResponseMode::get_response_failure) {
        return fake.cgl_calls == 1U ? cgl_response("AABB6101") : cgl_response("CCDD9300");
    }
    if (fake.mode == ResponseMode::bad_sw) {
        return cgl_response("AABB9300");
    }
    return cgl_response("9000");
}

void reset_fake(ResponseMode mode = ResponseMode::normal)
{
    fake = FakeModem();
    fake.mode = mode;
}

void assert_safe_message(const std::string& message)
{
    assert(message.size() < 128U);
    assert(message.find("SENTINEL") == std::string::npos);
    assert(message.find("+CGLA") == std::string::npos);
    assert(message.find("9000") == std::string::npos);
}

void test_tlv_codec()
{
    using idf_esim_internal::CsimParseResult;
    using idf_esim_internal::EuiccInfo1Fields;
    using idf_esim_internal::Tlv;
    using idf_esim_internal::TlvSpan;

    Tlv parsed;
    std::string message;
    assert(idf_esim_internal::parse_tlv({0xE0, 0x03, 0x5A, 0x01, 0x01}, parsed, message));
    assert(!parsed.children.empty());
    assert(!idf_esim_internal::parse_tlv({0x5A, 0x01, 0x01, 0x00}, parsed, message));
    assert(!idf_esim_internal::parse_tlv(std::vector<uint8_t>(16385U, 0), parsed, message));
    std::vector<uint8_t> nested = {0x5A, 0x00};
    for (size_t depth = 0U; depth < 10U; ++depth) {
        std::vector<uint8_t> wrapper = {0xE0, static_cast<uint8_t>(nested.size())};
        wrapper.insert(wrapper.end(), nested.begin(), nested.end());
        nested = std::move(wrapper);
    }
    assert(!idf_esim_internal::parse_tlv(nested, parsed, message));

    std::vector<uint8_t> bounded = {0x5A, 0x01, 0x01, 0x5A, 0x01, 0x02};
    size_t position = 0U;
    TlvSpan span;
    assert(idf_esim_internal::parse_tlv_span(bounded, bounded.size(), position, span, message));
    assert(span.valueLength == 1U && position == 3U);
    assert(idf_esim_internal::parse_tlv_span(bounded, bounded.size(), position, span, message));
    assert(span.valueOffset == 5U && position == bounded.size());
    assert(!idf_esim_internal::parse_tlv_span(bounded, bounded.size() + 1U, position, span, message));

    uint16_t status = 0U;
    assert(idf_esim_internal::parse_terminal_capability_csim(
               terminal_capability_response(), status, message) == CsimParseResult::success);
    assert(status == 0x9000U);
    assert(idf_esim_internal::parse_terminal_capability_csim(
               "\r\n+CSIM: 4,9000\r\nOK\r\n", status, message) == CsimParseResult::malformed);
    assert(idf_esim_internal::parse_terminal_capability_csim(
               "\r\n+CSIM: 4,\"9000\"\r\n+CSIM: 4,\"9000\"\r\nOK\r\n",
               status, message) == CsimParseResult::malformed);
    assert(idf_esim_internal::parse_terminal_capability_csim(
               "\r\n+CSIM: 4,\"9000\"\r\nSENTINEL\r\nOK\r\n",
               status, message) == CsimParseResult::malformed);
    assert(idf_esim_internal::parse_terminal_capability_csim(
               "\r\n+CSIM: 4,\"9300\"\r\nOK\r\n", status, message) == CsimParseResult::status_error);

    EuiccInfo1Fields info1;
    assert(idf_esim_internal::parse_euicc_info1(
               {0xBF, 0x20, 0x09, 0x82, 0x03, 0x01, 0x02, 0x03, 0xA9, 0x00, 0xAA, 0x00},
               info1, message));
}

void test_lpa_api()
{
    std::string message;
    std::vector<uint8_t> response;

    reset_fake();
    const std::vector<uint8_t> cancel = {0xBF,0x41,7,0x80,2,1,2,0x81,1,1};
    assert(idf_esim_lpa_cancel_session(cancel, response, message) == ESP_OK);
    assert(fake.commands.size() == 4U && fake.ccho_calls == 1U && fake.cchc_calls == 1U);
    assert(fake.commands[2] == "AT+CGLA=1,30,\"81E291000ABF410780020102810101\"");
    reset_fake();
    assert(idf_esim_lpa_cancel_session({0xBF,0x21,0}, response, message) != ESP_OK);
    assert(fake.commands.empty() && response.empty());

    reset_fake(ResponseMode::auth_material);
    std::vector<uint8_t> info1;
    std::array<uint8_t, 16> challenge = {};
    assert(idf_esim_lpa_get_auth_material(info1, challenge, message) == ESP_OK);
    assert(info1.size() == 12U && challenge[0] == 0x00U && challenge[15] == 0xFFU);
    assert(fake.owner_begin_calls == 1U && fake.owner_end_calls == 1U);
    assert(fake.ccho_calls == 1U && fake.cchc_calls == 1U);
    assert(fake.commands.front() == "AT+CSIM=20,\"80AA000005A903830107\"");

    reset_fake();
    const std::vector<uint8_t> prepare = {0xBF, 0x21, 0x00};
    assert(idf_esim_lpa_prepare_download(prepare, response, message) == ESP_OK);
    assert(fake.commands.size() == 4U);
    assert(fake.commands[0] == "AT+CSIM=20,\"80AA000005A903830107\"");
    assert(fake.ccho_calls == 1U && fake.cchc_calls == 1U);

    reset_fake();
    assert(idf_esim_lpa_authenticate_server({0xBF, 0x38, 0x00}, response, message) == ESP_OK);
    assert(fake.commands.front() == "AT+CSIM=20,\"80AA000005A903830107\"");

    reset_fake(ResponseMode::ccho_retry);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) == ESP_OK);
    assert(fake.ccho_calls == 2U && fake.cchc_calls == 4U);
    assert(fake.owner_begin_calls == 1U && fake.owner_end_calls == 1U);

    reset_fake(ResponseMode::ccho_bare);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) == ESP_OK);
    assert(fake.ccho_calls == 1U && fake.cchc_calls == 1U);

    reset_fake(ResponseMode::ccho_out_of_range);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) != ESP_OK);
    assert(fake.ccho_calls == 1U && fake.cgl_calls == 0U && fake.cchc_calls == 4U);
    assert(fake.commands.size() == 6U);
    assert(fake.commands[2] == "AT+CCHC=20");
    assert(fake.commands[3] == "AT+CCHC=1");
    assert(fake.commands[4] == "AT+CCHC=2");
    assert(fake.commands[5] == "AT+CCHC=3");

    reset_fake(ResponseMode::ccho_out_of_range_malformed);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) != ESP_OK);
    assert(fake.ccho_calls == 2U && fake.cgl_calls == 0U && fake.cchc_calls == 8U);
    assert(fake.commands.size() == 11U);
    assert(fake.commands[2] == "AT+CCHC=20");
    assert(fake.commands[3] == "AT+CCHC=1");
    assert(fake.commands[4] == "AT+CCHC=2");
    assert(fake.commands[5] == "AT+CCHC=3");
    assert(fake.commands[7] == "AT+CCHC=20");
    assert(fake.commands[8] == "AT+CCHC=1");
    assert(fake.commands[9] == "AT+CCHC=2");
    assert(fake.commands[10] == "AT+CCHC=3");

    reset_fake(ResponseMode::ccho_final_failure);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) != ESP_OK);
    assert(fake.ccho_calls == 2U && fake.cchc_calls == 6U);

    reset_fake(ResponseMode::terminal_capability_error);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) == ESP_ERR_NOT_SUPPORTED);
    assert(fake.owner_begin_calls == 1U && fake.owner_end_calls == 1U);
    assert(fake.ccho_calls == 0U && fake.cgl_calls == 0U && fake.cchc_calls == 0U);

    for (const ResponseMode mode : {ResponseMode::cgl_duplicate, ResponseMode::cgl_wrong_echo,
                                    ResponseMode::cgl_duplicate_echo,
                                    ResponseMode::cgl_unknown_line,
                                    ResponseMode::cgl_missing_ok, ResponseMode::cgl_error,
                                    ResponseMode::cgl_bad_hex, ResponseMode::cgl_bad_length,
                                    ResponseMode::cgl_unquoted, ResponseMode::cgl_after_ok}) {
        reset_fake(mode);
        assert(idf_esim_lpa_prepare_download(prepare, response, message) != ESP_OK);
        assert_safe_message(message);
        assert(fake.owner_begin_calls == 1U && fake.owner_end_calls == 1U);
        assert(fake.cchc_calls == 1U);
    }

    reset_fake(ResponseMode::cgl_interleaved);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) != ESP_OK);
    assert_safe_message(message);
    assert(fake.cchc_calls == 1U);

    reset_fake();
    response = {0xAA};
    assert(idf_esim_lpa_prepare_download({0xBF, 0x38, 0x00}, response, message) != ESP_OK);
    assert(response.empty() && fake.commands.empty());

    reset_fake(ResponseMode::chain_61);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) == ESP_OK);
    assert(fake.cgl_calls == 2U);

    reset_fake(ResponseMode::chain_91);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) == ESP_OK);
    assert(fake.cgl_calls == 1U);

    reset_fake(ResponseMode::chain_too_long);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) != ESP_OK);
    assert(fake.cgl_calls == 65U);
    assert_safe_message(message);

    reset_fake(ResponseMode::chain_too_large);
    assert(idf_esim_lpa_prepare_download(prepare, response, message) != ESP_OK);
    assert_safe_message(message);
}

void test_profile_urcs()
{
    std::vector<IdfEsimProfile> profiles;
    std::string eid;
    std::string message;

    reset_fake(ResponseMode::profile_interleaved);
    assert(idf_esim_list_profiles(profiles, eid, message) == ESP_OK);
    assert(!eid.empty() && profiles.size() == 1U);
    assert(profiles.front().iccid == "10");

    reset_fake(ResponseMode::profile_unknown_line);
    profiles.clear();
    eid.clear();
    assert(idf_esim_list_profiles(profiles, eid, message) != ESP_OK);
    assert(message.find("SENTINEL") == std::string::npos);
    assert(message.find("+CGLA") == std::string::npos);
}

void test_bpp_bounds()
{
    std::string message;
    std::vector<uint8_t> response;
    std::vector<uint8_t> block(120U, 0xA5U);

    reset_fake();
    IdfEsimLpaBppSession session;
    assert(session.begin_segment(message) == ESP_OK);
    const size_t before = fake.cgl_calls;
    assert(session.write_block(block.data(), 119U, false, 255U, response, message) == ESP_OK);
    assert(fake.cgl_calls == before + 1U);
    assert(session.write_block(block.data(), 120U, true, 255U, response, message) == ESP_OK);
    const size_t after_valid = fake.cgl_calls;
    assert(session.write_block(block.data(), 121U, true, 0U, response, message) != ESP_OK);
    assert(fake.cgl_calls == after_valid);
    assert(session.write_block(block.data(), 120U, true, 256U, response, message) != ESP_OK);
    assert(fake.cgl_calls == after_valid);
    IdfEsimLpaBppSession moved(std::move(session));
    session.close();
    moved.close();
    moved.close();
    session.close();
    assert(fake.cchc_calls == 1U);
    assert(fake.owner_begin_calls == 1U && fake.owner_end_calls == 1U);

    reset_fake();
    IdfEsimLpaBppSession reused;
    assert(reused.begin_segment(message) == ESP_OK);
    assert(reused.write_block(block.data(), 120U, true, 0U, response, message) == ESP_OK);
    assert(reused.begin_segment(message) == ESP_OK);
    assert(reused.write_block(block.data(), 120U, true, 0U, response, message) == ESP_OK);
    assert(fake.ccho_calls == 1U && fake.cchc_calls == 0U);
    reused.close();
    assert(fake.cchc_calls == 1U);
    assert(fake.owner_begin_calls == 1U && fake.owner_end_calls == 1U);

    for (const ResponseMode mode : {ResponseMode::bad_sw,
                                    ResponseMode::chain_overflow_nonempty,
                                    ResponseMode::get_response_failure}) {
        reset_fake(mode);
        IdfEsimLpaBppSession failed;
        assert(failed.begin_segment(message) == ESP_OK);
        response = {0xAA, 0xBB};
        assert(failed.write_block(block.data(), 1U, true, 0U, response, message) != ESP_OK);
        assert(response.empty());
        failed.close();
    }
}

void test_notifications()
{
    std::string message;
    std::vector<uint8_t> encoded;
    size_t offset = 0U;
    size_t length = 0U;

    reset_fake(ResponseMode::notifications);
    assert(idf_esim_lpa_retrieve_notifications(encoded, offset, length, message) == ESP_OK);
    assert(offset == 5U && length == 3U && offset + length == encoded.size());
    assert(encoded[offset] == 0x01U && encoded[offset + 1U] == 0x02U && encoded[offset + 2U] == 0x03U);

    for (uint8_t status : {0U, 1U, 2U, 3U}) {
        reset_fake(ResponseMode::notification_status);
        fake.notification_status = status;
        const esp_err_t result = idf_esim_lpa_remove_notification(0x01020304U, message);
        if (status < 2U) assert(result == ESP_OK);
        else assert(result != ESP_OK);
        assert_safe_message(message);
    }
}

}  // namespace

esp_err_t idf_modem_send_at(const std::string& command, uint32_t, std::string& response)
{
    fake.commands.push_back(command);
    if (command == "AT+CSIM=20,\"80AA000005A903830107\"") {
        if (fake.mode == ResponseMode::terminal_capability_error) {
            response = "\r\n+CSIM: 4,\"9300\"\r\nOK\r\n";
            return ESP_OK;
        }
        response = terminal_capability_response();
        return ESP_OK;
    }
    if (command.rfind("AT+CCHO=", 0U) == 0U) {
        ++fake.ccho_calls;
        if ((fake.mode == ResponseMode::ccho_retry || fake.mode == ResponseMode::ccho_final_failure) &&
            fake.ccho_calls == 1U) {
            response = "\r\n+CCHO: bad\r\nERROR\r\n";
            return ESP_FAIL;
        }
        if (fake.mode == ResponseMode::ccho_final_failure) {
            response = "\r\n+CCHO: bad\r\nERROR\r\n";
            return ESP_FAIL;
        }
        if (fake.mode == ResponseMode::ccho_bare) {
            response = "\r\n" + command + "\r\n1\r\nOK\r\n";
            return ESP_OK;
        }
        if (fake.mode == ResponseMode::ccho_out_of_range) {
            response = "\r\n+CCHO: 20\r\nOK\r\n";
            return ESP_OK;
        }
        if (fake.mode == ResponseMode::ccho_out_of_range_malformed) {
            response = "\r\n+CCHO: 20\r\nSENTINEL\r\nOK\r\n";
            return ESP_OK;
        }
        response = "\r\n+CCHO: 1\r\nOK\r\n";
        return ESP_OK;
    }
    if (command.rfind("AT+CGLA=", 0U) == 0U) {
        response = next_cgl_response();
        return ESP_OK;
    }
    if (command.rfind("AT+CCHC=", 0U) == 0U) {
        ++fake.cchc_calls;
        response = "\r\nOK\r\n";
        return ESP_OK;
    }
    response = "\r\nOK\r\n";
    return ESP_OK;
}

void idf_modem_begin_esim_operation() { ++fake.owner_begin_calls; }
void idf_modem_end_esim_operation() { ++fake.owner_end_calls; }
void idf_modem_set_sim_identity_hook(void (*)()) {}
esp_err_t idf_modem_request_reset(bool) { return ESP_OK; }

IdfModemStatus idf_modem_get_status() { return {}; }
void idf_log_line(const char*) {}
void idf_logf(const char*, ...) {}

int main()
{
    test_tlv_codec();
    test_lpa_api();
    test_profile_urcs();
    test_bpp_bounds();
    test_notifications();
    return 0;
}
