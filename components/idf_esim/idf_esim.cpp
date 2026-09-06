#include "idf_esim.h"
#include "idf_esim_codec.h"
#include "idf_esim_lpa.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <ctype.h>
#include <iterator>
#include <limits>
#include <memory>
#include <new>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <utility>

#include "esp_err.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "idf_log.h"
#include "idf_modem.h"
#include "idf_util.h"

namespace {

static constexpr const char* ISDR_AID_HEX = "A0000005591010FFFFFFFF8900000100";
// lpac uses 120-byte blocks by default. The 240 hex characters and framing fit common modem AT line limits.
static constexpr size_t STORE_DATA_MSS = 120;
// Request only the ES10c fields that the UI uses. Limit malformed 61xx chains so a task cannot hold the cellular channel forever.
static constexpr size_t APDU_RESPONSE_DATA_MAX = 16 * 1024;
static constexpr size_t GET_RESPONSE_CHAIN_MAX = 64;

using idf_esim_internal::Tlv;
using idf_esim_internal::append_tlv;
using idf_esim_internal::first_child;
using idf_esim_internal::parse_tlv;
using idf_esim_internal::tag_is;

struct ProfileIdentifier {
    std::vector<uint8_t> tag;
    std::vector<uint8_t> value;
    std::string display;
};

static std::string lower_ascii(std::string value)
{
    std::transform(value.begin(), value.end(), value.begin(), [](char ch) {
        return static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    });
    return value;
}

static bool equals_relaxed(const std::string& a, const std::string& b)
{
    return lower_ascii(idf_util_trim_copy(a)) == lower_ascii(idf_util_trim_copy(b));
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

static bool is_hex_string(const std::string& value)
{
    if (value.empty() || (value.size() % 2) != 0) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) { return hex_value(ch) >= 0; });
}

static bool hex_to_bytes(const std::string& hex, std::vector<uint8_t>& out)
{
    if (!is_hex_string(hex)) return false;
    out.clear();
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>((hex_value(hex[i]) << 4) | hex_value(hex[i + 1])));
    }
    return true;
}

static std::string bytes_to_hex(const uint8_t* data, size_t len)
{
    static constexpr char kHex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(data[i] >> 4) & 0x0F]);
        out.push_back(kHex[data[i] & 0x0F]);
    }
    return out;
}

static std::string bytes_to_hex(const std::vector<uint8_t>& data)
{
    return bytes_to_hex(data.data(), data.size());
}

static bool all_digits(const std::string& value)
{
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return isdigit(static_cast<unsigned char>(ch));
    });
}

static bool parse_positive_int_token(const std::string& value, int& out)
{
    // Reject empty, signed, and nondigit input before strtol. A digit-only string must be consumed in full.
    std::string text = idf_util_trim_copy(value);
    if (!all_digits(text)) return false;
    long parsed = strtol(text.c_str(), nullptr, 10);
    if (parsed <= 0 || parsed > 999) return false;
    out = static_cast<int>(parsed);
    return true;
}

static std::string compact_digits(const std::string& value)
{
    std::string out;
    out.reserve(value.size());
    std::copy_if(value.begin(), value.end(), std::back_inserter(out), [](char ch) {
        return isdigit(static_cast<unsigned char>(ch));
    });
    return out;
}

static std::string gsm_bcd_decode(const std::vector<uint8_t>& value)
{
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    out.reserve(value.size() * 2);
    for (uint8_t b : value) {
        uint8_t lo = b & 0x0F;
        uint8_t hi = (b >> 4) & 0x0F;
        if (lo != 0x0F) out.push_back(kHex[lo]);
        if (hi != 0x0F) out.push_back(kHex[hi]);
    }
    return out;
}

static bool gsm_bcd_encode(const std::string& digits, std::vector<uint8_t>& out)
{
    if (!all_digits(digits)) return false;
    out.clear();
    out.reserve((digits.size() + 1) / 2);
    for (size_t i = 0; i < digits.size(); i += 2) {
        uint8_t lo = static_cast<uint8_t>(digits[i] - '0');
        uint8_t hi = (i + 1 < digits.size()) ? static_cast<uint8_t>(digits[i + 1] - '0') : 0x0F;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    // SGP.22 defines ICCID (tag 5A) as 10 bytes. Pad short values with 0xFF as lpac does.
    while (out.size() < 10) out.push_back(0xFF);
    return true;
}

static std::string eid_decode(const std::vector<uint8_t>& value)
{
    std::string out;
    out.reserve(value.size() * 2);
    for (uint8_t b : value) {
        uint8_t hi = (b >> 4) & 0x0F;
        uint8_t lo = b & 0x0F;
        if (hi > 9 || lo > 9) return bytes_to_hex(value);
        out.push_back(static_cast<char>('0' + hi));
        out.push_back(static_cast<char>('0' + lo));
    }
    return out;
}

static int tlv_int_value(const Tlv& tlv, int def = 0)
{
    if (tlv.value.empty()) return def;
    // Card-controlled data: use only the final four bytes so a long TLV cannot cause signed overflow during a left shift.
    uint32_t out = 0;
    size_t start = tlv.value.size() > 4 ? tlv.value.size() - 4 : 0;
    for (size_t i = start; i < tlv.value.size(); ++i) out = (out << 8) | tlv.value[i];
    return static_cast<int>(out);
}

static std::string status_word_text(uint16_t sw)
{
    char buf[96];
    switch (sw) {
        case 0x9000: return "OK";
        case 0x6A82: return "eUICC application or profile not found";
        case 0x6985: return "Card policy rejected this operation";
        case 0x6A86: return "The card rejected the APDU parameters";
        case 0x6D00: return "The eUICC does not support this APDU command";
        case 0x6E00: return "The APDU logical channel rejected the CLA";
        default:
            snprintf(buf, sizeof(buf), "APDU status word %04X", static_cast<unsigned>(sw));
            return buf;
    }
}

static bool parse_size_token(const std::string& value, size_t& out)
{
    std::string text = idf_util_trim_copy(value);
    if (text.empty()) return false;
    size_t parsed = 0;
    for (char ch : text) {
        if (!isdigit(static_cast<unsigned char>(ch))) return false;
        size_t digit = static_cast<size_t>(ch - '0');
        if (parsed > (std::numeric_limits<size_t>::max() - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    out = parsed;
    return true;
}

enum class EsimResponsePolicy {
    strict_lpa,
    legacy_profile,
};

static bool is_profile_sms_pdu(const std::string& row)
{
    if (row.size() < 32U || (row.size() & 1U) != 0U) return false;
    return std::all_of(row.begin(), row.end(), [](char ch) { return hex_value(ch) >= 0; });
}

static bool is_profile_urc(const std::string& row, bool& expects_sms_pdu)
{
    if (row == "RING" || row.rfind("+CMTI:", 0) == 0 ||
        row.rfind("+CLIP:", 0) == 0 || row.rfind("+CEREG:", 0) == 0) {
        return true;
    }
    if (row.rfind("+CMT:", 0) == 0) {
        if (expects_sms_pdu) return false;
        expects_sms_pdu = true;
        return true;
    }
    return false;
}

static bool find_unique_response_line(const std::string& response,
                                      const std::string& command,
                                      const char* prefix,
                                      std::string& line,
                                      EsimResponsePolicy policy)
{
    line.clear();
    bool found = false;
    bool final_seen = false;
    bool echo_seen = false;
    bool expects_sms_pdu = false;
    size_t pos = 0;
    while (pos <= response.size()) {
        size_t end = response.find('\n', pos);
        if (end == std::string::npos) end = response.size();
        const std::string row = idf_util_trim_copy(response.substr(pos, end - pos));
        if (!row.empty()) {
            if (expects_sms_pdu) {
                if (policy != EsimResponsePolicy::legacy_profile || !is_profile_sms_pdu(row)) {
                    return false;
                }
                expects_sms_pdu = false;
            } else if (row == "OK") {
                if (final_seen) return false;
                final_seen = true;
            } else if (final_seen) {
                return false;
            } else if (row.rfind("AT+", 0) == 0) {
                if (echo_seen || row != command) return false;
                echo_seen = true;
            } else if (row == "ERROR" || row.rfind("+CME ERROR", 0) == 0 ||
                       row.rfind("+CMS ERROR", 0) == 0) {
                return false;
            } else if (row.rfind(prefix, 0) == 0) {
                if (found) return false;
                line = row;
                found = true;
            } else if (policy == EsimResponsePolicy::legacy_profile &&
                       is_profile_urc(row, expects_sms_pdu)) {
                // Only the modem's bounded preserved URCs are ignored for legacy profile reads.
            } else {
                return false;
            }
        }
        if (end == response.size()) break;
        pos = end + 1U;
    }
    return found && final_seen && !expects_sms_pdu;
}

static bool parse_quoted_hex_response(const std::string& resp,
                                      const std::string& command,
                                      const char* prefix,
                                      std::vector<uint8_t>& out,
                                      std::string& message,
                                      EsimResponsePolicy policy)
{
    out.clear();
    std::string line;
    if (!find_unique_response_line(resp, command, prefix, line, policy)) {
        message = "The modem APDU response is incomplete";
        return false;
    }
    const size_t colon = line.find(':');
    const size_t comma = line.find(',', colon == std::string::npos ? 0U : colon + 1U);
    if (colon == std::string::npos || comma == std::string::npos) {
        message = "The modem APDU response format cannot be parsed";
        return false;
    }
    size_t declared_length = 0;
    if (!parse_size_token(line.substr(colon + 1U, comma - colon - 1U), declared_length) ||
        declared_length > APDU_RESPONSE_DATA_MAX * 2U) {
        message = "The modem APDU response length is invalid";
        return false;
    }
    const size_t q1 = line.find('"', comma + 1U);
    if (q1 == std::string::npos || !idf_util_trim_copy(line.substr(comma + 1U, q1 - comma - 1U)).empty()) {
        message = "The modem APDU response data is not quoted";
        return false;
    }
    const size_t q2 = line.find('"', q1 + 1U);
    if (q2 == std::string::npos || !idf_util_trim_copy(line.substr(q2 + 1U)).empty()) {
        message = "The modem APDU response quotes are invalid";
        return false;
    }
    const std::string hex = line.substr(q1 + 1U, q2 - q1 - 1U);
    if (declared_length != hex.size() || hex.empty() || (hex.size() & 1U) != 0U ||
        !hex_to_bytes(hex, out)) {
        message = "The modem APDU response is not valid hex";
        out.clear();
        return false;
    }
    return true;
}

static bool parse_ccho_channel(const std::string& resp,
                               const std::string& command,
                               int& channel,
                               int& candidate_channel,
                               EsimResponsePolicy policy)
{
    channel = 0;
    candidate_channel = 0;
    bool found = false;
    bool final_seen = false;
    bool echo_seen = false;
    bool expects_sms_pdu = false;
    size_t pos = 0;
    while (pos <= resp.size()) {
        size_t end = resp.find('\n', pos);
        if (end == std::string::npos) end = resp.size();
        const std::string row = idf_util_trim_copy(resp.substr(pos, end - pos));
        if (!row.empty()) {
            if (expects_sms_pdu) {
                if (policy != EsimResponsePolicy::legacy_profile || !is_profile_sms_pdu(row)) {
                    return false;
                }
                expects_sms_pdu = false;
            } else if (row == "OK") {
                if (final_seen) return false;
                final_seen = true;
            } else if (final_seen) {
                return false;
            } else if (row.rfind("AT+", 0) == 0) {
                if (echo_seen || row != command) return false;
                echo_seen = true;
            } else if (row == "ERROR" || row.rfind("+CME ERROR", 0) == 0 ||
                       row.rfind("+CMS ERROR", 0) == 0) {
                return false;
            } else if (row.rfind("+CCHO:", 0) == 0) {
                const size_t colon = row.find(':');
                int parsed = 0;
                if (found || colon == std::string::npos ||
                    !parse_positive_int_token(row.substr(colon + 1U), parsed)) {
                    return false;
                }
                channel = parsed;
                candidate_channel = parsed;
                found = true;
            } else if (all_digits(row)) {
                int parsed = 0;
                if (found || !parse_positive_int_token(row, parsed)) return false;
                channel = parsed;
                candidate_channel = parsed;
                found = true;
            } else if (policy == EsimResponsePolicy::legacy_profile &&
                       is_profile_urc(row, expects_sms_pdu)) {
                // Only the modem's bounded preserved URCs are ignored for legacy profile reads.
            } else {
                return false;
            }
        }
        if (end == resp.size()) break;
        pos = end + 1U;
    }
    return found && final_seen && !expects_sms_pdu;
}

static uint8_t class_byte_for_channel(uint8_t cla, int channel)
{
    if (channel < 4) return static_cast<uint8_t>((cla & 0x9C) | channel);
    return static_cast<uint8_t>((cla & 0xB0) | 0x40 | (channel - 4));
}

static uint16_t response_sw(const std::vector<uint8_t>& resp)
{
    if (resp.size() < 2) return 0;
    return static_cast<uint16_t>((resp[resp.size() - 2] << 8) | resp[resp.size() - 1]);
}

static constexpr bool response_sw_ok(uint16_t sw) { return sw == 0x9000 || (sw >> 8) == 0x91; }
static_assert(response_sw_ok(0x9000) && response_sw_ok(0x9108) && !response_sw_ok(0x9300));

static esp_err_t declare_terminal_capability(std::string& message)
{
    static constexpr const char* TERMINAL_CAPABILITY_CMD =
        "AT+CSIM=20,\"80AA000005A903830107\"";
    std::string response;
    esp_err_t err = idf_modem_send_at(TERMINAL_CAPABILITY_CMD, 10000, response);
    const bool has_csim_line = response.find("+CSIM:") != std::string::npos;
    if (err != ESP_OK && !has_csim_line) {
        message = "Terminal capability command failed";
        return err;
    }
    uint16_t status = 0;
    const idf_esim_internal::CsimParseResult result =
        idf_esim_internal::parse_terminal_capability_csim(response, status, message);
    if (result == idf_esim_internal::CsimParseResult::success) return ESP_OK;
    return result == idf_esim_internal::CsimParseResult::status_error ? ESP_ERR_NOT_SUPPORTED : ESP_FAIL;
}

class EsimApduSession {
public:
    explicit EsimApduSession(bool terminal_capability_required = false,
                             EsimResponsePolicy response_policy = EsimResponsePolicy::strict_lpa)
        : m_terminal_capability_required(terminal_capability_required),
          m_response_policy(response_policy)
    {
    }

    esp_err_t open(std::string& message)
    {
        if (m_open) return ESP_OK;
        if (m_terminal_capability_required) {
            const esp_err_t capability_err = declare_terminal_capability(message);
            if (capability_err != ESP_OK) return capability_err;
        }
        std::string cmd = "AT+CCHO=\"";
        cmd += ISDR_AID_HEX;
        cmd += "\"";
        std::string resp;
        int candidate_channel = 0;
        esp_err_t err = idf_modem_send_at(cmd, 30000, resp);
        if (err != ESP_OK ||
            !parse_ccho_channel(resp, cmd, m_channel, candidate_channel, m_response_policy)) {
            // An abnormal previous session can leave a logical channel open. Close channels 1 through 3 and retry once.
            close_known_channels(candidate_channel);
            resp.clear();
            err = idf_modem_send_at(cmd, 30000, resp);
            candidate_channel = 0;
        }
        if (err != ESP_OK ||
            !parse_ccho_channel(resp, cmd, m_channel, candidate_channel, m_response_policy)) {
            message = (err == ESP_OK) ? "Failed to open the eUICC logical channel: invalid response"
                                      : "Failed to open the eUICC logical channel: modem command failed";
            close_known_channels(candidate_channel);
            return err == ESP_OK ? ESP_FAIL : err;
        }
        if (m_channel <= 0 || m_channel > 19) {
            message = "The modem returned an unsupported logical channel";
            close_known_channels(m_channel);
            m_channel = 0;
            return ESP_FAIL;
        }
        m_open = true;
        return ESP_OK;
    }

    void close()
    {
        if (!m_open) return;
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "AT+CCHC=%d", m_channel);
        std::string ignored;
        idf_modem_send_at(cmd, 5000, ignored);
        m_open = false;
        m_channel = 0;
    }

    ~EsimApduSession()
    {
        close();
    }

    esp_err_t transmit_apdu(const std::vector<uint8_t>& apdu,
                            std::vector<uint8_t>& response,
                            std::string& message)
    {
        if (!m_open) {
            message = "The eUICC logical channel is not open";
            return ESP_ERR_INVALID_STATE;
        }
        std::string hex = bytes_to_hex(apdu);
        char head[48];
        snprintf(head, sizeof(head), "AT+CGLA=%d,%u,\"", m_channel, static_cast<unsigned>(hex.size()));
        std::string cmd = head;
        cmd += hex;
        cmd += "\"";
        std::string resp;
        esp_err_t err = idf_modem_send_at(cmd, 30000, resp);
        if (err != ESP_OK) {
            message = "APDU modem command failed";
            return err;
        }
        if (!parse_quoted_hex_response(resp, cmd, "+CGLA:", response, message, m_response_policy)) {
            response.clear();
            return ESP_FAIL;
        }
        if (response.size() < 2) {
            message = "APDU response is too short";
            return ESP_FAIL;
        }
        return ESP_OK;
    }

    esp_err_t exchange_store_data(const std::vector<uint8_t>& payload,
                                  std::vector<uint8_t>& response_data,
                                  std::string& message)
    {
        if (payload.empty()) {
            message = "APDU payload is empty";
            return ESP_ERR_INVALID_ARG;
        }
        response_data.clear();
        size_t offset = 0;
        uint16_t block_number = 0;
        while (offset < payload.size()) {
            size_t n = std::min(STORE_DATA_MSS, payload.size() - offset);
            bool last = (offset + n == payload.size());
            if (block_number > 0xFFU) {
                message = "STORE DATA segment is too large";
                return ESP_ERR_INVALID_SIZE;
            }
            esp_err_t err = exchange_store_data_block(
                payload.data() + offset, n, last, static_cast<uint8_t>(block_number),
                response_data, message);
            if (err != ESP_OK) return err;

            offset += n;
            ++block_number;
        }
        return ESP_OK;
    }

    esp_err_t exchange_store_data_block(const uint8_t* data,
                                        size_t length,
                                        bool last,
                                        uint8_t block_number,
                                        std::vector<uint8_t>& response_data,
                                        std::string& message)
    {
        if (!data || length == 0U || length > STORE_DATA_MSS) {
            response_data.clear();
            message = "STORE DATA block size is invalid";
            return ESP_ERR_INVALID_ARG;
        }
        std::vector<uint8_t> apdu;
        apdu.reserve(5U + length);
        apdu.push_back(class_byte_for_channel(0x80, m_channel));
        apdu.push_back(0xE2);
        apdu.push_back(last ? 0x91 : 0x11);
        apdu.push_back(block_number);
        apdu.push_back(static_cast<uint8_t>(length));
        apdu.insert(apdu.end(), data, data + length);

        std::vector<uint8_t> resp;
        const esp_err_t err = transmit_apdu(apdu, resp, message);
        if (err != ESP_OK) {
            response_data.clear();
            return err;
        }
        std::vector<uint8_t> collected;
        const esp_err_t collect_err = collect_response(resp, collected, message);
        if (collect_err != ESP_OK) {
            response_data.clear();
            return collect_err;
        }
        response_data.swap(collected);
        return ESP_OK;
    }

private:
    void close_known_channels(int parsed_channel = 0)
    {
        if (parsed_channel > 0 && parsed_channel <= 999) {
            char cchc[24];
            snprintf(cchc, sizeof(cchc), "AT+CCHC=%d", parsed_channel);
            std::string ignored;
            idf_modem_send_at(cchc, 3000, ignored);
        }
        for (int ch = 1; ch <= 3; ++ch) {
            if (ch == parsed_channel) continue;
            char cchc[24];
            snprintf(cchc, sizeof(cchc), "AT+CCHC=%d", ch);
            std::string ignored;
            idf_modem_send_at(cchc, 3000, ignored);
        }
    }

    esp_err_t collect_response(const std::vector<uint8_t>& first,
                               std::vector<uint8_t>& out,
                               std::string& message)
    {
        std::vector<uint8_t> resp = first;
        size_t get_response_count = 0;
        while (true) {
            uint16_t sw = response_sw(resp);
            if (sw == 0) {
                message = "APDU response is too short";
                return ESP_FAIL;
            }
            size_t data_len = resp.size() - 2;
            if (out.size() + data_len > APDU_RESPONSE_DATA_MAX) {
                message = "APDU response is too large";
                return ESP_ERR_NO_MEM;
            }
            out.insert(out.end(), resp.begin(), resp.end() - 2);
            // 91xx means success and an upcoming SIM REFRESH. SW2 is the proactive-command length, not an error code.
            if (response_sw_ok(sw)) return ESP_OK;
            if ((sw >> 8) != 0x61) {
                message = status_word_text(sw);
                return ESP_FAIL;
            }
            if (++get_response_count > GET_RESPONSE_CHAIN_MAX) {
                message = "APDU response has too many segments";
                return ESP_FAIL;
            }

            uint8_t le = static_cast<uint8_t>(sw & 0xFF);
            std::vector<uint8_t> get_resp = {
                class_byte_for_channel(0x80, m_channel), 0xC0, 0x00, 0x00, le
            };
            esp_err_t err = transmit_apdu(get_resp, resp, message);
            if (err != ESP_OK) return err;
        }
    }

    int m_channel = 0;
    bool m_open = false;
    bool m_terminal_capability_required = false;
    EsimResponsePolicy m_response_policy = EsimResponsePolicy::strict_lpa;
};

class EsimOperationGuard {
public:
    EsimOperationGuard() { idf_modem_begin_esim_operation(); }
    ~EsimOperationGuard() { idf_modem_end_esim_operation(); }
};

static esp_err_t invoke_es10_raw(const std::vector<uint8_t>& request,
                                 bool terminal_capability_required,
                                 std::vector<uint8_t>& response,
                                 std::string& message,
                                 EsimResponsePolicy response_policy = EsimResponsePolicy::strict_lpa)
{
    response.clear();
    EsimOperationGuard guard;
    EsimApduSession session(terminal_capability_required, response_policy);
    const esp_err_t err = session.open(message);
    if (err != ESP_OK) return err;
    const esp_err_t exchange_err = session.exchange_store_data(request, response, message);
    if (exchange_err != ESP_OK) response.clear();
    return exchange_err;
}

static esp_err_t invoke_es10c(const std::vector<uint8_t>& request,
                              Tlv& response,
                              std::string& message)
{
    std::vector<uint8_t> raw;
    const esp_err_t err = invoke_es10_raw(
        request, false, raw, message, EsimResponsePolicy::legacy_profile);
    if (err != ESP_OK) return err;
    if (!parse_tlv(raw, response, message)) return ESP_FAIL;
    return ESP_OK;
}

static std::vector<uint8_t> make_empty_request(uint8_t tag_low)
{
    return {0xBF, tag_low, 0x00};
}

static std::vector<uint8_t> make_get_eid_request()
{
    std::vector<uint8_t> body = {0x5C, 0x01, 0x5A};
    std::vector<uint8_t> out;
    static constexpr uint8_t req_tag[] = {0xBF, 0x3E};
    append_tlv(out, req_tag, body);
    return out;
}

static std::vector<uint8_t> make_profile_list_request(bool with_tags)
{
    std::vector<uint8_t> body;
    if (with_tags) {
        // Request only fields that the UI uses. Large fields such as profile icons increase peak heap use.
        std::vector<uint8_t> tags = {0x5A, 0x4F, 0x9F, 0x70, 0x90, 0x91, 0x92, 0x95};
        static constexpr uint8_t tag_list_tag[] = {0x5C};
        append_tlv(body, tag_list_tag, tags);
    }
    std::vector<uint8_t> out;
    static constexpr uint8_t req_tag[] = {0xBF, 0x2D};
    append_tlv(out, req_tag, body);
    return out;
}

static std::string profile_state_text(int state)
{
    switch (state) {
        case 0: return "disabled";
        case 1: return "enabled";
        default: return "unknown";
    }
}

static std::string profile_class_text(int klass)
{
    switch (klass) {
        case 0: return "test";
        case 1: return "provisioning";
        case 2: return "operational";
        default: return "unknown";
    }
}

static void parse_profile_info(const Tlv& tlv, IdfEsimProfile& out)
{
    static constexpr uint8_t TAG_ICCID[] = {0x5A};
    static constexpr uint8_t TAG_ISDP[] = {0x4F};
    static constexpr uint8_t TAG_STATE[] = {0x9F, 0x70};
    static constexpr uint8_t TAG_NICK[] = {0x90};
    static constexpr uint8_t TAG_SPN[] = {0x91};
    static constexpr uint8_t TAG_NAME[] = {0x92};
    static constexpr uint8_t TAG_CLASS[] = {0x95};

    if (const Tlv* v = first_child(tlv, TAG_ICCID)) out.iccid = gsm_bcd_decode(v->value);
    if (const Tlv* v = first_child(tlv, TAG_ISDP)) out.isdpAid = bytes_to_hex(v->value);
    if (const Tlv* v = first_child(tlv, TAG_STATE)) out.state = profile_state_text(tlv_int_value(*v, -1));
    if (const Tlv* v = first_child(tlv, TAG_NICK)) out.nickname.assign(v->value.begin(), v->value.end());
    if (const Tlv* v = first_child(tlv, TAG_SPN)) out.serviceProvider.assign(v->value.begin(), v->value.end());
    if (const Tlv* v = first_child(tlv, TAG_NAME)) out.profileName.assign(v->value.begin(), v->value.end());
    if (const Tlv* v = first_child(tlv, TAG_CLASS)) out.profileClass = profile_class_text(tlv_int_value(*v, 1));
    if (out.state.empty()) out.state = "disabled";
    if (out.profileClass.empty()) out.profileClass = "provisioning";
}

static bool parse_profile_list_response(const Tlv& response,
                                        std::vector<IdfEsimProfile>& profiles,
                                        std::string& message)
{
    static constexpr uint8_t TAG_LIST[] = {0xBF, 0x2D};
    static constexpr uint8_t TAG_ERROR[] = {0x81};
    static constexpr uint8_t TAG_CONTAINER[] = {0xA0};
    static constexpr uint8_t TAG_PROFILE_E3[] = {0xE3};
    static constexpr uint8_t TAG_PROFILE_BF25[] = {0xBF, 0x25};

    if (!tag_is(response, TAG_LIST)) {
        message = "Profile list response tag does not match";
        return false;
    }
    if (const Tlv* err = first_child(response, TAG_ERROR)) {
        int code = tlv_int_value(*err, 127);
        message = (code == 1) ? "The eUICC rejected the profile list query" : "The eUICC returned an unknown profile list error";
        return false;
    }
    const Tlv* container = first_child(response, TAG_CONTAINER);
    const std::vector<Tlv>& rows = container ? container->children : response.children;
    profiles.clear();
    for (const Tlv& row : rows) {
        if (!tag_is(row, TAG_PROFILE_E3) && !tag_is(row, TAG_PROFILE_BF25)) continue;
        IdfEsimProfile p;
        parse_profile_info(row, p);
        if (!p.iccid.empty() || !p.isdpAid.empty()) profiles.push_back(std::move(p));
    }
    return true;
}

// The EID is fixed for one eUICC. Cache it after the first read to avoid an APDU session before each list request.
// The cellular-task mutex serializes callers. A replaceable eUICC can change its EID after a hot swap.
// The modem hook only sets an atomic dirty flag. The next read_eid call clears the cache in the serialized cellular task.
static std::string s_eid_cache;
static std::atomic<bool> s_eid_cache_stale{false};

static void on_sim_identity_changed()
{
    s_eid_cache_stale.store(true, std::memory_order_relaxed);
}

static esp_err_t read_eid(std::string& eid, std::string& message)
{
    static constexpr uint8_t TAG_EID_RESP[] = {0xBF, 0x3E};
    static constexpr uint8_t TAG_EID[] = {0x5A};

    if (s_eid_cache_stale.exchange(false, std::memory_order_relaxed)) s_eid_cache.clear();
    if (!s_eid_cache.empty()) {
        eid = s_eid_cache;
        message = "EID (cached)";
        return ESP_OK;
    }

    Tlv response;
    esp_err_t err = invoke_es10c(make_get_eid_request(), response, message);
    if (err != ESP_OK) return err;
    if (!tag_is(response, TAG_EID_RESP)) {
        message = "EID response tag does not match";
        return ESP_FAIL;
    }
    const Tlv* eid_tlv = first_child(response, TAG_EID);
    if (!eid_tlv || eid_tlv->value.empty()) {
        message = "The eUICC did not return an EID";
        return ESP_FAIL;
    }
    eid = eid_decode(eid_tlv->value);
    s_eid_cache = eid;
    message = "EID read succeeded";
    return ESP_OK;
}

static esp_err_t read_profiles(std::vector<IdfEsimProfile>& profiles, std::string& message)
{
    Tlv response;
    esp_err_t err = invoke_es10c(make_profile_list_request(true), response, message);
    if (err == ESP_OK && parse_profile_list_response(response, profiles, message)) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Read %u eSIM profiles", static_cast<unsigned>(profiles.size()));
        message = buf;
        return ESP_OK;
    }

    // Some cards reject the tag-list parameter. Fall back to BF2D00 and retry once.
    std::string first_error = message;
    response = Tlv();
    err = invoke_es10c(make_profile_list_request(false), response, message);
    if (err == ESP_OK && parse_profile_list_response(response, profiles, message)) {
        char buf[96];
        snprintf(buf, sizeof(buf), "Read %u eSIM profiles (compatibility mode)", static_cast<unsigned>(profiles.size()));
        message = buf;
        return ESP_OK;
    }
    if (!first_error.empty()) message = first_error + "; compatibility query also failed: " + message;
    return err == ESP_OK ? ESP_FAIL : err;
}

static bool make_direct_identifier(const std::string& raw,
                                   bool require_iccid,
                                   ProfileIdentifier& out,
                                   std::string& message)
{
    std::string value = idf_util_trim_copy(raw);
    std::string digits = compact_digits(value);
    if (digits.size() >= 18 && digits.size() <= 22 && digits.size() == value.size()) {
        std::vector<uint8_t> bcd;
        if (!gsm_bcd_encode(digits, bcd)) {
            message = "ICCID format is invalid";
            return false;
        }
        out.tag = {0x5A};
        out.value = std::move(bcd);
        out.display = digits;
        return true;
    }
    if (!require_iccid && value.size() >= 10 && value.size() <= 64 && is_hex_string(value)) {
        std::vector<uint8_t> aid;
        if (hex_to_bytes(value, aid)) {
            out.tag = {0x4F};
            out.value = std::move(aid);
            out.display = value;
            return true;
        }
    }
    return false;
}

static bool profile_matches(const IdfEsimProfile& p, const std::string& id)
{
    std::string v = idf_util_trim_copy(id);
    return (!p.iccid.empty() && equals_relaxed(p.iccid, v)) ||
           (!p.isdpAid.empty() && equals_relaxed(p.isdpAid, v)) ||
           (!p.nickname.empty() && equals_relaxed(p.nickname, v)) ||
           (!p.profileName.empty() && equals_relaxed(p.profileName, v)) ||
           (!p.serviceProvider.empty() && equals_relaxed(p.serviceProvider, v));
}

static bool identifier_from_profile(const IdfEsimProfile& profile,
                                    ProfileIdentifier& out,
                                    std::string& message)
{
    if (profile.iccid.empty()) {
        message = "The target profile has no ICCID, so this operation cannot continue";
        return false;
    }
    return make_direct_identifier(profile.iccid, true, out, message);
}

static esp_err_t resolve_identifier(const std::string& raw,
                                    bool require_iccid,
                                    ProfileIdentifier& out,
                                    std::string& message)
{
    if (raw.empty()) {
        message = "Profile identifier is empty";
        return ESP_ERR_INVALID_ARG;
    }
    if (make_direct_identifier(raw, require_iccid, out, message)) return ESP_OK;

    std::vector<IdfEsimProfile> profiles;
    std::string list_msg;
    esp_err_t err = read_profiles(profiles, list_msg);
    if (err != ESP_OK) {
        message = "Cannot resolve the alias or profile name: " + list_msg;
        return err;
    }
    const IdfEsimProfile* hit = nullptr;
    int matched = 0;
    for (const IdfEsimProfile& profile : profiles) {
        if (!profile_matches(profile, raw)) continue;
        ++matched;
        if (!hit) hit = &profile;
    }
    if (matched > 1) {
        // Nicknames and carrier names can repeat. Do not select the first match for irreversible operations.
        char buf[96];
        snprintf(buf, sizeof(buf), "The identifier matches %d profiles. Use the full ICCID", matched);
        message = buf;
        return ESP_ERR_INVALID_ARG;
    }
    if (hit) return identifier_from_profile(*hit, out, message) ? ESP_OK : ESP_FAIL;
    message = "No matching eSIM profile: " + idf_esim_mask_profile_id(raw);
    return ESP_ERR_NOT_FOUND;
}

static std::vector<uint8_t> make_profile_operation_request(const ProfileIdentifier& identifier,
                                                           bool enable)
{
    std::vector<uint8_t> id_tlv;
    append_tlv(id_tlv, identifier.tag.data(), identifier.tag.size(), identifier.value);

    std::vector<uint8_t> body;
    static constexpr uint8_t TAG_A0[] = {0xA0};
    append_tlv(body, TAG_A0, id_tlv);
    // Encode refreshFlag as FALSE (0x00). The ML307R does not consume a proactive REFRESH command.
    // A stale session then makes CCHO and ES10c alternate between catBusy and CME ERROR 4 (issue #17).
    // SGP.22 permits operation without refreshFlag. This LPA resets the UICC after success.
    std::vector<uint8_t> refresh_value = {0x00};
    static constexpr uint8_t TAG_REFRESH[] = {0x81};
    append_tlv(body, TAG_REFRESH, refresh_value);

    std::vector<uint8_t> out;
    const uint8_t tag_enable[] = {0xBF, 0x31};
    const uint8_t tag_disable[] = {0xBF, 0x32};
    if (enable) append_tlv(out, tag_enable, body);
    else append_tlv(out, tag_disable, body);
    return out;
}

static const char* operation_result_text(bool enable, int result)
{
    switch (result) {
        case 0: return "OK";
        case 1: return "ICCID/AID does not exist";
        case 2: return enable ? "Profile is not disabled" : "Profile is not enabled";
        case 3: return "Profile policy prohibits this operation";
        case 4: return "The card rejected repeated activation of the current profile";
        case 5: return "The card toolkit is busy. Retry later";
        case 127: return "Undefined eUICC error";
        default: return "Unknown result code";
    }
}

static const char* delete_result_text(int result)
{
    switch (result) {
        case 0: return "OK";
        case 1: return "ICCID/AID does not exist";
        case 2: return "Profile is not disabled";
        case 3: return "Profile policy prohibits deletion";
        case 5: return "The card toolkit is busy. Retry later";
        case 127: return "Undefined eUICC error";
        default: return "Unknown result code";
    }
}

static esp_err_t profile_operation_once(const ProfileIdentifier& identifier,
                                        bool enable,
                                        int& result_code,
                                        std::string& message)
{
    result_code = -1;
    Tlv response;
    esp_err_t err = invoke_es10c(make_profile_operation_request(identifier, enable), response, message);
    if (err != ESP_OK) return err;

    const uint8_t expected_enable[] = {0xBF, 0x31};
    const uint8_t expected_disable[] = {0xBF, 0x32};
    if ((enable && !tag_is(response, expected_enable)) || (!enable && !tag_is(response, expected_disable))) {
        message = "Profile operation response tag does not match";
        return ESP_FAIL;
    }
    static constexpr uint8_t TAG_RESULT[] = {0x80};
    const Tlv* result = first_child(response, TAG_RESULT);
    if (!result) {
        message = "Profile operation response has no result code";
        return ESP_FAIL;
    }
    result_code = tlv_int_value(*result, 127);
    if (result_code != 0) {
        message = operation_result_text(enable, result_code);
        return ESP_FAIL;
    }
    return ESP_OK;
}

// Wait for a soft or hard modem restart. The phase changes to powering when the request starts.
// It changes to registering after SMS and registration setup, when the SIM can open a logical channel again.
static bool wait_modem_reset_done(uint32_t timeout_ms)
{
    for (uint32_t waited = 0; waited < timeout_ms; waited += 1000) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        IdfModemStatus st = idf_modem_get_status();
        if (st.atReady && st.phase != "powering" && st.phase != "at_ready") return true;
    }
    return false;
}

static esp_err_t profile_operation(const std::string& raw, bool enable, std::string& message)
{
    ProfileIdentifier identifier;
    esp_err_t err = resolve_identifier(raw, false, identifier, message);
    if (err != ESP_OK) return err;

    int code = -1;
    err = profile_operation_once(identifier, enable, code, message);
    if (err != ESP_OK && code == 5) {
        // catBusy indicates a stale proactive session, often left by an old refreshFlag implementation.
        // It can survive an ESP restart or OTA update while modem power remains on. Power-cycle and retry once.
        idf_logf("eSIM operation returned catBusy; power-cycle the modem to reset the UICC and retry");
        idf_modem_request_reset(true);
        if (!wait_modem_reset_done(90000)) {
            message += "; modem restart timed out. Retry later";
            return ESP_FAIL;
        }
        err = profile_operation_once(identifier, enable, code, message);
    }
    if (err != ESP_OK) return err;
    // The eUICC contains the new state, but the current UICC session still uses the old profile.
    // Reset the UICC with a soft modem restart to apply the change automatically (issue #17).
    idf_modem_request_reset(false);
    message = enable ? "eSIM profile enabled; modem is restarting and attaching with the new card"
                     : "eSIM profile disabled; modem is restarting to apply the change";
    return ESP_OK;
}

static std::vector<uint8_t> make_delete_profile_request(const ProfileIdentifier& identifier)
{
    std::vector<uint8_t> id_tlv;
    append_tlv(id_tlv, identifier.tag.data(), identifier.tag.size(), identifier.value);

    std::vector<uint8_t> out;
    static constexpr uint8_t tag_delete[] = {0xBF, 0x33};
    append_tlv(out, tag_delete, id_tlv);
    return out;
}

static esp_err_t delete_profile(const std::string& raw, std::string& message)
{
    ProfileIdentifier identifier;
    esp_err_t err = resolve_identifier(raw, false, identifier, message);
    if (err != ESP_OK) return err;

    Tlv response;
    err = invoke_es10c(make_delete_profile_request(identifier), response, message);
    if (err != ESP_OK) return err;

    static constexpr uint8_t TAG_RESP[] = {0xBF, 0x33};
    static constexpr uint8_t TAG_RESULT[] = {0x80};
    if (!tag_is(response, TAG_RESP)) {
        message = "Profile deletion response tag does not match";
        return ESP_FAIL;
    }
    const Tlv* result = first_child(response, TAG_RESULT);
    if (!result) {
        message = "Profile deletion response has no result code";
        return ESP_FAIL;
    }
    int code = tlv_int_value(*result, 127);
    if (code != 0) {
        message = delete_result_text(code);
        return ESP_FAIL;
    }
    message = "eSIM profile deleted";
    return ESP_OK;
}

static std::vector<uint8_t> make_set_nickname_request(const ProfileIdentifier& identifier,
                                                      const std::string& nickname)
{
    std::vector<uint8_t> body;
    append_tlv(body, identifier.tag.data(), identifier.tag.size(), identifier.value);
    std::vector<uint8_t> nick(nickname.begin(), nickname.end());
    static constexpr uint8_t TAG_NICK[] = {0x90};
    append_tlv(body, TAG_NICK, nick);

    std::vector<uint8_t> out;
    static constexpr uint8_t TAG_REQ[] = {0xBF, 0x29};
    append_tlv(out, TAG_REQ, body);
    return out;
}

static esp_err_t set_profile_nickname(const std::string& raw,
                                      const std::string& nickname,
                                      std::string& message)
{
    std::string nick = idf_util_trim_copy(nickname);
    if (nick.size() > 64) {
        message = "Nickname cannot exceed 64 bytes";
        return ESP_ERR_INVALID_ARG;
    }

    ProfileIdentifier identifier;
    esp_err_t err = resolve_identifier(raw, true, identifier, message);
    if (err != ESP_OK) return err;

    Tlv response;
    err = invoke_es10c(make_set_nickname_request(identifier, nick), response, message);
    if (err != ESP_OK) return err;

    static constexpr uint8_t TAG_RESP[] = {0xBF, 0x29};
    static constexpr uint8_t TAG_RESULT[] = {0x80};
    if (!tag_is(response, TAG_RESP)) {
        message = "Nickname update response tag does not match";
        return ESP_FAIL;
    }
    const Tlv* result = first_child(response, TAG_RESULT);
    if (!result) {
        message = "Nickname update response has no result code";
        return ESP_FAIL;
    }
    int code = tlv_int_value(*result, 127);
    if (code == 0) {
        message = "eSIM profile nickname updated";
        return ESP_OK;
    }
    message = (code == 1) ? "ICCID does not exist" : "The eUICC failed to set the nickname";
    return ESP_FAIL;
}

static esp_err_t read_lpa_preflight(EsimApduSession& session,
                                    std::vector<uint8_t>* raw_info1,
                                    std::string& message)
{
    std::vector<uint8_t> raw;
    idf_esim_internal::EuiccInfo1Fields info1;
    esp_err_t err = session.exchange_store_data(make_empty_request(0x20), raw, message);
    if (err != ESP_OK) return err;
    if (!idf_esim_internal::parse_euicc_info1(raw, info1, message)) return ESP_FAIL;
    if (raw_info1) *raw_info1 = std::move(raw);

    raw.clear();
    idf_esim_internal::EuiccInfo2Fields info2;
    err = session.exchange_store_data(make_empty_request(0x22), raw, message);
    if (err != ESP_OK) return err;
    if (!idf_esim_internal::parse_euicc_info2(raw, info2, message)) return ESP_FAIL;
    return ESP_OK;
}

static esp_err_t read_lpa_auth_material(std::vector<uint8_t>& euicc_info1,
                                        std::array<uint8_t, 16>& challenge,
                                        std::string& message)
{
    euicc_info1.clear();
    challenge.fill(0);
    EsimOperationGuard guard;
    EsimApduSession session(true);
    esp_err_t err = session.open(message);
    if (err != ESP_OK) return err;

    err = read_lpa_preflight(session, &euicc_info1, message);
    if (err != ESP_OK) {
        euicc_info1.clear();
        return err;
    }

    std::vector<uint8_t> raw;
    err = session.exchange_store_data(make_empty_request(0x2E), raw, message);
    if (err != ESP_OK) {
        euicc_info1.clear();
        return err;
    }
    if (!idf_esim_internal::parse_euicc_challenge(raw, challenge.data(), message)) {
        euicc_info1.clear();
        challenge.fill(0);
        return ESP_FAIL;
    }
    message = "eUICC LPA authentication material is ready";
    return ESP_OK;
}

struct IdfEsimLpaBppSessionImpl {
    std::unique_ptr<EsimOperationGuard> guard;
    std::unique_ptr<EsimApduSession> session;
};

}  // namespace

void idf_esim_init(void)
{
    // Define this outside the anonymous namespace so app_main can link it.
    idf_modem_set_sim_identity_hook(on_sim_identity_changed);
}

esp_err_t idf_esim_get_eid(std::string& eid, std::string& message)
{
    return read_eid(eid, message);
}

esp_err_t idf_esim_lpa_get_auth_material(std::vector<uint8_t>& euicc_info1,
                                         std::array<uint8_t, 16>& challenge,
                                         std::string& safe_message)
{
    return read_lpa_auth_material(euicc_info1, challenge, safe_message);
}

esp_err_t idf_esim_lpa_authenticate_server(const std::vector<uint8_t>& request,
                                           std::vector<uint8_t>& response,
                                           std::string& safe_message)
{
    response.clear();
    if (request.empty() || request.size() > APDU_RESPONSE_DATA_MAX) {
        safe_message = "AuthenticateServer data object size is invalid";
        return ESP_ERR_INVALID_SIZE;
    }
    static constexpr uint8_t TAG_AUTHENTICATE_SERVER[] = {0xBF, 0x38};
    Tlv request_tlv;
    if (!parse_tlv(request, request_tlv, safe_message) ||
        !tag_is(request_tlv, TAG_AUTHENTICATE_SERVER)) {
        safe_message = "AuthenticateServer data object tag is invalid";
        return ESP_ERR_INVALID_ARG;
    }
    return invoke_es10_raw(request, true, response, safe_message);
}

esp_err_t idf_esim_lpa_prepare_download(const std::vector<uint8_t>& request,
                                        std::vector<uint8_t>& response,
                                        std::string& safe_message)
{
    response.clear();
    if (request.empty() || request.size() > APDU_RESPONSE_DATA_MAX) {
        safe_message = "PrepareDownload data object size is invalid";
        return ESP_ERR_INVALID_SIZE;
    }
    static constexpr uint8_t TAG_PREPARE_DOWNLOAD[] = {0xBF, 0x21};
    Tlv request_tlv;
    if (!parse_tlv(request, request_tlv, safe_message) ||
        !tag_is(request_tlv, TAG_PREPARE_DOWNLOAD)) {
        safe_message = "PrepareDownload data object tag is invalid";
        return ESP_ERR_INVALID_ARG;
    }
    return invoke_es10_raw(request, true, response, safe_message);
}

esp_err_t idf_esim_lpa_cancel_session(const std::vector<uint8_t>& request,
                                       std::vector<uint8_t>& response,
                                       std::string& safe_message)
{
    response.clear();
    if (request.empty() || request.size() > APDU_RESPONSE_DATA_MAX) {
        safe_message = "CancelSession data object size is invalid";
        return ESP_ERR_INVALID_SIZE;
    }
    static constexpr uint8_t TAG_CANCEL_SESSION[] = {0xBF, 0x41};
    Tlv request_tlv;
    if (!parse_tlv(request, request_tlv, safe_message) || !tag_is(request_tlv, TAG_CANCEL_SESSION)) {
        safe_message = "CancelSession data object tag is invalid";
        return ESP_ERR_INVALID_ARG;
    }
    return invoke_es10_raw(request, true, response, safe_message);
}

esp_err_t idf_esim_lpa_retrieve_notifications(std::vector<uint8_t>& encoded_response,
                                              size_t& list_offset,
                                              size_t& list_length,
                                              std::string& safe_message)
{
    encoded_response.clear();
    list_offset = 0;
    list_length = 0;
    static constexpr uint8_t TAG_RETRIEVE_NOTIFICATIONS[] = {0xBF, 0x2B};
    static constexpr uint8_t TAG_NOTIFICATION_LIST[] = {0xA0};
    static constexpr uint8_t TAG_RESULT_ERROR[] = {0x81};
    const std::vector<uint8_t> request = {0xBF, 0x2B, 0x00};

    esp_err_t err = invoke_es10_raw(request, true, encoded_response, safe_message);
    if (err != ESP_OK) return err;

    size_t pos = 0;
    idf_esim_internal::TlvSpan root;
    if (!idf_esim_internal::parse_tlv_span(
            encoded_response, encoded_response.size(), pos, root, safe_message) ||
        pos != encoded_response.size() ||
        !idf_esim_internal::tag_is(encoded_response, root, TAG_RETRIEVE_NOTIFICATIONS)) {
        encoded_response.clear();
        safe_message = "RetrieveNotificationsList response tag is invalid";
        return ESP_ERR_INVALID_RESPONSE;
    }

    pos = root.valueOffset;
    const size_t root_end = root.valueOffset + root.valueLength;
    idf_esim_internal::TlvSpan choice;
    if (!idf_esim_internal::parse_tlv_span(
            encoded_response, root_end, pos, choice, safe_message) || pos != root_end) {
        encoded_response.clear();
        safe_message = "RetrieveNotificationsList response choice is invalid";
        return ESP_ERR_INVALID_RESPONSE;
    }

    if (idf_esim_internal::tag_is(encoded_response, choice, TAG_RESULT_ERROR)) {
        if (choice.valueLength == 1U && encoded_response[choice.valueOffset] == 127U) {
            safe_message = "The eUICC could not retrieve pending notifications";
        } else {
            safe_message = "RetrieveNotificationsList error result is invalid";
        }
        encoded_response.clear();
        return ESP_ERR_INVALID_RESPONSE;
    }
    if (!idf_esim_internal::tag_is(encoded_response, choice, TAG_NOTIFICATION_LIST)) {
        encoded_response.clear();
        safe_message = "RetrieveNotificationsList success result is invalid";
        return ESP_ERR_INVALID_RESPONSE;
    }
    list_offset = choice.valueOffset;
    list_length = choice.valueLength;
    return ESP_OK;
}

esp_err_t idf_esim_lpa_remove_notification(uint32_t sequence_number,
                                           std::string& safe_message)
{
    std::vector<uint8_t> integer;
    uint32_t value = sequence_number;
    do {
        integer.push_back(static_cast<uint8_t>(value & 0xFFU));
        value >>= 8U;
    } while (value != 0U);
    std::reverse(integer.begin(), integer.end());
    if ((integer.front() & 0x80U) != 0U) integer.insert(integer.begin(), 0U);

    static constexpr uint8_t TAG_REMOVE_NOTIFICATION[] = {0xBF, 0x30};
    static constexpr uint8_t TAG_SEQUENCE_NUMBER[] = {0x80};
    std::vector<uint8_t> body;
    append_tlv(body, TAG_SEQUENCE_NUMBER, integer);
    std::vector<uint8_t> request;
    append_tlv(request, TAG_REMOVE_NOTIFICATION, body);
    std::vector<uint8_t> response;
    esp_err_t err = invoke_es10_raw(request, true, response, safe_message);
    if (err != ESP_OK) return err;

    static constexpr uint8_t TAG_STATUS[] = {0x80};
    Tlv root;
    if (!parse_tlv(response, root, safe_message) ||
        !tag_is(root, TAG_REMOVE_NOTIFICATION) || root.children.size() != 1U ||
        !tag_is(root.children.front(), TAG_STATUS) ||
        root.children.front().value.size() != 1U) {
        safe_message = "RemoveNotificationFromList response is invalid";
        return ESP_ERR_INVALID_RESPONSE;
    }
    switch (root.children.front().value[0]) {
        case 0x00:
            return ESP_OK;
        case 0x01:
            idf_log_line("eSIM pending notification is already absent");
            return ESP_OK;
        case 0x7F:
            safe_message = "The eUICC failed to remove the pending notification";
            return ESP_FAIL;
        default:
            safe_message = "RemoveNotificationFromList returned an unknown status";
            return ESP_ERR_INVALID_RESPONSE;
    }
}

IdfEsimLpaBppSession::IdfEsimLpaBppSession() : impl_(nullptr) {}

IdfEsimLpaBppSession::IdfEsimLpaBppSession(IdfEsimLpaBppSession&& other) noexcept
    : impl_(other.impl_)
{
    other.impl_ = nullptr;
}

IdfEsimLpaBppSession& IdfEsimLpaBppSession::operator=(IdfEsimLpaBppSession&& other) noexcept
{
    if (this == &other) return *this;
    close();
    impl_ = other.impl_;
    other.impl_ = nullptr;
    return *this;
}

IdfEsimLpaBppSession::~IdfEsimLpaBppSession()
{
    close();
}

esp_err_t IdfEsimLpaBppSession::begin_segment(std::string& safe_message)
{
    if (impl_) return ESP_OK;
    auto* impl = new (std::nothrow) IdfEsimLpaBppSessionImpl();
    if (!impl) {
        safe_message = "BPP segment session is out of memory";
        return ESP_ERR_NO_MEM;
    }
    impl->guard.reset(new (std::nothrow) EsimOperationGuard());
    impl->session.reset(new (std::nothrow) EsimApduSession(true));
    if (!impl->guard || !impl->session) {
        impl->session.reset();
        impl->guard.reset();
        delete impl;
        safe_message = "BPP segment session is out of memory";
        return ESP_ERR_NO_MEM;
    }
    const esp_err_t err = impl->session->open(safe_message);
    if (err != ESP_OK) {
        impl->session.reset();
        impl->guard.reset();
        delete impl;
        return err;
    }
    impl_ = impl;
    return ESP_OK;
}

esp_err_t IdfEsimLpaBppSession::write_block(const uint8_t* data,
                                            size_t length,
                                            bool last,
                                            uint16_t block_number,
                                            std::vector<uint8_t>& response,
                                            std::string& safe_message)
{
    auto* impl = static_cast<IdfEsimLpaBppSessionImpl*>(impl_);
    if (!impl || !impl->session) {
        response.clear();
        safe_message = "BPP segment session is not open";
        return ESP_ERR_INVALID_STATE;
    }
    if (block_number > 0xFFU) {
        response.clear();
        safe_message = "BPP block number is out of range";
        return ESP_ERR_INVALID_ARG;
    }
    return impl->session->exchange_store_data_block(data, length, last,
                                                    static_cast<uint8_t>(block_number),
                                                    response, safe_message);
}

void IdfEsimLpaBppSession::close()
{
    auto* impl = static_cast<IdfEsimLpaBppSessionImpl*>(impl_);
    if (!impl) return;
    if (impl->session) impl->session->close();
    impl->session.reset();
    impl->guard.reset();
    delete impl;
    impl_ = nullptr;
}

esp_err_t idf_esim_list_profiles(std::vector<IdfEsimProfile>& profiles,
                                 std::string& eid,
                                 std::string& message)
{
    std::string eid_msg;
    esp_err_t eid_err = read_eid(eid, eid_msg);
    esp_err_t list_err = read_profiles(profiles, message);
    if (list_err == ESP_OK) {
        if (eid_err != ESP_OK) {
            message += "; EID read failed: " + eid_msg;
        }
        return ESP_OK;
    }
    if (eid_err == ESP_OK) {
        message = "EID read succeeded, but the profile list failed: " + message;
    }
    return list_err;
}

esp_err_t idf_esim_enable_profile(const std::string& identifier, std::string& message)
{
    return profile_operation(identifier, true, message);
}

esp_err_t idf_esim_disable_profile(const std::string& identifier, std::string& message)
{
    return profile_operation(identifier, false, message);
}

esp_err_t idf_esim_delete_profile(const std::string& identifier,
                                  std::string& message)
{
    return delete_profile(identifier, message);
}

esp_err_t idf_esim_set_nickname(const std::string& identifier,
                                const std::string& nickname,
                                std::string& message)
{
    return set_profile_nickname(identifier, nickname, message);
}

esp_err_t idf_esim_switch_profile(const std::string& identifier, std::string& message)
{
    std::vector<IdfEsimProfile> profiles;
    std::string list_msg;
    esp_err_t err = read_profiles(profiles, list_msg);
    if (err != ESP_OK) {
        message = "Cannot read the profile list before switching: " + list_msg;
        return err;
    }
    for (const IdfEsimProfile& profile : profiles) {
        if (!profile_matches(profile, identifier)) continue;
        if (profile.state == "enabled") {
            std::string display_id = profile.iccid.empty() ? profile.isdpAid : profile.iccid;
            if (display_id.empty()) display_id = identifier;
            message = "The target eSIM profile is already enabled: " + idf_esim_mask_profile_id(display_id);
            return ESP_OK;
        }
        // A list entry can omit ICCID (tag 5A). Fall back to its ISD-P AID.
        const std::string& enable_id = profile.iccid.empty() ? profile.isdpAid : profile.iccid;
        if (enable_id.empty()) break;  // If both are absent, use the direct identifier fallback below
        err = idf_esim_enable_profile(enable_id, message);
        if (err == ESP_OK) {
            message = "Switched to eSIM profile: " + idf_esim_mask_profile_id(enable_id) +
                      "; modem is restarting and attaching with the new card";
        }
        return err;
    }

    // If the user enters an ICCID or AID, try it directly when list fields do not match.
    ProfileIdentifier direct;
    std::string direct_msg;
    if (make_direct_identifier(identifier, false, direct, direct_msg)) {
        err = idf_esim_enable_profile(identifier, message);
        if (err == ESP_OK) {
            message = "Tried to enable the eSIM profile by identifier: " + idf_esim_mask_profile_id(identifier) +
                      "; modem is restarting and attaching with the new card";
        }
        return err;
    }

    message = "Target eSIM profile not found: " + idf_esim_mask_profile_id(identifier);
    return ESP_ERR_NOT_FOUND;
}

bool idf_esim_profile_matches(const IdfEsimProfile& profile, const std::string& identifier)
{
    return profile_matches(profile, identifier);
}

std::string idf_esim_mask_profile_id(const std::string& identifier)
{
    std::string value = idf_util_trim_copy(identifier);
    if (value.size() <= 8) return value;
    // Byte truncation can make a non-ASCII alias invalid UTF-8 and corrupt JSON or notifications. Return aliases unchanged.
    if (std::any_of(value.begin(), value.end(), [](unsigned char ch) { return ch >= 0x80; })) return value;
    return value.substr(0, 4) + "****" + value.substr(value.size() - 4);
}
