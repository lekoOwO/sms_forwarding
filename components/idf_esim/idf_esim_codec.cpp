#include "idf_esim_codec.h"

#include <ctype.h>
#include <stdio.h>
#include <string.h>

#include <limits>
#include <utility>

namespace idf_esim_internal {
namespace {

static constexpr size_t TLV_RESPONSE_MAX = 16U * 1024U;

static std::string trim_ascii_copy(const std::string& value)
{
    size_t begin = 0;
    while (begin < value.size() && isspace(static_cast<unsigned char>(value[begin]))) ++begin;
    size_t end = value.size();
    while (end > begin && isspace(static_cast<unsigned char>(value[end - 1]))) --end;
    return value.substr(begin, end - begin);
}

static bool parse_decimal(const std::string& value, size_t& out)
{
    const std::string text = trim_ascii_copy(value);
    if (text.empty()) return false;
    size_t parsed = 0;
    for (char ch : text) {
        if (!isdigit(static_cast<unsigned char>(ch))) return false;
        const size_t digit = static_cast<size_t>(ch - '0');
        if (parsed > (std::numeric_limits<size_t>::max() - digit) / 10U) return false;
        parsed = parsed * 10U + digit;
    }
    out = parsed;
    return true;
}

static bool parse_tlv_one(const std::vector<uint8_t>& data,
                          size_t end,
                          size_t& pos,
                          Tlv& out,
                          std::string& message,
                          int depth)
{
    if (depth > 8) {
        message = "TLV nesting is too deep";
        return false;
    }
    if (end > data.size() || end > TLV_RESPONSE_MAX || pos >= end) {
        message = "TLV data is empty or out of bounds";
        return false;
    }

    const size_t tag_start = pos;
    const uint8_t first = data[pos++];
    if ((first & 0x1FU) == 0x1FU) {
        bool tag_complete = false;
        while (pos < end) {
            if ((data[pos++] & 0x80U) == 0U) {
                tag_complete = true;
                break;
            }
        }
        if (!tag_complete) {
            message = "TLV tag is incomplete";
            return false;
        }
    }
    const size_t tag_length = pos - tag_start;
    if (pos >= end) {
        message = "TLV length is missing";
        return false;
    }

    const uint8_t len0 = data[pos++];
    size_t length = 0;
    if ((len0 & 0x80U) == 0U) {
        length = len0;
    } else {
        const size_t count = len0 & 0x7FU;
        if (count == 0U || count > 3U || count > end - pos) {
            message = "TLV length format is not supported";
            return false;
        }
        for (size_t index = 0; index < count; ++index) {
            length = (length << 8U) | data[pos++];
        }
    }
    if (length > end - pos) {
        message = "TLV length exceeds the response";
        return false;
    }

    out = Tlv();
    out.constructed = (first & 0x20U) != 0U;
    out.tag.assign(data.begin() + tag_start, data.begin() + tag_start + tag_length);
    out.value.assign(data.begin() + pos, data.begin() + pos + length);
    if (out.constructed) {
        size_t child_pos = pos;
        const size_t child_end = pos + length;
        while (child_pos < child_end) {
            Tlv child;
            if (!parse_tlv_one(data, child_end, child_pos, child, message, depth + 1)) {
                return false;
            }
            out.children.push_back(std::move(child));
        }
    }
    pos += length;
    return true;
}

static void append_len(std::vector<uint8_t>& out, size_t length)
{
    if (length < 0x80U) {
        out.push_back(static_cast<uint8_t>(length));
    } else if (length <= 0xFFU) {
        out.push_back(0x81U);
        out.push_back(static_cast<uint8_t>(length));
    } else {
        out.push_back(0x82U);
        out.push_back(static_cast<uint8_t>((length >> 8U) & 0xFFU));
        out.push_back(static_cast<uint8_t>(length & 0xFFU));
    }
}

static bool find_unique_prefixed_line(const std::string& response,
                                      const std::string& command,
                                      const char* prefix,
                                      std::string& line)
{
    line.clear();
    bool found = false;
    bool final_seen = false;
    bool echo_seen = false;
    size_t pos = 0;
    while (pos <= response.size()) {
        size_t end = response.find('\n', pos);
        if (end == std::string::npos) end = response.size();
        const std::string row = trim_ascii_copy(response.substr(pos, end - pos));
        if (!row.empty()) {
            if (row == "OK") {
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
            } else {
                return false;
            }
        }
        if (end == response.size()) break;
        pos = end + 1U;
    }
    return found && final_seen;
}

static std::string version_text(const std::vector<uint8_t>& value)
{
    if (value.size() != 3U) return {};
    char buf[24];
    snprintf(buf, sizeof(buf), "%u.%u.%u",
             static_cast<unsigned>(value[0]),
             static_cast<unsigned>(value[1]),
             static_cast<unsigned>(value[2]));
    return std::string(buf);
}

static bool parse_ext_card_resource(const std::vector<uint8_t>& value,
                                    uint32_t& free_non_volatile,
                                    uint32_t& free_volatile,
                                    std::string& message)
{
    std::vector<Tlv> fields;
    if (!parse_tlv_list(value, fields, message)) return false;
    bool non_volatile_found = false;
    bool volatile_found = false;
    for (const Tlv& field : fields) {
        if (field.tag.size() != 1U || (field.tag[0] != 0x82U && field.tag[0] != 0x83U)) continue;
        if (field.value.empty() || field.value.size() > 4U) {
            message = "Extended card-resource memory field is invalid";
            return false;
        }
        uint32_t parsed = 0;
        for (uint8_t byte : field.value) parsed = (parsed << 8U) | byte;
        if (field.tag[0] == 0x82U) {
            if (non_volatile_found) {
                message = "Extended card-resource memory field is duplicated";
                return false;
            }
            free_non_volatile = parsed;
            non_volatile_found = true;
        } else {
            if (volatile_found) {
                message = "Extended card-resource volatile field is duplicated";
                return false;
            }
            free_volatile = parsed;
            volatile_found = true;
        }
    }
    if (!non_volatile_found || !volatile_found) {
        message = "Extended card-resource memory fields are incomplete";
        return false;
    }
    return true;
}

static bool bit_string_value(const std::vector<uint8_t>& value, size_t bit_index, bool& out)
{
    if (value.empty()) return false;
    const uint8_t unused = value[0];
    if (unused > 7U) return false;
    size_t bit_count = (value.size() - 1U) * 8U;
    if (unused > bit_count) return false;
    if (unused != 0U && (value.back() & static_cast<uint8_t>((1U << unused) - 1U)) != 0U) {
        return false;
    }
    bit_count -= unused;
    if (bit_index >= bit_count) {
        out = false;
        return true;
    }
    out = (value[1U + bit_index / 8U] & static_cast<uint8_t>(0x80U >> (bit_index % 8U))) != 0U;
    return true;
}

}  // namespace

bool tag_is(const Tlv& tlv, const uint8_t* tag, size_t len)
{
    return tag && tlv.tag.size() == len && memcmp(tlv.tag.data(), tag, len) == 0;
}

bool tag_is(const std::vector<uint8_t>& data,
            const TlvSpan& tlv,
            const uint8_t* tag,
            size_t len)
{
    return tag && tlv.offset <= data.size() && len <= data.size() - tlv.offset &&
           tlv.tagLength == len && memcmp(data.data() + tlv.offset, tag, len) == 0;
}

bool parse_tlv_span(const std::vector<uint8_t>& data,
                    size_t end,
                    size_t& pos,
                    TlvSpan& out,
                    std::string& message)
{
    if (data.size() > TLV_RESPONSE_MAX || end > data.size() || end > TLV_RESPONSE_MAX || pos >= end) {
        message = "TLV data is empty or out of bounds";
        return false;
    }
    const size_t tag_start = pos;
    const uint8_t first = data[pos++];
    if ((first & 0x1FU) == 0x1FU) {
        bool tag_complete = false;
        while (pos < end) {
            if ((data[pos++] & 0x80U) == 0U) {
                tag_complete = true;
                break;
            }
        }
        if (!tag_complete) {
            message = "TLV tag is incomplete";
            return false;
        }
    }
    const size_t tag_length = pos - tag_start;
    if (pos >= end) {
        message = "TLV length is missing";
        return false;
    }
    const uint8_t len0 = data[pos++];
    size_t length = 0;
    if ((len0 & 0x80U) == 0U) {
        length = len0;
    } else {
        const size_t count = len0 & 0x7FU;
        if (count == 0U || count > 3U || count > end - pos) {
            message = "TLV length format is not supported";
            return false;
        }
        for (size_t index = 0; index < count; ++index) {
            length = (length << 8U) | data[pos++];
        }
    }
    if (length > end - pos) {
        message = "TLV length exceeds the response";
        return false;
    }
    out.offset = tag_start;
    out.tagLength = tag_length;
    out.valueOffset = pos;
    out.valueLength = length;
    pos += length;
    return true;
}

bool parse_tlv_at(const std::vector<uint8_t>& data,
                  size_t end,
                  size_t& pos,
                  Tlv& out,
                  std::string& message)
{
    return parse_tlv_one(data, end, pos, out, message, 0);
}

bool parse_tlv(const std::vector<uint8_t>& data, Tlv& out, std::string& message)
{
    message.clear();
    if (data.size() > TLV_RESPONSE_MAX) {
        message = "TLV response is too large";
        return false;
    }
    size_t pos = 0;
    if (!parse_tlv_at(data, data.size(), pos, out, message)) return false;
    if (pos != data.size()) {
        message = "TLV response contains trailing data";
        return false;
    }
    return true;
}

bool parse_tlv_list(const std::vector<uint8_t>& data,
                    std::vector<Tlv>& out,
                    std::string& message)
{
    message.clear();
    if (data.size() > TLV_RESPONSE_MAX) {
        message = "TLV response is too large";
        return false;
    }
    out.clear();
    size_t pos = 0;
    while (pos < data.size()) {
        Tlv item;
        if (!parse_tlv_one(data, data.size(), pos, item, message, 0)) return false;
        out.push_back(std::move(item));
    }
    return true;
}

void append_tlv(std::vector<uint8_t>& out,
                const uint8_t* tag,
                size_t tag_len,
                const std::vector<uint8_t>& value)
{
    if (!tag || tag_len == 0U) return;
    out.insert(out.end(), tag, tag + tag_len);
    append_len(out, value.size());
    out.insert(out.end(), value.begin(), value.end());
}

CsimParseResult parse_terminal_capability_csim(const std::string& response,
                                               uint16_t& sw,
                                               std::string& message)
{
    static constexpr const char* TERMINAL_CAPABILITY_CMD =
        "AT+CSIM=20,\"80AA000005A903830107\"";
    sw = 0U;
    message.clear();
    std::string line;
    if (!find_unique_prefixed_line(response, TERMINAL_CAPABILITY_CMD, "+CSIM:", line)) {
        message = "Modem did not return one complete CSIM response";
        return CsimParseResult::malformed;
    }
    const size_t colon = line.find(':');
    const size_t comma = line.find(',', colon == std::string::npos ? 0U : colon + 1U);
    if (colon == std::string::npos || comma == std::string::npos) {
        message = "CSIM response fields are invalid";
        return CsimParseResult::malformed;
    }
    size_t declared_length = 0U;
    if (!parse_decimal(line.substr(colon + 1U, comma - colon - 1U), declared_length)) {
        message = "CSIM response length is invalid";
        return CsimParseResult::malformed;
    }
    const size_t q1 = line.find('"', comma + 1U);
    if (q1 == std::string::npos || !trim_ascii_copy(line.substr(comma + 1U, q1 - comma - 1U)).empty()) {
        message = "CSIM response data is not quoted";
        return CsimParseResult::malformed;
    }
    const size_t q2 = line.find('"', q1 + 1U);
    if (q2 == std::string::npos || !trim_ascii_copy(line.substr(q2 + 1U)).empty()) {
        message = "CSIM response quotes or trailing data are invalid";
        return CsimParseResult::malformed;
    }
    const std::string hex = line.substr(q1 + 1U, q2 - q1 - 1U);
    if (declared_length != hex.size() || hex.size() < 4U || (hex.size() & 1U) != 0U) {
        message = "CSIM response length or data is invalid";
        return CsimParseResult::malformed;
    }
    uint8_t sw_bytes[2] = {};
    for (size_t index = 0; index < hex.size(); ++index) {
        int nibble = -1;
        const char ch = hex[index];
        if (ch >= '0' && ch <= '9') nibble = ch - '0';
        else if (ch >= 'a' && ch <= 'f') nibble = ch - 'a' + 10;
        else if (ch >= 'A' && ch <= 'F') nibble = ch - 'A' + 10;
        if (nibble < 0) {
            message = "CSIM response data is not hexadecimal";
            return CsimParseResult::malformed;
        }
        if (index >= hex.size() - 4U) {
            const size_t byte_index = (index - (hex.size() - 4U)) / 2U;
            sw_bytes[byte_index] = static_cast<uint8_t>((sw_bytes[byte_index] << 4U) | nibble);
        }
    }
    sw = static_cast<uint16_t>((sw_bytes[0] << 8U) | sw_bytes[1]);
    if (sw != 0x9000U) {
        message = "Terminal capability status was rejected";
        return CsimParseResult::status_error;
    }
    return CsimParseResult::success;
}

bool parse_euicc_info1(const std::vector<uint8_t>& data,
                       EuiccInfo1Fields& out,
                       std::string& message)
{
    static constexpr uint8_t TAG_INFO1[] = {0xBF, 0x20};
    static constexpr uint8_t TAG_SVN[] = {0x82};
    static constexpr uint8_t TAG_VERIFY_KEYS[] = {0xA9};
    static constexpr uint8_t TAG_SIGN_KEYS[] = {0xAA};
    out = EuiccInfo1Fields();
    Tlv root;
    if (!parse_tlv(data, root, message) || !tag_is(root, TAG_INFO1)) {
        if (message.empty()) message = "EUICCInfo1 response tag is invalid";
        return false;
    }
    const Tlv* svn = first_child(root, TAG_SVN);
    if (!svn || (out.svn = version_text(svn->value)).empty()) {
        message = "EUICCInfo1 SVN is invalid";
        return false;
    }
    if (!first_child(root, TAG_VERIFY_KEYS) || !first_child(root, TAG_SIGN_KEYS)) {
        message = "EUICCInfo1 key identifiers are incomplete";
        return false;
    }
    return true;
}

bool parse_euicc_info2(const std::vector<uint8_t>& data,
                       EuiccInfo2Fields& out,
                       std::string& message)
{
    static constexpr uint8_t TAG_INFO2[] = {0xBF, 0x22};
    static constexpr uint8_t TAG_PROFILE_VERSION[] = {0x81};
    static constexpr uint8_t TAG_SVN[] = {0x82};
    static constexpr uint8_t TAG_FIRMWARE_VERSION[] = {0x83};
    static constexpr uint8_t TAG_EXT_CARD_RESOURCE[] = {0x84};
    static constexpr uint8_t TAG_RSP_CAPABILITY[] = {0x88};
    out = EuiccInfo2Fields();
    Tlv root;
    if (!parse_tlv(data, root, message) || !tag_is(root, TAG_INFO2)) {
        if (message.empty()) message = "EUICCInfo2 response tag is invalid";
        return false;
    }
    const Tlv* profile_version = first_child(root, TAG_PROFILE_VERSION);
    const Tlv* svn = first_child(root, TAG_SVN);
    const Tlv* firmware = first_child(root, TAG_FIRMWARE_VERSION);
    const Tlv* ext_resource = first_child(root, TAG_EXT_CARD_RESOURCE);
    const Tlv* rsp_capability = first_child(root, TAG_RSP_CAPABILITY);
    if (!profile_version || (out.profileVersion = version_text(profile_version->value)).empty() ||
        !svn || (out.svn = version_text(svn->value)).empty() ||
        !firmware || (out.firmwareVersion = version_text(firmware->value)).empty()) {
        message = "EUICCInfo2 version fields are invalid";
        return false;
    }
    if (!ext_resource || !parse_ext_card_resource(ext_resource->value,
                                                  out.freeNonVolatileMemory,
                                                  out.freeVolatileMemory,
                                                  message)) {
        if (message.empty()) message = "EUICCInfo2 card-resource fields are invalid";
        return false;
    }
    if (!rsp_capability || !bit_string_value(rsp_capability->value, 0U, out.additionalProfile) ||
        !bit_string_value(rsp_capability->value, 3U, out.testProfileSupport)) {
        message = "EUICCInfo2 RSP capability is invalid";
        return false;
    }
    return true;
}

bool parse_euicc_challenge(const std::vector<uint8_t>& data,
                           uint8_t out[16],
                           std::string& message)
{
    static constexpr uint8_t TAG_CHALLENGE_RESPONSE[] = {0xBF, 0x2E};
    static constexpr uint8_t TAG_CHALLENGE[] = {0x80};
    if (!out) {
        message = "eUICC challenge output is invalid";
        return false;
    }
    Tlv root;
    if (!parse_tlv(data, root, message) || !tag_is(root, TAG_CHALLENGE_RESPONSE)) {
        if (message.empty()) message = "eUICC challenge response tag is invalid";
        return false;
    }
    const Tlv* challenge = nullptr;
    for (const Tlv& child : root.children) {
        if (!tag_is(child, TAG_CHALLENGE)) continue;
        if (challenge) {
            message = "eUICC challenge is duplicated";
            return false;
        }
        challenge = &child;
    }
    if (!challenge || challenge->value.size() != 16U) {
        message = "eUICC challenge length is invalid";
        return false;
    }
    memcpy(out, challenge->value.data(), 16U);
    return true;
}

}  // namespace idf_esim_internal
