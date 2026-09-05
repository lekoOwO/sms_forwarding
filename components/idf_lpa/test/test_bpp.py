import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


COMPONENT = Path(__file__).resolve().parents[1]
HEADER = COMPONENT / "include" / "idf_lpa_bpp.h"
SOURCE = COMPONENT / "idf_lpa_bpp.cpp"


ESP_ERR_H = r'''
#pragma once
using esp_err_t = int;
inline constexpr esp_err_t ESP_OK = 0;
inline constexpr esp_err_t ESP_FAIL = -1;
inline constexpr esp_err_t ESP_ERR_INVALID_ARG = -2;
inline constexpr esp_err_t ESP_ERR_INVALID_STATE = -3;
inline constexpr esp_err_t ESP_ERR_NO_MEM = -4;
inline constexpr esp_err_t ESP_ERR_INVALID_SIZE = -5;
inline constexpr esp_err_t ESP_ERR_INVALID_RESPONSE = -6;
'''


CARD_H = r'''
#pragma once
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include "esp_err.h"

class IdfEsimLpaBppSession {
public:
    IdfEsimLpaBppSession() = default;
    IdfEsimLpaBppSession(const IdfEsimLpaBppSession&) = delete;
    IdfEsimLpaBppSession& operator=(const IdfEsimLpaBppSession&) = delete;
    IdfEsimLpaBppSession(IdfEsimLpaBppSession&&) noexcept = default;
    IdfEsimLpaBppSession& operator=(IdfEsimLpaBppSession&&) noexcept = default;
    ~IdfEsimLpaBppSession() = default;

    esp_err_t begin_segment(std::string& safe_message);
    esp_err_t write_block(const std::uint8_t* data,
                          std::size_t length,
                          bool last,
                          std::uint16_t block_number,
                          std::vector<std::uint8_t>& response,
                          std::string& safe_message);
    void close();
};

struct FakeCardState {
    int begin_calls = 0;
    int close_calls = 0;
    int write_calls = 0;
    int fail_write_call = 0;
    bool intermediate_response = false;
    bool begin_failure = false;
    std::size_t final_response_begin_call = 0U;
    std::vector<std::uint16_t> block_numbers;
    std::vector<std::size_t> block_lengths;
    std::vector<bool> last_flags;
    std::vector<std::vector<std::uint8_t>> wire_segments;
};

extern FakeCardState fake_card;
'''


HOST_CPP = r'''
#include "idf_lpa_bpp.h"
#include "idf_esim_lpa.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

FakeCardState fake_card;

static_assert(IDF_LPA_BPP_MAX_ENCODED_BYTES == 1536U * 1024U);
static_assert(IDF_LPA_BPP_MAX_DECODED_BYTES == 1024U * 1024U);
static_assert(IDF_LPA_BPP_MAX_SEGMENT_BYTES == 30720U);
static_assert(IDF_LPA_BPP_MAX_ELEMENTS == 4096U);

esp_err_t IdfEsimLpaBppSession::begin_segment(std::string& message)
{
    ++fake_card.begin_calls;
    fake_card.wire_segments.emplace_back();
    if (fake_card.begin_failure) {
        message = "card body sentinel";
        return ESP_FAIL;
    }
    return ESP_OK;
}

esp_err_t IdfEsimLpaBppSession::write_block(const std::uint8_t* data,
                                            std::size_t length,
                                            bool last,
                                            std::uint16_t block_number,
                                            std::vector<std::uint8_t>& response,
                                            std::string& message)
{
    ++fake_card.write_calls;
    fake_card.block_numbers.push_back(block_number);
    fake_card.block_lengths.push_back(length);
    fake_card.last_flags.push_back(last);
    if (fake_card.fail_write_call != 0 &&
        fake_card.write_calls == fake_card.fail_write_call) {
        message = "card payload sentinel";
        return ESP_FAIL;
    }
    assert(data != nullptr && length <= IDF_LPA_BPP_BLOCK_BYTES);
    fake_card.wire_segments.back().insert(fake_card.wire_segments.back().end(), data, data + length);
    response.clear();
    if (!last && fake_card.intermediate_response) response.push_back(0xEEU);
    if (last) {
        if (static_cast<std::size_t>(fake_card.begin_calls) ==
            fake_card.final_response_begin_call) {
            response = {0x90U, 0x00U};
        } else if (fake_card.intermediate_response) {
            response = {0xEEU};
        }
    }
    return ESP_OK;
}

void IdfEsimLpaBppSession::close()
{
    ++fake_card.close_calls;
}

static std::vector<std::uint8_t> tlv(std::initializer_list<std::uint8_t> tag,
                                     const std::vector<std::uint8_t>& value)
{
    std::vector<std::uint8_t> result(tag);
    if (value.size() < 128U) {
        result.push_back(static_cast<std::uint8_t>(value.size()));
    } else {
        std::array<std::uint8_t, sizeof(std::size_t)> encoded = {};
        std::size_t length = value.size();
        std::size_t count = 0U;
        while (length != 0U) {
            encoded[encoded.size() - 1U - count] = static_cast<std::uint8_t>(length);
            length >>= 8U;
            ++count;
        }
        assert(count != 0U && count <= 4U);
        result.push_back(static_cast<std::uint8_t>(0x80U | count));
        result.insert(result.end(), encoded.end() - count, encoded.end());
    }
    result.insert(result.end(), value.begin(), value.end());
    return result;
}

static LpaRspProfileMetadata expected_metadata() { return {"Carrier", "Travel", false}; }

static std::vector<std::uint8_t> store_metadata(bool ppr = false, bool changed_name = false,
                                                std::size_t icon_bytes = 0)
{
    std::vector<std::uint8_t> value = {
        0x5A,10,0x98,0x88,0x12,0x32,0x54,0x76,0x98,0x10,0x32,0xF4,
        0x91,7,'C','a','r','r','i','e','r',0x92,6,'T','r','a','v','e','l'};
    if (changed_name) value.back() = 'X';
    if (icon_bytes) {
        const auto icon = tlv({0x94}, std::vector<std::uint8_t>(icon_bytes, 0xFF));
        value.insert(value.end(), {0x93,1,0});
        value.insert(value.end(), icon.begin(), icon.end());
    }
    if (ppr) value.insert(value.end(), {0xB7,5,0x80,3,0x42,0xF6,0x18,0x99,2,6,0x40});
    return tlv({0xBF,0x25}, value);
}

static std::vector<std::uint8_t> metadata_sequence(
    const std::vector<std::uint8_t>& clear, std::size_t fragments = 1)
{
    assert(fragments > 0 && fragments <= clear.size());
    std::vector<std::uint8_t> wire;
    for (std::size_t index = 0; index < fragments; ++index) {
        const std::size_t begin = clear.size() * index / fragments;
        const std::size_t end = clear.size() * (index + 1) / fragments;
        std::vector<std::uint8_t> segment(clear.begin() + begin, clear.begin() + end);
        // Synthetic 8-byte C-MAC trailer; actual MAC verification stays on the eUICC.
        segment.insert(segment.end(), {0xAA,0xBB,0xCC,0xDD,0x11,0x22,0x33,0x44});
        const auto encoded = tlv({0x88}, segment);
        wire.insert(wire.end(), encoded.begin(), encoded.end());
    }
    return tlv({0xA1}, wire);
}

static std::vector<std::uint8_t> valid_bpp()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    const auto second = tlv({0xA2U}, tlv({0x87U}, {0x04U}));
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, second, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> valid_bpp_variant(bool include_second,
                                                   std::size_t metadata_count,
                                                   std::size_t profile_count,
                                                   std::size_t metadata_bytes = 1U,
                                                   std::size_t profile_bytes = 1U)
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata(false, false,
        metadata_bytes == 1U ? 0U : metadata_bytes), metadata_count);
    const auto second = tlv({0xA2U}, tlv({0x87U}, {0x04U}));
    std::vector<std::uint8_t> profile_content;
    for (std::size_t i = 0U; i < profile_count; ++i) {
        const auto child = tlv({0x86U}, std::vector<std::uint8_t>(profile_bytes,
                                                                    static_cast<std::uint8_t>(i + 5U)));
        profile_content.insert(profile_content.end(), child.begin(), child.end());
    }
    const auto profile = tlv({0xA3U}, profile_content);
    std::vector<std::uint8_t> content;
    content.insert(content.end(), init.begin(), init.end());
    content.insert(content.end(), first.begin(), first.end());
    content.insert(content.end(), metadata.begin(), metadata.end());
    if (include_second) content.insert(content.end(), second.begin(), second.end());
    content.insert(content.end(), profile.begin(), profile.end());
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_wrong_order()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    const auto metadata = metadata_sequence(store_metadata());
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, profile, metadata}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_extra_outer_child()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    const auto extra = tlv({0xBFU, 0x24U}, {0x06U});
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile, extra}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_oversized_init()
{
    const auto init = tlv({0xBFU, 0x23U}, std::vector<std::uint8_t>(30717U, 0x01U));
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_noncanonical_init_length()
{
    auto init = tlv({0xBFU, 0x23U}, {0x01U});
    init[2] = 0x81U;
    init.insert(init.begin() + 3, 0x01U);
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_oversized_first_child()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U},
                           tlv({0x87U}, std::vector<std::uint8_t>(30714U, 0x02U)));
    const auto metadata = metadata_sequence(store_metadata());
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_oversized_second_child()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    const auto second = tlv({0xA2U},
                            tlv({0x87U}, std::vector<std::uint8_t>(30714U, 0x04U)));
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, second, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_noncanonical_first_child_length()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    // Replace the minimal short 87 length with a nonminimal long form.
    first[1] = 0x04U;
    first[3] = 0x81U;
    first.insert(first.begin() + 4, 0x01U);
    const auto metadata = metadata_sequence(store_metadata());
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_sequence_child_overrun(bool optional_second)
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    auto second = tlv({0xA2U}, tlv({0x87U}, {0x04U}));
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    content.insert(content.end(), init.begin(), init.end());
    if (optional_second) {
        content.insert(content.end(), first.begin(), first.end());
        content.insert(content.end(), metadata.begin(), metadata.end());
        ++second[1];
        content.insert(content.end(), second.begin(), second.end());
    } else {
        auto malformed_first = first;
        ++malformed_first[1];
        content.insert(content.end(), malformed_first.begin(), malformed_first.end());
        content.insert(content.end(), metadata.begin(), metadata.end());
    }
    content.insert(content.end(), profile.begin(), profile.end());
    return tlv({0xBFU, 0x36U}, content);
}

static std::size_t valid_bpp_segment_count(bool include_second,
                                           std::size_t metadata_count,
                                           std::size_t profile_count)
{
    // BF36/BF23, A0/87, A1, A3, and one segment per repeated child.
    return 4U + metadata_count + profile_count + (include_second ? 1U : 0U);
}

static std::vector<std::uint8_t> bpp_with_profile_elements(std::size_t count)
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    std::vector<std::uint8_t> profile_content;
    for (std::size_t i = 0U; i < count; ++i) {
        profile_content.push_back(0x86U);
        profile_content.push_back(0x01U);
        profile_content.push_back(static_cast<std::uint8_t>(i));
    }
    const auto metadata = metadata_sequence(store_metadata());
    const auto profile = tlv({0xA3U}, profile_content);
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_profile_bytes(std::size_t count)
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    const auto profile = tlv({0xA3U}, tlv({0x86U}, std::vector<std::uint8_t>(count, 0xA5U)));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_metadata_bytes(std::size_t count)
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = tlv({0xA1U}, tlv({0x88U}, std::vector<std::uint8_t>(count, 0x03U)));
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_profile_segments(std::size_t count,
                                                            std::size_t bytes_each)
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    std::vector<std::uint8_t> profile_content;
    for (std::size_t i = 0U; i < count; ++i) {
        const auto child = tlv({0x86U}, std::vector<std::uint8_t>(bytes_each, 0xA5U));
        profile_content.insert(profile_content.end(), child.begin(), child.end());
    }
    const auto profile = tlv({0xA3U}, profile_content);
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_empty_metadata()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = tlv({0xA1U}, {});
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_empty_profile()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    const auto metadata = metadata_sequence(store_metadata());
    const auto profile = tlv({0xA3U}, {});
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_two_first_children()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first_child = tlv({0x87U}, {0x02U});
    const auto second_child = tlv({0x87U}, {0x03U});
    std::vector<std::uint8_t> first_content(first_child);
    first_content.insert(first_content.end(), second_child.begin(), second_child.end());
    const auto first = tlv({0xA0U}, first_content);
    const auto metadata = tlv({0xA1U}, tlv({0x88U}, {0x04U}));
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_metadata_child_overrun()
{
    const auto init = tlv({0xBFU, 0x23U}, {0x01U});
    const auto first = tlv({0xA0U}, tlv({0x87U}, {0x02U}));
    auto metadata = metadata_sequence(store_metadata());
    --metadata[1];
    const auto profile = tlv({0xA3U}, tlv({0x86U}, {0x05U}));
    std::vector<std::uint8_t> content;
    for (const auto& part : {init, first, metadata, profile}) {
        content.insert(content.end(), part.begin(), part.end());
    }
    return tlv({0xBFU, 0x36U}, content);
}

static std::vector<std::uint8_t> bpp_with_outer_truncated_before_metadata()
{
    auto bpp = valid_bpp();
    // BF23 (4 bytes) and A0 (5 bytes) are complete; A1 has no enclosing bytes.
    assert(bpp[2] == 63U && bpp[12] == 0xA1U);
    bpp[2] = 9U;
    return bpp;
}

static std::vector<std::uint8_t> bpp_with_outer_truncated_before_profile()
{
    auto bpp = valid_bpp();
    // BF23, A0, A1, and A2 are complete; A3 has no enclosing bytes.
    assert(bpp[2] == 63U && bpp[61] == 0xA3U);
    bpp[2] = 58U;
    return bpp;
}

static std::vector<std::uint8_t> bpp_with_metadata_parent_truncated_child()
{
    auto bpp = valid_bpp();
    assert(bpp[12] == 0xA1U && bpp[13] == 42U);
    bpp[13] = 2U;
    return bpp;
}

static std::vector<std::uint8_t> bpp_with_profile_parent_truncated_child()
{
    auto bpp = valid_bpp();
    assert(bpp[61] == 0xA3U && bpp[62] == 3U);
    bpp[62] = 2U;
    return bpp;
}

static std::string base64(const std::vector<std::uint8_t>& bytes)
{
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string result;
    for (std::size_t i = 0; i < bytes.size(); i += 3U) {
        const std::size_t remaining = bytes.size() - i;
        const std::uint32_t first = bytes[i];
        const std::uint32_t second = remaining > 1U ? bytes[i + 1U] : 0U;
        const std::uint32_t third = remaining > 2U ? bytes[i + 2U] : 0U;
        const std::uint32_t value = (first << 16U) | (second << 8U) | third;
        result.push_back(alphabet[(value >> 18U) & 0x3FU]);
        result.push_back(alphabet[(value >> 12U) & 0x3FU]);
        result.push_back(remaining > 1U ? alphabet[(value >> 6U) & 0x3FU] : '=');
        result.push_back(remaining > 2U ? alphabet[value & 0x3FU] : '=');
    }
    return result;
}

static std::string response(std::string_view bpp,
                            std::string_view transaction = "001122",
                            std::string_view status = "Executed-Success")
{
    return std::string("{\"header\":{\"functionExecutionStatus\":{\"status\":\"") +
           std::string(status) + "\"}},\"transactionId\":\"" +
           std::string(transaction) + "\",\"boundProfilePackage\":\"" +
           std::string(bpp) + "\"}";
}

static void reset_card()
{
    fake_card = FakeCardState();
}

static esp_err_t execute(std::string_view json,
                         std::string_view expected_transaction,
                         std::vector<std::uint8_t>& result,
                         std::string& message,
                         std::size_t chunk_size = 1U,
                         bool intermediate_response = false,
                         int fail_write_call = 0,
                         std::size_t final_response_begin_call = 0U)
{
    reset_card();
    fake_card.intermediate_response = intermediate_response;
    fake_card.fail_write_call = fail_write_call;
    fake_card.final_response_begin_call = final_response_begin_call;
    IdfLpaBppStream parser(expected_transaction, expected_metadata());
    esp_err_t error = ESP_OK;
    for (std::size_t offset = 0; offset < json.size(); offset += chunk_size) {
        const std::size_t length = std::min(chunk_size, json.size() - offset);
        error = parser.feed(json.data() + offset, length, message);
        if (error != ESP_OK) break;
    }
    if (error == ESP_OK) error = parser.finish(result, message);
    else {
        const esp_err_t ignored = parser.finish(result, message);
        (void)ignored;
    }
    return error;
}

int main()
{
    for (const bool ppr : {false, true}) {
        const auto init = tlv({0xBF,0x23}, {1});
        const auto first = tlv({0xA0}, tlv({0x87}, {2}));
        const auto metadata = metadata_sequence(store_metadata(ppr, !ppr), 3);
        const auto profile = tlv({0xA3}, tlv({0x86}, {5}));
        std::vector<std::uint8_t> content;
        for (const auto& part : {init, first, metadata, profile})
            content.insert(content.end(), part.begin(), part.end());
        std::vector<std::uint8_t> result;
        std::string message;
        assert(execute(response(base64(tlv({0xBF,0x36}, content))), "001122", result,
            message, 1, false, 0, 8) != ESP_OK);
        assert(result.empty() && fake_card.wire_segments.size() == 2);
        assert(fake_card.wire_segments.back() == first);
    }
    for (const std::size_t fragments : {1U, 3U, 32U}) {
        const auto init = tlv({0xBF,0x23}, {1});
        const auto first = tlv({0xA0}, tlv({0x87}, {2}));
        const auto metadata = metadata_sequence(store_metadata(), fragments);
        const auto profile = tlv({0xA3}, tlv({0x86}, {5}));
        std::vector<std::uint8_t> content;
        for (const auto& part : {init, first, metadata, profile})
            content.insert(content.end(), part.begin(), part.end());
        const auto original = tlv({0xBF,0x36}, content);
        std::vector<std::uint8_t> result, replayed;
        std::string message;
        assert(execute(response(base64(original)), "001122", result, message,
            1, false, 0, 5 + fragments) == ESP_OK);
        for (const auto& segment : fake_card.wire_segments)
            replayed.insert(replayed.end(), segment.begin(), segment.end());
        assert(replayed == original && result == (std::vector<std::uint8_t>{0x90,0}));
    }
    for (const bool missing_plaintext : {false, true}) {
        auto payload = missing_plaintext ? std::vector<std::uint8_t>() : store_metadata();
        payload.insert(payload.end(), missing_plaintext ? 8U : 7U, 0xAA);
        const auto init = tlv({0xBF,0x23}, {1});
        const auto first = tlv({0xA0}, tlv({0x87}, {2}));
        const auto metadata = tlv({0xA1}, tlv({0x88}, payload));
        const auto profile = tlv({0xA3}, tlv({0x86}, {5}));
        std::vector<std::uint8_t> content, result;
        for (const auto& part : {init, first, metadata, profile})
            content.insert(content.end(), part.begin(), part.end());
        std::string message;
        assert(execute(response(base64(tlv({0xBF,0x36}, content))), "001122", result,
            message, 1, false, 0, 6) != ESP_OK);
        assert(result.empty() && fake_card.wire_segments.size() == 2);
    }
    {
        reset_card();
        auto unsupported = expected_metadata();
        unsupported.has_policy_rules = true;
        IdfLpaBppStream guarded("001122", unsupported);
        std::string message;
        assert(guarded.feed(response(base64(valid_bpp())), message) != ESP_OK);
        assert(fake_card.begin_calls == 0 && guarded.test_sensitive_storage_is_zero());
    }
    const std::string encoded = base64(valid_bpp());
    std::vector<std::uint8_t> result;
    std::string message;
    for (const std::size_t chunk_size : {1U, 2U, 3U, 4U, 5U, 7U, 64U}) {
        result.clear();
        message.clear();
        assert(execute(response(encoded), "001122", result, message, chunk_size, false, 0,
                       valid_bpp_segment_count(true, 1U, 1U)) == ESP_OK);
        assert(result == std::vector<std::uint8_t>({0x90U, 0x00U}));
        assert(message.empty());
        assert(fake_card.begin_calls != 0);
        assert(fake_card.close_calls == fake_card.begin_calls);
        assert(!fake_card.last_flags.empty() && fake_card.last_flags.back());
        for (std::size_t i = 0U; i < fake_card.block_lengths.size(); ++i) {
            assert(fake_card.block_lengths[i] <= IDF_LPA_BPP_BLOCK_BYTES);
            assert(fake_card.block_numbers[i] <= 0xFFU);
            assert(fake_card.last_flags[i]);
        }
    }

    auto expect_success = [&](std::string_view package,
                              std::size_t final_response_begin_call,
                              std::size_t chunk_size) {
        result = {0xA5U};
        message = "success sentinel";
        assert(execute(response(package), "001122", result, message, chunk_size, false, 0,
                       final_response_begin_call) == ESP_OK);
        assert(result == std::vector<std::uint8_t>({0x90U, 0x00U}));
        assert(message.empty());
        assert(fake_card.close_calls == fake_card.begin_calls);
    };

    // A2 is optional; repeated 88 and 86 children are valid.
    expect_success(base64(valid_bpp_variant(false, 1U, 1U)),
                   valid_bpp_segment_count(false, 1U, 1U), 2U);
    expect_success(base64(valid_bpp_variant(true, 2U, 1U)),
                   valid_bpp_segment_count(true, 2U, 1U), 3U);
    expect_success(base64(valid_bpp_variant(true, 1U, 2U)),
                   valid_bpp_segment_count(true, 1U, 2U), 5U);

    // All long-form lengths are minimally encoded (the child values are 126 bytes).
    expect_success(base64(valid_bpp_variant(true, 1U, 1U, 126U, 126U)),
                   valid_bpp_segment_count(true, 1U, 1U), 7U);

    const std::string reordered =
        "{\"note\":{\"nested\":[true,null,7]},\"transactionId\":\"001122\","
        "\"header\":{\"note\":1,\"functionExecutionStatus\":{\"detail\":false,"
        "\"status\":\"Executed-Success\"}},\"boundProfilePackage\":\"" + encoded + "\"}";
    result.clear();
    message.clear();
    assert(execute(reordered, "001122", result, message, 3U, false, 0,
                   valid_bpp_segment_count(true, 1U, 1U)) == ESP_OK);
    assert(result == std::vector<std::uint8_t>({0x90U, 0x00U}));
    assert(message.empty());

    const std::string unknown_between =
        "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},"
        "\"unknown\":{\"header\":{\"status\":\"decoy\"},"
        "\"transactionId\":\"decoy\",\"nested\":[true,null,7]},"
        "\"transactionId\":\"001122\","
        "\"boundProfilePackage\":\"" + encoded + "\"}";
    result = {0xA5U};
    message = "between sentinel";
    assert(execute(unknown_between, "001122", result, message, 3U, false, 0,
                   valid_bpp_segment_count(true, 1U, 1U)) == ESP_OK);
    assert(result == std::vector<std::uint8_t>({0x90U, 0x00U}));
    assert(message.empty());

    const std::string bpp_first =
        "{\"boundProfilePackage\":\"" + encoded +
        "\",\"transactionId\":\"001122\",\"header\":{\"functionExecutionStatus\":{"
        "\"status\":\"Executed-Success\"}}}";
    result = {0xA5U};
    message = "bpp-first sentinel";
    assert(execute(bpp_first, "001122", result, message, 5U) != ESP_OK);
    assert(result.empty());
    assert(fake_card.begin_calls == 0);

    const std::string unknown_after_bpp =
        "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},"
        "\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded +
        "\",\"note\":1}";
    result = {0xA5U};
    message = "trailing sentinel";
    assert(execute(unknown_after_bpp, "001122", result, message, 5U) != ESP_OK);
    assert(result.empty());

    auto expect_rejected = [&](std::string_view json,
                               std::string_view expected = "001122") {
        result = {0xA5U};
        message = "body sentinel";
        const esp_err_t error = execute(json, expected, result, message, 1U);
        assert(error != ESP_OK);
        assert(result.empty());
        assert(message.find("sentinel") == std::string::npos);
        assert(fake_card.close_calls == fake_card.begin_calls);
    };

    expect_rejected(std::string("{\"boundProfilePackage\":\"") + encoded +
                    "\",\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\"transactionId\":\"001122\"}");
    expect_rejected(
        "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},"
        "\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded +
        "\",\"boundProfilePackage\":\"" + encoded + "\"}");
    expect_rejected(response(base64(bpp_with_wrong_order())));
    expect_rejected(response(encoded, "001123"));
    expect_rejected(response(encoded, "001122", "Failed"));
    expect_rejected("{\"header\":{\"status\":\"Executed-Success\"},\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded + "\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":false},\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded + "\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\",\"status\":\"Executed-Success\"}},\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded + "\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\"transactionId\":\"001122\",\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded + "\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded + "\",\"extra\":1}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\"transactionId\":1,\"boundProfilePackage\":\"" + encoded + "\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-\\qSuccess\"}},\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded + "\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\"transactionId\":\"001122\",\"boundProfilePackage\":\"" + encoded + "\\\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\"transactionId\":\"001122\",\"boundProfilePackage\":\"Zg==\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\"transactionId\":\"001122\",\"boundProfilePackage\":\"Zh==\"}");
    expect_rejected("{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},\"transactionId\":\"001122\",\"boundProfilePackage\":\"Z g==\"}");

    std::vector<std::uint8_t> malformed = valid_bpp();
    malformed[0] = 0xBFU;
    malformed[1] = 0x35U;
    expect_rejected(response(base64(malformed)));
    malformed = valid_bpp();
    malformed[2] = 0x80U;
    expect_rejected(response(base64(malformed)));
    malformed = valid_bpp();
    malformed.insert(malformed.end(), 0x00U);
    expect_rejected(response(base64(malformed)));
    malformed = valid_bpp();
    malformed[0] = 0x1FU;
    expect_rejected(response(base64(malformed)));
    malformed = valid_bpp();
    const auto original_outer_length = malformed[2];
    malformed[2] = 0x81U;
    malformed.insert(malformed.begin() + 3, original_outer_length);
    expect_rejected(response(base64(malformed)));
    malformed = valid_bpp();
    malformed[2] = 0x82U;
    malformed.insert(malformed.begin() + 3, 0x00U);
    malformed.insert(malformed.begin() + 4, original_outer_length);
    expect_rejected(response(base64(malformed)));

    expect_rejected(response(base64(bpp_with_empty_metadata())));
    expect_rejected(response(base64(bpp_with_empty_profile())));
    expect_rejected(response(base64(bpp_with_two_first_children())));
    expect_rejected(response(base64(bpp_with_noncanonical_first_child_length())));
    expect_rejected(response(base64(bpp_with_extra_outer_child())));
    expect_rejected(response(base64(bpp_with_metadata_child_overrun())));

    // The enclosing-segment preflight rejects before opening the offending
    // segment. Earlier valid segments may already have completed I/O.
    expect_rejected(response(base64(bpp_with_noncanonical_init_length())));
    assert(fake_card.begin_calls == 0);
    assert(fake_card.write_calls == 0);
    expect_rejected(response(base64(bpp_with_oversized_init())));
    assert(fake_card.begin_calls == 0);
    assert(fake_card.write_calls == 0);
    expect_rejected(response(base64(bpp_with_oversized_first_child())));
    assert(fake_card.begin_calls == 1);
    assert(fake_card.write_calls == 1);
    expect_rejected(response(base64(bpp_with_oversized_second_child())));
    assert(fake_card.begin_calls == 4);
    assert(fake_card.write_calls == 4);
    expect_rejected(response(base64(bpp_with_outer_truncated_before_metadata())));
    assert(fake_card.begin_calls == 2);
    assert(fake_card.write_calls == 2);
    expect_rejected(response(base64(bpp_with_outer_truncated_before_profile())));
    assert(fake_card.begin_calls == 5);
    assert(fake_card.write_calls == 5);
    expect_rejected(response(base64(bpp_with_metadata_parent_truncated_child())));
    assert(fake_card.begin_calls == 2);
    assert(fake_card.write_calls == 2);
    expect_rejected(response(base64(bpp_with_profile_parent_truncated_child())));
    assert(fake_card.begin_calls == 6);
    assert(fake_card.write_calls == 6);
    expect_rejected(response(base64(bpp_with_sequence_child_overrun(false))));
    assert(fake_card.begin_calls == 1);
    assert(fake_card.write_calls == 1);
    expect_rejected(response(base64(bpp_with_sequence_child_overrun(true))));
    assert(fake_card.begin_calls == 4);
    assert(fake_card.write_calls == 4);
    expect_rejected(
        "{\"unknown\":1,\"unknown\":2,\"transactionId\":\"001122\","
        "\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"}},"
        "\"boundProfilePackage\":\"" + encoded + "\"}");
    expect_rejected(
        "{\"header\":{\"functionExecutionStatus\":{\"status\":\"Executed-Success\"},"
        "\"unknown\":{\"same\":1,\"same\":2}},\"transactionId\":\"001122\","
        "\"boundProfilePackage\":\"" + encoded + "\"}");

    std::string too_deep = "{\"unknown\":";
    for (std::size_t i = 0U; i < 8U; ++i) too_deep += "[";
    too_deep += "true";
    for (std::size_t i = 0U; i < 8U; ++i) too_deep += "]";
    too_deep += ",\"transactionId\":\"001122\",\"header\":{\"functionExecutionStatus\":{"
                "\"status\":\"Executed-Success\"}},\"boundProfilePackage\":\"" + encoded + "\"}";
    expect_rejected(too_deep);

    const std::string too_large_unknown =
        "{\"unknown\":\"" + std::string(17000U, 'x') + "\"}";
    expect_rejected(too_large_unknown);

    result = {0xA5U};
    message = "request sentinel";
    assert(execute(response(encoded), "001122", result, message, 1U, false, 0,
                   valid_bpp_segment_count(true, 1U, 1U)) == ESP_OK);
    assert(result == std::vector<std::uint8_t>({0x90U, 0x00U}));
    assert(message.empty());

    result = {0xA5U};
    message = "response sentinel";
    assert(execute(response(encoded), "001122", result, message, 1U, true) != ESP_OK);
    assert(result.empty());
    assert(message.find("sentinel") == std::string::npos);

    result = {0xA5U};
    message = "card sentinel";
    assert(execute(response(encoded), "001122", result, message, 1U, false, 1) != ESP_OK);
    assert(result.empty());
    assert(message.find("sentinel") == std::string::npos);

    // A nested decoder failure performs one observable card close and remains
    // safe when finish/abort are called again by the owner.
    reset_card();
    IdfLpaBppStream nested_failure("001122", expected_metadata());
    std::string malformed_encoded = encoded;
    malformed_encoded[malformed_encoded.size() / 2U] = '?';
    result = {0xA5U};
    message = "nested sentinel";
    assert(nested_failure.feed(response(malformed_encoded), message) != ESP_OK);
    assert(fake_card.begin_calls != 0);
    const int nested_close_calls = fake_card.close_calls;
    assert(nested_close_calls == fake_card.begin_calls);
    assert(nested_failure.test_cleanup_count() == 1U);
    result = {0xA5U};
    assert(nested_failure.finish(result, message) != ESP_OK);
    assert(result.empty());
    assert(fake_card.close_calls == nested_close_calls);
    nested_failure.abort();
    assert(fake_card.close_calls == nested_close_calls);
    assert(nested_failure.test_cleanup_count() == 1U);
    assert(nested_failure.test_sensitive_storage_is_zero());

    reset_card();
    fake_card.begin_failure = true;
    IdfLpaBppStream begin_failed("001122", expected_metadata());
    result = {0xA5U};
    message = "begin sentinel";
    assert(begin_failed.feed(response(encoded), message) != ESP_OK);
    assert(begin_failed.finish(result, message) != ESP_OK);
    assert(result.empty());
    assert(message.find("sentinel") == std::string::npos);
    assert(fake_card.close_calls == 0);

    reset_card();
    IdfLpaBppStream aborted("001122", expected_metadata());
    assert(aborted.feed(response(encoded).substr(0, 90), message) == ESP_OK);
    result = {0xA5U};
    aborted.abort();
    assert(aborted.test_sensitive_storage_is_zero());
    assert(aborted.finish(result, message) != ESP_OK);
    assert(result.empty());

    const std::string too_many_elements = base64(bpp_with_profile_elements(4097U));
    result = {0xA5U};
    message = "element sentinel";
    assert(execute(response(too_many_elements), "001122", result, message, 13U, false, 0, 0) ==
           ESP_ERR_INVALID_SIZE);
    assert(result.empty());
    assert(fake_card.close_calls == fake_card.begin_calls);
    assert(fake_card.begin_calls <= 4096);

    const std::string too_many_blocks = base64(bpp_with_profile_bytes(30720U));
    result = {0xA5U};
    message = "block sentinel";
    assert(execute(response(too_many_blocks), "001122", result, message, 31U) ==
           ESP_ERR_INVALID_SIZE);
    assert(result.empty());
    assert(fake_card.close_calls == fake_card.begin_calls);
    // The five preceding DER segments are complete; the oversized 86 TLV is
    // rejected from its header before its segment opens or writes a card block.
    assert(fake_card.begin_calls == 5);
    assert(fake_card.write_calls == 5);
    for (const auto block : fake_card.block_numbers) assert(block <= 0xFFU);

    const std::string segment_boundary = base64(bpp_with_profile_bytes(30716U));
    result = {0xA5U};
    message = "segment boundary sentinel";
    assert(execute(response(segment_boundary), "001122", result, message, 4096U, false, 0,
                   valid_bpp_segment_count(false, 1U, 1U)) ==
           ESP_OK);
    assert(result == std::vector<std::uint8_t>({0x90U, 0x00U}));
    assert(fake_card.block_lengths.size() >= 256U);
    assert(fake_card.block_lengths[fake_card.block_lengths.size() - 1U] ==
           IDF_LPA_BPP_BLOCK_BYTES);

    const std::string oversized_metadata = base64(bpp_with_metadata_bytes(30717U));
    result = {0xA5U};
    message = "metadata limit sentinel";
    assert(execute(response(oversized_metadata), "001122", result, message, 31U) ==
           ESP_ERR_INVALID_SIZE);
    assert(result.empty());
    assert(fake_card.begin_calls == 2);
    assert(fake_card.write_calls == 2);
    assert(fake_card.close_calls == fake_card.begin_calls);

    const std::string oversized_decoded = base64(bpp_with_profile_segments(35U, 30716U));
    result = {0xA5U};
    message = "decoded limit sentinel";
    assert(execute(response(oversized_decoded), "001122", result, message, 4096U) ==
           ESP_ERR_INVALID_SIZE);
    assert(result.empty());
    assert(fake_card.begin_calls == 0);
    assert(fake_card.write_calls == 0);

    const std::string oversized_b64(IDF_LPA_BPP_MAX_ENCODED_BYTES + 1U, 'A');
    result = {0xA5U};
    message = "encoded sentinel";
    assert(execute(response(oversized_b64), "001122", result, message, 4096U) != ESP_OK);
    assert(result.empty());
    assert(message.find("sentinel") == std::string::npos);
    assert(fake_card.close_calls == fake_card.begin_calls);

    return 0;
}
'''


class BppHostTest(unittest.TestCase):
    def test_bpp_streaming_fixture(self):
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "g++ is required for the BPP host check")
        self.assertTrue(HEADER.exists(), "missing BPP API header")
        self.assertTrue(SOURCE.exists(), "missing BPP implementation")

        with tempfile.TemporaryDirectory(prefix="idf-lpa-bpp-") as directory:
            root = Path(directory)
            stubs = root / "stubs"
            stubs.mkdir()
            (stubs / "esp_err.h").write_text(ESP_ERR_H, encoding="utf-8")
            (stubs / "idf_esim_lpa.h").write_text(CARD_H, encoding="utf-8")
            fixture = root / "bpp_fixture.cpp"
            fixture.write_text(HOST_CPP, encoding="utf-8")
            binary = root / "bpp_fixture"
            result = subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-pedantic",
                    "-fno-exceptions",
                    "-fno-rtti",
                    "-DIDF_LPA_BPP_TESTING",
                    "-I",
                    str(stubs),
                    "-I",
                    str(COMPONENT / "include"),
                    "-I", str(COMPONENT.parent / "idf_esim" / "include"),
                    str(SOURCE),
                    str(COMPONENT / "idf_lpa_rsp.cpp"),
                    str(COMPONENT / "idf_lpa_activation_code.cpp"),
                    str(COMPONENT.parent / "idf_esim" / "idf_esim_codec.cpp"),
                    str(fixture),
                    "-lcrypto",
                    "-o",
                    str(binary),
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            run = subprocess.run(
                [str(binary)], check=False, capture_output=True, text=True, timeout=30
            )
            self.assertEqual(run.returncode, 0, run.stderr)


if __name__ == "__main__":
    unittest.main()
