#pragma once

#include <array>
#include <cctype>
#include <cstdint>
#include <cstdio>
#include <string>
#include <string_view>
#include <vector>

struct IdfModemCpolSummaryState {
    size_t response_length = 0;
    unsigned records = 0;
    unsigned malformed = 0;
    unsigned format_bitmap = 0;
    std::array<unsigned, 3> format_counts{};
    std::array<unsigned, 4> rat_counts{};
    bool saw_rat = false;
    bool saw_missing_rat = false;
    bool final_ok = false;
};

inline std::string_view idf_modem_cpol_trim(std::string_view value)
{
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.remove_prefix(1);
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.remove_suffix(1);
    return value;
}

inline bool idf_modem_cpol_number(std::string_view value, unsigned maximum, unsigned& output)
{
    value = idf_modem_cpol_trim(value);
    if (value.empty()) return false;
    unsigned parsed = 0;
    for (unsigned char ch : value) {
        if (!std::isdigit(ch)) return false;
        if (parsed > maximum / 10 ||
            (parsed == maximum / 10 && static_cast<unsigned>(ch - '0') > maximum % 10)) return false;
        parsed = parsed * 10 + (ch - '0');
    }
    output = parsed;
    return true;
}

inline bool idf_modem_cpol_operator_safe(std::string_view value)
{
    for (size_t index = 0; index < value.size();) {
        const unsigned char first = static_cast<unsigned char>(value[index]);
        uint32_t codepoint = 0;
        size_t width = 1;
        if (first < 0x80) {
            codepoint = first;
        } else if (first >= 0xC2 && first <= 0xDF) {
            width = 2;
            codepoint = first & 0x1F;
        } else if (first >= 0xE0 && first <= 0xEF) {
            width = 3;
            codepoint = first & 0x0F;
        } else if (first >= 0xF0 && first <= 0xF4) {
            width = 4;
            codepoint = first & 0x07;
        } else {
            return false;
        }
        if (index + width > value.size()) return false;
        for (size_t offset = 1; offset < width; ++offset) {
            const unsigned char continuation = static_cast<unsigned char>(value[index + offset]);
            if ((continuation & 0xC0) != 0x80) return false;
            codepoint = (codepoint << 6) | (continuation & 0x3F);
        }
        if ((width == 2 && codepoint < 0x80) || (width == 3 && codepoint < 0x800) ||
            (width == 4 && codepoint < 0x10000) || codepoint > 0x10FFFF ||
            (codepoint >= 0xD800 && codepoint <= 0xDFFF) || codepoint < 0x20 ||
            (codepoint >= 0x7F && codepoint <= 0x9F)) {
            return false;
        }
        index += width;
    }
    return true;
}

inline bool idf_modem_cpol_fields(std::string_view line, unsigned& index, unsigned& format,
                                  bool& has_rat, std::array<unsigned, 4>& rat_flags)
{
    line = idf_modem_cpol_trim(line);
    if (line.rfind("+CPOL:", 0) != 0) return false;
    line.remove_prefix(6);
    std::array<std::string_view, 8> fields{};
    size_t count = 0;
    size_t start = 0;
    bool quoted = false;
    for (size_t field_offset = 0; field_offset <= line.size(); ++field_offset) {
        if (field_offset < line.size() && line[field_offset] == '"') quoted = !quoted;
        if (field_offset != line.size() && (line[field_offset] != ',' || quoted)) continue;
        if (count >= fields.size()) return false;
        fields[count++] = idf_modem_cpol_trim(line.substr(start, field_offset - start));
        start = field_offset + 1;
    }
    if (quoted || (count != 3 && count != 7)) return false;
    if (!idf_modem_cpol_number(fields[0], 65535, index) ||
        !idf_modem_cpol_number(fields[1], 2, format) ||
        fields[2].size() < 2 || fields[2].front() != '"' || fields[2].back() != '"') {
        return false;
    }
    if (!idf_modem_cpol_operator_safe(fields[2].substr(1, fields[2].size() - 2))) return false;
    has_rat = count == 7;
    rat_flags.fill(0);
    for (size_t field = 0; field < rat_flags.size(); ++field) {
        if (has_rat && !idf_modem_cpol_number(fields[field + 3], 1, rat_flags[field])) {
            return false;
        }
    }
    return true;
}

inline void idf_modem_cpol_parse(std::string_view response, IdfModemCpolSummaryState& state)
{
    state.response_length = response.size();
    std::vector<unsigned> indexes;
    size_t start = 0;
    while (start <= response.size()) {
        size_t end = response.find_first_of("\r\n", start);
        if (end == std::string_view::npos) end = response.size();
        std::string_view line = idf_modem_cpol_trim(response.substr(start, end - start));
        if (!line.empty()) {
            if (line == "OK" && !state.final_ok) {
                state.final_ok = true;
            } else if (state.final_ok) {
                ++state.malformed;
            } else {
                unsigned format = 0;
                unsigned index = 0;
                std::array<unsigned, 4> rat_flags{};
                bool has_rat = false;
                if (!idf_modem_cpol_fields(line, index, format, has_rat, rat_flags)) {
                    ++state.malformed;
                } else {
                    bool duplicate = false;
                    for (unsigned seen : indexes) duplicate = duplicate || seen == index;
                    if (duplicate) {
                        ++state.malformed;
                    } else {
                        indexes.push_back(index);
                        ++state.records;
                        ++state.format_counts[format];
                        state.format_bitmap |= 1U << format;
                        if (has_rat) {
                            state.saw_rat = true;
                            for (size_t rat = 0; rat < rat_flags.size(); ++rat) {
                                state.rat_counts[rat] += rat_flags[rat];
                            }
                        } else {
                            state.saw_missing_rat = true;
                        }
                    }
                }
            }
        }
        if (end == response.size()) break;
        start = end + 1;
        while (start < response.size() && (response[start] == '\r' || response[start] == '\n')) ++start;
    }
}

inline std::string idf_modem_cpol_compact_summary(std::string_view response)
{
    IdfModemCpolSummaryState state;
    idf_modem_cpol_parse(response, state);
    const bool failed = !state.final_ok || state.malformed != 0;
    const char* rat_status = state.saw_rat && !state.saw_missing_rat ? "complete" : "missing";
    char body[120];
    std::snprintf(body, sizeof(body), "CPOL1;len=%u;rec=%u;fmt=%u,%u,%u,%u;rat=%s,%u,%u,%u,%u;bad=%u;fail=%u",
                  static_cast<unsigned>(state.response_length), state.records,
                  state.format_bitmap,
                  state.format_counts[0], state.format_counts[1], state.format_counts[2],
                  rat_status, state.rat_counts[0], state.rat_counts[1], state.rat_counts[2],
                  state.rat_counts[3], state.malformed, failed ? 1U : 0U);
    std::string summary = body;
    summary += "\r\nOK\r\n";
    if (summary.size() <= 96) return summary;
    std::snprintf(body, sizeof(body), "CPOL1;len=%u;rec=%u;fmt=%u,%u,%u,%u;rat=missing,0,0,0,0;bad=%u;fail=%u",
                  static_cast<unsigned>(state.response_length), state.records,
                  state.format_bitmap,
                  state.format_counts[0], state.format_counts[1], state.format_counts[2],
                  state.malformed, failed ? 1U : 0U);
    summary = body;
    summary += "\r\nOK\r\n";
    return summary.size() <= 96 ? summary : "CPOL1;len=0;rec=0;fmt=0,0,0,0;rat=overflow;bad=1;fail=1\r\nOK\r\n";
}
