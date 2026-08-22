#pragma once

#include <algorithm>
#include <cstddef>
#include <string_view>

inline void idf_modem_trim_cereg_ascii(std::string_view& text)
{
    while (!text.empty() && text.front() == ' ') {
        text.remove_prefix(1);
    }
    while (!text.empty() && text.back() == ' ') {
        text.remove_suffix(1);
    }
}

inline bool idf_modem_parse_cereg_decimal(std::string_view text, int& value, int maximum)
{
    idf_modem_trim_cereg_ascii(text);
    if (text.empty() || (text.size() > 1 && text.front() == '0')) return false;
    int parsed = 0;
    for (char ch : text) {
        if (ch < '0' || ch > '9') return false;
        if (parsed > (maximum - (ch - '0')) / 10) return false;
        parsed = parsed * 10 + (ch - '0');
    }
    value = parsed;
    return true;
}

inline bool idf_modem_parse_cereg_number(std::string_view text, int& value)
{
    return idf_modem_parse_cereg_decimal(text, value, 100);
}

inline bool idf_modem_cereg_status_allowed(int value)
{
    return (value >= 0 && value <= 5) || value == 11;
}

inline bool idf_modem_cereg_hex_field(std::string_view& text, size_t digits)
{
    idf_modem_trim_cereg_ascii(text);
    if (text.empty() || text.front() != '"') return false;
    text.remove_prefix(1);
    for (size_t index = 0; index < digits; ++index) {
        if (text.empty()) return false;
        const char ch = text.front();
        const bool hex = (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') ||
                         (ch >= 'a' && ch <= 'f');
        if (!hex) return false;
        text.remove_prefix(1);
    }
    if (text.empty() || text.front() != '"') return false;
    text.remove_prefix(1);
    return true;
}

inline bool idf_modem_parse_cereg_line(std::string_view line, int& stat)
{
    constexpr std::string_view token = "+CEREG:";
    if (!std::all_of(line.begin(), line.end(), [](unsigned char ch) {
            return ch >= 0x20 && !(ch >= 0x7F && ch <= 0x9F);
        })) return false;
    idf_modem_trim_cereg_ascii(line);
    if (line.size() < token.size() || line.substr(0, token.size()) != token) return false;
    line.remove_prefix(token.size());
    idf_modem_trim_cereg_ascii(line);

    const size_t first_comma = line.find(',');
    if (first_comma == std::string_view::npos) return false;
    int mode = -1;
    if (!idf_modem_parse_cereg_decimal(line.substr(0, first_comma), mode, 5)) return false;
    line.remove_prefix(first_comma + 1);

    const size_t second_comma = line.find(',');
    const std::string_view stat_field = line.substr(0, second_comma);
    int parsed_stat = -1;
    if (!idf_modem_parse_cereg_decimal(stat_field, parsed_stat, 11) ||
        !idf_modem_cereg_status_allowed(parsed_stat)) {
        return false;
    }
    if (second_comma == std::string_view::npos) {
        if (mode > 1) return false;
        stat = parsed_stat;
        return true;
    }
    if (mode != 2) return false;
    line.remove_prefix(second_comma + 1);
    if (!idf_modem_cereg_hex_field(line, 4)) return false;
    idf_modem_trim_cereg_ascii(line);
    if (line.empty() || line.front() != ',') return false;
    line.remove_prefix(1);
    if (!idf_modem_cereg_hex_field(line, 8)) return false;
    idf_modem_trim_cereg_ascii(line);
    if (line.empty() || line.front() != ',') return false;
    line.remove_prefix(1);

    idf_modem_trim_cereg_ascii(line);
    if (line != "7") return false;
    stat = parsed_stat;
    return true;
}

inline bool idf_modem_parse_cereg_status(std::string_view response, int& stat)
{
    bool found_cereg = false;
    bool found_ok = false;
    int parsed_stat = -1;
    size_t position = 0;
    while (position < response.size()) {
        const size_t line_end = response.find_first_of("\r\n", position);
        const size_t end = line_end == std::string_view::npos ? response.size() : line_end;
        std::string_view line = response.substr(position, end - position);
        idf_modem_trim_cereg_ascii(line);
        if (!line.empty()) {
            if (line == "OK") {
                if (found_ok) return false;
                found_ok = true;
            } else {
                if (found_ok || found_cereg || !idf_modem_parse_cereg_line(line, parsed_stat)) {
                    return false;
                }
                found_cereg = true;
            }
        } else if (found_cereg && !found_ok) {
            return false;
        }
        if (line_end == std::string_view::npos) break;
        position = line_end + 1;
        if (response[line_end] == '\r' && position < response.size() &&
            response[position] == '\n') {
            ++position;
        }
    }
    if (!found_cereg || !found_ok) return false;
    stat = parsed_stat;
    return true;
}

inline bool idf_modem_data_activation_allowed(int cereg_stat)
{
    return cereg_stat == 1;
}

inline bool idf_modem_sms_health_reset_required(bool at_ready, bool sim_ready,
                                                bool cereg_query_ok, bool sms_ok,
                                                bool storage_ok)
{
    return !at_ready || !sim_ready || !cereg_query_ok || !sms_ok || !storage_ok;
}

inline bool idf_modem_identity_sampling_allowed(int cereg_stat)
{
    return cereg_stat == 1;
}

inline void idf_modem_invalidate_registration_stat(int& cereg_stat)
{
    cereg_stat = -1;
}
