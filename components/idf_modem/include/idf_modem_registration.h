#pragma once

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <string>
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

inline bool idf_modem_valid_ipv4_address(std::string_view value, bool require_non_zero = true)
{
    if (value.empty() || !std::all_of(value.begin(), value.end(), [](unsigned char ch) {
            return (ch >= '0' && ch <= '9') || ch == '.';
        })) return false;
    bool non_zero = false;
    for (int part = 0; part < 4; ++part) {
        const size_t dot = value.find('.');
        const std::string_view octet_text = value.substr(0, dot);
        int octet = -1;
        if (!idf_modem_parse_cereg_decimal(octet_text, octet, 255)) return false;
        if (octet != 0) non_zero = true;
        if (part == 3) {
            return dot == std::string_view::npos && (non_zero || !require_non_zero);
        }
        if (dot == std::string_view::npos) return false;
        value.remove_prefix(dot + 1);
    }
    return false;
}

inline bool idf_modem_valid_ipv6_address(std::string_view value)
{
    const size_t compression = value.find("::");
    if (value.empty() || value.find(':') == std::string_view::npos ||
        (compression != std::string_view::npos &&
         value.find("::", compression + 2) != std::string_view::npos)) {
        return false;
    }
    const auto count_parts = [](std::string_view side, bool allow_ipv4, int& units) {
        if (side.empty()) return true;
        size_t position = 0;
        while (position <= side.size()) {
            const size_t colon = side.find(':', position);
            const std::string_view part = side.substr(
                position, colon == std::string_view::npos ? std::string_view::npos
                                                          : colon - position);
            if (part.empty()) return false;
            if (part.find('.') != std::string_view::npos) {
                if (!allow_ipv4 || colon != std::string_view::npos ||
                    !idf_modem_valid_ipv4_address(part, false)) {
                    return false;
                }
                units += 2;
            } else {
                if (part.size() > 4 || !std::all_of(part.begin(), part.end(), [](unsigned char ch) {
                        return (ch >= '0' && ch <= '9') || (ch >= 'A' && ch <= 'F') ||
                               (ch >= 'a' && ch <= 'f');
                    })) {
                    return false;
                }
                ++units;
            }
            if (units > 8) return false;
            if (colon == std::string_view::npos) break;
            position = colon + 1;
        }
        return true;
    };

    int units = 0;
    if (compression == std::string_view::npos) {
        return count_parts(value, true, units) && units == 8;
    }
    const std::string_view left = value.substr(0, compression);
    const std::string_view right = value.substr(compression + 2);
    return count_parts(left, false, units) && count_parts(right, true, units) && units < 8;
}

inline bool idf_modem_parse_cgpaddr_ipv4(std::string_view response, std::string& ip)
{
    const auto parse_line = [](std::string_view line, std::string& selected_ipv4) {
        constexpr std::string_view prefix = "+CGPADDR:";
        if (!std::all_of(line.begin(), line.end(), [](unsigned char ch) {
                return ch >= 0x20 && ch <= 0x7E;
            })) return false;
        idf_modem_trim_cereg_ascii(line);
        if (line.size() < prefix.size() || line.substr(0, prefix.size()) != prefix) return false;
        line.remove_prefix(prefix.size());
        idf_modem_trim_cereg_ascii(line);

        const size_t first_comma = line.find(',');
        int cid = 0;
        if (!idf_modem_parse_cereg_decimal(line.substr(0, first_comma), cid, 255) || cid == 0) {
            return false;
        }
        if (first_comma == std::string_view::npos) return true;
        line.remove_prefix(first_comma + 1);

        int address_count = 0;
        while (true) {
            if (++address_count > 2) return false;
            const size_t comma = line.find(',');
            std::string_view address = line.substr(0, comma);
            idf_modem_trim_cereg_ascii(address);
            if (address.empty()) return false;
            const bool starts_quote = address.front() == '"';
            const bool ends_quote = address.back() == '"';
            if (starts_quote != ends_quote) return false;
            if (starts_quote) {
                if (address.size() < 2) return false;
                address.remove_prefix(1);
                address.remove_suffix(1);
            }
            if (address.empty() || address.find('"') != std::string_view::npos) return false;
            if (idf_modem_valid_ipv4_address(address)) {
                if (selected_ipv4.empty()) selected_ipv4.assign(address);
            } else if (!idf_modem_valid_ipv6_address(address)) {
                return false;
            }
            if (comma == std::string_view::npos) break;
            line.remove_prefix(comma + 1);
        }
        return true;
    };

    bool found_data = false;
    bool found_ok = false;
    std::string selected_ipv4;
    size_t position = 0;
    while (position < response.size()) {
        const size_t line_end = response.find_first_of("\r\n", position);
        const size_t end = line_end == std::string_view::npos ? response.size() : line_end;
        std::string_view line = response.substr(position, end - position);
        idf_modem_trim_cereg_ascii(line);
        if (!line.empty()) {
            if (found_ok) return false;
            if (line == "OK") {
                if (!found_data) return false;
                found_ok = true;
            } else {
                if (found_data || !parse_line(line, selected_ipv4)) return false;
                found_data = true;
            }
        } else if (found_data && !found_ok) {
            return false;
        }
        if (line_end == std::string_view::npos) break;
        position = line_end + 1;
        if (response[line_end] == '\r' && position < response.size() &&
            response[position] == '\n') {
            ++position;
        }
    }
    if (!found_data || !found_ok || selected_ipv4.empty()) return false;
    ip = selected_ipv4;
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

inline bool idf_modem_sms_health_complete(bool registered, bool phase2, bool pdu, bool cnmi,
                                          bool storage)
{
    return registered && phase2 && pdu && cnmi && storage;
}

inline bool idf_modem_health_reset_required(bool at_ready, bool sim_present, bool sim_ready,
                                            bool cereg_query_ok, int cereg_stat, bool sms_ok,
                                            bool storage_ok)
{
    if (!sim_present || cereg_stat == 11) return false;
    return idf_modem_sms_health_reset_required(at_ready, sim_ready, cereg_query_ok, sms_ok,
                                               storage_ok);
}

inline bool idf_modem_unregistered_reset_allowed(bool sim_present, int cereg_stat)
{
    return sim_present && cereg_stat != 1 && cereg_stat != 5 && cereg_stat != 11;
}

inline int idf_modem_sim_presence(std::string_view state)
{
    if (state == "absent") return 0;
    if (state == "unknown") return -1;
    return 1;
}

enum class IdfModemSimPresenceEvent : uint8_t {
    none,
    inserted,
    removed,
};

inline IdfModemSimPresenceEvent idf_modem_sim_presence_event(int last_confirmed,
                                                             int observed)
{
    if (last_confirmed < 0 || observed < 0 || last_confirmed == observed) {
        return IdfModemSimPresenceEvent::none;
    }
    return observed == 1 ? IdfModemSimPresenceEvent::inserted
                         : IdfModemSimPresenceEvent::removed;
}

inline bool idf_modem_health_reset_retry_allowed(uint8_t retry_count)
{
    constexpr uint8_t maximum_attempts = 3;
    return retry_count < maximum_attempts;
}

inline uint32_t idf_modem_health_reset_backoff_ms(uint8_t retry_count)
{
    constexpr uint32_t initial_ms = 60000UL;
    constexpr uint32_t maximum_ms = 300000UL;
    uint32_t delay_ms = initial_ms;
    while (retry_count-- > 0 && delay_ms < maximum_ms) {
        delay_ms = std::min(maximum_ms, delay_ms * 2U);
    }
    return delay_ms;
}

inline bool idf_modem_identity_sampling_allowed(int cereg_stat)
{
    return cereg_stat == 1;
}

inline void idf_modem_invalidate_registration_stat(int& cereg_stat)
{
    cereg_stat = -1;
}
