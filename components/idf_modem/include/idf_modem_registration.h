#pragma once

#include <cstddef>
#include <string_view>

inline bool idf_modem_parse_cereg_number(std::string_view text, int& value)
{
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    while (!text.empty() && (text.back() == ' ' || text.back() == '\t')) text.remove_suffix(1);
    if (text.empty()) return false;
    int parsed = 0;
    for (char ch : text) {
        if (ch < '0' || ch > '9') return false;
        if (parsed > 100) return false;
        parsed = parsed * 10 + (ch - '0');
    }
    value = parsed;
    return true;
}

inline bool idf_modem_parse_cereg_status(std::string_view response, int& stat)
{
    constexpr std::string_view token = "+CEREG:";
    const size_t token_pos = response.find(token);
    if (token_pos == std::string_view::npos) return false;
    const size_t line_start = response.rfind('\n', token_pos) == std::string_view::npos
                                  ? 0 : response.rfind('\n', token_pos) + 1;
    const size_t line_end = response.find('\n', token_pos);
    std::string_view line = response.substr(line_start, line_end == std::string_view::npos
                                                       ? std::string_view::npos
                                                       : line_end - line_start);
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t' || line.front() == '\r')) {
        line.remove_prefix(1);
    }
    while (!line.empty() && (line.back() == ' ' || line.back() == '\t' || line.back() == '\r')) {
        line.remove_suffix(1);
    }
    const size_t colon = line.find(':');
    if (colon == std::string_view::npos) return false;
    std::string_view fields = line.substr(colon + 1);
    const size_t comma = fields.find(',');
    const std::string_view first = fields.substr(0, comma);
    int first_value = -1;
    if (!idf_modem_parse_cereg_number(first, first_value)) return false;
    int status_value = first_value;
    if (comma != std::string_view::npos) {
        const size_t second_end = fields.find(',', comma + 1);
        const std::string_view second = fields.substr(
            comma + 1, second_end == std::string_view::npos ? std::string_view::npos
                                                              : second_end - comma - 1);
        int second_value = -1;
        if (idf_modem_parse_cereg_number(second, second_value)) status_value = second_value;
    }
    if (status_value < 0 || status_value > 11) return false;
    stat = status_value;
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
