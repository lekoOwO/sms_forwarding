#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>
#include <utility>

#include "idf_modem_query_filter.h"

inline bool idf_modem_imei_digits(std::string_view value)
{
    return value.size() == 15 && std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= '0' && ch <= '9';
    });
}

inline bool idf_modem_imei_known_urc(std::string_view line)
{
    return idf_modem_is_standalone_urc_line(line) || line.rfind("+CMT:", 0) == 0;
}

inline bool idf_modem_imei_pdu_line(std::string_view line)
{
    if (line.size() < 32 || (line.size() & 1U) != 0) return false;
    return std::all_of(line.begin(), line.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

inline bool idf_modem_is_imei_command(std::string_view command)
{
    return command == "AT+CGSN=1" || command == "AT+GSN=1" ||
           command == "AT+CGSN" || command == "AT+GSN";
}

inline bool idf_modem_parse_imei_frame(std::string_view frame, std::string_view command,
                                       std::string& out, bool* complete = nullptr,
                                       bool waiting_for_pdu = false)
{
    out.clear();
    if (complete) *complete = false;
    if (!idf_modem_is_imei_command(command) || frame.size() > 8192) return false;

    bool echo_seen = false;
    bool payload_seen = false;
    bool terminal_seen = false;
    bool invalid = false;
    bool partial = false;
    std::string parsed;
    size_t pos = 0;
    while (pos < frame.size()) {
        size_t end = frame.find_first_of("\r\n", pos);
        if (end == std::string_view::npos && complete) {
            partial = true;
            break;
        }
        if (end == std::string_view::npos) end = frame.size();
        const std::string_view line = frame.substr(pos, end - pos);
        if (!line.empty()) {
            if (waiting_for_pdu && idf_modem_imei_pdu_line(line)) {
                waiting_for_pdu = false;
            } else if (idf_modem_imei_known_urc(line)) {
                if (line.rfind("+CMT:", 0) == 0) waiting_for_pdu = true;
            } else if (terminal_seen) {
                invalid = true;
            } else if (line == command) {
                if (echo_seen || payload_seen) invalid = true;
                echo_seen = true;
            } else if (line == "OK") {
                if (!payload_seen || waiting_for_pdu) invalid = true;
                terminal_seen = true;
            } else if (line == "ERROR" || line.rfind("+CMS ERROR:", 0) == 0 ||
                       line.rfind("+CME ERROR:", 0) == 0) {
                terminal_seen = true;
                invalid = true;
            } else {
                std::string_view candidate;
                if (line.rfind("+CGSN:", 0) == 0) {
                    candidate = line.substr(6);
                    while (!candidate.empty() &&
                           (candidate.front() == ' ' || candidate.front() == '\t')) {
                        candidate.remove_prefix(1);
                    }
                } else if (line.rfind("+GSN:", 0) == 0) {
                    candidate = line.substr(5);
                    while (!candidate.empty() &&
                           (candidate.front() == ' ' || candidate.front() == '\t')) {
                        candidate.remove_prefix(1);
                    }
                } else if (idf_modem_imei_digits(line)) {
                    candidate = line;
                } else {
                    invalid = true;
                }
                if (waiting_for_pdu || payload_seen || !idf_modem_imei_digits(candidate)) {
                    invalid = true;
                }
                parsed.assign(candidate.data(), candidate.size());
                payload_seen = true;
            }
        }
        if (end == frame.size()) break;
        pos = end + 1;
        while (pos < frame.size() && (frame[pos] == '\r' || frame[pos] == '\n')) ++pos;
    }

    if (complete) *complete = terminal_seen && !partial;
    if (!terminal_seen || !payload_seen || invalid || partial) return false;
    out = std::move(parsed);
    return true;
}
