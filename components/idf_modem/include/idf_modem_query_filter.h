#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

#include "idf_modem_registration.h"

enum class IdfModemUsbQueryAdmission {
    busy,
    not_ready,
    submit,
};

inline IdfModemUsbQueryAdmission idf_modem_usb_query_admission(bool owner_queue_ready,
                                                                bool at_ready,
                                                                bool reset_requested)
{
    if (!owner_queue_ready) return IdfModemUsbQueryAdmission::busy;
    return at_ready && !reset_requested ? IdfModemUsbQueryAdmission::submit
                                        : IdfModemUsbQueryAdmission::not_ready;
}

// The USB diagnostic response is a line-oriented AT response. Keep this small
// filter independent from ESP-IDF so the exact interleaving behavior is host-testable.
inline bool idf_modem_query_transport_ready(bool owner_queue_ready, bool at_ready,
                                             bool reset_requested)
{
    return owner_queue_ready && at_ready && !reset_requested;
}

// Check this at the owner command mutex boundary. Priority work is limited to
// modem-owned SMS acknowledgements; normal callers must not cross a reset or
// closed-runtime boundary into UART.
inline bool idf_modem_owner_command_allowed(bool priority, bool reset_requested,
                                            bool runtime_queue_ready)
{
    return priority || (runtime_queue_ready && !reset_requested);
}

inline bool idf_modem_is_standalone_urc_line(std::string_view line)
{
    return line == "RING" || line.rfind("+CMTI:", 0) == 0 ||
           line.rfind("+CLIP:", 0) == 0 || line.rfind("+CEREG:", 0) == 0;
}

class IdfModemQueryResponseFilter {
public:
    IdfModemQueryResponseFilter(std::string_view command, std::string_view response_prefix,
                                std::string_view initial_carry, bool waiting_for_pdu,
                                size_t response_limit = 8192)
        : command_(command), response_prefix_(response_prefix), carry_(initial_carry),
          waiting_for_pdu_(waiting_for_pdu),
          allow_multiple_response_lines_(command == "AT+CPOL?" || command == "AT+CGDCONT?" ||
                                         (command == "AT+CCLK?" && response_prefix == "+CCLK:")),
          track_other_line_(command == "AT+MSSLCIPHER=?"),
          response_limit_(response_limit)
    {
    }

    void feed(const char* data, size_t length)
    {
        if (!data) return;
        for (size_t i = 0; i < length; ++i) {
            char ch = data[i];
            if (ch == '\r' || ch == '\n') {
                flush_line();
            } else if (carry_.size() < 768) {
                carry_ += ch;
            } else {
                if (track_other_line_) other_line_present_ = true;
                carry_.clear();
                waiting_for_pdu_ = false;
            }
        }
    }

    const std::string& response() const { return response_; }
    const std::string& urcs() const { return urcs_; }
    const std::string& carry() const { return carry_; }
    bool waiting_for_pdu() const { return waiting_for_pdu_; }
    bool other_line_present() const { return other_line_present_; }

    void flush_pending() { flush_line(); }
    void clear_urcs() { urcs_.clear(); }

private:
    static std::string trim(std::string_view raw, bool spaces_only)
    {
        const auto trim_char = [spaces_only](unsigned char ch) {
            return ch == ' ' || (!spaces_only && std::isspace(ch));
        };
        size_t start = 0;
        size_t end = raw.size();
        while (start < end && trim_char(static_cast<unsigned char>(raw[start]))) ++start;
        while (end > start && trim_char(static_cast<unsigned char>(raw[end - 1]))) --end;
        return std::string(raw.substr(start, end - start));
    }

    static bool starts_with(std::string_view value, std::string_view prefix)
    {
        return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
    }

    static bool looks_like_pdu(std::string_view line)
    {
        if (line.size() < 4 || (line.size() & 1) != 0) return false;
        return std::all_of(line.begin(), line.end(), [](unsigned char ch) {
            return std::isxdigit(ch);
        });
    }

    static bool is_final(std::string_view line)
    {
        return line == "OK" || line == "ERROR" || starts_with(line, "+CMS ERROR") ||
               starts_with(line, "+CME ERROR");
    }

    static bool is_unsolicited_text(std::string_view line)
    {
        return line == "RING" || line == "RDY" || line == "SMS READY" ||
               line == "CALL READY" || line == "SMS DONE" || line == "NO CARRIER" ||
               line == "BUSY" || line == "NO ANSWER" || line == "NORMAL POWER DOWN";
    }

    void append_response(const std::string& line)
    {
        if (response_limit_ == 0 || response_.size() >= response_limit_) return;
        size_t room = response_limit_ - response_.size();
        response_.append(line.data(), line.size() < room ? line.size() : room);
        if (response_.size() < response_limit_ && room > line.size()) response_ += "\r\n";
    }

    void flush_line()
    {
        if (carry_.empty()) return;
        std::string line = trim(carry_, response_prefix_ == "+CEREG:");
        carry_.clear();
        if (line.empty()) return;

        // Echo is transport noise, not a solicited query result. In particular,
        // do not let an echoed fixed command become the response payload.
        if (line == command_) return;

        bool cmt = starts_with(line, "+CMT:");
        bool pdu = waiting_for_pdu_ && looks_like_pdu(line);
        bool unsolicited_text = is_unsolicited_text(line);
        bool solicited = is_final(line);
        if (!solicited && !response_prefix_.empty() && starts_with(line, response_prefix_)) {
            if (response_prefix_ == "+CEREG:") {
                int ignored_stat = -1;
                solicited = !expected_line_seen_ && idf_modem_parse_cereg_line(line, ignored_stat);
            } else {
                solicited = allow_multiple_response_lines_ || !expected_line_seen_;
            }
            if (solicited) expected_line_seen_ = true;
        }
        // ATI returns bounded free-form model/firmware lines. Other fixed
        // queries must match their expected +PREFIX; all remaining + lines are
        // unsolicited and preserved.
        if (!solicited && response_prefix_.empty() && !unsolicited_text &&
            !starts_with(line, "+") && !pdu && !waiting_for_pdu_) {
            solicited = true;
        }

        if (track_other_line_ && (!solicited || pdu)) other_line_present_ = true;

        if (solicited && !pdu) {
            append_response(line);
        } else {
            urcs_ += line;
            urcs_ += "\r\n";
        }

        if (cmt) {
            waiting_for_pdu_ = true;
        } else if (pdu) {
            waiting_for_pdu_ = false;
        }
    }

    std::string command_;
    std::string response_prefix_;
    std::string carry_;
    std::string response_;
    std::string urcs_;
    bool waiting_for_pdu_ = false;
    bool allow_multiple_response_lines_ = false;
    bool expected_line_seen_ = false;
    bool track_other_line_ = false;
    bool other_line_present_ = false;
    size_t response_limit_ = 0;
};
