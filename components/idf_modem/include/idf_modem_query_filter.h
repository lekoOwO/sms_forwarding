#pragma once

#include <algorithm>
#include <cctype>
#include <cstddef>
#include <string>
#include <string_view>

#include "idf_modem_msslcipher_telemetry.h"
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
            } else {
                if (track_other_line_) observe_msslcipher_char(ch);
                if (carry_.size() < 768) {
                    carry_ += ch;
                } else {
                    if (track_other_line_) {
                        msslcipher_telemetry_ |= IDF_MODEM_MSSLCIPHER_TELEMETRY_LINE_OVERFLOW;
                        msslcipher_line_overflowed_ = true;
                    }
                    carry_.clear();
                    waiting_for_pdu_ = false;
                }
            }
        }
    }

    const std::string& response() const { return response_; }
    const std::string& urcs() const { return urcs_; }
    const std::string& carry() const { return carry_; }
    bool waiting_for_pdu() const { return waiting_for_pdu_; }
    bool other_line_present() const { return other_line_present_; }
    uint8_t msslcipher_telemetry() const { return msslcipher_telemetry_; }

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

    void observe_msslcipher_char(char ch)
    {
        constexpr std::string_view token = "MSSLCIPHER";
        constexpr std::string_view prefix = "+MSSLCIPHER:";
        if (ch == '(' || ch == ')') {
            line_telemetry_ |= IDF_MODEM_MSSLCIPHER_TELEMETRY_PARENTHESES_PRESENT;
        } else if (ch == ',') {
            line_telemetry_ |= IDF_MODEM_MSSLCIPHER_TELEMETRY_COMMA_PRESENT;
        }

        const bool starts_prefix = prefix_match_ == 0 && ch == prefix.front();
        if (starts_prefix) {
            prefix_leading_whitespace_ = line_has_data_ && line_only_whitespace_;
        }
        if (prefix_match_ < prefix.size() && ch == prefix[prefix_match_]) {
            ++prefix_match_;
        } else {
            prefix_match_ = starts_prefix ? 1 : 0;
        }
        if (prefix_match_ == prefix.size()) {
            line_telemetry_ |= IDF_MODEM_MSSLCIPHER_TELEMETRY_CONTAINS_EXACT_OFFICIAL_PREFIX_ANYWHERE;
            if (prefix_leading_whitespace_) {
                line_telemetry_ |= IDF_MODEM_MSSLCIPHER_TELEMETRY_LEADING_WHITESPACE_BEFORE_PREFIX;
            }
            msslcipher_summary_line_candidate_ = true;
            prefix_match_ = 0;
            prefix_leading_whitespace_ = false;
        }

        if (token_match_ < token.size() && ch == token[token_match_]) {
            ++token_match_;
        } else {
            token_match_ = ch == token.front() ? 1 : 0;
        }
        if (token_match_ == token.size()) {
            line_telemetry_ |= IDF_MODEM_MSSLCIPHER_TELEMETRY_CONTAINS_MSSLCIPHER_TOKEN;
            token_match_ = 0;
        }

        observe_msslcipher_summary_char(ch);
        line_has_data_ = true;
        if (!std::isspace(static_cast<unsigned char>(ch))) line_only_whitespace_ = false;
    }

    enum class MsslcipherSummaryState : uint8_t {
        leading,
        prefix,
        after_prefix,
        token_start,
        token,
        after_token,
        closed,
        invalid,
    };

    static bool is_hex_digit(char ch)
    {
        return std::isxdigit(static_cast<unsigned char>(ch));
    }

    static uint8_t hex_digit_value(char ch)
    {
        if (ch >= '0' && ch <= '9') return static_cast<uint8_t>(ch - '0');
        if (ch >= 'A' && ch <= 'F') return static_cast<uint8_t>(ch - 'A' + 10);
        return static_cast<uint8_t>(ch - 'a' + 10);
    }

    static uint8_t msslcipher_known_bit(uint16_t value)
    {
        switch (value) {
            case 0xC02B: return IDF_MODEM_MSSLCIPHER_SUMMARY_C02B;
            case 0xC02C: return IDF_MODEM_MSSLCIPHER_SUMMARY_C02C;
            case 0xC02F: return IDF_MODEM_MSSLCIPHER_SUMMARY_C02F;
            case 0xC030: return IDF_MODEM_MSSLCIPHER_SUMMARY_C030;
            default: return 0;
        }
    }

    void invalidate_msslcipher_summary_line()
    {
        msslcipher_summary_state_ = MsslcipherSummaryState::invalid;
    }

    bool append_msslcipher_summary_digit(char ch)
    {
        if (!is_hex_digit(ch) || msslcipher_summary_token_digits_ >= 4) return false;
        msslcipher_summary_token_value_ = static_cast<uint16_t>(
            (msslcipher_summary_token_value_ << 4) | hex_digit_value(ch));
        ++msslcipher_summary_token_digits_;
        return true;
    }

    bool finish_msslcipher_summary_token()
    {
        if (msslcipher_summary_token_zero_pending_) {
            if (!append_msslcipher_summary_digit('0')) return false;
            msslcipher_summary_token_zero_pending_ = false;
        }
        if (msslcipher_summary_token_digits_ == 0 ||
            msslcipher_line_count_ == IDF_MODEM_MSSLCIPHER_SUMMARY_MAX_COUNT) {
            return false;
        }
        ++msslcipher_line_count_;
        const uint8_t known_bit = msslcipher_known_bit(msslcipher_summary_token_value_);
        if (known_bit != 0) {
            if ((msslcipher_line_known_bits_ & known_bit) != 0) return false;
            msslcipher_line_known_bits_ |= known_bit;
        } else {
            // ponytail: accept unknown duplicates without an ID set; add bounded duplicate tracking
            // only if the modem contract later requires it.
            msslcipher_line_unknown_present_ = true;
        }
        msslcipher_summary_token_digits_ = 0;
        msslcipher_summary_token_value_ = 0;
        return true;
    }

    void start_msslcipher_summary_token(char ch)
    {
        msslcipher_summary_token_digits_ = 0;
        msslcipher_summary_token_value_ = 0;
        msslcipher_summary_token_zero_pending_ = ch == '0';
        msslcipher_summary_state_ = MsslcipherSummaryState::token;
        if (!msslcipher_summary_token_zero_pending_ && !append_msslcipher_summary_digit(ch)) {
            invalidate_msslcipher_summary_line();
        }
    }

    void consume_msslcipher_summary_after_token(char ch)
    {
        if (ch == ' ') {
            msslcipher_summary_state_ = MsslcipherSummaryState::after_token;
        } else if (ch == ',') {
            msslcipher_summary_state_ = MsslcipherSummaryState::token_start;
        } else if (ch == ')' && msslcipher_summary_open_paren_) {
            msslcipher_summary_state_ = MsslcipherSummaryState::closed;
        } else {
            invalidate_msslcipher_summary_line();
        }
    }

    void consume_msslcipher_summary_token(char ch)
    {
        if (msslcipher_summary_token_zero_pending_) {
            if (ch == 'x' || ch == 'X') {
                msslcipher_summary_token_zero_pending_ = false;
                return;
            }
            if (!append_msslcipher_summary_digit('0')) {
                invalidate_msslcipher_summary_line();
                return;
            }
            msslcipher_summary_token_zero_pending_ = false;
        }
        if (is_hex_digit(ch)) {
            if (!append_msslcipher_summary_digit(ch)) invalidate_msslcipher_summary_line();
            return;
        }
        if (ch == ' ' || ch == ',' || ch == ')') {
            if (!finish_msslcipher_summary_token()) {
                invalidate_msslcipher_summary_line();
                return;
            }
            consume_msslcipher_summary_after_token(ch);
            return;
        }
        invalidate_msslcipher_summary_line();
    }

    void observe_msslcipher_summary_char(char ch)
    {
        constexpr std::string_view prefix = "+MSSLCIPHER:";
        if (msslcipher_summary_state_ == MsslcipherSummaryState::invalid) return;
        switch (msslcipher_summary_state_) {
            case MsslcipherSummaryState::leading:
                if (ch == ' ') return;
                if (ch != '+') {
                    invalidate_msslcipher_summary_line();
                    return;
                }
                msslcipher_summary_prefix_index_ = 1;
                msslcipher_summary_state_ = MsslcipherSummaryState::prefix;
                return;
            case MsslcipherSummaryState::prefix:
                if (msslcipher_summary_prefix_index_ >= prefix.size() ||
                    ch != prefix[msslcipher_summary_prefix_index_]) {
                    invalidate_msslcipher_summary_line();
                    return;
                }
                ++msslcipher_summary_prefix_index_;
                if (msslcipher_summary_prefix_index_ == prefix.size()) {
                    msslcipher_summary_line_candidate_ = true;
                    msslcipher_summary_state_ = MsslcipherSummaryState::after_prefix;
                }
                return;
            case MsslcipherSummaryState::after_prefix:
                if (ch == ' ') return;
                if (ch == '(' && !msslcipher_summary_open_paren_) {
                    msslcipher_summary_open_paren_ = true;
                    msslcipher_summary_state_ = MsslcipherSummaryState::token_start;
                    return;
                }
                if (is_hex_digit(ch)) {
                    start_msslcipher_summary_token(ch);
                    return;
                }
                invalidate_msslcipher_summary_line();
                return;
            case MsslcipherSummaryState::token_start:
                if (ch == ' ') return;
                if (is_hex_digit(ch)) {
                    start_msslcipher_summary_token(ch);
                    return;
                }
                invalidate_msslcipher_summary_line();
                return;
            case MsslcipherSummaryState::token:
                consume_msslcipher_summary_token(ch);
                return;
            case MsslcipherSummaryState::after_token:
                consume_msslcipher_summary_after_token(ch);
                return;
            case MsslcipherSummaryState::closed:
                if (ch != ' ') invalidate_msslcipher_summary_line();
                return;
            case MsslcipherSummaryState::invalid:
                return;
        }
    }

    bool finish_msslcipher_summary_line()
    {
        if (msslcipher_summary_state_ == MsslcipherSummaryState::token) {
            if (!finish_msslcipher_summary_token()) {
                invalidate_msslcipher_summary_line();
            } else {
                msslcipher_summary_state_ = MsslcipherSummaryState::after_token;
            }
        }
        if (!msslcipher_summary_line_candidate_ ||
            msslcipher_summary_state_ == MsslcipherSummaryState::invalid ||
            msslcipher_line_count_ == 0 ||
            (msslcipher_summary_open_paren_
                 ? msslcipher_summary_state_ != MsslcipherSummaryState::closed
                 : msslcipher_summary_state_ != MsslcipherSummaryState::after_token)) {
            return false;
        }
        return true;
    }

    bool finish_msslcipher_line(bool echo)
    {
        const bool has_token = (line_telemetry_ &
                                IDF_MODEM_MSSLCIPHER_TELEMETRY_CONTAINS_MSSLCIPHER_TOKEN) != 0;
        const bool partial_prefix = prefix_match_ != 0;
        const bool candidate = msslcipher_summary_line_candidate_;
        bool accepted = false;
        if (!echo) {
            msslcipher_telemetry_ |= line_telemetry_;
            const bool valid = finish_msslcipher_summary_line();
            if (candidate || has_token || partial_prefix) {
                if (candidate && valid && !msslcipher_summary_seen_ &&
                    !msslcipher_summary_invalid_) {
                    msslcipher_summary_seen_ = true;
                    msslcipher_summary_known_bits_ = msslcipher_line_known_bits_;
                    msslcipher_summary_total_count_ = msslcipher_line_count_;
                    msslcipher_summary_total_unknown_present_ = msslcipher_line_unknown_present_;
                    accepted = true;
                } else {
                    msslcipher_summary_invalid_ = true;
                }
            }
        }
        line_telemetry_ = 0;
        line_has_data_ = false;
        line_only_whitespace_ = true;
        prefix_match_ = 0;
        token_match_ = 0;
        prefix_leading_whitespace_ = false;
        msslcipher_summary_state_ = MsslcipherSummaryState::leading;
        msslcipher_summary_prefix_index_ = 0;
        msslcipher_summary_line_candidate_ = false;
        msslcipher_line_overflowed_ = false;
        msslcipher_summary_open_paren_ = false;
        msslcipher_summary_token_zero_pending_ = false;
        msslcipher_summary_token_digits_ = 0;
        msslcipher_summary_token_value_ = 0;
        msslcipher_line_known_bits_ = 0;
        msslcipher_line_count_ = 0;
        msslcipher_line_unknown_present_ = false;
        return accepted;
    }

    std::string msslcipher_summary_response() const
    {
        static constexpr char hex[] = "0123456789ABCDEF";
        std::string line = "+MSSLCIPHER: SUMMARY;v=";
        line += std::to_string(IDF_MODEM_MSSLCIPHER_SUMMARY_VERSION);
        line += ";known=0x";
        line += hex[(msslcipher_summary_known_bits_ >> 4) & 0x0F];
        line += hex[msslcipher_summary_known_bits_ & 0x0F];
        line += ";count=";
        line += std::to_string(msslcipher_summary_total_count_);
        line += ";unknown=";
        line += msslcipher_summary_total_unknown_present_ ? "1" : "0";
        return line;
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
        if (carry_.empty() && !(track_other_line_ && line_has_data_)) return;
        std::string line = trim(carry_, response_prefix_ == "+CEREG:");
        carry_.clear();
        const bool echo = line == command_;
        bool msslcipher_line = false;
        bool msslcipher_line_accepted = false;
        if (track_other_line_) {
            msslcipher_line = msslcipher_summary_line_candidate_ ||
                              prefix_match_ != 0 ||
                              msslcipher_line_overflowed_ ||
                              (line_telemetry_ &
                               IDF_MODEM_MSSLCIPHER_TELEMETRY_CONTAINS_MSSLCIPHER_TOKEN);
            msslcipher_line_accepted = finish_msslcipher_line(echo);
        }
        if (msslcipher_line) {
            if (!echo && !msslcipher_line_accepted) {
                other_line_present_ = true;
                msslcipher_telemetry_ |= IDF_MODEM_MSSLCIPHER_TELEMETRY_OTHER_LINE_PRESENT;
            }
            return;
        }
        if (line.empty()) return;

        // Echo is transport noise, not a solicited query result. In particular,
        // do not let an echoed fixed command become the response payload.
        if (echo) return;

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

        if (track_other_line_ && (!solicited || pdu)) {
            other_line_present_ = true;
            msslcipher_telemetry_ |= IDF_MODEM_MSSLCIPHER_TELEMETRY_OTHER_LINE_PRESENT;
        }

        if (solicited && !pdu) {
            if (track_other_line_ && line == "OK" && msslcipher_summary_seen_ &&
                !msslcipher_summary_invalid_ && !msslcipher_summary_emitted_) {
                append_response(msslcipher_summary_response());
                msslcipher_summary_emitted_ = true;
            }
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
    uint8_t msslcipher_telemetry_ = 0;
    uint8_t line_telemetry_ = 0;
    size_t prefix_match_ = 0;
    size_t token_match_ = 0;
    bool prefix_leading_whitespace_ = false;
    bool line_has_data_ = false;
    bool line_only_whitespace_ = true;
    MsslcipherSummaryState msslcipher_summary_state_ = MsslcipherSummaryState::leading;
    size_t msslcipher_summary_prefix_index_ = 0;
    bool msslcipher_summary_line_candidate_ = false;
    bool msslcipher_line_overflowed_ = false;
    bool msslcipher_summary_open_paren_ = false;
    bool msslcipher_summary_token_zero_pending_ = false;
    uint8_t msslcipher_summary_token_digits_ = 0;
    uint16_t msslcipher_summary_token_value_ = 0;
    uint8_t msslcipher_line_known_bits_ = 0;
    uint16_t msslcipher_line_count_ = 0;
    bool msslcipher_line_unknown_present_ = false;
    bool msslcipher_summary_seen_ = false;
    bool msslcipher_summary_invalid_ = false;
    bool msslcipher_summary_emitted_ = false;
    uint8_t msslcipher_summary_known_bits_ = 0;
    uint16_t msslcipher_summary_total_count_ = 0;
    bool msslcipher_summary_total_unknown_present_ = false;
    size_t response_limit_ = 0;
};
