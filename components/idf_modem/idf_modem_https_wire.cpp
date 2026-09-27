#include "idf_modem_https_wire.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <climits>

namespace idf_modem_https_wire {
namespace {

using ParseReason = IdfModemHttpsParseReason;
using ParseShape = IdfModemHttpsParseShape;

constexpr uint32_t kTraceEcho = 1U << 0;
constexpr uint32_t kTraceOk = 1U << 1;
constexpr uint32_t kTraceRtcp = 1U << 2;
constexpr uint32_t kTraceMiprd = 1U << 3;
constexpr uint32_t kTraceDisconnect = 1U << 4;
constexpr uint32_t kTraceOkBeforeRtcp = 1U << 5;
constexpr uint32_t kTraceRtcpBeforeOk = 1U << 6;

void clear_parse_reason(ParseReason* reason)
{
    if (reason) *reason = ParseReason::none;
}

void set_parse_reason(ParseReason* reason, ParseReason value)
{
    if (reason && *reason == ParseReason::none) *reason = value;
}

void clear_parse_shape(ParseShape* shape)
{
    if (shape) *shape = {};
}

void set_line_class(ParseShape* shape, IdfModemHttpsParseLineClass line)
{
    if (shape && shape->lineClass == IdfModemHttpsParseLineClass::none) {
        shape->lineClass = line;
    }
}

void mark_response_trace(ParseShape* shape, uint32_t event)
{
    if (!shape) return;
    if (event == kTraceOk && (shape->responseTraceMask & kTraceRtcp) != 0) {
        shape->responseTraceMask |= kTraceRtcpBeforeOk;
    } else if (event == kTraceRtcp && (shape->responseTraceMask & kTraceOk) != 0) {
        shape->responseTraceMask |= kTraceOkBeforeRtcp;
    }
    shape->responseTraceMask |= event;
}

bool starts_with(std::string_view value, std::string_view prefix)
{
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

std::string_view trim_spaces(std::string_view value)
{
    size_t begin = 0;
    while (begin < value.size() && (value[begin] == ' ' || value[begin] == '\t')) ++begin;
    size_t end = value.size();
    while (end > begin && (value[end - 1] == ' ' || value[end - 1] == '\t')) --end;
    return value.substr(begin, end - begin);
}

bool parse_uint(std::string_view value, uint32_t& output)
{
    value = trim_spaces(value);
    if (value.empty()) return false;
    uint64_t number = 0;
    for (unsigned char ch : value) {
        if (ch < '0' || ch > '9') return false;
        number = number * 10U + static_cast<uint32_t>(ch - '0');
        if (number > UINT32_MAX) return false;
    }
    output = static_cast<uint32_t>(number);
    return true;
}

enum class CsvFailure : uint8_t {
    none,
    field_count,
    quote,
};

template <size_t FieldCount>
bool parse_csv(std::string_view input, std::array<std::string_view, FieldCount>& fields,
               std::array<bool, FieldCount>& quoted, size_t& count,
               CsvFailure* failure = nullptr)
{
    count = 0;
    if (failure) *failure = CsvFailure::none;
    size_t position = 0;
    while (position <= input.size()) {
        if (count == fields.size()) {
            if (failure) *failure = CsvFailure::field_count;
            return false;
        }
        while (position < input.size() && (input[position] == ' ' || input[position] == '\t')) {
            ++position;
        }
        bool is_quoted = false;
        std::string_view value;
        if (position < input.size() && input[position] == '"') {
            is_quoted = true;
            const size_t begin = ++position;
            while (position < input.size() && input[position] != '"') ++position;
            if (position == input.size()) {
                if (failure) *failure = CsvFailure::quote;
                return false;
            }
            value = input.substr(begin, position - begin);
            ++position;
            while (position < input.size() && (input[position] == ' ' || input[position] == '\t')) {
                ++position;
            }
            if (position < input.size() && input[position] != ',') {
                if (failure) *failure = CsvFailure::quote;
                return false;
            }
        } else {
            const size_t begin = position;
            const size_t comma = input.find(',', position);
            position = comma == std::string_view::npos ? input.size() : comma;
            value = trim_spaces(input.substr(begin, position - begin));
        }
        fields[count] = value;
        quoted[count] = is_quoted;
        ++count;
        if (position == input.size()) break;
        ++position;
    }
    return count != 0;
}

bool is_known_urc(std::string_view line)
{
    static constexpr std::string_view prefixes[] = {
        "+CMT:", "+CMTI:", "+CEREG:", "+CREG:", "+CGREG:", "+CLIP:",
        "+CSQ:", "+CESQ:", "+MUESTATS:", "RING",
    };
    return std::any_of(std::begin(prefixes), std::end(prefixes),
                       [line](std::string_view prefix) { return starts_with(line, prefix); });
}

void mark_presence(ParseShape* shape, std::string_view line)
{
    if (!shape) return;
    if (starts_with(line, "+MIPSTATE")) {
        shape->presenceMask |= IdfModemHttpsParsePresence::mipstate;
    } else if (starts_with(line, "+MIPOPEN")) {
        shape->presenceMask |= IdfModemHttpsParsePresence::mipopen;
    } else if (starts_with(line, "+MIPCLOSE")) {
        shape->presenceMask |= IdfModemHttpsParsePresence::mipclose;
    } else if (starts_with(line, "+MIPURC:")) {
        shape->presenceMask |= IdfModemHttpsParsePresence::mipurc;
    } else if (!is_known_urc(line)) {
        shape->presenceMask |= IdfModemHttpsParsePresence::other;
    }
}

template <size_t FieldCount>
void capture_csv_shape(ParseShape* shape, size_t count,
                       const std::array<std::string_view, FieldCount>& fields,
                       const std::array<bool, FieldCount>& quoted)
{
    if (!shape) return;
    shape->fieldCount = static_cast<uint8_t>(std::min<size_t>(count, 8));
    shape->quoteMask = 0;
    const size_t limit = std::min<size_t>(quoted.size(), 8);
    for (size_t index = 0; index < limit; ++index) {
        if (quoted[index]) shape->quoteMask |= static_cast<uint8_t>(1U << index);
    }
    shape->singleFieldClass = IdfModemHttpsParseSingleFieldClass::none;
    if (count == 1) {
        uint32_t value = 0;
        if (!parse_uint(fields[0], value)) {
            shape->singleFieldClass = IdfModemHttpsParseSingleFieldClass::non_numeric;
        } else {
            shape->singleFieldClass = value == 0
                                           ? IdfModemHttpsParseSingleFieldClass::zero
                                           : IdfModemHttpsParseSingleFieldClass::nonzero;
        }
    }
}

bool looks_like_pdu_line(std::string_view line)
{
    if (line.size() < 32 || (line.size() & 1) != 0) return false;
    return std::all_of(line.begin(), line.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

bool cgdcont_field_safe(std::string_view value, bool quoted)
{
    return std::all_of(value.begin(), value.end(), [quoted](unsigned char ch) {
        if (ch < 0x20 || ch > 0x7e) return false;
        return !quoted || (ch != '"' && ch != '\\');
    });
}

bool header_value_bytes_valid(std::string_view value)
{
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= 0x20 && ch != 0x7f;
    });
}

bool header_name_token(std::string_view value)
{
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0 ||
               std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(ch)) !=
                   std::string_view::npos;
    });
}

}  // namespace

bool scan_frame(std::string_view response, std::string_view command,
                std::vector<std::string_view>& body, ParseReason* reason, ParseShape* shape,
                uint8_t* command_echo_count, bool* ignored_auxiliary_seen)
{
    clear_parse_reason(reason);
    clear_parse_shape(shape);
    if (command_echo_count) *command_echo_count = 0;
    if (ignored_auxiliary_seen) *ignored_auxiliary_seen = false;
    body.clear();
    if (response.size() > kResponseMax) {
        set_parse_reason(reason, ParseReason::oversize);
        return false;
    }
    size_t position = 0;
    size_t terminal_count = 0;
    bool waiting_for_cmt_pdu = false;
    while (position < response.size()) {
        const size_t end = response.find_first_of("\r\n", position);
        const size_t line_end = end == std::string_view::npos ? response.size() : end;
        const std::string_view line = trim_spaces(response.substr(position, line_end - position));
        if (line.size() > kLineMax) {
            set_parse_reason(reason, ParseReason::oversize);
            return false;
        }
        if (!line.empty()) {
            if (line == command) {
                if (command_echo_count && *command_echo_count < 2) ++*command_echo_count;
                mark_response_trace(shape, kTraceEcho);
            } else if (line == "OK") {
                if (++terminal_count != 1) {
                    set_parse_reason(reason, ParseReason::terminal);
                    return false;
                }
                mark_response_trace(shape, kTraceOk);
            } else if (line == "ERROR" || starts_with(line, "+CME ERROR") ||
                       starts_with(line, "+CMS ERROR")) {
                return false;
            } else if (starts_with(line, "+CMT:")) {
                if (ignored_auxiliary_seen) *ignored_auxiliary_seen = true;
                waiting_for_cmt_pdu = true;
            } else if (waiting_for_cmt_pdu && looks_like_pdu_line(line)) {
                if (ignored_auxiliary_seen) *ignored_auxiliary_seen = true;
                waiting_for_cmt_pdu = false;
            } else if (!is_known_urc(line)) {
                if (starts_with(line, "+MIPURC:")) {
                    uint32_t received = 0;
                    uint32_t total = 0;
                    uint8_t state = 0;
                    bool disconnected = false;
                    if (parse_mip_urc(line, received, total, state, disconnected)) {
                        mark_response_trace(shape, disconnected ? kTraceDisconnect : kTraceRtcp);
                    }
                } else if (starts_with(line, "+MIPRD:")) {
                    mark_response_trace(shape, kTraceMiprd);
                }
                mark_presence(shape, line);
                body.push_back(line);
                waiting_for_cmt_pdu = false;
            } else {
                if (ignored_auxiliary_seen) *ignored_auxiliary_seen = true;
                waiting_for_cmt_pdu = false;
            }
        }
        if (end == std::string_view::npos) break;
        position = end + 1;
        while (position < response.size() &&
               (response[position] == '\r' || response[position] == '\n')) ++position;
    }
    if (terminal_count != 1) {
        set_parse_reason(reason, ParseReason::terminal);
        return false;
    }
    if (shape) shape->available = true;
    return true;
}

bool parse_mip_urc(std::string_view line, uint32_t& received, uint32_t& total,
                   uint8_t& state, bool& disconnected)
{
    received = 0;
    total = 0;
    state = 0;
    disconnected = false;
    if (!starts_with(line, "+MIPURC:")) return false;
    std::array<std::string_view, 8> fields;
    std::array<bool, 8> quoted{};
    size_t count = 0;
    if (!parse_csv(line.substr(std::string_view("+MIPURC:").size()), fields, quoted, count)) {
        return false;
    }
    if (count == 4 && quoted[0] && fields[0] == "rtcp" && !quoted[1] &&
        !quoted[2] && !quoted[3]) {
        if (fields[1] != "0" || !parse_uint(fields[2], received) ||
            !parse_uint(fields[3], total) ||
            received > kHttpBodyMax || total > kHttpBodyMax || received > total) {
            return false;
        }
        return true;
    }
    if (count == 3 && quoted[0] && fields[0] == "disconn" && !quoted[1] &&
        !quoted[2] && fields[1] == "0") {
        uint32_t parsed_state = 0;
        if (!parse_uint(fields[2], parsed_state) || parsed_state < 1 || parsed_state > 3) {
            return false;
        }
        state = static_cast<uint8_t>(parsed_state);
        disconnected = true;
        return true;
    }
    return false;
}

namespace {

bool consume_nonfatal_mip_urc(std::string_view line)
{
    uint32_t received = 0;
    uint32_t total = 0;
    uint8_t state = 0;
    bool disconnected = false;
    return parse_mip_urc(line, received, total, state, disconnected) && !disconnected;
}

bool parse_mip_open_line(std::string_view line, uint8_t expected_cid, ParseReason* reason,
                         ParseShape* shape)
{
    if (!starts_with(line, "+MIPOPEN:")) {
        set_parse_reason(reason, ParseReason::prefix);
        return false;
    }
    std::array<std::string_view, 8> fields;
    std::array<bool, 8> quoted{};
    size_t count = 0;
    CsvFailure csv_failure = CsvFailure::none;
    if (!parse_csv(line.substr(std::string_view("+MIPOPEN:").size()), fields, quoted, count,
                   &csv_failure)) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, csv_failure == CsvFailure::quote
                                  ? ParseReason::quote
                                  : ParseReason::field_count);
        return false;
    }
    if (count != 2) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::field_count);
        return false;
    }
    if (quoted[0] || quoted[1]) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::quote);
        return false;
    }
    uint32_t cid = 0;
    uint32_t result = 0;
    if (!parse_uint(fields[0], cid) || cid != expected_cid) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::cid);
        return false;
    }
    if (!parse_uint(fields[1], result)) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::result);
        return false;
    }
    // A numeric nonzero MIPOPEN result is a modem outcome, not a malformed
    // frame.  Keep the parser rejection for its existing caller while
    // leaving parse telemetry unset for this semantic failure.
    if (result != 0) {
        clear_parse_shape(shape);
        return false;
    }
    return true;
}

constexpr size_t kMipAddressMax = 255;

bool mip_address_safe(std::string_view address)
{
    return !address.empty() && address.size() <= kMipAddressMax &&
           std::all_of(address.begin(), address.end(), [](unsigned char ch) {
               return ch >= 0x21 && ch <= 0x7e && ch != '"' && ch != '\\' && ch != '@';
           });
}

bool parse_mip_tcp_endpoint(const std::array<std::string_view, 8>& fields,
                            const std::array<bool, 8>& quoted, ParseReason* reason)
{
    uint32_t port = 0;
    if (!quoted[1] || fields[1] != "TCP" || !quoted[2] || !mip_address_safe(fields[2]) ||
        quoted[3] || !parse_uint(fields[3], port) || port == 0 || port > UINT16_MAX) {
        set_parse_reason(reason, ParseReason::endpoint);
        return false;
    }
    return true;
}

MipStateDisposition parse_mip_state_disposition(std::string_view response,
                                                std::string_view command,
                                                uint8_t& cid, ParseReason* reason,
                                                ParseShape* shape)
{
    clear_parse_reason(reason);
    clear_parse_shape(shape);
    std::vector<std::string_view> body;
    if (!scan_frame(response, command, body, reason, shape)) {
        return MipStateDisposition::invalid;
    }
    std::string_view state_line;
    bool open_seen = false;
    for (std::string_view line : body) {
        if (starts_with(line, "+MIPURC:")) {
            if (!consume_nonfatal_mip_urc(line)) {
                set_line_class(shape, IdfModemHttpsParseLineClass::unexpected);
                set_parse_reason(reason, ParseReason::urc);
                return MipStateDisposition::invalid;
            }
        } else if (starts_with(line, "+MIPOPEN")) {
            if (open_seen) {
                set_line_class(shape, IdfModemHttpsParseLineClass::duplicate);
                set_parse_reason(reason, ParseReason::result);
                return MipStateDisposition::invalid;
            }
            if (!parse_mip_open_line(line, 0, reason, shape)) {
                return MipStateDisposition::invalid;
            }
            open_seen = true;
        } else if (state_line.empty()) {
            state_line = line;
        } else {
            set_line_class(shape, starts_with(line, "+MIPSTATE")
                                      ? IdfModemHttpsParseLineClass::duplicate
                                      : IdfModemHttpsParseLineClass::extra);
            set_parse_reason(reason, ParseReason::prefix);
            return MipStateDisposition::invalid;
        }
    }
    if (state_line.empty()) {
        set_line_class(shape, IdfModemHttpsParseLineClass::missing);
        set_parse_reason(reason, ParseReason::prefix);
        return MipStateDisposition::invalid;
    }
    if (!starts_with(state_line, "+MIPSTATE:")) {
        set_line_class(shape, IdfModemHttpsParseLineClass::unexpected);
        set_parse_reason(reason, ParseReason::prefix);
        return MipStateDisposition::invalid;
    }
    std::array<std::string_view, 8> fields;
    std::array<bool, 8> quoted{};
    size_t count = 0;
    CsvFailure csv_failure = CsvFailure::none;
    if (!parse_csv(state_line.substr(std::string_view("+MIPSTATE:").size()), fields, quoted,
                   count, &csv_failure)) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, csv_failure == CsvFailure::quote
                                  ? ParseReason::quote
                                  : ParseReason::field_count);
        return MipStateDisposition::invalid;
    }
    if (count != 5) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::field_count);
        return MipStateDisposition::invalid;
    }
    if (quoted[0] || !quoted[4]) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::quote);
        return MipStateDisposition::invalid;
    }
    uint32_t connect_id = 0;
    if (!parse_uint(fields[0], connect_id) || connect_id > UINT8_MAX) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::cid);
        return MipStateDisposition::invalid;
    }
    if (fields[4] == "INITIAL") {
        if (shape) shape->stateClass = IdfModemHttpsParseStateClass::initial;
        if (quoted[1] || quoted[2] || quoted[3] || !fields[1].empty() ||
            !fields[2].empty() || !fields[3].empty()) {
            capture_csv_shape(shape, count, fields, quoted);
            set_parse_reason(reason, ParseReason::endpoint);
            return MipStateDisposition::invalid;
        }
        cid = static_cast<uint8_t>(connect_id);
        return MipStateDisposition::initial;
    }
    if (fields[4] == "CLOSED") {
        if (shape) shape->stateClass = IdfModemHttpsParseStateClass::closed;
        const bool empty_endpoint = !quoted[1] && !quoted[2] && !quoted[3] &&
                                    fields[1].empty() && fields[2].empty() && fields[3].empty();
        if (!empty_endpoint && !parse_mip_tcp_endpoint(fields, quoted, reason)) {
            capture_csv_shape(shape, count, fields, quoted);
            return MipStateDisposition::invalid;
        }
        cid = static_cast<uint8_t>(connect_id);
        return MipStateDisposition::closed;
    }
    if (fields[4] == "CONNECTED") {
        if (shape) shape->stateClass = IdfModemHttpsParseStateClass::connected;
        if (!parse_mip_tcp_endpoint(fields, quoted, reason)) {
            capture_csv_shape(shape, count, fields, quoted);
            return MipStateDisposition::invalid;
        }
        cid = static_cast<uint8_t>(connect_id);
        return MipStateDisposition::connected;
    }
    if (fields[4] == "CONNECTING") {
        if (shape) shape->stateClass = IdfModemHttpsParseStateClass::connecting;
        if (!parse_mip_tcp_endpoint(fields, quoted, reason)) {
            capture_csv_shape(shape, count, fields, quoted);
            return MipStateDisposition::invalid;
        }
        cid = static_cast<uint8_t>(connect_id);
        if (shape) shape->stateClass = IdfModemHttpsParseStateClass::none;
        return MipStateDisposition::connecting;
    }
    if (shape) {
        shape->stateClass = IdfModemHttpsParseStateClass::unknown;
    }
    capture_csv_shape(shape, count, fields, quoted);
    set_parse_reason(reason, ParseReason::state);
    return MipStateDisposition::invalid;
}

}  // namespace

bool parse_cfg_response(std::string_view response, std::string_view command,
                        std::string_view parameter, uint8_t& first, uint8_t& second,
                        bool& has_second)
{
    std::vector<std::string_view> body;
    if (!scan_frame(response, command, body)) return false;
    std::string_view config_line;
    for (std::string_view line : body) {
        if (starts_with(line, "+MIPURC:")) {
            if (!consume_nonfatal_mip_urc(line)) return false;
        } else if (config_line.empty()) {
            config_line = line;
        } else {
            return false;
        }
    }
    if (config_line.empty() || !starts_with(config_line, "+MIPCFG:")) return false;
    std::array<std::string_view, 8> fields;
    std::array<bool, 8> quoted{};
    size_t count = 0;
    if (!parse_csv(config_line.substr(std::string_view("+MIPCFG:").size()), fields, quoted, count) ||
        count < 3 || !quoted[0] || fields[0] != parameter) return false;
    uint32_t connect_id = 0;
    if (!parse_uint(fields[1], connect_id) || connect_id != 0) return false;
    uint32_t value = 0;
    if (!parse_uint(fields[2], value) || value > UINT8_MAX) return false;
    first = static_cast<uint8_t>(value);
    has_second = false;
    second = 0;
    if (count == 4) {
        if (!parse_uint(fields[3], value) || value > UINT8_MAX) return false;
        second = static_cast<uint8_t>(value);
        has_second = true;
    } else if (count != 3) {
        return false;
    }
    return true;
}

bool parse_mip_state(std::string_view response, std::string_view command,
                     std::string_view expected, uint8_t& cid, ParseReason* reason,
                     ParseShape* shape)
{
    uint8_t parsed_cid = 0;
    const MipStateDisposition disposition =
        parse_mip_state_disposition(response, command, parsed_cid, reason, shape);
    const bool matches =
        (expected == "INITIAL" && disposition == MipStateDisposition::initial) ||
        (expected == "CONNECTED" && disposition == MipStateDisposition::connected);
    if (!matches && disposition != MipStateDisposition::invalid &&
        disposition != MipStateDisposition::connecting) {
        set_parse_reason(reason, ParseReason::state);
    }
    if (matches) cid = parsed_cid;
    return matches;
}

MipStateDisposition classify_mip_state(std::string_view response,
                                       std::string_view command,
                                       uint8_t expected_cid, ParseReason* reason,
                                       ParseShape* shape)
{
    uint8_t cid = 0;
    const MipStateDisposition disposition =
        parse_mip_state_disposition(response, command, cid, reason, shape);
    if (disposition != MipStateDisposition::invalid && cid != expected_cid) {
        set_parse_reason(reason, ParseReason::cid);
        return MipStateDisposition::invalid;
    }
    return disposition;
}

bool parse_mip_open(std::string_view response, std::string_view command,
                    uint8_t expected_cid, bool& present)
{
    std::vector<std::string_view> body;
    if (!scan_frame(response, command, body)) return false;
    present = false;
    for (std::string_view line : body) {
        if (starts_with(line, "+MIPURC:")) {
            if (!consume_nonfatal_mip_urc(line)) return false;
            continue;
        }
        if (!starts_with(line, "+MIPOPEN:") || present) return false;
        if (!parse_mip_open_line(line, expected_cid, nullptr, nullptr)) return false;
        present = true;
    }
    return true;
}

void MipOpenLatch::begin()
{
    reset();
    active_ = true;
}

bool MipOpenLatch::consume_line(std::string_view line)
{
    line = trim_spaces(line);
    if (line.empty()) return true;
    if (starts_with(line, "+MIPOPEN")) {
        if (success_seen_ || !parse_mip_open_line(line, 0, nullptr, nullptr)) return false;
        success_seen_ = true;
        return true;
    }
    if (starts_with(line, "+MIPURC")) return consume_nonfatal_mip_urc(line);
    return true;
}

bool MipOpenLatch::feed(std::string_view bytes)
{
    if (!active_) return true;
    if (failed_) return false;
    for (const char ch : bytes) {
        if (ch == '\r' || ch == '\n') {
            if (!carry_.empty() && !consume_line(carry_)) {
                failed_ = true;
                return false;
            }
            carry_.clear();
        } else {
            if (carry_.size() == kLineMax) {
                failed_ = true;
                return false;
            }
            carry_.push_back(ch);
        }
    }
    return true;
}

bool MipOpenLatch::finish()
{
    if (!active_ || connected_ || failed_) return false;
    const std::string_view remaining = trim_spaces(carry_);
    if (!remaining.empty()) {
        static constexpr std::string_view targets[] = {"+MIPOPEN", "+MIPURC"};
        for (const std::string_view target : targets) {
            if (starts_with(remaining, target) || starts_with(target, remaining)) {
                failed_ = true;
                return false;
            }
        }
    }
    carry_.clear();
    connected_ = true;
    return true;
}

void MipOpenLatch::reset()
{
    carry_.clear();
    active_ = false;
    connected_ = false;
    failed_ = false;
    success_seen_ = false;
}

bool parse_cgdccont(std::string_view response, std::string_view command, uint8_t cid,
                    std::string* apn, std::string* profile)
{
    std::vector<std::string_view> body;
    if (cid == 0 || cid > 16 || !scan_frame(response, command, body) || body.empty()) return false;
    bool found = false;
    std::array<bool, 17> seen{};
    for (std::string_view line : body) {
        if (starts_with(line, "+MIPURC:")) {
            if (!consume_nonfatal_mip_urc(line)) return false;
            continue;
        }
        if (!starts_with(line, "+CGDCONT:")) return false;
        std::array<std::string_view, 16> fields;
        std::array<bool, 16> quoted{};
        size_t count = 0;
        if (!parse_csv(line.substr(std::string_view("+CGDCONT:").size()), fields, quoted, count) ||
            count < 3 || count > fields.size() || !quoted[1] || !quoted[2]) return false;
        uint32_t context = 0;
        if (!parse_uint(fields[0], context) || context == 0 || context > 16 ||
            seen[context]) return false;
        seen[context] = true;
        uint32_t value = 0;
        for (size_t index = 0; index < count; ++index) {
            if (!cgdcont_field_safe(fields[index], quoted[index])) return false;
            if (!quoted[index] && !fields[index].empty() && !parse_uint(fields[index], value)) {
                return false;
            }
        }
        if (context == cid) {
            found = true;
            if (apn) {
                apn->assign(fields[2].data(), fields[2].size());
            }
            if (profile) {
                profile->clear();
                for (size_t index = 0; index < count; ++index) {
                    if (index != 0) profile->push_back(',');
                    if (quoted[index]) profile->push_back('"');
                    profile->append(fields[index].data(), fields[index].size());
                    if (quoted[index]) profile->push_back('"');
                }
            }
        }
    }
    return found;
}

bool build_cgdccont_command(uint8_t cid, std::string_view apn, std::string& command)
{
    if (cid == 0 || cid > 16 || apn.empty() || apn.size() > 96 ||
        !cgdcont_field_safe(apn, true)) {
        command.clear();
        return false;
    }
    command = "AT+CGDCONT=" + std::to_string(cid) + ",\"IPV4V6\",\"" +
              std::string(apn) + "\"";
    return true;
}

bool parse_cgact(std::string_view response, std::string_view command, uint8_t cid,
                bool& active)
{
    std::vector<std::string_view> body;
    if (cid == 0 || cid > 16 || !scan_frame(response, command, body) || body.empty()) return false;
    active = false;
    bool found = false;
    std::array<bool, 256> seen{};
    for (std::string_view line : body) {
        if (starts_with(line, "+MIPURC:")) {
            if (!consume_nonfatal_mip_urc(line)) return false;
            continue;
        }
        if (!starts_with(line, "+CGACT:")) return false;
        std::array<std::string_view, 8> fields;
        std::array<bool, 8> quoted{};
        size_t count = 0;
        if (!parse_csv(line.substr(std::string_view("+CGACT:").size()), fields, quoted, count) ||
            count != 2 || quoted[0] || quoted[1]) return false;
        uint32_t context = 0;
        uint32_t state = 0;
        if (!parse_uint(fields[0], context) || !parse_uint(fields[1], state) ||
            context == 0 || context > 16 || state > 1) return false;
        if (seen[context]) return false;
        seen[context] = true;
        if (context == cid) {
            if (found) return false;
            found = true;
            active = state == 1;
        }
    }
    return found;
}

namespace {

bool has_single_mip_close_zero(std::string_view response)
{
    bool candidate_seen = false;
    bool terminal_seen = false;
    size_t position = 0;
    while (position < response.size()) {
        const size_t end = response.find_first_of("\r\n", position);
        const size_t line_end = end == std::string_view::npos ? response.size() : end;
        const std::string_view line = response.substr(position, line_end - position);
        const std::string_view normalized = trim_spaces(line);
        if (normalized == "OK") {
            if (terminal_seen) return false;
            terminal_seen = true;
        } else if (starts_with(normalized, "+MIPCLOSE:") &&
                   trim_spaces(normalized.substr(std::string_view("+MIPCLOSE:").size())) == "0") {
            if (candidate_seen) return false;
            candidate_seen = true;
        }
        if (end == std::string_view::npos) break;
        position = end + 1;
        while (position < response.size() &&
               (response[position] == '\r' || response[position] == '\n')) {
            ++position;
        }
    }
    return candidate_seen;
}

bool parse_result_impl(std::string_view response, std::string_view command,
                       std::string_view prefix, uint8_t expected_cid,
                       bool allow_single_close, uint32_t& value,
                       ParseReason* reason, ParseShape* shape)
{
    clear_parse_reason(reason);
    clear_parse_shape(shape);
    std::vector<std::string_view> body;
    if (!scan_frame(response, command, body, reason, shape)) return false;
    std::string_view result_line;
    for (std::string_view line : body) {
        if (starts_with(line, "+MIPURC:")) {
            if (!consume_nonfatal_mip_urc(line)) {
                set_line_class(shape, IdfModemHttpsParseLineClass::unexpected);
                set_parse_reason(reason, ParseReason::urc);
                return false;
            }
        } else if (starts_with(line, prefix) && result_line.empty()) {
            result_line = line;
        } else if (starts_with(line, prefix)) {
            set_line_class(shape, IdfModemHttpsParseLineClass::duplicate);
            set_parse_reason(reason, ParseReason::prefix);
            return false;
        } else {
            set_line_class(shape, result_line.empty() ? IdfModemHttpsParseLineClass::unexpected
                                                      : IdfModemHttpsParseLineClass::extra);
            set_parse_reason(reason, ParseReason::prefix);
            return false;
        }
    }
    if (result_line.empty()) {
        set_line_class(shape, IdfModemHttpsParseLineClass::missing);
        set_parse_reason(reason, ParseReason::prefix);
        return false;
    }
    std::array<std::string_view, 8> fields;
    std::array<bool, 8> quoted{};
    size_t count = 0;
    CsvFailure csv_failure = CsvFailure::none;
    if (!parse_csv(result_line.substr(prefix.size()), fields, quoted, count, &csv_failure)) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, csv_failure == CsvFailure::quote
                                  ? ParseReason::quote
                                  : ParseReason::field_count);
        return false;
    }
    if (count == 1) {
        if (allow_single_close && expected_cid == 0) {
            value = 0;
            return true;
        }
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::field_count);
        return false;
    }
    if (count != 2) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::field_count);
        return false;
    }
    uint32_t cid = 0;
    if (!parse_uint(fields[0], cid) || cid != expected_cid) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::cid);
        return false;
    }
    if (!parse_uint(fields[1], value)) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::result);
        return false;
    }
    return true;
}

}  // namespace

bool parse_result(std::string_view response, std::string_view command,
                  std::string_view prefix, uint8_t expected_cid, uint32_t& value,
                  ParseReason* reason, ParseShape* shape)
{
    return parse_result_impl(response, command, prefix, expected_cid, false, value, reason,
                             shape);
}

bool parse_mip_close_result(std::string_view response, std::string_view command,
                            uint8_t expected_cid, uint32_t& value,
                            ParseReason* reason, ParseShape* shape,
                            bool* requires_confirmation)
{
    if (requires_confirmation) *requires_confirmation = false;
    const bool allow_single_close = expected_cid == 0 && has_single_mip_close_zero(response);
    if (!parse_result_impl(response, command, "+MIPCLOSE:", expected_cid, allow_single_close,
                           value, reason, shape)) {
        return false;
    }
    if (requires_confirmation) *requires_confirmation = allow_single_close;
    return true;
}

bool parse_read(std::string_view response, std::string_view command, uint8_t cid,
                uint32_t& unread, std::vector<uint8_t>& data, bool& remote_closed,
                ParseReason* reason, ParseShape* shape, bool* no_data)
{
    clear_parse_reason(reason);
    clear_parse_shape(shape);
    if (no_data) *no_data = false;
    unread = 0;
    data.clear();
    remote_closed = false;
    std::vector<std::string_view> body;
    uint8_t command_echo_count = 0;
    bool ignored_auxiliary_seen = false;
    if (!scan_frame(response, command, body, reason, shape, &command_echo_count,
                    &ignored_auxiliary_seen)) {
        return false;
    }
    std::string_view read_line;
    bool saw_remote_closed = false;
    bool rtcp_lengths_seen = false;
    for (std::string_view line : body) {
        if (starts_with(line, "+MIPURC:")) {
            uint32_t received = 0;
            uint32_t total = 0;
            uint8_t state = 0;
            bool disconnected = false;
            if (!parse_mip_urc(line, received, total, state, disconnected) ||
                (disconnected && saw_remote_closed)) {
                set_line_class(shape, disconnected && saw_remote_closed
                                         ? IdfModemHttpsParseLineClass::duplicate
                                         : IdfModemHttpsParseLineClass::unexpected);
                set_parse_reason(reason, ParseReason::urc);
                return false;
            }
            if (!disconnected && shape && !rtcp_lengths_seen) {
                shape->rtcpRecvLength = received;
                shape->rtcpTotalLength = total;
                rtcp_lengths_seen = true;
            }
            saw_remote_closed = saw_remote_closed || disconnected;
        } else if (starts_with(line, "+MIPRD:") && read_line.empty()) {
            read_line = line;
        } else if (starts_with(line, "+MIPRD:")) {
            set_line_class(shape, IdfModemHttpsParseLineClass::duplicate);
            set_parse_reason(reason, ParseReason::prefix);
            return false;
        } else {
            set_line_class(shape, read_line.empty() ? IdfModemHttpsParseLineClass::unexpected
                                                     : IdfModemHttpsParseLineClass::extra);
            set_parse_reason(reason, ParseReason::prefix);
            return false;
        }
    }
    if (read_line.empty()) {
        if (saw_remote_closed) {
            remote_closed = true;
            return true;
        }
        if (body.empty() && command_echo_count <= 1 && !ignored_auxiliary_seen) {
            if (no_data) *no_data = true;
            return true;
        }
        set_line_class(shape, IdfModemHttpsParseLineClass::missing);
        set_parse_reason(reason, ParseReason::prefix);
        return false;
    }
    std::array<std::string_view, 8> fields;
    std::array<bool, 8> quoted{};
    size_t count = 0;
    CsvFailure csv_failure = CsvFailure::none;
    if (!parse_csv(read_line.substr(std::string_view("+MIPRD:").size()), fields, quoted, count,
                   &csv_failure)) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, csv_failure == CsvFailure::quote
                                  ? ParseReason::quote
                                  : ParseReason::field_count);
        return false;
    }
    if (count != 4) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::field_count);
        return false;
    }
    if (quoted[3]) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::quote);
        return false;
    }
    uint32_t parsed_cid = 0;
    uint32_t parsed_unread = 0;
    uint32_t length = 0;
    if (!parse_uint(fields[0], parsed_cid) || parsed_cid != cid) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::cid);
        return false;
    }
    if (!parse_uint(fields[1], parsed_unread) || parsed_unread > UINT16_MAX ||
        !parse_uint(fields[2], length) || length > kReadMax ||
        fields[3].size() != static_cast<size_t>(length) * 2U ||
        (saw_remote_closed && parsed_unread != 0)) {
        capture_csv_shape(shape, count, fields, quoted);
        set_parse_reason(reason, ParseReason::read_data);
        return false;
    }
    std::vector<uint8_t> decoded;
    decoded.reserve(length);
    for (size_t i = 0; i < fields[3].size(); i += 2) {
        const auto digit = [](unsigned char ch) -> int {
            if (ch >= '0' && ch <= '9') return ch - '0';
            if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
            return -1;
        };
        const int high = digit(static_cast<unsigned char>(fields[3][i]));
        const int low = digit(static_cast<unsigned char>(fields[3][i + 1]));
        if (high < 0 || low < 0) {
            capture_csv_shape(shape, count, fields, quoted);
            set_parse_reason(reason, ParseReason::read_data);
            return false;
        }
        decoded.push_back(static_cast<uint8_t>((high << 4) | low));
    }
    unread = parsed_unread;
    remote_closed = saw_remote_closed;
    data = std::move(decoded);
    return true;
}

std::string hex_encode(const uint8_t* bytes, size_t length)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string output;
    output.reserve(length * 2U);
    for (size_t i = 0; i < length; ++i) {
        output += hex[bytes[i] >> 4];
        output += hex[bytes[i] & 0x0f];
    }
    return output;
}

bool HttpResponse::feed(const uint8_t* bytes, size_t length, IdfModemHttpsPostResult& result)
{
    if (!bytes && length != 0) return false;
    if (complete_ && length != 0) return false;
    size_t position = 0;
    while (position < length) {
        if (!header_complete_) {
            header_.push_back(static_cast<char>(bytes[position++]));
            ++response_bytes_;
            if (header_.size() > kHttpHeaderMax) return false;
            const size_t marker = header_.find("\r\n\r\n");
            if (marker == std::string::npos) continue;
            if (!parse_header(marker + 4, result)) return false;
            header_complete_ = true;
            if (has_content_length_ && result.expectedResponseBytes == 0) complete_ = true;
            continue;
        }
        if (has_content_length_ && body_bytes_ >= result.expectedResponseBytes) return false;
        ++position;
        ++body_bytes_;
        result.bodyBytes = static_cast<uint32_t>(body_bytes_);
        ++response_bytes_;
        if (body_bytes_ > kHttpBodyMax) return false;
        if (has_content_length_ && body_bytes_ == result.expectedResponseBytes) complete_ = true;
    }
    if (response_bytes_ > kHttpHeaderMax + kHttpBodyMax) return false;
    result.responseBytes = static_cast<uint32_t>(response_bytes_);
    return true;
}

bool HttpResponse::finish_eof(IdfModemHttpsPostResult& result)
{
    if (complete_) return true;
    if (!header_complete_ || (has_content_length_ &&
                              body_bytes_ != result.expectedResponseBytes)) {
        return false;
    }
    complete_ = true;
    result.responseBytes = static_cast<uint32_t>(response_bytes_);
    return true;
}

bool HttpResponse::parse_header(size_t body_start, IdfModemHttpsPostResult& result)
{
    const size_t first_end = header_.find("\r\n");
    if (first_end == std::string::npos || first_end == 0 || body_start < 4) return false;
    header_bytes_ = body_start;
    const std::string_view status(header_.data(), first_end);
    if (!(starts_with(status, "HTTP/1.0 ") || starts_with(status, "HTTP/1.1 ")) ||
        status.size() < 12) return false;
    uint32_t code = 0;
    if (!parse_uint(status.substr(9, 3), code) || code > INT_MAX ||
        (status.size() > 12 && status[12] != ' ')) return false;
    result.httpStatus = static_cast<int>(code);
    result.expectedResponseBytes = 0;
    has_content_length_ = false;
    const size_t header_end = body_start - 4;
    size_t position = first_end + 2;
    while (position < header_end) {
        const size_t end = header_.find("\r\n", position);
        if (end == std::string::npos || end > header_end) return false;
        const std::string_view line = std::string_view(header_).substr(position, end - position);
        const size_t colon = line.find(':');
        if (colon == std::string_view::npos || colon == 0 || !header_value_bytes_valid(line)) {
            return false;
        }
        const std::string_view name = line.substr(0, colon);
        if (!header_name_token(name)) return false;
        auto name_equals = [name](std::string_view expected) {
            return name.size() == expected.size() && std::equal(
                name.begin(), name.end(), expected.begin(), [](unsigned char left, unsigned char right) {
                    return std::tolower(left) == std::tolower(right);
                });
        };
        const bool transfer_encoding = name_equals("Transfer-Encoding");
        if (transfer_encoding) return false;
        if (name_equals("Content-Length")) {
            if (has_content_length_) return false;
            uint32_t content_length = 0;
            if (!parse_uint(line.substr(colon + 1), content_length) ||
                content_length > kHttpBodyMax) return false;
            result.expectedResponseBytes = content_length;
            has_content_length_ = true;
        }
        position = end + 2;
    }
    return body_start == header_.size();
}

}  // namespace idf_modem_https_wire
