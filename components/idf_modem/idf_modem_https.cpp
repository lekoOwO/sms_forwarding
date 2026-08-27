#include "idf_modem_https.h"

#include <algorithm>
#include <cctype>
#include <climits>
#include <utility>

#include "idf_modem_query_filter.h"

namespace {

constexpr std::string_view kHttpsPrefix = "https://";
constexpr size_t kMaxLine = 768;

const char* pre_create_failure_message(size_t index)
{
    constexpr const char* messages[] = {
        "HTTPS TLS certificate binding failed",
        "HTTPS TLS auth failed",
        "HTTPS TLS encoding failed",
        "HTTPS TLS negotiation timeout failed",
        "HTTPS TLS version failed",
        "HTTPS TLS timestamp check failed",
        "HTTPS TLS certificate verification failed",
        "HTTPS connection creation failed",
    };
    return index < std::size(messages) ? messages[index] : "HTTPS TLS setup failed";
}

const char* post_create_failure_message(size_t index)
{
    constexpr const char* messages[] = {
        "HTTPS SSL binding failed",
        "HTTPS HTTP timeout configuration failed",
    };
    return index < std::size(messages) ? messages[index] : "HTTPS POST request setup failed";
}

std::string trim_spaces(std::string_view value)
{
    size_t start = 0;
    while (start < value.size() && value[start] == ' ') ++start;
    size_t end = value.size();
    while (end > start && value[end - 1] == ' ') --end;
    return std::string(value.substr(start, end - start));
}

bool contains_control_or_space(std::string_view value)
{
    return std::any_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch < 0x20 || ch > 0x7e || ch == ' ';
    });
}

bool has_forbidden_header_byte(std::string_view value)
{
    return std::any_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\r' || ch == '\n';
    });
}

bool is_header_name_token(std::string_view value)
{
    if (value.empty()) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) != 0 ||
               std::string_view("!#$%&'*+-.^_`|~").find(static_cast<char>(ch)) !=
                   std::string_view::npos;
    });
}

bool parse_uint(std::string_view value, uint32_t& output)
{
    if (value.empty()) return false;
    uint64_t parsed = 0;
    for (unsigned char ch : value) {
        if (ch < '0' || ch > '9') return false;
        parsed = parsed * 10U + static_cast<uint32_t>(ch - '0');
        if (parsed > UINT32_MAX) return false;
    }
    output = static_cast<uint32_t>(parsed);
    return true;
}

bool parse_uint_fields(std::string_view value, uint32_t* fields, size_t minimum,
                       size_t maximum, size_t& count)
{
    count = 0;
    size_t start = 0;
    while (start <= value.size()) {
        if (count == maximum) {
            // Do not silently accept a new field after the bounded array is full.
            return value.find(',', start) == std::string_view::npos && count >= minimum;
        }
        const size_t comma = value.find(',', start);
        const size_t end = comma == std::string_view::npos ? value.size() : comma;
        if (!parse_uint(value.substr(start, end - start), fields[count])) return false;
        ++count;
        if (comma == std::string_view::npos) break;
        start = comma + 1;
    }
    return count >= minimum;
}

bool starts_with(std::string_view value, std::string_view prefix)
{
    return value.size() >= prefix.size() && value.compare(0, prefix.size(), prefix) == 0;
}

bool looks_like_pdu(std::string_view line)
{
    if (line.size() < 4 || (line.size() & 1U) != 0) return false;
    return std::all_of(line.begin(), line.end(), [](unsigned char ch) {
        return std::isxdigit(ch) != 0;
    });
}

void append_urc_line(std::string& output, std::string_view line)
{
    output.append(line.data(), line.size());
    output += "\r\n";
}

}  // namespace

bool idf_modem_https_parse_url(std::string_view raw_url, IdfModemHttpsTarget& target,
                               std::string& error)
{
    target = {};
    error.clear();
    std::string url = trim_spaces(raw_url);
    if (url.empty() || url.size() > IDF_MODEM_HTTPS_POST_MAX_URL) {
        error = "HTTPS URL is empty or too long";
        return false;
    }
    if (!starts_with(url, kHttpsPrefix)) {
        error = "HTTPS URL must use https://";
        return false;
    }

    const size_t host_start = kHttpsPrefix.size();
    const size_t path_start = url.find_first_of("/?#", host_start);
    const size_t host_end = path_start == std::string::npos ? url.size() : path_start;
    std::string host = url.substr(host_start, host_end - host_start);
    if (host.empty() || host.find('@') != std::string::npos || host.find('"') != std::string::npos ||
        host.find('\\') != std::string::npos || contains_control_or_space(host)) {
        error = "HTTPS URL host is invalid";
        return false;
    }
    if (path_start != std::string::npos && url[path_start] == '#') {
        error = "HTTPS URL fragment is not allowed";
        return false;
    }
    std::string path = path_start == std::string::npos ? "/" : url.substr(path_start);
    if (!path.empty() && path[0] == '#') {
        error = "HTTPS URL fragment is not allowed";
        return false;
    }
    if (const size_t fragment = path.find('#'); fragment != std::string::npos) {
        error = "HTTPS URL fragment is not allowed";
        return false;
    }
    if (path.empty() || contains_control_or_space(path) || path.find('"') != std::string::npos ||
        path.find('\\') != std::string::npos) {
        error = "HTTPS URL path is invalid";
        return false;
    }
    target.host = std::move(host);
    target.path = std::move(path);
    return true;
}

bool idf_modem_https_validate_request(const IdfModemHttpsPostRequest& request,
                                      std::string& error)
{
    IdfModemHttpsTarget target;
    if (request.url.size() > IDF_MODEM_HTTPS_POST_MAX_URL ||
        !idf_modem_https_parse_url(request.url, target, error)) {
        return false;
    }
    if (request.body.empty() || request.body.size() > IDF_MODEM_HTTPS_POST_MAX_BODY) {
        error = request.body.empty() ? "HTTPS POST body is empty" : "HTTPS POST body is too large";
        return false;
    }
    if (request.contentType.empty() || request.contentType.size() > IDF_MODEM_HTTPS_POST_MAX_CONTENT_TYPE ||
        has_forbidden_header_byte(request.contentType)) {
        error = "HTTPS Content-Type is invalid";
        return false;
    }
    if (request.headerName.size() > IDF_MODEM_HTTPS_POST_MAX_HEADER_NAME ||
        request.headerValue.size() > IDF_MODEM_HTTPS_POST_MAX_HEADER_VALUE ||
        (!request.headerName.empty() && request.headerValue.empty()) ||
        (request.headerName.empty() && !request.headerValue.empty()) ||
        (!request.headerName.empty() && !is_header_name_token(request.headerName)) ||
        has_forbidden_header_byte(request.headerValue)) {
        error = "HTTPS header is invalid";
        return false;
    }
    if (request.timeoutMs == 0 || request.timeoutMs > IDF_MODEM_HTTPS_POST_MAX_TIMEOUT_MS) {
        error = "HTTPS timeout is invalid";
        return false;
    }
    if (request.apn.size() > 96 || has_forbidden_header_byte(request.apn)) {
        error = "APN is invalid";
        return false;
    }
    return true;
}

bool idf_modem_https_model_allowed(std::string_view model)
{
    return model == "ML307A";
}

bool idf_modem_https_status_success(int httpStatus)
{
    return httpStatus >= 200 && httpStatus < 300;
}

int idf_modem_https_parse_create_id(std::string_view response)
{
    constexpr std::string_view prefix = "+MHTTPCREATE:";
    const size_t found = response.find(prefix);
    if (found == std::string_view::npos) return -1;
    size_t start = found + prefix.size();
    while (start < response.size() && response[start] == ' ') ++start;
    const size_t end = response.find_first_of("\r\n,", start);
    uint32_t id = 0;
    if (!parse_uint(response.substr(start, end == std::string_view::npos ? response.size() - start : end - start), id) ||
        id > 255) {
        return -1;
    }
    return static_cast<int>(id);
}

std::string idf_modem_https_create_command(std::string_view host)
{
    return std::string("AT+MHTTPCREATE=\"https://") + std::string(host) + "\"";
}

std::string idf_modem_https_cert_query_command()
{
    return "AT+MSSLCFG=\"cert\",1";
}

std::string idf_modem_https_cert_bind_command(std::string_view name)
{
    if (name.empty() ||
        !std::all_of(name.begin(), name.end(), [](unsigned char ch) {
            return std::isalnum(ch) != 0 || ch == '_' || ch == '-' || ch == '.';
        })) {
        return {};
    }
    return std::string("AT+MSSLCFG=\"cert\",1,\"") + std::string(name) + "\"";
}

bool idf_modem_https_parse_cert_binding(std::string_view response, std::string& name)
{
    name.clear();
    constexpr std::string_view prefix = "+MSSLCFG:";
    constexpr std::string_view field = "\"cert\",1,\"";
    size_t line_start = response.find(prefix);
    while (line_start != std::string_view::npos) {
        const size_t line_end = response.find_first_of("\r\n", line_start);
        const std::string_view line = response.substr(
            line_start, line_end == std::string_view::npos ? response.size() - line_start
                                                             : line_end - line_start);
        const size_t value_start = line.find(field);
        if (value_start != std::string_view::npos) {
            const size_t name_start = value_start + field.size();
            const size_t name_end = line.find('"', name_start);
            if (name_end == std::string_view::npos || name_end == name_start ||
                name_end - name_start > 128) {
                return false;
            }
            const std::string_view candidate = line.substr(name_start, name_end - name_start);
            if (idf_modem_https_cert_bind_command(candidate).empty()) return false;
            name.assign(candidate.data(), candidate.size());
            return true;
        }
        if (line_end == std::string_view::npos) break;
        line_start = response.find(prefix, line_end + 1);
    }
    return false;
}

bool idf_modem_https_build_post_wire(const IdfModemHttpsPostRequest& request,
                                     const IdfModemHttpsTarget& target,
                                     std::string_view certName, uint8_t httpId,
                                     IdfModemHttpsPostWire& wire, std::string& error)
{
    wire = {};
    if (!idf_modem_https_validate_request(request, error)) return false;
    if (target.host.empty() || target.path.empty()) {
        error = "HTTPS target is empty";
        return false;
    }
    const std::string cert_bind = idf_modem_https_cert_bind_command(certName);
    if (cert_bind.empty()) {
        error = "HTTPS certificate binding is invalid";
        return false;
    }

    wire.preCreate = {
        {false, cert_bind},
        {false, "AT+MSSLCFG=\"auth\",1,1"},
        {false, "AT+MSSLCFG=\"encoding\",1,2"},
        {false, "AT+MSSLCFG=\"negotime\",1,60"},
        {false, "AT+MSSLCFG=\"version\",1,3"},
        {false, "AT+MSSLCFG=\"ignorestamp\",1,0"},
        {false, "AT+MSSLCFG=\"ignoreverify\",1,0"},
        {false, idf_modem_https_create_command(target.host)},
    };

    const bool has_extra_header = !request.headerName.empty();
    wire.postCreate = {
        {false, idf_modem_https_ssl_command(httpId)},
        {false, idf_modem_https_timeout_command(httpId, request.timeoutMs)},
        {false, idf_modem_https_header_command(httpId, has_extra_header,
                                               "Content-Type: " + request.contentType)},
    };
    if (has_extra_header) {
        wire.postCreate.push_back(
            {false, idf_modem_https_header_command(httpId, false,
                                                   request.headerName + ": " + request.headerValue)});
    }
    wire.postCreate.push_back({true, idf_modem_https_content_command(httpId, request.body.size())});
    wire.postCreate.push_back({false, idf_modem_https_request_command(httpId, target.path)});
    return true;
}

IdfModemHttpsRunResult idf_modem_https_run_post(const IdfModemHttpsPostRequest& request,
                                                const IdfModemHttpsCallbacks& callbacks,
                                                IdfModemHttpsPostResult& result)
{
    result = {};
    std::string error;
    IdfModemHttpsTarget target;
    if (!idf_modem_https_validate_request(request, error) ||
        !idf_modem_https_parse_url(request.url, target, error)) {
        result.message = error;
        return IdfModemHttpsRunResult::invalid_request;
    }
    if (!callbacks.sendCommand || !callbacks.waitResponse) {
        result.message = "HTTPS callbacks unavailable";
        return IdfModemHttpsRunResult::invalid_request;
    }

    std::string response;
    int http_id = -1;
    bool activated_pdp = false;
    auto finish = [&](IdfModemHttpsRunResult outcome) {
        bool cleanup_ok = true;
        if (http_id >= 0) {
            const auto terminate_result = callbacks.sendCommand(
                callbacks.context, "AT+MHTTPTERM=" + std::to_string(http_id), response, {}, true,
                false);
            if (terminate_result != IdfModemHttpsCommandResult::ok) cleanup_ok = false;
            const auto cleanup_result = callbacks.sendCommand(
                callbacks.context, "AT+MHTTPDEL=" + std::to_string(http_id), response, {}, true,
                false);
            if (cleanup_result != IdfModemHttpsCommandResult::ok) cleanup_ok = false;
        }
        if (activated_pdp && !request.dataEnabled) {
            const auto cleanup_result = callbacks.sendCommand(
                callbacks.context, "AT+CGACT=0,1", response, {}, true, false);
            if (cleanup_result != IdfModemHttpsCommandResult::ok) cleanup_ok = false;
        }
        if (!cleanup_ok) {
            result.ok = false;
            result.message = "HTTPS cleanup failed";
            return IdfModemHttpsRunResult::cleanup_failed;
        }
        return outcome;
    };
    auto command_failure = [](IdfModemHttpsCommandResult command_result) {
        return command_result == IdfModemHttpsCommandResult::timeout
                   ? IdfModemHttpsRunResult::timed_out
                   : IdfModemHttpsRunResult::command_failed;
    };
    auto send = [&](std::string_view command, std::string_view raw_payload = {}) {
        return callbacks.sendCommand(callbacks.context, command, response, raw_payload, false,
                                     false);
    };

    const std::string apn = trim_spaces(request.apn);
    if (!apn.empty()) {
        const std::string command = "AT+CGDCONT=1,\"IP\",\"" + apn + "\"";
        const auto command_result = send(command);
        if (command_result != IdfModemHttpsCommandResult::ok) {
            result.message = "Cellular PDP profile setup failed";
            return finish(command_failure(command_result));
        }
    }
    if (const auto command_result = send("AT+CGACT=1,1");
        command_result != IdfModemHttpsCommandResult::ok) {
        result.message = "Cellular PDP activation failed";
        return finish(command_failure(command_result));
    }
    activated_pdp = true;

    for (uint8_t stale_id = 0; stale_id < 4; ++stale_id) {
        const auto stale_result = callbacks.sendCommand(
            callbacks.context, "AT+MHTTPDEL=" + std::to_string(stale_id), response, {}, false,
            true);
        if (stale_result != IdfModemHttpsCommandResult::ok &&
            stale_result != IdfModemHttpsCommandResult::modem_error) {
            result.message = "HTTPS stale connection cleanup failed";
            return finish(command_failure(stale_result));
        }
    }

    const auto cert_result = send(idf_modem_https_cert_query_command());
    std::string cert_name;
    if (cert_result != IdfModemHttpsCommandResult::ok ||
        !idf_modem_https_parse_cert_binding(response, cert_name)) {
        result.message = "HTTPS TLS context 1 has no pre-provisioned certificate";
        return finish(command_failure(cert_result));
    }

    IdfModemHttpsPostWire wire;
    if (!idf_modem_https_build_post_wire(request, target, cert_name, 0, wire, error)) {
        result.message = error;
        return finish(IdfModemHttpsRunResult::command_failed);
    }
    bool create_seen = false;
    for (size_t index = 0; index < wire.preCreate.size(); ++index) {
        const IdfModemHttpsWireStep& step = wire.preCreate[index];
        const auto command_result = send(step.command);
        if (command_result != IdfModemHttpsCommandResult::ok) {
            result.message = pre_create_failure_message(index);
            return finish(command_failure(command_result));
        }
        if (index + 1 == wire.preCreate.size()) {
            create_seen = true;
            http_id = idf_modem_https_parse_create_id(response);
            if (http_id < 0) {
                result.message = "HTTPS connection creation returned no valid ID";
                return finish(IdfModemHttpsRunResult::command_failed);
            }
            break;
        }
    }
    if (!create_seen) {
        result.message = "HTTPS connection creation was not submitted";
        return finish(IdfModemHttpsRunResult::command_failed);
    }

    if (!idf_modem_https_build_post_wire(request, target, cert_name,
                                         static_cast<uint8_t>(http_id), wire, error)) {
        result.message = error;
        return finish(IdfModemHttpsRunResult::command_failed);
    }
    for (size_t index = 0; index < wire.postCreate.size(); ++index) {
        const IdfModemHttpsWireStep& step = wire.postCreate[index];
        const auto command_result = send(step.command, step.rawPayload ? request.body : "");
        if (command_result != IdfModemHttpsCommandResult::ok) {
            result.message = step.rawPayload ? "HTTPS request body upload failed"
                                             : post_create_failure_message(index);
            return finish(command_failure(command_result));
        }
    }

    const auto wait_result = callbacks.waitResponse(callbacks.context,
                                                    static_cast<uint8_t>(http_id), result);
    if (wait_result != IdfModemHttpsCommandResult::ok) {
        if (wait_result == IdfModemHttpsCommandResult::timeout) {
            result.message = "HTTPS POST timed out";
            return finish(IdfModemHttpsRunResult::timed_out);
        }
        if (result.message.empty()) result.message = "HTTPS POST response failed";
        return finish(IdfModemHttpsRunResult::response_failed);
    }
    if (!idf_modem_https_status_success(result.httpStatus)) {
        result.ok = false;
        result.message = "HTTPS POST returned a non-2xx status";
        return finish(IdfModemHttpsRunResult::response_failed);
    }
    result.ok = true;
    result.message = "HTTPS POST succeeded";
    return finish(IdfModemHttpsRunResult::ok);
}

std::string idf_modem_https_ssl_command(uint8_t httpId)
{
    return "AT+MHTTPCFG=\"ssl\"," + std::to_string(httpId) + ",1,1";
}

std::string idf_modem_https_timeout_command(uint8_t httpId, uint32_t timeoutMs)
{
    const uint32_t timeoutSeconds = timeoutMs / 1000U + (timeoutMs % 1000U != 0U ? 1U : 0U);
    return "AT+MHTTPCFG=\"timeout\"," + std::to_string(httpId) + "," +
           std::to_string(timeoutSeconds);
}

std::string idf_modem_https_header_command(uint8_t httpId, bool more, std::string_view line)
{
    return "AT+MHTTPHEADER=" + std::to_string(httpId) + "," + (more ? "1," : "0,") +
           std::to_string(line.size()) + ",\"" + std::string(line) + "\"";
}

std::string idf_modem_https_content_command(uint8_t httpId, size_t length)
{
    return "AT+MHTTPCONTENT=" + std::to_string(httpId) + ",0," + std::to_string(length);
}

std::string idf_modem_https_request_command(uint8_t httpId, std::string_view path)
{
    return "AT+MHTTPREQUEST=" + std::to_string(httpId) + ",2,0,\"" +
           std::string(path) + "\"";
}

IdfModemHttpsUrcParser::IdfModemHttpsUrcParser(uint8_t httpId) : http_id_(httpId) {}

void IdfModemHttpsUrcParser::fail(std::string_view message)
{
    if (failed_) return;
    failed_ = true;
    complete_ = true;
    result_.message.assign(message.data(), message.size());
}

void IdfModemHttpsUrcParser::feed(std::string_view bytes)
{
    for (size_t index = 0; index < bytes.size(); ++index) {
        if (discard_remaining_ > 0) {
            const size_t count = std::min(discard_remaining_, bytes.size() - index);
            discard_remaining_ -= count;
            index += count - 1;
            continue;
        }
        if (content_remaining_ > 0) {
            const size_t count = std::min(content_remaining_, bytes.size() - index);
            content_remaining_ -= count;
            const uint64_t next_bytes = static_cast<uint64_t>(result_.responseBytes) + count;
            if (result_.expectedResponseBytes > 0 && next_bytes > result_.expectedResponseBytes) {
                fail("HTTPS response content exceeds declared length");
                return;
            }
            result_.responseBytes = static_cast<uint32_t>(next_bytes);
            index += count - 1;
            if (content_remaining_ == 0 && result_.expectedResponseBytes > 0 &&
                result_.responseBytes >= result_.expectedResponseBytes) {
                complete_ = true;
            }
            continue;
        }
        feed_line_byte(bytes[index]);
        if (failed_) return;
    }
}

void IdfModemHttpsUrcParser::feed_line_byte(char byte)
{
    if (byte == '\r' || byte == '\n') {
        finish_line();
        return;
    }
    if (line_.size() >= kMaxLine) {
        fail("HTTPS modem URC line is too long");
        return;
    }
    line_ += byte;
    if (byte == ',') begin_inline_payload();
}

void IdfModemHttpsUrcParser::finish_line()
{
    if (line_.empty()) return;
    const std::string line = trim_spaces(line_);
    line_.clear();
    if (!line.empty()) parse_line(line);
}

bool IdfModemHttpsUrcParser::begin_inline_payload()
{
    constexpr std::string_view header_prefix = "+MHTTPURC: \"header\",";
    constexpr std::string_view content_prefix = "+MHTTPURC: \"content\",";
    const bool header = starts_with(line_, header_prefix);
    const bool content = starts_with(line_, content_prefix);
    if (!header && !content) return false;

    const std::string_view prefix = header ? header_prefix : content_prefix;
    if (line_.size() <= prefix.size()) return false;
    const size_t expected_fields = header ? 3 : 4;
    const std::string_view fields_text(line_.data() + prefix.size(),
                                       line_.size() - prefix.size() - 1);
    const size_t separators = static_cast<size_t>(
        std::count(fields_text.begin(), fields_text.end(), ','));
    if (separators + 1 < expected_fields) return false;
    if (separators + 1 > expected_fields) {
        fail(header ? "Malformed HTTPS response header"
                    : "Malformed HTTPS response content");
        return true;
    }

    uint32_t fields[4] = {};
    size_t field_count = 0;
    if (!parse_uint_fields(fields_text, fields, expected_fields, expected_fields, field_count) ||
        field_count != expected_fields) {
        fail(header ? "Malformed HTTPS response header"
                    : "Malformed HTTPS response content");
        return true;
    }
    line_.clear();

    if (header) {
        if (fields[2] > IDF_MODEM_HTTPS_POST_MAX_BODY * 4U) {
            fail("HTTPS response header length is invalid");
            return true;
        }
        discard_remaining_ = fields[2];
        if (fields[0] == http_id_) {
            result_.httpStatus = fields[1] > INT_MAX ? -1 : static_cast<int>(fields[1]);
        }
        return true;
    }

    if (fields[3] > IDF_MODEM_HTTPS_POST_MAX_BODY * 4U) {
        fail("HTTPS response content length is invalid");
        return true;
    }
    if (fields[0] != http_id_) {
        discard_remaining_ = fields[3];
        return true;
    }
    const uint64_t next_bytes = static_cast<uint64_t>(result_.responseBytes) + fields[3];
    if (fields[1] > IDF_MODEM_HTTPS_POST_MAX_BODY * 4U || fields[2] > fields[1] ||
        fields[3] > fields[2] || next_bytes != fields[2] ||
        (content_seen_ && result_.expectedResponseBytes != fields[1])) {
        fail("HTTPS response content length is invalid");
        return true;
    }
    content_seen_ = true;
    result_.expectedResponseBytes = fields[1];
    content_remaining_ = fields[3];
    if (content_remaining_ == 0) {
        complete_ = fields[2] == fields[1];
        if (!complete_) fail("HTTPS response content ended early");
    }
    return true;
}

void IdfModemHttpsUrcParser::parse_line(std::string_view line)
{
    if (waiting_for_cmt_payload_) {
        append_urc_line(urcs_, line);
        waiting_for_cmt_payload_ = false;
        return;
    }

    constexpr std::string_view header_prefix = "+MHTTPURC: \"header\",";
    constexpr std::string_view content_prefix = "+MHTTPURC: \"content\",";
    constexpr std::string_view error_prefix = "+MHTTPURC: \"err\",";
    const bool is_http_line = starts_with(line, "+MHTTPURC:");
    if (starts_with(line, header_prefix)) {
        fail("Malformed HTTPS response header");
        return;
    }
    if (starts_with(line, content_prefix)) {
        fail("Malformed HTTPS response content");
        return;
    }
    if (starts_with(line, error_prefix)) {
        uint32_t fields[8] = {};
        size_t field_count = 0;
        if (!parse_uint_fields(line.substr(error_prefix.size()), fields, 2, 8, field_count)) {
            fail("Malformed HTTPS response error");
            return;
        }
        if (fields[0] != http_id_) return;
        result_.mhttpError = fields[1] > INT_MAX ? -1 : static_cast<int>(fields[1]);
        failed_ = true;
        complete_ = true;
        result_.message = "HTTPS modem request failed";
        return;
    }
    if (is_http_line) return;

    if (starts_with(line, "+CMT:")) {
        append_urc_line(urcs_, line);
        waiting_for_cmt_payload_ = true;
    } else if (idf_modem_is_standalone_urc_line(line) || line == "RING" || looks_like_pdu(line)) {
        append_urc_line(urcs_, line);
    }
}
