#include "idf_modem_https.h"

#include <algorithm>
#include <cctype>
#include <climits>
#include <ctime>
#include <utility>

#include "idf_modem_query_filter.h"

namespace {

constexpr std::string_view kHttpsPrefix = "https://";
constexpr size_t kMaxLine = 768;
constexpr size_t kMaxPinnedCertificate = 8192;
constexpr int kMinimumTrustedYear = 2023;
constexpr int64_t kMinimumTrustedEpoch = 1700000000;
constexpr int64_t kLastCclkEpoch = 2145916799;
constexpr int64_t kClockReadbackToleranceSeconds = 5;
constexpr std::string_view kClockSynchronizationError =
    "HTTPS modem clock synchronization failed";
// Application trust floor is 2023-11-14 (1700000000); ML307A CCLK ends at 2037-12-31.

bool starts_with(std::string_view value, std::string_view prefix);

bool parse_two_digits(std::string_view value, size_t offset, int& output)
{
    if (offset + 2 > value.size() || value[offset] < '0' || value[offset] > '9' ||
        value[offset + 1] < '0' || value[offset + 1] > '9') {
        return false;
    }
    output = static_cast<int>(value[offset] - '0') * 10 +
             static_cast<int>(value[offset + 1] - '0');
    return true;
}

bool leap_year(int year)
{
    return year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
}

bool valid_civil_date(int year, int month, int day)
{
    constexpr int days_per_month[] = {31, 28, 31, 30, 31, 30,
                                       31, 31, 30, 31, 30, 31};
    if (year < kMinimumTrustedYear || year > 2037 || month < 1 || month > 12) return false;
    const int maximum = days_per_month[month - 1] +
                        (month == 2 && leap_year(year) ? 1 : 0);
    return day >= 1 && day <= maximum;
}

// Convert civil UTC fields without depending on the device timezone.
int64_t days_from_civil(int year, int month, int day)
{
    const int adjusted_year = year - (month <= 2 ? 1 : 0);
    const int era = (adjusted_year >= 0 ? adjusted_year : adjusted_year - 399) / 400;
    const int year_of_era = adjusted_year - era * 400;
    const int month_of_year = month + (month > 2 ? -3 : 9);
    const int day_of_year = (153 * month_of_year + 2) / 5 + day - 1;
    const int day_of_era = year_of_era * 365 + year_of_era / 4 - year_of_era / 100 +
                           day_of_year;
    return static_cast<int64_t>(era) * 146097 + day_of_era - 719468;
}

int64_t cclk_epoch(int year, int month, int day, int hour, int minute, int second)
{
    return days_from_civil(year, month, day) * 86400LL +
           static_cast<int64_t>(hour) * 3600LL +
           static_cast<int64_t>(minute) * 60LL + second;
}

void append_two_digits(std::string& output, int value)
{
    if (value < 10) output += '0';
    output += std::to_string(value);
}

bool cclk_command_from_epoch(int64_t epoch, std::string& command)
{
    if (epoch < kMinimumTrustedEpoch || epoch > kLastCclkEpoch) return false;
    const time_t timestamp = static_cast<time_t>(epoch);
    if (static_cast<int64_t>(timestamp) != epoch) return false;
    struct tm utc = {};
    if (::gmtime_r(&timestamp, &utc) == nullptr) return false;
    const int year = utc.tm_year + 1900;
    if (!valid_civil_date(year, utc.tm_mon + 1, utc.tm_mday) || utc.tm_hour < 0 ||
        utc.tm_hour > 23 || utc.tm_min < 0 || utc.tm_min > 59 || utc.tm_sec < 0 ||
        utc.tm_sec > 59) {
        return false;
    }

    command = "AT+CCLK=\"";
    append_two_digits(command, year % 100);
    command += '/';
    append_two_digits(command, utc.tm_mon + 1);
    command += '/';
    append_two_digits(command, utc.tm_mday);
    command += ',';
    append_two_digits(command, utc.tm_hour);
    command += ':';
    append_two_digits(command, utc.tm_min);
    command += ':';
    append_two_digits(command, utc.tm_sec);
    command += "+00\"";
    return true;
}

bool parse_cclk_readback(std::string_view response, int64_t& epoch)
{
    // Parse only the modem's UTC +00 representation; local-time offsets and
    // Pre-2023 dates are outside the application trust floor and are rejected.
    constexpr std::string_view prefix = "+CCLK: \"";
    constexpr size_t payload_length = 20;
    bool clock_seen = false;
    bool ok_seen = false;
    size_t start = 0;
    while (start < response.size()) {
        const size_t end = response.find_first_of("\r\n", start);
        const std::string_view line = response.substr(
            start, end == std::string_view::npos ? response.size() - start : end - start);
        if (!line.empty()) {
            if (line == "OK") {
                if (ok_seen) return false;
                ok_seen = true;
            } else {
                if (clock_seen || ok_seen || !starts_with(line, prefix) ||
                    line.size() != prefix.size() + payload_length + 1 || line.back() != '"') {
                    return false;
                }
                const std::string_view payload = line.substr(prefix.size(), payload_length);
                if (payload[2] != '/' || payload[5] != '/' || payload[8] != ',' ||
                    payload[11] != ':' || payload[14] != ':' || payload[17] != '+' ||
                    payload.substr(18) != "00") {
                    return false;
                }
                int year_suffix = 0;
                int month = 0;
                int day = 0;
                int hour = 0;
                int minute = 0;
                int second = 0;
                if (!parse_two_digits(payload, 0, year_suffix) ||
                    !parse_two_digits(payload, 3, month) || !parse_two_digits(payload, 6, day) ||
                    !parse_two_digits(payload, 9, hour) ||
                    !parse_two_digits(payload, 12, minute) ||
                    !parse_two_digits(payload, 15, second)) {
                    return false;
                }
                const int year = 2000 + year_suffix;
                if (!valid_civil_date(year, month, day) || hour > 23 || minute > 59 ||
                    second > 59) {
                    return false;
                }
                epoch = cclk_epoch(year, month, day, hour, minute, second);
                clock_seen = true;
            }
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
        while (start < response.size() &&
               (response[start] == '\r' || response[start] == '\n')) {
            ++start;
        }
    }
    return clock_seen && ok_seen;
}

bool cclk_readback_matches(std::string_view response, int64_t requested_epoch)
{
    int64_t readback_epoch = 0;
    if (!parse_cclk_readback(response, readback_epoch)) return false;
    const int64_t difference = readback_epoch - requested_epoch;
    return difference >= -kClockReadbackToleranceSeconds &&
           difference <= kClockReadbackToleranceSeconds;
}

enum class PinnedCertificateListResult { missing, present, invalid };

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

PinnedCertificateListResult inspect_pinned_certificate_list(
    std::string_view response, std::string_view expected_name, size_t expected_length)
{
    constexpr std::string_view prefix = "+MSSLLIST:";
    bool present = false;
    size_t start = 0;
    while (start < response.size()) {
        const size_t end = response.find_first_of("\r\n", start);
        std::string_view line = response.substr(
            start, end == std::string_view::npos ? response.size() - start : end - start);
        if (starts_with(line, prefix)) {
            line.remove_prefix(prefix.size());
            while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
            if (line.size() < 4 || line.front() != '"') {
                return PinnedCertificateListResult::invalid;
            }
            const size_t quote = line.find('"', 1);
            if (quote == std::string_view::npos || quote + 2 > line.size() ||
                line[quote + 1] != ',') {
                return PinnedCertificateListResult::invalid;
            }
            uint32_t length = 0;
            if (!parse_uint(line.substr(quote + 2), length)) {
                return PinnedCertificateListResult::invalid;
            }
            if (line.substr(1, quote - 1) == expected_name) {
                if (present || length != expected_length) {
                    return PinnedCertificateListResult::invalid;
                }
                present = true;
            }
        }
        if (end == std::string_view::npos) break;
        start = end + 1;
        while (start < response.size() &&
               (response[start] == '\r' || response[start] == '\n')) ++start;
    }
    return present ? PinnedCertificateListResult::present
                   : PinnedCertificateListResult::missing;
}

bool root_der_to_pem(const IdfModemHttpsPostRequest& request, std::string& name,
                     std::string& pem)
{
    static constexpr char b64[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    if (request.rootCertificateDer.empty() ||
        request.rootCertificateDer.size() > IDF_MODEM_HTTPS_ROOT_DER_MAX) return false;
    const bool hash_present = std::any_of(request.rootCertificateSha256.begin(),
                                          request.rootCertificateSha256.end(),
                                          [](uint8_t byte) { return byte != 0; });
    name = "ca_";
    static constexpr char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < 28; ++i) {
        const uint8_t byte = request.rootCertificateSha256[i];
        name += hex[byte >> 4];
        name += hex[byte & 0x0f];
    }
    name += ".pem";
    if (!hash_present || name.size() > IDF_MODEM_HTTPS_CERT_NAME_MAX) return false;
    pem = "-----BEGIN CERTIFICATE-----\n";
    size_t column = 0;
    for (size_t offset = 0; offset < request.rootCertificateDer.size(); offset += 3) {
        const size_t left = request.rootCertificateDer.size() - offset;
        const uint32_t value = static_cast<uint32_t>(request.rootCertificateDer[offset]) << 16 |
            (left > 1 ? static_cast<uint32_t>(request.rootCertificateDer[offset + 1]) << 8 : 0) |
            (left > 2 ? request.rootCertificateDer[offset + 2] : 0);
        const char encoded[4] = {b64[(value >> 18) & 63], b64[(value >> 12) & 63],
                                 left > 1 ? b64[(value >> 6) & 63] : '=',
                                 left > 2 ? b64[value & 63] : '='};
        for (char ch : encoded) {
            pem += ch;
            if (++column == 64) { pem += '\n'; column = 0; }
        }
    }
    if (column != 0) pem += '\n';
    pem += "-----END CERTIFICATE-----\n";
    return pem.size() <= kMaxPinnedCertificate;
}

bool pinned_certificate_readback_matches(std::string_view response,
                                         std::string_view certificate)
{
    constexpr std::string_view prefix = "+MSSLCERTRD:";
    const size_t found = response.find(prefix);
    if (found == std::string_view::npos) return false;
    size_t length_start = found + prefix.size();
    while (length_start < response.size() && response[length_start] == ' ') ++length_start;
    const size_t comma = response.find(',', length_start);
    if (comma == std::string_view::npos) return false;
    uint32_t declared_length = 0;
    if (!parse_uint(response.substr(length_start, comma - length_start), declared_length) ||
        declared_length != certificate.size()) {
        return false;
    }
    const size_t payload_start = comma + 1;
    return payload_start <= response.size() &&
           declared_length <= response.size() - payload_start &&
           response.compare(payload_start, declared_length, certificate) == 0;
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
    if (!callbacks.sendCommand || !callbacks.waitResponse || !callbacks.getEpoch) {
        result.message = "HTTPS callbacks unavailable";
        return IdfModemHttpsRunResult::invalid_request;
    }
    std::string certificate_name;
    std::string pinned_certificate;
    if (!root_der_to_pem(request, certificate_name, pinned_certificate)) {
        result.message = "HTTPS pinned certificate is unavailable";
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

    const int64_t requested_epoch = callbacks.getEpoch(callbacks.context);
    std::string clock_command;
    if (!cclk_command_from_epoch(requested_epoch, clock_command)) {
        result.message.assign(kClockSynchronizationError.data(), kClockSynchronizationError.size());
        return finish(IdfModemHttpsRunResult::command_failed);
    }
    auto clock_result = send(clock_command);
    if (clock_result != IdfModemHttpsCommandResult::ok) {
        result.message.assign(kClockSynchronizationError.data(), kClockSynchronizationError.size());
        return finish(command_failure(clock_result));
    }
    clock_result = send("AT+CCLK?");
    if (clock_result != IdfModemHttpsCommandResult::ok ||
        !cclk_readback_matches(response, requested_epoch)) {
        result.message.assign(kClockSynchronizationError.data(), kClockSynchronizationError.size());
        return finish(command_failure(clock_result));
    }

    auto cert_result = send("AT+MSSLLIST=1");
    if (cert_result != IdfModemHttpsCommandResult::ok) {
        result.message = "HTTPS pinned certificate list failed";
        return finish(command_failure(cert_result));
    }
    const PinnedCertificateListResult list_result = inspect_pinned_certificate_list(
        response, certificate_name, pinned_certificate.size());
    if (list_result == PinnedCertificateListResult::invalid) {
        result.message = "HTTPS pinned certificate list mismatch";
        return finish(IdfModemHttpsRunResult::command_failed);
    }
    if (list_result == PinnedCertificateListResult::missing) {
        const std::string write_command =
            "AT+MSSLCERTWR=\"" + certificate_name +
            "\",0," + std::to_string(pinned_certificate.size());
        cert_result = send(write_command, pinned_certificate);
        if (cert_result != IdfModemHttpsCommandResult::ok) {
            result.message = "HTTPS pinned certificate write failed";
            return finish(command_failure(cert_result));
        }
    }
    const std::string read_command =
        "AT+MSSLCERTRD=\"" + certificate_name + "\"";
    cert_result = send(read_command);
    if (cert_result != IdfModemHttpsCommandResult::ok) {
        result.message = "HTTPS pinned certificate read failed";
        return finish(command_failure(cert_result));
    }
    if (!pinned_certificate_readback_matches(response, pinned_certificate)) {
        result.message = "HTTPS pinned certificate readback mismatch";
        return finish(IdfModemHttpsRunResult::command_failed);
    }

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

    IdfModemHttpsPostWire wire;
    if (!idf_modem_https_build_post_wire(request, target, certificate_name,
                                         0, wire, error)) {
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

    if (!idf_modem_https_build_post_wire(request, target, certificate_name,
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
