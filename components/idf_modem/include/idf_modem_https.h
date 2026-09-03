#pragma once

#include <cstddef>
#include <cstdint>
#include <array>
#include <string>
#include <string_view>
#include <vector>

// Keep modem-native HTTPS requests small enough for one owner slot and one UART transaction.
static constexpr size_t IDF_MODEM_HTTPS_POST_MAX_URL = 240;
static constexpr size_t IDF_MODEM_HTTPS_POST_MAX_BODY = 4096;
static constexpr size_t IDF_MODEM_HTTPS_POST_MAX_CONTENT_TYPE = 96;
static constexpr size_t IDF_MODEM_HTTPS_POST_MAX_HEADER_NAME = 64;
static constexpr size_t IDF_MODEM_HTTPS_POST_MAX_HEADER_VALUE = 512;
static constexpr uint32_t IDF_MODEM_HTTPS_POST_DEFAULT_TIMEOUT_MS = 30000;
static constexpr uint32_t IDF_MODEM_HTTPS_POST_MAX_TIMEOUT_MS = 90000;
static constexpr size_t IDF_MODEM_HTTPS_ROOT_DER_MAX = 8192;
static constexpr size_t IDF_MODEM_HTTPS_CERT_NAME_MAX = 64;

struct IdfModemHttpsPostRequest {
    std::string url;
    std::string body;
    std::string contentType = "application/json";
    std::string headerName;
    std::string headerValue;
    std::string apn;
    std::vector<uint8_t> rootCertificateDer;
    std::array<uint8_t, 32> rootCertificateSha256{};
    bool dataEnabled = false;
    uint32_t timeoutMs = IDF_MODEM_HTTPS_POST_DEFAULT_TIMEOUT_MS;
};

enum class IdfModemHttpsDiagnosticReason : uint8_t {
    none = 0,
    command_failure = 1,
    timeout = 2,
    response_invalid = 3,
    terminal_failure = 4,
    poll_timeout = 5,
    result_nonzero = 6,
    unknown = 255,
};

// A bounded classification for a failed HTTPS response read.  It is populated
// only when the response-read stage fails and is kept separate from the
// transport-independent diagnostic reason.
enum class IdfModemHttpsFailureResponseReason : uint8_t {
    timeout = 0,
    peer_eof,
    modem_read,
    tls_read,
    http_parse,
    http_incomplete,
    modem_command,
    unknown,
};

constexpr std::string_view idf_modem_https_failure_response_reason_name(
    IdfModemHttpsFailureResponseReason reason)
{
    switch (reason) {
        case IdfModemHttpsFailureResponseReason::timeout: return "timeout";
        case IdfModemHttpsFailureResponseReason::peer_eof: return "peer_eof";
        case IdfModemHttpsFailureResponseReason::modem_read: return "modem_read";
        case IdfModemHttpsFailureResponseReason::tls_read: return "tls_read";
        case IdfModemHttpsFailureResponseReason::http_parse: return "http_parse";
        case IdfModemHttpsFailureResponseReason::http_incomplete: return "http_incomplete";
        case IdfModemHttpsFailureResponseReason::modem_command: return "modem_command";
        case IdfModemHttpsFailureResponseReason::unknown: return "unknown";
    }
    return "unknown";
}

// A bounded classification for a rejected modem response.  This is only
// populated when the response grammar rejects a frame; transport, command,
// result, and HTTP failures intentionally keep the value at none.
enum class IdfModemHttpsParseReason : uint8_t {
    none = 0,
    oversize,
    terminal,
    urc,
    prefix,
    field_count,
    quote,
    cid,
    state,
    endpoint,
    result,
    unknown = 255,
};

constexpr std::string_view idf_modem_https_parse_reason_name(
    IdfModemHttpsParseReason reason)
{
    switch (reason) {
        case IdfModemHttpsParseReason::none: return {};
        case IdfModemHttpsParseReason::oversize: return "oversize";
        case IdfModemHttpsParseReason::terminal: return "terminal";
        case IdfModemHttpsParseReason::urc: return "urc";
        case IdfModemHttpsParseReason::prefix: return "prefix";
        case IdfModemHttpsParseReason::field_count: return "field_count";
        case IdfModemHttpsParseReason::quote: return "quote";
        case IdfModemHttpsParseReason::cid: return "cid";
        case IdfModemHttpsParseReason::state: return "state";
        case IdfModemHttpsParseReason::endpoint: return "endpoint";
        case IdfModemHttpsParseReason::result: return "result";
        case IdfModemHttpsParseReason::unknown: return "unknown";
    }
    return "unknown";
}

enum class IdfModemHttpsParseStateClass : uint8_t {
    none = 0,
    initial,
    closed,
    connected,
    connecting,
    unknown,
};

constexpr std::string_view idf_modem_https_parse_state_class_name(
    IdfModemHttpsParseStateClass state)
{
    switch (state) {
        case IdfModemHttpsParseStateClass::none: return "none";
        case IdfModemHttpsParseStateClass::initial: return "initial";
        case IdfModemHttpsParseStateClass::closed: return "closed";
        case IdfModemHttpsParseStateClass::connected: return "connected";
        case IdfModemHttpsParseStateClass::connecting: return "connecting";
        case IdfModemHttpsParseStateClass::unknown: return "unknown";
    }
    return {};
}

enum class IdfModemHttpsParseSingleFieldClass : uint8_t {
    none = 0,
    zero,
    nonzero,
    non_numeric,
};

constexpr std::string_view idf_modem_https_parse_single_field_class_name(
    IdfModemHttpsParseSingleFieldClass field)
{
    switch (field) {
        case IdfModemHttpsParseSingleFieldClass::none: return "none";
        case IdfModemHttpsParseSingleFieldClass::zero: return "zero";
        case IdfModemHttpsParseSingleFieldClass::nonzero: return "nonzero";
        case IdfModemHttpsParseSingleFieldClass::non_numeric: return "non_numeric";
    }
    return {};
}

enum class IdfModemHttpsParseLineClass : uint8_t {
    none = 0,
    missing,
    unexpected,
    duplicate,
    extra,
};

constexpr std::string_view idf_modem_https_parse_line_class_name(
    IdfModemHttpsParseLineClass line)
{
    switch (line) {
        case IdfModemHttpsParseLineClass::none: return "none";
        case IdfModemHttpsParseLineClass::missing: return "missing";
        case IdfModemHttpsParseLineClass::unexpected: return "unexpected";
        case IdfModemHttpsParseLineClass::duplicate: return "duplicate";
        case IdfModemHttpsParseLineClass::extra: return "extra";
    }
    return {};
}

struct IdfModemHttpsParsePresence {
    static constexpr uint8_t mipstate = 1U << 0;
    static constexpr uint8_t mipopen = 1U << 1;
    static constexpr uint8_t mipclose = 1U << 2;
    static constexpr uint8_t mipurc = 1U << 3;
    static constexpr uint8_t other = 1U << 4;
    static constexpr uint8_t all = mipstate | mipopen | mipclose | mipurc | other;
};

// A fixed snapshot of parser structure.  It contains no response values.
// fieldCount is zero when no CSV line was inspected and eight means eight or
// more fields.  quoteMask bits 0..7 indicate quoted CSV fields in that line;
// presenceMask uses the constants above.  The availability flag is internal
// and is never serialized.
struct IdfModemHttpsParseShape {
    bool available;
    uint8_t fieldCount;
    uint8_t quoteMask;
    uint8_t presenceMask;
    IdfModemHttpsParseStateClass stateClass;
    IdfModemHttpsParseLineClass lineClass;
    IdfModemHttpsParseSingleFieldClass singleFieldClass;
};

// A bounded, transport-agnostic stage for safe terminal diagnostics. Keep this
// separate from the modem diagnostic reason: reasons are implementation detail
// while the stage is part of the push-test status contract.
enum class IdfHttpsFailureStage : uint8_t {
    none = 0,
    preflight,
    target,
    ca,
    modem,
    registration,
    pdp,
    socket,
    tls,
    request,
    response,
    http,
    cleanup,
};

constexpr std::string_view idf_https_failure_stage_name(IdfHttpsFailureStage stage)
{
    switch (stage) {
        case IdfHttpsFailureStage::none: return "none";
        case IdfHttpsFailureStage::preflight: return "preflight";
        case IdfHttpsFailureStage::target: return "target";
        case IdfHttpsFailureStage::ca: return "ca";
        case IdfHttpsFailureStage::modem: return "modem";
        case IdfHttpsFailureStage::registration: return "registration";
        case IdfHttpsFailureStage::pdp: return "pdp";
        case IdfHttpsFailureStage::socket: return "socket";
        case IdfHttpsFailureStage::tls: return "tls";
        case IdfHttpsFailureStage::request: return "request";
        case IdfHttpsFailureStage::response: return "response";
        case IdfHttpsFailureStage::http: return "http";
        case IdfHttpsFailureStage::cleanup: return "cleanup";
    }
    return {};
}

constexpr std::string_view idf_modem_https_diagnostic_reason_name(
    IdfModemHttpsDiagnosticReason reason)
{
    switch (reason) {
        case IdfModemHttpsDiagnosticReason::command_failure: return "command_failure";
        case IdfModemHttpsDiagnosticReason::timeout: return "timeout";
        case IdfModemHttpsDiagnosticReason::response_invalid: return "response_invalid";
        case IdfModemHttpsDiagnosticReason::terminal_failure: return "terminal_failure";
        case IdfModemHttpsDiagnosticReason::poll_timeout: return "poll_timeout";
        case IdfModemHttpsDiagnosticReason::result_nonzero: return "result_nonzero";
        case IdfModemHttpsDiagnosticReason::none: return {};
        case IdfModemHttpsDiagnosticReason::unknown: return "unknown";
    }
    return "unknown";
}

constexpr std::string_view idf_modem_https_cleanup_reason_name(
    IdfModemHttpsDiagnosticReason reason)
{
    switch (reason) {
        case IdfModemHttpsDiagnosticReason::command_failure: return "command_failure";
        case IdfModemHttpsDiagnosticReason::timeout: return "timeout";
        case IdfModemHttpsDiagnosticReason::response_invalid: return "response_invalid";
        case IdfModemHttpsDiagnosticReason::result_nonzero: return "result_nonzero";
        case IdfModemHttpsDiagnosticReason::unknown: return "unknown";
        case IdfModemHttpsDiagnosticReason::none: return {};
        case IdfModemHttpsDiagnosticReason::terminal_failure:
        case IdfModemHttpsDiagnosticReason::poll_timeout: return "unknown";
    }
    return "unknown";
}

struct IdfModemHttpsPostResult {
    static constexpr size_t MAX_CLEANUP_MESSAGE = 96;
    bool ok = false;
    int httpStatus = -1;
    uint32_t responseBytes = 0;
    uint32_t expectedResponseBytes = 0;
    int mhttpError = 0;
    std::string message;
    std::string cleanupMessage;
    IdfModemHttpsDiagnosticReason failureReason = IdfModemHttpsDiagnosticReason::none;
    IdfModemHttpsDiagnosticReason cleanupReason = IdfModemHttpsDiagnosticReason::none;
    IdfModemHttpsFailureResponseReason failureResponseReason =
        IdfModemHttpsFailureResponseReason::unknown;
    bool failureResponseReasonAvailable = false;
    IdfModemHttpsParseReason failureParseReason = IdfModemHttpsParseReason::none;
    IdfModemHttpsParseReason cleanupParseReason = IdfModemHttpsParseReason::none;
    IdfModemHttpsParseShape failureParseShape{};
    IdfModemHttpsParseShape cleanupParseShape{};
    bool cleanupRequiresReset = false;
    IdfHttpsFailureStage failureStage = IdfHttpsFailureStage::none;
};

struct IdfModemHttpsTarget {
    std::string host;
    std::string path;
    uint16_t port = 443;
};

enum class IdfModemHttpsCommandResult : int {
    ok = 0,
    modem_error = 1,
    failed = -1,
    timeout = -2,
    open_failed = -3,
};

enum class IdfModemHttpsRunResult : int {
    ok = 0,
    invalid_request = -1,
    command_failed = -2,
    timed_out = -3,
    response_failed = -4,
    cleanup_failed = -5,
};

using IdfModemHttpsSendCommand = IdfModemHttpsCommandResult (*)(
    void* context, std::string_view command, std::string& response, bool cleanup);
using IdfModemHttpsConfirmOpen = IdfModemHttpsCommandResult (*)(void* context);
struct IdfModemHttpsCallbacks {
    void* context = nullptr;
    IdfModemHttpsSendCommand sendCommand = nullptr;
    IdfModemHttpsConfirmOpen confirmOpen = nullptr;
};

bool idf_modem_https_validate_request(const IdfModemHttpsPostRequest& request,
                                      std::string& error);
bool idf_modem_https_model_allowed(std::string_view model);
bool idf_modem_https_status_success(int httpStatus);
bool idf_modem_https_parse_url(std::string_view url, IdfModemHttpsTarget& target,
                               std::string& error);
IdfModemHttpsRunResult idf_modem_https_run_post(const IdfModemHttpsPostRequest& request,
                                                const IdfModemHttpsCallbacks& callbacks,
                                                IdfModemHttpsPostResult& result);
