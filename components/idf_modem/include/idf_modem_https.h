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
    bool cleanupRequiresReset = false;
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
