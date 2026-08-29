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

struct IdfModemHttpsPostResult {
    bool ok = false;
    int httpStatus = -1;
    uint32_t responseBytes = 0;
    uint32_t expectedResponseBytes = 0;
    int mhttpError = 0;
    std::string message;
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
