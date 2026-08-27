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
};

struct IdfModemHttpsWireStep {
    bool rawPayload = false;
    std::string command;
};

struct IdfModemHttpsPostWire {
    std::vector<IdfModemHttpsWireStep> preCreate;
    std::vector<IdfModemHttpsWireStep> postCreate;
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
    void* context, std::string_view command, std::string& response,
    std::string_view rawPayload, bool cleanup, bool tolerateModemError);
using IdfModemHttpsWaitResponse = IdfModemHttpsCommandResult (*)(
    void* context, uint8_t httpId, IdfModemHttpsPostResult& result);

struct IdfModemHttpsCallbacks {
    void* context = nullptr;
    IdfModemHttpsSendCommand sendCommand = nullptr;
    IdfModemHttpsWaitResponse waitResponse = nullptr;
};

bool idf_modem_https_validate_request(const IdfModemHttpsPostRequest& request,
                                      std::string& error);
bool idf_modem_https_model_allowed(std::string_view model);
bool idf_modem_https_status_success(int httpStatus);
bool idf_modem_https_parse_url(std::string_view url, IdfModemHttpsTarget& target,
                               std::string& error);
bool idf_modem_https_build_post_wire(const IdfModemHttpsPostRequest& request,
                                     const IdfModemHttpsTarget& target,
                                     std::string_view certName, uint8_t httpId,
                                     IdfModemHttpsPostWire& wire, std::string& error);
IdfModemHttpsRunResult idf_modem_https_run_post(const IdfModemHttpsPostRequest& request,
                                                const IdfModemHttpsCallbacks& callbacks,
                                                IdfModemHttpsPostResult& result);

int idf_modem_https_parse_create_id(std::string_view response);
std::string idf_modem_https_create_command(std::string_view host);
std::string idf_modem_https_cert_bind_command(std::string_view name);
std::string idf_modem_https_ssl_command(uint8_t httpId);
std::string idf_modem_https_timeout_command(uint8_t httpId, uint32_t timeoutMs);
std::string idf_modem_https_header_command(uint8_t httpId, bool more,
                                           std::string_view line);
std::string idf_modem_https_content_command(uint8_t httpId, size_t length);
std::string idf_modem_https_request_command(uint8_t httpId, std::string_view path);

// Parse modem-native response URCs while treating content as length-delimited bytes.
class IdfModemHttpsUrcParser {
public:
    explicit IdfModemHttpsUrcParser(uint8_t httpId);

    void feed(std::string_view bytes);
    const IdfModemHttpsPostResult& result() const { return result_; }
    const std::string& urcs() const { return urcs_; }
    bool complete() const { return complete_; }
    bool failed() const { return failed_; }

private:
    void feed_line_byte(char byte);
    void finish_line();
    bool begin_inline_payload();
    void parse_line(std::string_view line);
    void fail(std::string_view message);

    uint8_t http_id_;
    IdfModemHttpsPostResult result_;
    std::string line_;
    std::string urcs_;
    size_t content_remaining_ = 0;
    size_t discard_remaining_ = 0;
    bool waiting_for_cmt_payload_ = false;
    bool content_seen_ = false;
    bool complete_ = false;
    bool failed_ = false;
};
