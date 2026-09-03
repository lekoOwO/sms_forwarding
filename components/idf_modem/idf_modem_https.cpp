#include "idf_modem_https.h"
#include "idf_modem_https_wire.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <climits>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <string>
#include <string_view>
#include <vector>

#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#include "mbedtls/net_sockets.h"
#include "mbedtls/sha256.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

namespace {

constexpr std::string_view kHttpsPrefix = "https://";
constexpr uint32_t kConnectedPollWindowMs = 5000;
constexpr uint32_t kConnectedPollCadenceMs = 250;
constexpr size_t kConnectedPollMaxQueries = 21;

enum class HttpsFailureStage : uint8_t {
    initial_state,
    runtime_snapshot,
    pdp_apn,
    runtime_config,
    socket_open,
    connected_state,
    tls_setup,
    tls_handshake,
    request_write,
    response_read,
    cleanup,
    count,
};

constexpr std::array<std::string_view,
                     static_cast<size_t>(HttpsFailureStage::count)> kFailureMessages = {
    "HTTPS modem initial-state check failed",
    "HTTPS modem runtime snapshot failed",
    "HTTPS modem PDP/APN setup failed",
    "HTTPS modem runtime configuration failed",
    "HTTPS modem socket open failed",
    "HTTPS modem connected-state poll failed",
    "HTTPS TLS setup failed",
    "HTTPS TLS handshake failed",
    "HTTPS request write failed",
    "HTTPS response failed",
    "HTTPS cleanup failed",
};

constexpr std::string_view kInitialQueryCommandFailure =
    "HTTPS modem initial query command failed";
constexpr std::string_view kInitialQueryResponseInvalid =
    "HTTPS modem initial query response invalid";
constexpr std::string_view kStaleCloseCommandFailure =
    "HTTPS modem stale socket close command failed";
constexpr std::string_view kStaleCloseResponseInvalid =
    "HTTPS modem stale socket close response invalid";
constexpr std::string_view kPostCloseQueryCommandFailure =
    "HTTPS modem post-close query command failed";
constexpr std::string_view kPostCloseQueryResponseInvalid =
    "HTTPS modem post-close query response invalid";
constexpr std::string_view kCleanupSocketCloseFailure =
    "HTTPS cleanup socket close failed";
constexpr std::string_view kCleanupSslRestoreFailure =
    "HTTPS cleanup SSL config restore failed";
constexpr std::string_view kCleanupAutofreeRestoreFailure =
    "HTTPS cleanup autofree config restore failed";
constexpr std::string_view kCleanupEncodingRestoreFailure =
    "HTTPS cleanup encoding config restore failed";
constexpr std::string_view kCleanupPdpDeactivateFailure =
    "HTTPS cleanup PDP deactivate failed";
constexpr std::string_view kCleanupPdpProfileRestoreFailure =
    "HTTPS cleanup PDP profile restore failed";

static_assert(kCleanupSocketCloseFailure.size() < IdfModemHttpsPostResult::MAX_CLEANUP_MESSAGE);
static_assert(kCleanupSslRestoreFailure.size() < IdfModemHttpsPostResult::MAX_CLEANUP_MESSAGE);
static_assert(kCleanupAutofreeRestoreFailure.size() < IdfModemHttpsPostResult::MAX_CLEANUP_MESSAGE);
static_assert(kCleanupEncodingRestoreFailure.size() < IdfModemHttpsPostResult::MAX_CLEANUP_MESSAGE);
static_assert(kCleanupPdpDeactivateFailure.size() < IdfModemHttpsPostResult::MAX_CLEANUP_MESSAGE);
static_assert(kCleanupPdpProfileRestoreFailure.size() < IdfModemHttpsPostResult::MAX_CLEANUP_MESSAGE);

constexpr std::string_view failure_message(HttpsFailureStage stage)
{
    return kFailureMessages[static_cast<size_t>(stage)];
}

constexpr IdfHttpsFailureStage public_failure_stage(HttpsFailureStage stage)
{
    switch (stage) {
        case HttpsFailureStage::initial_state:
        case HttpsFailureStage::runtime_snapshot:
        case HttpsFailureStage::runtime_config:
            return IdfHttpsFailureStage::modem;
        case HttpsFailureStage::pdp_apn:
            return IdfHttpsFailureStage::pdp;
        case HttpsFailureStage::socket_open:
            return IdfHttpsFailureStage::socket;
        case HttpsFailureStage::connected_state:
            return IdfHttpsFailureStage::registration;
        case HttpsFailureStage::tls_setup:
        case HttpsFailureStage::tls_handshake:
            return IdfHttpsFailureStage::tls;
        case HttpsFailureStage::request_write:
            return IdfHttpsFailureStage::request;
        case HttpsFailureStage::response_read:
            return IdfHttpsFailureStage::response;
        case HttpsFailureStage::cleanup:
            return IdfHttpsFailureStage::cleanup;
        case HttpsFailureStage::count:
            return IdfHttpsFailureStage::modem;
    }
    return IdfHttpsFailureStage::modem;
}

using namespace idf_modem_https_wire;
using ParseReason = IdfModemHttpsParseReason;
using ParseShape = IdfModemHttpsParseShape;

using Clock = std::chrono::steady_clock;

class Deadline {
public:
    explicit Deadline(uint32_t milliseconds)
        : end_(Clock::now() + std::chrono::milliseconds(milliseconds)) {}

    bool expired() const { return Clock::now() >= end_; }
    Clock::time_point end() const { return end_; }

private:
    Clock::time_point end_;
};

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

bool forbidden_header_byte(std::string_view value)
{
    return std::any_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch < 0x20 || ch == 0x7f || ch == '"' || ch == '\r' || ch == '\n';
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

bool parse_port(std::string_view value, uint16_t& port)
{
    uint32_t parsed = 0;
    if (!parse_uint(value, parsed) || parsed == 0 || parsed > UINT16_MAX) return false;
    port = static_cast<uint16_t>(parsed);
    return true;
}

bool host_valid(std::string_view host)
{
    return !host.empty() && std::none_of(host.begin(), host.end(), [](unsigned char ch) {
        return ch < 0x21 || ch > 0x7e || ch == '"' || ch == '\\' || ch == '@';
    });
}

bool sha256_matches(const std::vector<uint8_t>& der,
                    const std::array<uint8_t, 32>& expected)
{
    if (der.empty() || der.size() > IDF_MODEM_HTTPS_ROOT_DER_MAX ||
        std::all_of(expected.begin(), expected.end(), [](uint8_t byte) { return byte == 0; })) {
        return false;
    }
    std::array<uint8_t, 32> actual{};
    if (mbedtls_sha256(der.data(), der.size(), actual.data(), 0) != 0) return false;
    uint8_t difference = 0;
    for (size_t i = 0; i < actual.size(); ++i) difference |= actual[i] ^ expected[i];
    std::fill(actual.begin(), actual.end(), 0);
    return difference == 0;
}

bool certificate_valid(const IdfModemHttpsPostRequest& request)
{
    if (!sha256_matches(request.rootCertificateDer, request.rootCertificateSha256)) return false;
    auto certificate = std::unique_ptr<mbedtls_x509_crt>(new (std::nothrow) mbedtls_x509_crt);
    if (!certificate) return false;
    mbedtls_x509_crt_init(certificate.get());
    const int parsed = mbedtls_x509_crt_parse_der(certificate.get(),
                                                   request.rootCertificateDer.data(),
                                                   request.rootCertificateDer.size());
    const bool valid = parsed == 0 && mbedtls_x509_crt_get_ca_istrue(certificate.get()) == 1 &&
                       mbedtls_x509_crt_check_key_usage(
                           certificate.get(), MBEDTLS_X509_KU_KEY_CERT_SIGN) == 0;
    mbedtls_x509_crt_free(certificate.get());
    return valid;
}

struct MipConfig {
    uint8_t cid = 0;
    uint8_t send = 0;
    uint8_t receive = 0;
    uint8_t autofree = 0;
    uint8_t ssl = 0;
    uint8_t sslId = 0;
    bool sslIdPresent = false;
};

class MipTlsSession;

int mip_bio_send(void* context, const unsigned char* bytes, size_t length);
int mip_bio_recv(void* context, unsigned char* bytes, size_t length);

class MipTlsSession {
public:
    MipTlsSession(const IdfModemHttpsPostRequest& request,
                  const IdfModemHttpsTarget& target,
                  const IdfModemHttpsCallbacks& callbacks,
                  Deadline& deadline)
        : request_(request), target_(target), callbacks_(callbacks), deadline_(deadline) {}

    ~MipTlsSession()
    {
        if (ssl_initialized_) mbedtls_ssl_free(ssl_.get());
        if (config_initialized_) mbedtls_ssl_config_free(config_.get());
        if (certificate_initialized_) mbedtls_x509_crt_free(certificate_.get());
        if (drbg_initialized_) mbedtls_ctr_drbg_free(drbg_.get());
        if (entropy_initialized_) mbedtls_entropy_free(entropy_.get());
    }

    bool init()
    {
        ssl_ = std::unique_ptr<mbedtls_ssl_context>(new (std::nothrow) mbedtls_ssl_context);
        if (!ssl_) return false;
        mbedtls_ssl_init(ssl_.get());
        ssl_initialized_ = true;

        config_ = std::unique_ptr<mbedtls_ssl_config>(new (std::nothrow) mbedtls_ssl_config);
        if (!config_) return false;
        mbedtls_ssl_config_init(config_.get());
        config_initialized_ = true;

        certificate_ = std::unique_ptr<mbedtls_x509_crt>(new (std::nothrow) mbedtls_x509_crt);
        if (!certificate_) return false;
        mbedtls_x509_crt_init(certificate_.get());
        certificate_initialized_ = true;

        drbg_ = std::unique_ptr<mbedtls_ctr_drbg_context>(new (std::nothrow) mbedtls_ctr_drbg_context);
        if (!drbg_) return false;
        mbedtls_ctr_drbg_init(drbg_.get());
        drbg_initialized_ = true;

        entropy_ = std::unique_ptr<mbedtls_entropy_context>(new (std::nothrow) mbedtls_entropy_context);
        if (!entropy_) return false;
        mbedtls_entropy_init(entropy_.get());
        entropy_initialized_ = true;
        if (mbedtls_x509_crt_parse_der(certificate_.get(), request_.rootCertificateDer.data(),
                                       request_.rootCertificateDer.size()) != 0) return false;
        static constexpr char personalization[] = "idf-modem-mip-tls";
        if (mbedtls_ctr_drbg_seed(drbg_.get(), mbedtls_entropy_func, entropy_.get(),
                                  reinterpret_cast<const unsigned char*>(personalization),
                                  sizeof(personalization) - 1) != 0 ||
            mbedtls_ssl_config_defaults(config_.get(), MBEDTLS_SSL_IS_CLIENT,
                                        MBEDTLS_SSL_TRANSPORT_STREAM,
                                        MBEDTLS_SSL_PRESET_DEFAULT) != 0) return false;
        mbedtls_ssl_conf_rng(config_.get(), mbedtls_ctr_drbg_random, drbg_.get());
        mbedtls_ssl_conf_authmode(config_.get(), MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_min_tls_version(config_.get(), MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_max_tls_version(config_.get(), MBEDTLS_SSL_VERSION_TLS1_2);
        mbedtls_ssl_conf_ca_chain(config_.get(), certificate_.get(), nullptr);
        if (mbedtls_ssl_setup(ssl_.get(), config_.get()) != 0 ||
            mbedtls_ssl_set_hostname(ssl_.get(), target_.host.c_str()) != 0) return false;
        mbedtls_ssl_set_bio(ssl_.get(), this, &mip_bio_send, &mip_bio_recv, nullptr);
        return true;
    }

    bool handshake()
    {
        while (!deadline_.expired()) {
            const int result = mbedtls_ssl_handshake(ssl_.get());
            if (result == 0) {
                return mbedtls_ssl_get_verify_result(ssl_.get()) == 0;
            }
            if (result != MBEDTLS_ERR_SSL_WANT_READ && result != MBEDTLS_ERR_SSL_WANT_WRITE) {
                return false;
            }
        }
        timed_out_ = true;
        return false;
    }

    bool write_all(std::string_view bytes)
    {
        size_t sent = 0;
        while (sent < bytes.size() && !deadline_.expired()) {
            const int result = mbedtls_ssl_write(
                ssl_.get(), reinterpret_cast<const unsigned char*>(bytes.data() + sent),
                bytes.size() - sent);
            if (result > 0) {
                sent += static_cast<size_t>(result);
            } else if (result != MBEDTLS_ERR_SSL_WANT_READ &&
                       result != MBEDTLS_ERR_SSL_WANT_WRITE) {
                return false;
            }
        }
        if (sent != bytes.size()) timed_out_ = true;
        return sent == bytes.size();
    }

    bool read_http(IdfModemHttpsPostResult& result)
    {
        constexpr size_t kTlsPlaintextReadBytes = 1024;
        HttpResponse parser;
        std::array<uint8_t, kTlsPlaintextReadBytes> bytes{};
        while (!deadline_.expired() && !parser.complete()) {
            const int received = mbedtls_ssl_read(ssl_.get(), bytes.data(), bytes.size());
            if (received > 0) {
                if (!parser.feed(bytes.data(), static_cast<size_t>(received), result)) {
                    record_failure_response_reason(
                        IdfModemHttpsFailureResponseReason::http_parse);
                    return false;
                }
                continue;
            }
            if (received == MBEDTLS_ERR_SSL_WANT_READ || received == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }
            if (received == 0 || received == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
                if (!parser.finish_eof(result)) {
                    record_failure_response_reason(
                        parser.header_bytes() == 0
                            ? IdfModemHttpsFailureResponseReason::peer_eof
                            : IdfModemHttpsFailureResponseReason::http_incomplete);
                    return false;
                }
                break;
            }
            if (timed_out_ || received == MBEDTLS_ERR_SSL_TIMEOUT) {
                record_failure_response_reason(IdfModemHttpsFailureResponseReason::timeout);
                return false;
            }
            if (!failure_response_reason_available_) {
                record_failure_response_reason(IdfModemHttpsFailureResponseReason::tls_read);
            }
            return false;
        }
        if (!parser.complete()) {
            timed_out_ = true;
            record_failure_response_reason(IdfModemHttpsFailureResponseReason::timeout);
        }
        return parser.complete();
    }

    bool timed_out() const { return timed_out_; }
    bool remote_closed() const { return remote_closed_; }
    bool open_failed() const { return open_failed_; }
    IdfModemHttpsFailureResponseReason failure_response_reason() const
    {
        return failure_response_reason_;
    }

private:
    friend int mip_bio_send(void*, const unsigned char*, size_t);
    friend int mip_bio_recv(void*, unsigned char*, size_t);

    bool send_mip_bytes(const unsigned char* bytes, size_t length, size_t& sent)
    {
        sent = 0;
        if (length == 0) return true;
        const size_t chunk = std::min(length, kSendMax);
        const std::string hex = hex_encode(bytes, chunk);
        const std::string command = "AT+MIPSEND=0," + std::to_string(chunk) + ",\"" + hex + "\"";
        std::string response;
        if (!send_command(command, response, false)) return false;
        uint32_t accepted = 0;
        if (!parse_result(response, command, "+MIPSEND:", 0, accepted) || accepted != chunk) {
            return false;
        }
        sent = chunk;
        return true;
    }

    bool receive_mip_bytes(unsigned char* bytes, size_t length, size_t& received)
    {
        received = 0;
        if (!pending_.empty()) {
            const size_t count = std::min(length, pending_.size());
            std::copy_n(pending_.begin(), count, bytes);
            pending_.erase(pending_.begin(), pending_.begin() + static_cast<ptrdiff_t>(count));
            received = count;
            return true;
        }
        if (remote_closed()) return true;
        if (length == 0) return true;
        const std::string command = "AT+MIPRD=0,4096";
        std::string response;
        if (!send_command(command, response, false)) {
            if (!timed_out_ && !open_failed_) {
                record_failure_response_reason(IdfModemHttpsFailureResponseReason::modem_command);
            }
            return false;
        }
        uint32_t unread = 0;
        std::vector<uint8_t> data;
        bool remote_closed = false;
        if (!parse_read(response, command, 0, unread, data, remote_closed)) {
            record_failure_response_reason(IdfModemHttpsFailureResponseReason::modem_read);
            return false;
        }
        if (remote_closed) remote_closed_ = true;
        pending_ = std::move(data);
        if (pending_.empty()) return true;
        const size_t count = std::min(length, pending_.size());
        std::copy_n(pending_.begin(), count, bytes);
        pending_.erase(pending_.begin(), pending_.begin() + static_cast<ptrdiff_t>(count));
        received = count;
        return true;
    }

    bool send_command(const std::string& command, std::string& response, bool cleanup)
    {
        if (!cleanup && deadline_.expired()) {
            timed_out_ = true;
            return false;
        }
        const IdfModemHttpsCommandResult result = callbacks_.sendCommand(
            callbacks_.context, command, response, cleanup);
        if (result == IdfModemHttpsCommandResult::timeout) timed_out_ = true;
        if (result == IdfModemHttpsCommandResult::open_failed) open_failed_ = true;
        if (result != IdfModemHttpsCommandResult::ok) return false;
        return response.size() <= kResponseMax;
    }

    void record_failure_response_reason(IdfModemHttpsFailureResponseReason reason)
    {
        if (!failure_response_reason_available_) {
            failure_response_reason_ = reason;
            failure_response_reason_available_ = true;
        }
    }

    const IdfModemHttpsPostRequest& request_;
    const IdfModemHttpsTarget& target_;
    const IdfModemHttpsCallbacks& callbacks_;
    Deadline& deadline_;
    std::unique_ptr<mbedtls_ssl_context> ssl_;
    std::unique_ptr<mbedtls_ssl_config> config_;
    std::unique_ptr<mbedtls_x509_crt> certificate_;
    std::unique_ptr<mbedtls_ctr_drbg_context> drbg_;
    std::unique_ptr<mbedtls_entropy_context> entropy_;
    std::vector<uint8_t> pending_;
    bool ssl_initialized_ = false;
    bool config_initialized_ = false;
    bool certificate_initialized_ = false;
    bool drbg_initialized_ = false;
    bool entropy_initialized_ = false;
    bool timed_out_ = false;
    bool remote_closed_ = false;
    bool open_failed_ = false;
    IdfModemHttpsFailureResponseReason failure_response_reason_ =
        IdfModemHttpsFailureResponseReason::unknown;
    bool failure_response_reason_available_ = false;
};

int mip_bio_send(void* context, const unsigned char* bytes, size_t length)
{
    auto* session = static_cast<MipTlsSession*>(context);
    size_t sent = 0;
    if (!session->send_mip_bytes(bytes, length, sent)) {
        return session->timed_out() ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_SEND_FAILED;
    }
    return static_cast<int>(sent);
}

int mip_bio_recv(void* context, unsigned char* bytes, size_t length)
{
    auto* session = static_cast<MipTlsSession*>(context);
    size_t received = 0;
    if (!session->receive_mip_bytes(bytes, length, received)) {
        return session->timed_out() ? MBEDTLS_ERR_SSL_TIMEOUT : MBEDTLS_ERR_NET_RECV_FAILED;
    }
    if (received != 0) return static_cast<int>(received);
    if (session->remote_closed()) return 0;
    return MBEDTLS_ERR_SSL_WANT_READ;
}

class MipPostSession {
public:
    MipPostSession(const IdfModemHttpsPostRequest& request,
                   const IdfModemHttpsTarget& target,
                   const IdfModemHttpsCallbacks& callbacks,
                   Deadline& deadline,
                   IdfModemHttpsPostResult& result)
        : request_(request), target_(target), callbacks_(callbacks), deadline_(deadline), result_(result) {}

    ~MipPostSession() { cleanup(); }

    IdfModemHttpsRunResult run()
    {
        if (!ensure_initial_state()) return fail(HttpsFailureStage::initial_state);
        if (!snapshot_config()) return fail(HttpsFailureStage::runtime_snapshot);
        if (!prepare_pdp()) return fail(HttpsFailureStage::pdp_apn);
        if (!apply_runtime_config()) return fail(HttpsFailureStage::runtime_config);
        if (!open_socket()) return fail(HttpsFailureStage::socket_open);
        if (!wait_for_connected()) {
            return fail(open_failed_ ? HttpsFailureStage::socket_open
                                     : HttpsFailureStage::connected_state);
        }
        {
            MipTlsSession tls(request_, target_, callbacks_, deadline_);
            if (!tls.init()) {
                result_.message = failure_message(HttpsFailureStage::tls_setup);
                return fail(HttpsFailureStage::tls_setup);
            }
            if (!tls.handshake()) {
                result_.message = tls.open_failed()
                                      ? failure_message(HttpsFailureStage::socket_open)
                                      : tls.timed_out() ? "HTTPS TLS handshake timed out"
                                                        : failure_message(
                                                              HttpsFailureStage::tls_handshake);
                return tls.timed_out()
                           ? fail(HttpsFailureStage::tls_handshake,
                                  IdfModemHttpsRunResult::timed_out)
                           : fail(tls.open_failed() ? HttpsFailureStage::socket_open
                                                    : HttpsFailureStage::tls_handshake);
            }
            const std::string request_wire = build_http_request();
            if (!tls.write_all(request_wire)) {
                result_.message = tls.open_failed()
                                      ? failure_message(HttpsFailureStage::socket_open)
                                      : failure_message(HttpsFailureStage::request_write);
                const HttpsFailureStage stage = tls.open_failed()
                                                    ? HttpsFailureStage::socket_open
                                                    : HttpsFailureStage::request_write;
                return tls.timed_out() ? fail(stage, IdfModemHttpsRunResult::timed_out)
                                       : fail(stage);
            }
            if (!tls.read_http(result_)) {
                if (!tls.open_failed()) {
                    result_.failureResponseReason = tls.failure_response_reason();
                    result_.failureResponseReasonAvailable = true;
                }
                result_.message = tls.open_failed()
                                      ? failure_message(HttpsFailureStage::socket_open)
                                      : tls.timed_out() ? "HTTPS response timed out"
                                                        : failure_message(
                                                              HttpsFailureStage::response_read);
                const HttpsFailureStage stage = tls.open_failed()
                                                    ? HttpsFailureStage::socket_open
                                                    : HttpsFailureStage::response_read;
                return tls.timed_out()
                           ? fail(stage, IdfModemHttpsRunResult::timed_out)
                           : fail(stage, IdfModemHttpsRunResult::response_failed);
            }
        }
        const bool valid_http_status = result_.httpStatus >= 100 && result_.httpStatus <= 599;
        if (!valid_http_status) {
            result_.message = "HTTPS response status is invalid";
            record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
            record_failure_stage(IdfHttpsFailureStage::response);
            return finish(IdfModemHttpsRunResult::response_failed);
        }
        if (!idf_modem_https_status_success(result_.httpStatus)) {
            result_.message = "HTTPS POST returned a non-2xx status";
            record_failure_stage(IdfHttpsFailureStage::http);
            return fail(HttpsFailureStage::response_read,
                        IdfModemHttpsRunResult::response_failed);
        }
        result_.ok = true;
        result_.message = "HTTPS POST succeeded";
        return finish(IdfModemHttpsRunResult::ok);
    }

private:
    IdfModemHttpsRunResult fail(
        HttpsFailureStage stage,
        IdfModemHttpsRunResult fallback = IdfModemHttpsRunResult::command_failed)
    {
        record_failure_stage(public_failure_stage(stage));
        if (result_.message.empty()) result_.message = failure_message(stage);
        if (timed_out_ || deadline_.expired()) return finish(IdfModemHttpsRunResult::timed_out);
        return finish(fallback);
    }

    IdfModemHttpsRunResult finish(IdfModemHttpsRunResult outcome)
    {
        cleanup();
        if (!cleanup_ok_) {
            result_.ok = false;
            if (outcome == IdfModemHttpsRunResult::ok ||
                result_.failureStage == IdfHttpsFailureStage::none) {
                result_.failureStage = IdfHttpsFailureStage::cleanup;
            }
            if (outcome == IdfModemHttpsRunResult::ok || result_.message.empty()) {
                result_.message = failure_message(HttpsFailureStage::cleanup);
            }
            return IdfModemHttpsRunResult::cleanup_failed;
        }
        return outcome;
    }

    bool command(const std::string& text, std::string& response, bool cleanup = false,
                 IdfModemHttpsCommandResult* command_result = nullptr)
    {
        if (!cleanup && deadline_.expired()) {
            if (command_result) *command_result = IdfModemHttpsCommandResult::failed;
            return false;
        }
        const IdfModemHttpsCommandResult result = callbacks_.sendCommand(
            callbacks_.context, text, response, cleanup);
        if (command_result) *command_result = result;
        if (result == IdfModemHttpsCommandResult::timeout) timed_out_ = true;
        if (result == IdfModemHttpsCommandResult::open_failed) open_failed_ = true;
        return result == IdfModemHttpsCommandResult::ok && response.size() <= kResponseMax;
    }

    bool query_state(std::string_view expected, std::string_view command_failure,
                     std::string_view response_failure)
    {
        const std::string command_text = "AT+MIPSTATE=0";
        std::string response;
        uint8_t cid = 0;
        IdfModemHttpsCommandResult command_result = IdfModemHttpsCommandResult::failed;
        if (!command(command_text, response, false, &command_result)) {
            if (command_result == IdfModemHttpsCommandResult::ok) {
                record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
                record_failure_parse_reason(ParseReason::oversize);
            }
            result_.message = command_result == IdfModemHttpsCommandResult::ok
                                  ? response_failure
                                  : command_failure;
            return false;
        }
        ParseReason parse_reason = ParseReason::none;
        ParseShape parse_shape{};
        if (!parse_mip_state(response, command_text, expected, cid, &parse_reason,
                             &parse_shape) || cid != 0) {
            record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
            if (cid != 0 && parse_reason == ParseReason::none) {
                parse_reason = ParseReason::cid;
            }
            record_failure_parse_reason(parse_reason, parse_shape);
            result_.message = response_failure;
            return false;
        }
        return true;
    }

    bool confirm_cleanup_close_state()
    {
        const std::string command_text = "AT+MIPSTATE=0";
        std::string response;
        IdfModemHttpsCommandResult command_result = IdfModemHttpsCommandResult::failed;
        if (!command(command_text, response, true, &command_result)) {
            const ParseReason parse_reason = command_result == IdfModemHttpsCommandResult::ok
                                                 ? ParseReason::oversize
                                                 : ParseReason::none;
            const IdfModemHttpsDiagnosticReason reason =
                command_result == IdfModemHttpsCommandResult::timeout
                    ? IdfModemHttpsDiagnosticReason::timeout
                    : command_result == IdfModemHttpsCommandResult::ok
                        ? IdfModemHttpsDiagnosticReason::response_invalid
                        : IdfModemHttpsDiagnosticReason::command_failure;
            record_cleanup_failure(kCleanupSocketCloseFailure, reason, true, parse_reason);
            return false;
        }

        ParseReason parse_reason = ParseReason::none;
        ParseShape parse_shape{};
        const MipStateDisposition disposition =
            classify_mip_state(response, command_text, 0, &parse_reason, &parse_shape);
        if (disposition == MipStateDisposition::invalid) {
            record_cleanup_failure(kCleanupSocketCloseFailure,
                                   IdfModemHttpsDiagnosticReason::response_invalid, true,
                                   parse_reason, parse_shape);
            return false;
        }
        if (disposition != MipStateDisposition::initial) {
            record_cleanup_failure(kCleanupSocketCloseFailure,
                                   IdfModemHttpsDiagnosticReason::terminal_failure, true);
            return false;
        }
        return true;
    }

    bool ensure_initial_state()
    {
        const std::string state_command = "AT+MIPSTATE=0";
        std::string response;
        IdfModemHttpsCommandResult state_command_result = IdfModemHttpsCommandResult::failed;
        if (!command(state_command, response, false, &state_command_result)) {
            if (state_command_result == IdfModemHttpsCommandResult::ok) {
                record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
                record_failure_parse_reason(ParseReason::oversize);
            }
            result_.message = state_command_result == IdfModemHttpsCommandResult::ok
                                  ? kInitialQueryResponseInvalid
                                  : kInitialQueryCommandFailure;
            return false;
        }
        ParseReason parse_reason = ParseReason::none;
        ParseShape parse_shape{};
        const MipStateDisposition disposition =
            classify_mip_state(response, state_command, 0, &parse_reason, &parse_shape);
        if (disposition == MipStateDisposition::invalid) {
            record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
            record_failure_parse_reason(parse_reason, parse_shape);
            result_.message = kInitialQueryResponseInvalid;
            return false;
        }
        if (disposition == MipStateDisposition::initial) return true;
        if (disposition != MipStateDisposition::connected &&
            disposition != MipStateDisposition::closed) {
            result_.message = kInitialQueryResponseInvalid;
            return false;
        }
        const std::string close = "AT+MIPCLOSE=0";
        uint32_t result = 0;
        IdfModemHttpsCommandResult close_command_result = IdfModemHttpsCommandResult::failed;
        if (!command(close, response, true, &close_command_result)) {
            if (close_command_result == IdfModemHttpsCommandResult::ok) {
                record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
                record_failure_parse_reason(ParseReason::oversize);
            }
            result_.message = close_command_result == IdfModemHttpsCommandResult::ok
                                  ? kStaleCloseResponseInvalid
                                  : kStaleCloseCommandFailure;
            return false;
        }
        parse_reason = ParseReason::none;
        parse_shape = {};
        if (!parse_mip_close_result(response, close, 0, result, &parse_reason,
                                    &parse_shape)) {
            record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
            record_failure_parse_reason(parse_reason, parse_shape);
            result_.message = kStaleCloseResponseInvalid;
            return false;
        }
        if (result != 0) {
            result_.message = kStaleCloseResponseInvalid;
            return false;
        }
        return query_state("INITIAL", kPostCloseQueryCommandFailure,
                           kPostCloseQueryResponseInvalid);
    }

    bool wait_for_connected()
    {
        const Clock::time_point poll_end = std::min(
            deadline_.end(), Clock::now() + std::chrono::milliseconds(kConnectedPollWindowMs));
        const auto cadence = std::chrono::milliseconds(kConnectedPollCadenceMs);
        const std::string state_command = "AT+MIPSTATE=0";
        for (size_t query = 0; query < kConnectedPollMaxQueries; ++query) {
            if (Clock::now() >= poll_end) break;
            std::string response;
            IdfModemHttpsCommandResult command_result = IdfModemHttpsCommandResult::failed;
            if (!command(state_command, response, false, &command_result)) {
                if (command_result == IdfModemHttpsCommandResult::timeout || deadline_.expired()) {
                    record_failure_reason(IdfModemHttpsDiagnosticReason::timeout);
                } else if (command_result == IdfModemHttpsCommandResult::ok) {
                    record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
                } else if (command_result == IdfModemHttpsCommandResult::open_failed) {
                    record_failure_reason(IdfModemHttpsDiagnosticReason::terminal_failure);
                } else {
                    record_failure_reason(IdfModemHttpsDiagnosticReason::command_failure);
                }
                if (command_result == IdfModemHttpsCommandResult::ok) {
                    record_failure_parse_reason(ParseReason::oversize);
                }
                return false;
            }
            ParseReason parse_reason = ParseReason::none;
            ParseShape parse_shape{};
            const MipStateDisposition disposition =
                classify_mip_state(response, state_command, 0, &parse_reason, &parse_shape);
            if (disposition == MipStateDisposition::connected) {
                const IdfModemHttpsCommandResult confirmed =
                    callbacks_.confirmOpen(callbacks_.context);
                if (confirmed == IdfModemHttpsCommandResult::timeout) timed_out_ = true;
                if (confirmed == IdfModemHttpsCommandResult::open_failed) open_failed_ = true;
                if (confirmed == IdfModemHttpsCommandResult::timeout) {
                    record_failure_reason(IdfModemHttpsDiagnosticReason::timeout);
                } else if (confirmed == IdfModemHttpsCommandResult::open_failed) {
                    record_failure_reason(IdfModemHttpsDiagnosticReason::terminal_failure);
                } else if (confirmed != IdfModemHttpsCommandResult::ok) {
                    record_failure_reason(IdfModemHttpsDiagnosticReason::command_failure);
                }
                return confirmed == IdfModemHttpsCommandResult::ok;
            }
            if (disposition == MipStateDisposition::invalid) {
                record_failure_reason(IdfModemHttpsDiagnosticReason::response_invalid);
                record_failure_parse_reason(parse_reason, parse_shape);
                return false;
            }
            if (disposition != MipStateDisposition::initial &&
                disposition != MipStateDisposition::connecting) {
                record_failure_reason(IdfModemHttpsDiagnosticReason::terminal_failure);
                return false;
            }
            if (query + 1 == kConnectedPollMaxQueries || poll_end - Clock::now() < cadence) {
                break;
            }
            vTaskDelay(pdMS_TO_TICKS(kConnectedPollCadenceMs));
        }
        timed_out_ = true;
        record_failure_reason(deadline_.expired()
                                  ? IdfModemHttpsDiagnosticReason::timeout
                                  : IdfModemHttpsDiagnosticReason::poll_timeout);
        return false;
    }

    bool query_config(std::string_view parameter, uint8_t& first, uint8_t& second,
                      bool& has_second)
    {
        const std::string command_text = "AT+MIPCFG=\"" + std::string(parameter) + "\",0";
        std::string response;
        return command(command_text, response) &&
               parse_cfg_response(response, command_text, parameter, first, second, has_second);
    }

    bool snapshot_config()
    {
        uint8_t second = 0;
        bool has_second = false;
        if (!query_config("cid", snapshot_.cid, second, has_second) || has_second ||
            snapshot_.cid == 0 || snapshot_.cid > 16 ||
            !query_config("encoding", snapshot_.send, snapshot_.receive, has_second) ||
            !has_second || snapshot_.send > 1 || snapshot_.receive > 1 ||
            !query_config("autofree", snapshot_.autofree, second, has_second) || has_second ||
            snapshot_.autofree > 1 || !query_config("ssl", snapshot_.ssl, snapshot_.sslId,
                                                      snapshot_.sslIdPresent) ||
            snapshot_.ssl > 1) {
            return false;
        }
        return true;
    }

    bool prepare_pdp()
    {
        const std::string context_query = "AT+CGDCONT?";
        std::string response;
        std::string current_apn;
        std::string current_profile;
        if (!command(context_query, response) ||
            !parse_cgdccont(response, context_query, snapshot_.cid, &current_apn,
                             &current_profile)) {
            return false;
        }
        const std::string active_query = "AT+CGACT?";
        if (!command(active_query, response)) return false;
        bool active = false;
        if (!parse_cgact(response, active_query, snapshot_.cid, active)) return false;

        const std::string requested_apn(trim_spaces(request_.apn));
        std::string configure;
        if (!requested_apn.empty() &&
            !build_cgdccont_command(snapshot_.cid, requested_apn, configure)) {
            return false;
        }
        if (!requested_apn.empty() && requested_apn != current_apn) {
            // Never rewrite a live PDP.  The original profile is complete and safe to
            // restore because parse_cgdccont canonicalizes every observed field.
            if (active || current_profile.empty()) return false;
            original_cgdccont_ = current_profile;
            pdp_profile_changed_ = true;
            if (!command(configure, response)) return false;
            std::vector<std::string_view> body;
            if (!scan_frame(response, configure, body) || !body.empty()) return false;
            std::string configured_apn;
            if (!command(context_query, response) ||
                !parse_cgdccont(response, context_query, snapshot_.cid, &configured_apn) ||
                configured_apn != requested_apn) {
                return false;
            }
        }
        if (active) return true;
        const std::string activate = "AT+CGACT=1," + std::to_string(snapshot_.cid);
        pdp_activated_ = true;
        if (!command(activate, response)) return false;
        std::vector<std::string_view> body;
        if (!scan_frame(response, activate, body) || !body.empty()) return false;
        return true;
    }

    bool apply_runtime_config()
    {
        touched_encoding_ = true;
        if (!set_config("encoding", "1,1") || !verify_config("encoding", 1, 1, true)) return false;
        touched_autofree_ = true;
        if (!set_config("autofree", "1") || !verify_config("autofree", 1, 0, false)) return false;
        touched_ssl_ = true;
        if (!set_config("ssl", "0,0") || !verify_config("ssl", 0, 0, true)) return false;
        return true;
    }

    bool set_config(std::string_view parameter, std::string_view values)
    {
        const std::string text = "AT+MIPCFG=\"" + std::string(parameter) + "\",0," +
                                 std::string(values);
        std::string response;
        std::vector<std::string_view> body;
        return command(text, response) && scan_frame(response, text, body) && body.empty();
    }

    bool verify_config(std::string_view parameter, uint8_t expected, uint8_t expected_second,
                       bool has_second)
    {
        uint8_t first = 0;
        uint8_t second = 0;
        bool actual_has_second = false;
        return query_config(parameter, first, second, actual_has_second) && first == expected &&
               actual_has_second == has_second && (!has_second || second == expected_second);
    }

    bool open_socket()
    {
        maybe_open_ = true;
        const uint32_t timeout = std::max<uint32_t>(1, (request_.timeoutMs + 999U) / 1000U);
        const std::string text = "AT+MIPOPEN=0,\"TCP\",\"" + target_.host + "\"," +
                                 std::to_string(target_.port) + "," + std::to_string(timeout) + ",2";
        std::string response;
        if (!command(text, response)) return false;
        bool async_result_present = false;
        return parse_mip_open(response, text, 0, async_result_present);
    }

    bool restore_config(std::string_view parameter, std::string_view values,
                        uint8_t expected, uint8_t expected_second, bool has_second,
                        std::string_view cleanup_failure)
    {
        const std::string text = "AT+MIPCFG=\"" + std::string(parameter) + "\",0," +
                                 std::string(values);
        std::string response;
        std::vector<std::string_view> body;
        if (!command(text, response, true) || !scan_frame(response, text, body) || !body.empty()) {
            record_cleanup_failure(cleanup_failure);
            return false;
        }
        const std::string query = "AT+MIPCFG=\"" + std::string(parameter) + "\",0";
        if (!command(query, response, true)) {
            record_cleanup_failure(cleanup_failure);
            return false;
        }
        uint8_t first = 0;
        uint8_t second = 0;
        bool actual_has_second = false;
        if (!parse_cfg_response(response, query, parameter, first, second, actual_has_second) ||
            first != expected || actual_has_second != has_second ||
            (has_second && second != expected_second)) {
            record_cleanup_failure(cleanup_failure);
            return false;
        }
        return true;
    }

    bool restore_cgdccont()
    {
        if (original_cgdccont_.empty()) {
            record_cleanup_failure(kCleanupPdpProfileRestoreFailure);
            return false;
        }
        const std::string command_text = "AT+CGDCONT=" + original_cgdccont_;
        std::string response;
        std::vector<std::string_view> body;
        if (!command(command_text, response, true) ||
            !scan_frame(response, command_text, body) || !body.empty()) {
            record_cleanup_failure(kCleanupPdpProfileRestoreFailure);
            return false;
        }
        const std::string query = "AT+CGDCONT?";
        std::string restored_profile;
        if (!command(query, response, true) ||
            !parse_cgdccont(response, query, snapshot_.cid, nullptr, &restored_profile) ||
            restored_profile != original_cgdccont_) {
            record_cleanup_failure(kCleanupPdpProfileRestoreFailure);
            return false;
        }
        return true;
    }

    void record_cleanup_failure(std::string_view message)
    {
        cleanup_ok_ = false;
        if (result_.cleanupMessage.empty()) result_.cleanupMessage = message;
    }

    void record_cleanup_failure(std::string_view message,
                                IdfModemHttpsDiagnosticReason reason,
                                bool requires_reset = false,
                                ParseReason parse_reason = ParseReason::none,
                                ParseShape parse_shape = {})
    {
        cleanup_ok_ = false;
        if (result_.cleanupMessage.empty()) result_.cleanupMessage = message;
        if (result_.cleanupReason == IdfModemHttpsDiagnosticReason::none) {
            result_.cleanupReason = reason;
            if (reason == IdfModemHttpsDiagnosticReason::response_invalid) {
                result_.cleanupParseReason = parse_reason;
                result_.cleanupParseShape = parse_shape;
            }
        }
        if (requires_reset) result_.cleanupRequiresReset = true;
    }

    void record_failure_reason(IdfModemHttpsDiagnosticReason reason)
    {
        if (result_.failureReason == IdfModemHttpsDiagnosticReason::none) {
            result_.failureReason = reason;
        }
    }

    void record_failure_parse_reason(ParseReason reason, ParseShape parse_shape = {})
    {
        if (result_.failureReason == IdfModemHttpsDiagnosticReason::response_invalid &&
            result_.failureParseReason == ParseReason::none && reason != ParseReason::none) {
            result_.failureParseReason = reason;
            result_.failureParseShape = parse_shape;
        }
    }

    void record_failure_stage(IdfHttpsFailureStage stage)
    {
        if (result_.failureStage == IdfHttpsFailureStage::none) {
            result_.failureStage = stage;
        }
    }

    void cleanup()
    {
        if (cleanup_done_) return;
        cleanup_done_ = true;
        std::string response;
        if (maybe_open_) {
            const std::string close = "AT+MIPCLOSE=0";
            uint32_t result = 0;
            IdfModemHttpsCommandResult close_command_result = IdfModemHttpsCommandResult::failed;
            if (!command(close, response, true, &close_command_result)) {
                const ParseReason parse_reason =
                    close_command_result == IdfModemHttpsCommandResult::ok
                        ? ParseReason::oversize
                        : ParseReason::none;
                record_cleanup_failure(
                    kCleanupSocketCloseFailure,
                    close_command_result == IdfModemHttpsCommandResult::timeout
                        ? IdfModemHttpsDiagnosticReason::timeout
                        : close_command_result == IdfModemHttpsCommandResult::ok
                            ? IdfModemHttpsDiagnosticReason::response_invalid
                            : IdfModemHttpsDiagnosticReason::command_failure,
                    true, parse_reason);
            } else {
                ParseReason parse_reason = ParseReason::none;
                ParseShape parse_shape{};
                bool close_requires_confirmation = false;
                if (!parse_mip_close_result(response, close, 0, result, &parse_reason,
                                            &parse_shape, &close_requires_confirmation)) {
                    record_cleanup_failure(kCleanupSocketCloseFailure,
                                           IdfModemHttpsDiagnosticReason::response_invalid, true,
                                           parse_reason, parse_shape);
                } else if (result != 0) {
                    record_cleanup_failure(kCleanupSocketCloseFailure,
                                           IdfModemHttpsDiagnosticReason::result_nonzero, true);
                } else if (close_requires_confirmation) {
                    confirm_cleanup_close_state();
                }
            }
        }
        if (touched_ssl_) {
            const std::string values = std::to_string(snapshot_.ssl) +
                                       (snapshot_.sslIdPresent ? "," + std::to_string(snapshot_.sslId) : "");
            restore_config("ssl", values, snapshot_.ssl, snapshot_.sslId,
                           snapshot_.sslIdPresent, kCleanupSslRestoreFailure);
        }
        if (touched_autofree_) {
            restore_config("autofree", std::to_string(snapshot_.autofree),
                           snapshot_.autofree, 0, false, kCleanupAutofreeRestoreFailure);
        }
        if (touched_encoding_) {
            restore_config("encoding", std::to_string(snapshot_.send) + "," +
                               std::to_string(snapshot_.receive), snapshot_.send,
                               snapshot_.receive, true, kCleanupEncodingRestoreFailure);
        }
        if (pdp_activated_ && !request_.dataEnabled) {
            const std::string deactivate = "AT+CGACT=0," + std::to_string(snapshot_.cid);
            if (!command(deactivate, response, true)) {
                record_cleanup_failure(kCleanupPdpDeactivateFailure);
            }
            std::vector<std::string_view> body;
            if (cleanup_ok_ && (!scan_frame(response, deactivate, body) || !body.empty())) {
                record_cleanup_failure(kCleanupPdpDeactivateFailure);
            }
        }
        if (pdp_profile_changed_ && !request_.dataEnabled) restore_cgdccont();
    }

    const IdfModemHttpsPostRequest& request_;
    const IdfModemHttpsTarget& target_;
    const IdfModemHttpsCallbacks& callbacks_;
    Deadline& deadline_;
    IdfModemHttpsPostResult& result_;
    MipConfig snapshot_;
    bool pdp_activated_ = false;
    bool pdp_profile_changed_ = false;
    std::string original_cgdccont_;
    bool maybe_open_ = false;
    bool cleanup_done_ = false;
    bool cleanup_ok_ = true;
    bool touched_encoding_ = false;
    bool touched_autofree_ = false;
    bool touched_ssl_ = false;
    bool timed_out_ = false;
    bool open_failed_ = false;

    std::string build_http_request() const
    {
        std::string host = target_.host;
        if (host.find(':') != std::string::npos) host = "[" + host + "]";
        if (target_.port != 443) host += ":" + std::to_string(target_.port);
        std::string wire = "POST " + target_.path + " HTTP/1.1\r\nHost: " + host +
                           "\r\nContent-Type: " + request_.contentType +
                           "\r\nContent-Length: " + std::to_string(request_.body.size()) +
                           "\r\nConnection: close\r\n";
        if (!request_.headerName.empty()) wire += request_.headerName + ": " + request_.headerValue + "\r\n";
        wire += "\r\n";
        wire += request_.body;
        return wire;
    }
};

}  // namespace

bool idf_modem_https_parse_url(std::string_view raw_url, IdfModemHttpsTarget& target,
                               std::string& error)
{
    target = {};
    error.clear();
    std::string owned(trim_spaces(raw_url));
    if (owned.empty() || owned.size() > IDF_MODEM_HTTPS_POST_MAX_URL ||
        !starts_with(owned, kHttpsPrefix)) {
        error = owned.empty() ? "HTTPS URL is empty or too long" : "HTTPS URL must use https://";
        return false;
    }
    const size_t authority_start = kHttpsPrefix.size();
    const size_t path_start = owned.find_first_of("/?#", authority_start);
    const size_t authority_end = path_start == std::string::npos ? owned.size() : path_start;
    std::string_view authority(owned.data() + authority_start, authority_end - authority_start);
    if (authority.empty() || authority.find('@') != std::string_view::npos) {
        error = "HTTPS URL host is invalid";
        return false;
    }
    std::string host;
    uint16_t port = 443;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string_view::npos || close == 1) {
            error = "HTTPS URL host is invalid";
            return false;
        }
        host.assign(authority.substr(1, close - 1));
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':' || !parse_port(authority.substr(close + 2), port)) {
                error = "HTTPS URL port is invalid";
                return false;
            }
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string_view::npos) {
            if (authority.find(':') != colon || !parse_port(authority.substr(colon + 1), port)) {
                error = "HTTPS URL port is invalid";
                return false;
            }
            host.assign(authority.substr(0, colon));
        } else {
            host.assign(authority);
        }
    }
    if (!host_valid(host)) {
        error = "HTTPS URL host is invalid";
        return false;
    }
    std::string path;
    if (path_start == std::string::npos) {
        path = "/";
    } else {
        if (owned[path_start] == '#') {
            error = "HTTPS URL fragment is not allowed";
            return false;
        }
        path = owned.substr(path_start);
        if (path[0] == '?') path.insert(path.begin(), '/');
        if (path.find('#') != std::string::npos || forbidden_header_byte(path) ||
            path.find('\\') != std::string::npos) {
            error = "HTTPS URL path is invalid";
            return false;
        }
    }
    target.host = std::move(host);
    target.path = std::move(path);
    target.port = port;
    return true;
}

bool idf_modem_https_validate_request(const IdfModemHttpsPostRequest& request,
                                      std::string& error)
{
    if (request.rootCertificateDer.empty() ||
        request.rootCertificateDer.size() > IDF_MODEM_HTTPS_ROOT_DER_MAX ||
        request.rootCertificateSha256.size() != 32 ||
        std::all_of(request.rootCertificateSha256.begin(), request.rootCertificateSha256.end(),
                    [](uint8_t byte) { return byte == 0; })) {
        error = "HTTPS pinned certificate is invalid";
        return false;
    }
    IdfModemHttpsTarget target;
    if (!idf_modem_https_parse_url(request.url, target, error)) return false;
    if (request.body.empty() || request.body.size() > IDF_MODEM_HTTPS_POST_MAX_BODY) {
        error = request.body.empty() ? "HTTPS POST body is empty" : "HTTPS POST body is too large";
        return false;
    }
    if (request.contentType.empty() || request.contentType.size() > IDF_MODEM_HTTPS_POST_MAX_CONTENT_TYPE ||
        forbidden_header_byte(request.contentType)) {
        error = "HTTPS Content-Type is invalid";
        return false;
    }
    if (request.headerName.size() > IDF_MODEM_HTTPS_POST_MAX_HEADER_NAME ||
        request.headerValue.size() > IDF_MODEM_HTTPS_POST_MAX_HEADER_VALUE ||
        (!request.headerName.empty() && request.headerValue.empty()) ||
        (request.headerName.empty() && !request.headerValue.empty()) ||
        (!request.headerName.empty() && !header_name_token(request.headerName)) ||
        forbidden_header_byte(request.headerValue)) {
        error = "HTTPS header is invalid";
        return false;
    }
    if (request.timeoutMs == 0 || request.timeoutMs > IDF_MODEM_HTTPS_POST_MAX_TIMEOUT_MS) {
        error = "HTTPS timeout is invalid";
        return false;
    }
    if (request.apn.size() > 96 || forbidden_header_byte(request.apn)) {
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

IdfModemHttpsRunResult idf_modem_https_run_post(const IdfModemHttpsPostRequest& request,
                                                const IdfModemHttpsCallbacks& callbacks,
                                                IdfModemHttpsPostResult& result)
{
    result = {};
    std::string error;
    IdfModemHttpsTarget target;
    const bool certificate_material_invalid =
        request.rootCertificateDer.empty() ||
        request.rootCertificateDer.size() > IDF_MODEM_HTTPS_ROOT_DER_MAX ||
        std::all_of(request.rootCertificateSha256.begin(), request.rootCertificateSha256.end(),
                    [](uint8_t byte) { return byte == 0; });
    if (!idf_modem_https_parse_url(request.url, target, error)) {
        result.message = error;
        result.failureStage = IdfHttpsFailureStage::target;
        return IdfModemHttpsRunResult::invalid_request;
    }
    if (!idf_modem_https_validate_request(request, error)) {
        result.message = error;
        result.failureStage = certificate_material_invalid
                                  ? IdfHttpsFailureStage::ca
                                  : IdfHttpsFailureStage::request;
        return IdfModemHttpsRunResult::invalid_request;
    }
    if (!callbacks.sendCommand || !callbacks.confirmOpen) {
        result.message = "HTTPS callbacks unavailable";
        result.failureStage = IdfHttpsFailureStage::modem;
        return IdfModemHttpsRunResult::invalid_request;
    }
    if (!certificate_valid(request)) {
        result.message = "HTTPS pinned certificate is invalid";
        result.failureStage = IdfHttpsFailureStage::ca;
        return IdfModemHttpsRunResult::invalid_request;
    }
    Deadline deadline(request.timeoutMs);
    MipPostSession session(request, target, callbacks, deadline, result);
    const IdfModemHttpsRunResult outcome = session.run();
    if (outcome == IdfModemHttpsRunResult::ok &&
        (result.httpStatus < 100 || result.httpStatus > 599)) {
        result.ok = false;
        result.failureStage = IdfHttpsFailureStage::response;
        result.failureReason = IdfModemHttpsDiagnosticReason::response_invalid;
        result.message = "HTTPS response status is invalid";
        return IdfModemHttpsRunResult::response_failed;
    }
    return outcome;
}
