#include "idf_push_ca.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <string>
#include <vector>

#include "esp_crt_bundle.h"
#include "esp_idf_version.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "idf_config.h"
#include "idf_push_ca_allowlist_generated.h"
#include "idf_push_cellular.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"
#endif
#include "mbedtls/net_sockets.h"
#include "mbedtls/md.h"
#include "mbedtls/ssl.h"
#include "mbedtls/x509_crt.h"

namespace {

constexpr int64_t PROBE_TIMEOUT_US = 8000000;

struct ProbeSession {
    bool valid = false;
    uint64_t generation = 0;
    int64_t expiresUs = 0;
    std::string nonce;
    std::string origin;
    std::string hostname;
    std::vector<std::vector<uint8_t>> chain;
};

std::array<ProbeSession, IDF_MAX_PUSH_CHANNELS> sessions;
SemaphoreHandle_t session_mutex;
StaticSemaphore_t session_mutex_storage;
portMUX_TYPE session_init_lock = portMUX_INITIALIZER_UNLOCKED;

void ensure_mutex()
{
    taskENTER_CRITICAL(&session_init_lock);
    if (!session_mutex) session_mutex = xSemaphoreCreateMutexStatic(&session_mutex_storage);
    taskEXIT_CRITICAL(&session_init_lock);
}

void clear_session(ProbeSession& session)
{
    for (auto& cert : session.chain) std::fill(cert.begin(), cert.end(), 0);
    session = {};
}

std::string hex_nonce()
{
    std::array<uint8_t, 16> bytes{};
    esp_fill_random(bytes.data(), bytes.size());
    static constexpr char hex[] = "0123456789abcdef";
    std::string out;
    out.reserve(32);
    for (uint8_t byte : bytes) {
        out += hex[byte >> 4];
        out += hex[byte & 15];
    }
    std::fill(bytes.begin(), bytes.end(), 0);
    return out;
}

bool split_origin(const std::string& origin, std::string& host, std::string& port)
{
    if (origin.rfind("https://", 0) != 0) return false;
    std::string authority = origin.substr(8);
    if (authority.empty()) return false;
    port = "443";
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos) return false;
        host = authority.substr(1, close - 1);
        if (close + 1 < authority.size()) {
            if (authority[close + 1] != ':') return false;
            port = authority.substr(close + 2);
        }
    } else {
        const size_t colon = authority.rfind(':');
        if (colon != std::string::npos) {
            host = authority.substr(0, colon);
            port = authority.substr(colon + 1);
        } else {
            host = authority;
        }
    }
    return !host.empty() && !port.empty();
}

void set_timeouts(int fd, int64_t deadline)
{
    int64_t remaining = std::max<int64_t>(1, deadline - esp_timer_get_time());
    timeval timeout{static_cast<time_t>(remaining / 1000000),
                    static_cast<suseconds_t>(remaining % 1000000)};
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
}

bool connect_deadline(int fd, const sockaddr* address, socklen_t length, int64_t deadline)
{
    const int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) != 0) return false;
    int rc = connect(fd, address, length);
    if (rc != 0 && errno == EINPROGRESS) {
        const int64_t remaining = deadline - esp_timer_get_time();
        if (remaining <= 0) return false;
        fd_set writes;
        FD_ZERO(&writes);
        FD_SET(fd, &writes);
        timeval timeout{static_cast<time_t>(remaining / 1000000),
                        static_cast<suseconds_t>(remaining % 1000000)};
        rc = select(fd + 1, nullptr, &writes, nullptr, &timeout);
        int error = 0;
        socklen_t error_length = sizeof(error);
        if (rc <= 0 || getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &error_length) != 0 ||
            error != 0) return false;
    } else if (rc != 0) {
        return false;
    }
    if (fcntl(fd, F_SETFL, flags) != 0) return false;
    set_timeouts(fd, deadline);
    return true;
}

bool tls_chain_probe(const std::string& origin, std::string& hostname,
                     std::vector<std::vector<uint8_t>>& chain)
{
    std::string port;
    if (!split_origin(origin, hostname, port)) return false;
    const int64_t deadline = esp_timer_get_time() + PROBE_TIMEOUT_US;
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo* addresses = nullptr;
    if (getaddrinfo(hostname.c_str(), port.c_str(), &hints, &addresses) != 0 || !addresses) {
        return false;
    }
    int fd = -1;
    for (addrinfo* address = addresses; address && esp_timer_get_time() < deadline;
         address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype, address->ai_protocol);
        if (fd >= 0 && connect_deadline(fd, address->ai_addr, address->ai_addrlen, deadline)) break;
        if (fd >= 0) close(fd);
        fd = -1;
    }
    freeaddrinfo(addresses);
    if (fd < 0) return false;

    mbedtls_net_context net;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config config;
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
    mbedtls_ctr_drbg_context drbg;
    mbedtls_entropy_context entropy;
#endif
    mbedtls_net_init(&net);
    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&config);
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
    mbedtls_ctr_drbg_init(&drbg);
    mbedtls_entropy_init(&entropy);
#endif
    net.fd = fd;
    bool ok = false;
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
    const char personalization[] = "push-ca-probe";
    const bool random_ready = mbedtls_ctr_drbg_seed(
        &drbg, mbedtls_entropy_func, &entropy,
        reinterpret_cast<const unsigned char*>(personalization),
        sizeof(personalization) - 1) == 0;
#else
    const bool random_ready = true;
#endif
    if (random_ready &&
        mbedtls_ssl_config_defaults(&config, MBEDTLS_SSL_IS_CLIENT,
                                    MBEDTLS_SSL_TRANSPORT_STREAM,
                                    MBEDTLS_SSL_PRESET_DEFAULT) == 0) {
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
        mbedtls_ssl_conf_rng(&config, mbedtls_ctr_drbg_random, &drbg);
#endif
        mbedtls_ssl_conf_authmode(&config, MBEDTLS_SSL_VERIFY_REQUIRED);
        if (esp_crt_bundle_attach(&config) == ESP_OK && mbedtls_ssl_setup(&ssl, &config) == 0 &&
            mbedtls_ssl_set_hostname(&ssl, hostname.c_str()) == 0) {
            mbedtls_ssl_set_bio(&ssl, &net, mbedtls_net_send, mbedtls_net_recv, nullptr);
            int result = 0;
            while (esp_timer_get_time() < deadline &&
                   (result = mbedtls_ssl_handshake(&ssl)) != 0 &&
                   (result == MBEDTLS_ERR_SSL_WANT_READ ||
                    result == MBEDTLS_ERR_SSL_WANT_WRITE)) {}
            if (result == 0 && mbedtls_ssl_get_verify_result(&ssl) == 0) {
                const mbedtls_x509_crt* cert = mbedtls_ssl_get_peer_cert(&ssl);
                while (cert && chain.size() < IDF_PUSH_CA_CHAIN_MAX) {
                    if (!cert->raw.p || cert->raw.len == 0 ||
                        cert->raw.len > IDF_CONFIG_CA_MAX_DER_BYTES ||
                        cert->issuer_raw.len > IDF_PUSH_CA_ISSUER_DER_MAX ||
                        cert->authority_key_id.keyIdentifier.len > IDF_PUSH_CA_AKI_MAX) {
                        chain.clear();
                        break;
                    }
                    chain.emplace_back(cert->raw.p, cert->raw.p + cert->raw.len);
                    cert = cert->next;
                }
                ok = !chain.empty() && cert == nullptr;
            }
        }
    }
    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&config);
#if ESP_IDF_VERSION < ESP_IDF_VERSION_VAL(6, 0, 0)
    mbedtls_ctr_drbg_free(&drbg);
    mbedtls_entropy_free(&entropy);
#endif
    close(fd);
    return ok;
}

bool sha256(const uint8_t* data, size_t length, std::array<uint8_t, 32>& output)
{
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return info && mbedtls_md(info, data, length, output.data()) == 0;
}

bool allowlisted(const std::array<uint8_t, 32>& hash)
{
    return std::binary_search(IDF_PUSH_CA_ALLOWLIST.begin(), IDF_PUSH_CA_ALLOWLIST.end(), hash);
}

bool candidate_valid(const uint8_t* der, size_t length, const ProbeSession& session)
{
    std::array<uint8_t, 32> hash{};
    if (!der || length == 0 || length > IDF_CONFIG_CA_MAX_DER_BYTES ||
        !sha256(der, length, hash) || !allowlisted(hash)) return false;
    mbedtls_x509_crt candidate;
    mbedtls_x509_crt_init(&candidate);
    bool valid = mbedtls_x509_crt_parse_der(&candidate, der, length) == 0 &&
                 mbedtls_x509_crt_get_ca_istrue(&candidate) == 1 &&
                 mbedtls_x509_crt_check_key_usage(
                     &candidate, MBEDTLS_X509_KU_KEY_CERT_SIGN) == 0 &&
                 candidate.subject_raw.len == candidate.issuer_raw.len &&
                 memcmp(candidate.subject_raw.p, candidate.issuer_raw.p,
                        candidate.subject_raw.len) == 0 &&
                 mbedtls_x509_time_is_future(&candidate.valid_from) == 0 &&
                 mbedtls_x509_time_is_past(&candidate.valid_to) == 0;
    uint32_t flags = UINT32_MAX;
    if (valid) {
        valid = mbedtls_x509_crt_verify(&candidate, &candidate, nullptr, nullptr, &flags,
                                        nullptr, nullptr) == 0 && flags == 0;
    }
    bool path_valid = false;
    for (size_t count = 1; valid && !path_valid && count <= session.chain.size(); ++count) {
        mbedtls_x509_crt peer;
        mbedtls_x509_crt_init(&peer);
        bool parsed = true;
        for (size_t i = 0; i < count; ++i) {
            if (mbedtls_x509_crt_parse_der(&peer, session.chain[i].data(),
                                           session.chain[i].size()) != 0) {
                parsed = false;
                break;
            }
        }
        flags = UINT32_MAX;
        path_valid = parsed &&
            mbedtls_x509_crt_verify_with_profile(&peer, &candidate, nullptr,
                                                 &mbedtls_x509_crt_profile_default,
                                                 session.hostname.c_str(), &flags,
                                                 nullptr, nullptr) == 0 && flags == 0;
        mbedtls_x509_crt_free(&peer);
    }
    mbedtls_x509_crt_free(&candidate);
    return valid && path_valid;
}

bool current_target(uint8_t channel, IdfPushCellularTarget& target)
{
    IdfPushChannel config;
    return channel < IDF_MAX_PUSH_CHANNELS && idf_config_get_push_channel(channel, config) &&
           idf_push_prepare_cellular_target(config, target);
}

}  // namespace

esp_err_t idf_push_ca_probe(uint8_t channel, IdfPushCaProbeResult& result)
{
    result = {};
    const uint64_t generation = idf_config_generation();
    IdfPushCellularTarget target;
    if (!current_target(channel, target) || generation != idf_config_generation()) {
        return ESP_ERR_INVALID_STATE;
    }
    ensure_mutex();
    if (!session_mutex || xSemaphoreTake(session_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    clear_session(sessions[channel]);
    xSemaphoreGive(session_mutex);
    std::string hostname;
    std::vector<std::vector<uint8_t>> chain;
    if (!tls_chain_probe(target.canonicalOrigin, hostname, chain)) return ESP_FAIL;
    if (generation != idf_config_generation()) return ESP_ERR_INVALID_STATE;

    ProbeSession session;
    session.valid = true;
    session.generation = generation;
    session.expiresUs = esp_timer_get_time() +
        static_cast<int64_t>(IDF_PUSH_CA_SESSION_TTL_MS) * 1000;
    session.nonce = hex_nonce();
    session.origin = target.canonicalOrigin;
    session.hostname = hostname;
    session.chain = std::move(chain);
    result.nonce = session.nonce;
    result.expiresInMs = IDF_PUSH_CA_SESSION_TTL_MS;
    for (const auto& raw : session.chain) {
        mbedtls_x509_crt cert;
        mbedtls_x509_crt_init(&cert);
        IdfPushCaCertificateMetadata metadata;
        if (mbedtls_x509_crt_parse_der(&cert, raw.data(), raw.size()) != 0 ||
            !sha256(raw.data(), raw.size(), metadata.sha256)) {
            mbedtls_x509_crt_free(&cert);
            return ESP_FAIL;
        }
        metadata.issuerDer.assign(cert.issuer_raw.p,
                                  cert.issuer_raw.p + cert.issuer_raw.len);
        if (cert.authority_key_id.keyIdentifier.len != 0) {
            metadata.authorityKeyIdentifier.assign(
                cert.authority_key_id.keyIdentifier.p,
                cert.authority_key_id.keyIdentifier.p +
                    cert.authority_key_id.keyIdentifier.len);
        }
        mbedtls_x509_crt_free(&cert);
        result.chain.push_back(std::move(metadata));
    }
    if (xSemaphoreTake(session_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return ESP_ERR_TIMEOUT;
    sessions[channel] = std::move(session);
    xSemaphoreGive(session_mutex);
    return ESP_OK;
}

esp_err_t idf_push_ca_install(uint8_t channel, const std::string& nonce,
                              const uint8_t* der, size_t derLength,
                              IdfConfigCaStatus& status)
{
    status = {};
    if (channel >= IDF_MAX_PUSH_CHANNELS || nonce.size() != 32) return ESP_ERR_INVALID_ARG;
    ensure_mutex();
    if (!session_mutex || xSemaphoreTake(session_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    ProbeSession session;
    ProbeSession& retained = sessions[channel];
    if (!retained.valid || retained.nonce != nonce ||
        retained.expiresUs <= esp_timer_get_time()) {
        clear_session(retained);
        xSemaphoreGive(session_mutex);
        return ESP_ERR_NOT_FOUND;
    }
    session = std::move(retained);
    retained = {};
    xSemaphoreGive(session_mutex);
    if (session.generation != idf_config_generation()) {
        clear_session(session);
        return ESP_ERR_INVALID_STATE;
    }
    if (!candidate_valid(der, derLength, session)) {
        clear_session(session);
        return ESP_ERR_INVALID_ARG;
    }
    if (session.generation != idf_config_generation()) {
        clear_session(session);
        return ESP_ERR_INVALID_STATE;
    }
    const esp_err_t err = idf_config_ca_install(session.origin, der, derLength, &status);
    const bool generation_changed = session.generation != idf_config_generation();
    clear_session(session);
    return err == ESP_OK && generation_changed ? ESP_ERR_INVALID_STATE : err;
}

esp_err_t idf_push_ca_status(uint8_t channel, IdfConfigCaStatus& status)
{
    status = {};
    IdfPushCellularTarget target;
    if (!current_target(channel, target)) return ESP_ERR_INVALID_ARG;
    return idf_config_ca_status(target.canonicalOrigin, status);
}
