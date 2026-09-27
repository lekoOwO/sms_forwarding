#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "esp_err.h"
#include "idf_config_ca_store.h"
#include "idf_config.h"
#include "idf_push_cellular.h"

// 獨立憑證工作槽，不是可寄送通知的推送通道。
constexpr uint8_t IDF_PUSH_CA_KEEPALIVE_TARGET = IDF_MAX_PUSH_CHANNELS;
bool idf_push_prepare_keepalive_target(const std::string& url, IdfPushCellularTarget& target);

constexpr size_t IDF_PUSH_CA_CHAIN_MAX = 4;
constexpr size_t IDF_PUSH_CA_ISSUER_DER_MAX = 160;
constexpr size_t IDF_PUSH_CA_AKI_MAX = 32;
constexpr uint32_t IDF_PUSH_CA_SESSION_TTL_MS = 120000;

struct IdfPushCaCertificateMetadata {
    std::array<uint8_t, IDF_CONFIG_CA_SHA256_BYTES> sha256{};
    std::vector<uint8_t> issuerDer;
    std::vector<uint8_t> authorityKeyIdentifier;
};

struct IdfPushCaProbeResult {
    std::string nonce;
    uint32_t expiresInMs = 0;
    std::vector<IdfPushCaCertificateMetadata> chain;
};

esp_err_t idf_push_ca_probe(uint8_t channel, IdfPushCaProbeResult& result);
esp_err_t idf_push_ca_install(uint8_t channel, const std::string& nonce,
                              const uint8_t* der, size_t derLength,
                              IdfConfigCaStatus& status);
esp_err_t idf_push_ca_status(uint8_t channel, IdfConfigCaStatus& status);
