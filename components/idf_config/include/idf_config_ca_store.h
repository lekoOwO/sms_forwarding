#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "esp_err.h"

constexpr size_t IDF_CONFIG_CA_SHA256_BYTES = 32;
constexpr size_t IDF_CONFIG_CA_MAX_DER_BYTES = 8192;
constexpr size_t IDF_CONFIG_CA_MAX_ORIGIN_BYTES = 512;
constexpr size_t IDF_CONFIG_CA_CERT_SLOTS = 6;
constexpr size_t IDF_CONFIG_CA_BINDING_SLOTS = 5;

struct IdfConfigCaStatus {
    bool configured = false;
    size_t derLength = 0;
    std::array<uint8_t, IDF_CONFIG_CA_SHA256_BYTES> sha256{};
};

// Origins are canonical HTTPS origins: https://host or https://host:port,
// with no path, query, fragment, userinfo, uppercase ASCII, or trailing slash.
// A miss clears all outputs and returns ESP_ERR_NOT_FOUND.
esp_err_t idf_config_ca_lookup(const std::string& canonicalOrigin,
                               std::vector<uint8_t>& der,
                               IdfConfigCaStatus* status = nullptr);

// The DER is content-addressed by its complete SHA-256. The certificate is
// committed and read back before the origin binding is changed.
esp_err_t idf_config_ca_install(const std::string& canonicalOrigin,
                                const uint8_t* der, size_t derLength,
                                IdfConfigCaStatus* status = nullptr);

esp_err_t idf_config_ca_status(const std::string& canonicalOrigin,
                               IdfConfigCaStatus& status);
