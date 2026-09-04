#include "idf_config_ca_store.h"

#include <algorithm>
#include <array>
#include <cstdio>
#include <cstring>
#include <new>
#include <vector>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/md.h"
#include "nvs.h"
#include "nvs_flash.h"

namespace {

constexpr char kPartition[] = "appcfg";
constexpr char kNamespace[] = "ca_cache";
constexpr uint8_t kCertMagic[] = {'C', 'A', 'D', '1'};
constexpr uint8_t kBindingMagic[] = {'C', 'A', 'B', '1'};
constexpr size_t kConfigReserveEntries = 1100;
constexpr size_t kNvsEntryBytes = 32;
constexpr size_t kCertRecordMax = sizeof(kCertMagic) + IDF_CONFIG_CA_SHA256_BYTES + 2 +
                                  IDF_CONFIG_CA_MAX_DER_BYTES;
constexpr size_t kBindingRecordMax = sizeof(kBindingMagic) + 2 + IDF_CONFIG_CA_MAX_ORIGIN_BYTES +
                                     IDF_CONFIG_CA_SHA256_BYTES;

using Digest = std::array<uint8_t, IDF_CONFIG_CA_SHA256_BYTES>;

struct CertSlot {
    bool present = false;
    size_t index = 0;
    Digest digest{};
    std::vector<uint8_t> der;
};

struct BindingSlot {
    bool present = false;
    size_t index = 0;
    std::string origin;
    Digest digest{};
};

class NvsHandle {
public:
    ~NvsHandle() { if (value_ != 0) nvs_close(value_); }
    nvs_handle_t* output() { return &value_; }
    nvs_handle_t get() const { return value_; }

private:
    nvs_handle_t value_ = 0;
};

bool s_partitionReady = false;
SemaphoreHandle_t s_cacheMutex = nullptr;
StaticSemaphore_t s_cacheMutexStorage;
portMUX_TYPE s_cacheMutexInitLock = portMUX_INITIALIZER_UNLOCKED;

bool ensureCacheMutex()
{
    taskENTER_CRITICAL(&s_cacheMutexInitLock);
    if (!s_cacheMutex) s_cacheMutex = xSemaphoreCreateMutexStatic(&s_cacheMutexStorage);
    taskEXIT_CRITICAL(&s_cacheMutexInitLock);
    return s_cacheMutex != nullptr;
}

class CacheLock {
public:
    CacheLock()
    {
        if (ensureCacheMutex() &&
            xSemaphoreTake(s_cacheMutex, pdMS_TO_TICKS(5000)) == pdTRUE) {
            locked_ = true;
        }
    }

    ~CacheLock()
    {
        if (locked_) xSemaphoreGive(s_cacheMutex);
    }

    bool locked() const { return locked_; }

private:
    bool locked_ = false;
};

void clearStatus(IdfConfigCaStatus* status)
{
    if (status) *status = IdfConfigCaStatus{};
}

void fillStatus(IdfConfigCaStatus* status, size_t derLength, const Digest& digest)
{
    if (!status) return;
    status->configured = true;
    status->derLength = derLength;
    status->sha256 = digest;
}

bool validDnsHost(const std::string& host)
{
    if (host.empty() || host.front() == '.' || host.back() == '.') return false;
    size_t labelStart = 0;
    for (size_t i = 0; i <= host.size(); ++i) {
        if (i != host.size() && host[i] != '.') continue;
        if (i == labelStart || host[labelStart] == '-' || host[i - 1] == '-') return false;
        for (size_t j = labelStart; j < i; ++j) {
            const char ch = host[j];
            if (!((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-')) {
                return false;
            }
        }
        labelStart = i + 1;
    }
    return true;
}

bool validPort(const std::string& port)
{
    if (port.empty() || port.size() > 5) return false;
    unsigned value = 0;
    for (char ch : port) {
        if (ch < '0' || ch > '9') return false;
        value = value * 10U + static_cast<unsigned>(ch - '0');
    }
    return value >= 1 && value <= 65535;
}

bool canonicalOriginValid(const std::string& origin)
{
    constexpr char prefix[] = "https://";
    if (origin.size() <= sizeof(prefix) - 1 || origin.size() > IDF_CONFIG_CA_MAX_ORIGIN_BYTES ||
        origin.compare(0, sizeof(prefix) - 1, prefix) != 0) return false;
    const std::string authority = origin.substr(sizeof(prefix) - 1);
    if (authority.find_first_of("/?#@") != std::string::npos) return false;
    if (authority.front() == '[') {
        const size_t close = authority.find(']');
        if (close == std::string::npos || close == 1) return false;
        for (size_t i = 1; i < close; ++i) {
            const char ch = authority[i];
            if (!((ch >= 'a' && ch <= 'f') || (ch >= '0' && ch <= '9') || ch == ':' || ch == '.')) {
                return false;
            }
        }
        if (close + 1 == authority.size()) return true;
        return authority[close + 1] == ':' && validPort(authority.substr(close + 2));
    }
    const size_t colon = authority.find(':');
    if (colon == std::string::npos) return validDnsHost(authority);
    if (authority.find(':', colon + 1) != std::string::npos) return false;
    return validDnsHost(authority.substr(0, colon)) && validPort(authority.substr(colon + 1));
}

esp_err_t sha256(const uint8_t* data, size_t length, Digest& digest)
{
    const mbedtls_md_info_t* info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    return info && mbedtls_md(info, data, length, digest.data()) == 0
               ? ESP_OK
               : ESP_ERR_INVALID_STATE;
}

void put16(std::vector<uint8_t>& bytes, uint16_t value)
{
    bytes.push_back(static_cast<uint8_t>(value));
    bytes.push_back(static_cast<uint8_t>(value >> 8));
}

uint16_t get16(const uint8_t* bytes)
{
    return static_cast<uint16_t>(bytes[0]) |
           static_cast<uint16_t>(static_cast<uint16_t>(bytes[1]) << 8);
}

std::string slotKey(const char* prefix, size_t index)
{
    char key[8];
    std::snprintf(key, sizeof(key), "%s%u", prefix, static_cast<unsigned>(index));
    return key;
}

esp_err_t ensurePartition()
{
    if (s_partitionReady) return ESP_OK;
    const esp_err_t err = nvs_flash_init_partition(kPartition);
    if (err == ESP_OK) s_partitionReady = true;
    return err;
}

esp_err_t openCache(nvs_open_mode_t mode, NvsHandle& handle)
{
    const esp_err_t err = ensurePartition();
    return err == ESP_OK
               ? nvs_open_from_partition(kPartition, kNamespace, mode, handle.output())
               : err;
}

esp_err_t readBlob(nvs_handle_t nvs, const std::string& key, size_t maximum,
                   std::vector<uint8_t>& output, bool& present)
{
    output.clear();
    size_t length = 0;
    esp_err_t err = nvs_get_blob(nvs, key.c_str(), nullptr, &length);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        present = false;
        return ESP_OK;
    }
    present = true;
    if (err != ESP_OK) return err;
    if (length == 0 || length > maximum) return ESP_ERR_INVALID_STATE;
    output.resize(length);
    err = nvs_get_blob(nvs, key.c_str(), output.data(), &length);
    return err == ESP_OK && length == output.size() ? ESP_OK :
           err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
}

esp_err_t readCert(nvs_handle_t nvs, size_t index, CertSlot& slot)
{
    slot = CertSlot{};
    slot.index = index;
    std::vector<uint8_t> record;
    bool present = false;
    esp_err_t err = readBlob(nvs, slotKey("cert", index), kCertRecordMax, record, present);
    if (err != ESP_OK || !present) return err;
    if (record.size() < sizeof(kCertMagic) + IDF_CONFIG_CA_SHA256_BYTES + 2 ||
        std::memcmp(record.data(), kCertMagic, sizeof(kCertMagic)) != 0) {
        return ESP_ERR_INVALID_STATE;
    }
    std::copy_n(record.data() + sizeof(kCertMagic), slot.digest.size(), slot.digest.begin());
    const size_t lengthOffset = sizeof(kCertMagic) + slot.digest.size();
    const uint16_t derLength = get16(record.data() + lengthOffset);
    const size_t derOffset = lengthOffset + 2;
    if (derLength == 0 || derLength > IDF_CONFIG_CA_MAX_DER_BYTES ||
        record.size() != derOffset + derLength) return ESP_ERR_INVALID_STATE;
    slot.der.assign(record.begin() + static_cast<std::ptrdiff_t>(derOffset), record.end());
    Digest actual{};
    err = sha256(slot.der.data(), slot.der.size(), actual);
    if (err != ESP_OK || actual != slot.digest) return ESP_ERR_INVALID_STATE;
    slot.present = true;
    return ESP_OK;
}

esp_err_t readBinding(nvs_handle_t nvs, size_t index, BindingSlot& slot)
{
    slot = BindingSlot{};
    slot.index = index;
    std::vector<uint8_t> record;
    bool present = false;
    esp_err_t err = readBlob(nvs, slotKey("bind", index), kBindingRecordMax, record, present);
    if (err != ESP_OK || !present) return err;
    if (record.size() < sizeof(kBindingMagic) + 2 + IDF_CONFIG_CA_SHA256_BYTES ||
        std::memcmp(record.data(), kBindingMagic, sizeof(kBindingMagic)) != 0) {
        return ESP_ERR_INVALID_STATE;
    }
    const uint16_t originLength = get16(record.data() + sizeof(kBindingMagic));
    const size_t originOffset = sizeof(kBindingMagic) + 2;
    if (originLength == 0 || originLength > IDF_CONFIG_CA_MAX_ORIGIN_BYTES ||
        record.size() != originOffset + originLength + IDF_CONFIG_CA_SHA256_BYTES ||
        std::memchr(record.data() + originOffset, 0, originLength) != nullptr) {
        return ESP_ERR_INVALID_STATE;
    }
    slot.origin.assign(reinterpret_cast<const char*>(record.data() + originOffset), originLength);
    if (!canonicalOriginValid(slot.origin)) return ESP_ERR_INVALID_STATE;
    std::copy_n(record.data() + originOffset + originLength, slot.digest.size(), slot.digest.begin());
    slot.present = true;
    return ESP_OK;
}

template <typename Slot, size_t Count, typename Reader>
esp_err_t readSlots(nvs_handle_t nvs, std::array<Slot, Count>& slots, Reader reader)
{
    for (size_t i = 0; i < Count; ++i) {
        const esp_err_t err = reader(nvs, i, slots[i]);
        if (err != ESP_OK) return err;
    }
    return ESP_OK;
}

std::vector<uint8_t> encodeCert(const uint8_t* der, size_t derLength, const Digest& digest)
{
    std::vector<uint8_t> record;
    record.reserve(sizeof(kCertMagic) + digest.size() + 2 + derLength);
    record.insert(record.end(), std::begin(kCertMagic), std::end(kCertMagic));
    record.insert(record.end(), digest.begin(), digest.end());
    put16(record, static_cast<uint16_t>(derLength));
    record.insert(record.end(), der, der + derLength);
    return record;
}

std::vector<uint8_t> encodeBinding(const std::string& origin, const Digest& digest)
{
    std::vector<uint8_t> record;
    record.reserve(sizeof(kBindingMagic) + 2 + origin.size() + digest.size());
    record.insert(record.end(), std::begin(kBindingMagic), std::end(kBindingMagic));
    put16(record, static_cast<uint16_t>(origin.size()));
    record.insert(record.end(), origin.begin(), origin.end());
    record.insert(record.end(), digest.begin(), digest.end());
    return record;
}

size_t nvsEntriesFor(size_t bytes)
{
    return 2 + (bytes + kNvsEntryBytes - 1) / kNvsEntryBytes;
}

esp_err_t reserveSpace(size_t certBytes, size_t bindingBytes)
{
    nvs_stats_t stats{};
    const esp_err_t err = nvs_get_stats(kPartition, &stats);
    if (err != ESP_OK) return err;
    const size_t needed = (certBytes ? nvsEntriesFor(certBytes) : 0) + nvsEntriesFor(bindingBytes);
    return stats.free_entries >= kConfigReserveEntries + needed ? ESP_OK : ESP_ERR_NO_MEM;
}

bool referenced(const Digest& digest,
                const std::array<BindingSlot, IDF_CONFIG_CA_BINDING_SLOTS>& bindings)
{
    return std::any_of(bindings.begin(), bindings.end(), [&digest](const BindingSlot& slot) {
        return slot.present && slot.digest == digest;
    });
}

void gcUnreferenced(nvs_handle_t nvs,
                    const std::array<CertSlot, IDF_CONFIG_CA_CERT_SLOTS>& certs,
                    const std::array<BindingSlot, IDF_CONFIG_CA_BINDING_SLOTS>& bindings)
{
    bool changed = false;
    for (const CertSlot& cert : certs) {
        if (!cert.present || referenced(cert.digest, bindings)) continue;
        const esp_err_t err = nvs_erase_key(nvs, slotKey("cert", cert.index).c_str());
        if (err == ESP_OK) changed = true;
    }
    if (changed) (void)nvs_commit(nvs);
}

esp_err_t findBoundCert(const std::string& origin,
                        const std::array<BindingSlot, IDF_CONFIG_CA_BINDING_SLOTS>& bindings,
                        const std::array<CertSlot, IDF_CONFIG_CA_CERT_SLOTS>& certs,
                        const BindingSlot*& binding, const CertSlot*& cert)
{
    binding = nullptr;
    cert = nullptr;
    for (const BindingSlot& candidate : bindings) {
        if (candidate.present && candidate.origin == origin) {
            binding = &candidate;
            break;
        }
    }
    if (!binding) return ESP_ERR_NOT_FOUND;
    for (const CertSlot& candidate : certs) {
        if (candidate.present && candidate.digest == binding->digest) {
            cert = &candidate;
            return ESP_OK;
        }
    }
    return ESP_ERR_INVALID_STATE;
}

}  // namespace

esp_err_t idf_config_ca_lookup(const std::string& canonicalOrigin,
                               std::vector<uint8_t>& der, IdfConfigCaStatus* status)
try {
    der.clear();
    clearStatus(status);
    if (!canonicalOriginValid(canonicalOrigin)) return ESP_ERR_INVALID_ARG;
    CacheLock lock;
    if (!lock.locked()) return ESP_ERR_INVALID_STATE;
    NvsHandle handle;
    esp_err_t err = openCache(NVS_READONLY, handle);
    if (err != ESP_OK) return err == ESP_ERR_NVS_NOT_FOUND ? ESP_ERR_NOT_FOUND : err;
    std::array<BindingSlot, IDF_CONFIG_CA_BINDING_SLOTS> bindings{};
    std::array<CertSlot, IDF_CONFIG_CA_CERT_SLOTS> certs{};
    err = readSlots(handle.get(), bindings, readBinding);
    if (err == ESP_OK) err = readSlots(handle.get(), certs, readCert);
    if (err != ESP_OK) return err;
    const BindingSlot* binding = nullptr;
    const CertSlot* cert = nullptr;
    err = findBoundCert(canonicalOrigin, bindings, certs, binding, cert);
    if (err != ESP_OK) return err;
    der = cert->der;
    fillStatus(status, der.size(), cert->digest);
    return ESP_OK;
} catch (const std::bad_alloc&) {
    der.clear();
    clearStatus(status);
    return ESP_ERR_NO_MEM;
}

esp_err_t idf_config_ca_status(const std::string& canonicalOrigin, IdfConfigCaStatus& status)
{
    std::vector<uint8_t> der;
    return idf_config_ca_lookup(canonicalOrigin, der, &status);
}

esp_err_t idf_config_ca_install(const std::string& canonicalOrigin,
                                const uint8_t* der, size_t derLength,
                                IdfConfigCaStatus* status)
try {
    clearStatus(status);
    if (!canonicalOriginValid(canonicalOrigin) || !der) return ESP_ERR_INVALID_ARG;
    if (derLength == 0 || derLength > IDF_CONFIG_CA_MAX_DER_BYTES) return ESP_ERR_INVALID_SIZE;
    Digest digest{};
    esp_err_t err = sha256(der, derLength, digest);
    if (err != ESP_OK) return err;

    CacheLock lock;
    if (!lock.locked()) return ESP_ERR_INVALID_STATE;
    NvsHandle handle;
    err = openCache(NVS_READWRITE, handle);
    if (err != ESP_OK) return err;
    std::array<BindingSlot, IDF_CONFIG_CA_BINDING_SLOTS> bindings{};
    std::array<CertSlot, IDF_CONFIG_CA_CERT_SLOTS> certs{};
    err = readSlots(handle.get(), bindings, readBinding);
    if (err == ESP_OK) err = readSlots(handle.get(), certs, readCert);
    if (err != ESP_OK) return err;

    BindingSlot* binding = nullptr;
    for (BindingSlot& candidate : bindings) {
        if (candidate.present && candidate.origin == canonicalOrigin) binding = &candidate;
    }
    if (!binding) {
        for (BindingSlot& candidate : bindings) {
            if (!candidate.present) { binding = &candidate; break; }
        }
    }
    if (!binding) return ESP_ERR_NO_MEM;

    CertSlot* cert = nullptr;
    for (CertSlot& candidate : certs) {
        if (candidate.present && candidate.digest == digest) { cert = &candidate; break; }
    }
    if (!cert) {
        for (CertSlot& candidate : certs) {
            if (!candidate.present) { cert = &candidate; break; }
        }
    }
    if (!cert) {
        for (CertSlot& candidate : certs) {
            if (!referenced(candidate.digest, bindings)) { cert = &candidate; break; }
        }
    }
    if (!cert) return ESP_ERR_NO_MEM;

    std::vector<uint8_t> certRecord;
    const bool mustStageCert = !cert->present || cert->digest != digest;
    if (mustStageCert) certRecord = encodeCert(der, derLength, digest);
    const std::vector<uint8_t> bindingRecord = encodeBinding(canonicalOrigin, digest);
    err = reserveSpace(mustStageCert ? certRecord.size() : 0, bindingRecord.size());
    if (err != ESP_OK) return err;

    if (mustStageCert) {
        const std::string key = slotKey("cert", cert->index);
        err = nvs_set_blob(handle.get(), key.c_str(), certRecord.data(), certRecord.size());
        if (err == ESP_OK) err = nvs_commit(handle.get());
        CertSlot checked;
        if (err == ESP_OK) err = readCert(handle.get(), cert->index, checked);
        if (err != ESP_OK || !checked.present || checked.digest != digest || checked.der.size() != derLength ||
            std::memcmp(checked.der.data(), der, derLength) != 0) {
            (void)nvs_erase_key(handle.get(), key.c_str());
            (void)nvs_commit(handle.get());
            return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
        }
        *cert = std::move(checked);
    }

    const std::string bindingKey = slotKey("bind", binding->index);
    err = nvs_set_blob(handle.get(), bindingKey.c_str(), bindingRecord.data(), bindingRecord.size());
    if (err == ESP_OK) err = nvs_commit(handle.get());
    BindingSlot checkedBinding;
    if (err == ESP_OK) err = readBinding(handle.get(), binding->index, checkedBinding);
    if (err != ESP_OK || !checkedBinding.present || checkedBinding.origin != canonicalOrigin ||
        checkedBinding.digest != digest) return err == ESP_OK ? ESP_ERR_INVALID_STATE : err;
    *binding = std::move(checkedBinding);
    gcUnreferenced(handle.get(), certs, bindings);
    fillStatus(status, derLength, digest);
    return ESP_OK;
} catch (const std::bad_alloc&) {
    clearStatus(status);
    return ESP_ERR_NO_MEM;
}
