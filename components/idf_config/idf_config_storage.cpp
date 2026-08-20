#include "idf_config_storage.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <limits>
#include <memory>
#include <new>
#include <utility>
#include <vector>

#include "config_schema_generated.h"
#include "esp_log.h"
#include "nvs.h"
#include "nvs_flash.h"

#if IDF_HAS_WIFI_CONFIG_H
#include "wifi_config.h"
#else
#define WIFI_SSID ""
#define WIFI_PASS ""
#endif

namespace {

constexpr char kPartition[] = "appcfg";
constexpr char kNamespace[] = "config";
constexpr char kBlobKeys[][5] = {"cfgA", "cfgB"};
constexpr char kMarkerKeys[][6] = {"markA", "markB"};
constexpr char kStateKey[] = "state";
constexpr uint32_t kConfigMagic = 0x32474643U;  // CFG2
constexpr uint32_t kMarkerMagic = 0x324B524DU;  // MRK2
constexpr size_t kHeaderBytes = 20;
// MRK2 is intentionally kept at the shipped 20-byte layout.  The CFG2 blob
// header is authoritative for schema; the marker only authenticates the
// generation, blob length, and blob CRC before selecting a slot.
constexpr size_t kMarkerBytes = 20;
constexpr uint8_t CONFIG_STATE_MIGRATING = 1;
constexpr uint8_t CONFIG_STATE_READY = 2;

enum class DecodeResult : uint8_t {
    Invalid,
    Unsupported,
    Valid,
};

struct Slot {
    bool blobPresent = false;
    bool markerPresent = false;
    bool resumableBlob = false;
    bool hardInvalid = false;
    bool unsupported = false;
    bool valid = false;
    uint16_t schema = 0;
    uint32_t generation = 0;
};

int s_activeSlot = -1;
uint32_t s_activeGeneration = 0;
bool s_partitionReady = false;

uint32_t crc32(const uint8_t* data, size_t length)
{
    uint32_t crc = 0xFFFFFFFFU;
    for (size_t i = 0; i < length; ++i) {
        crc ^= data[i];
        for (uint8_t bit = 0; bit < 8; ++bit) {
            crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
        }
    }
    return ~crc;
}

class Writer {
public:
    void u8(uint8_t value) { bytes_.push_back(value); }

    void u16(uint16_t value)
    {
        bytes_.push_back(static_cast<uint8_t>(value));
        bytes_.push_back(static_cast<uint8_t>(value >> 8));
    }

    void u32(uint32_t value)
    {
        for (uint8_t shift = 0; shift < 32; shift += 8) {
            bytes_.push_back(static_cast<uint8_t>(value >> shift));
        }
    }

    void bytes(const uint8_t* data, size_t length) { bytes_.insert(bytes_.end(), data, data + length); }

    void text(const char* value, size_t length)
    {
        u16(static_cast<uint16_t>(length));
        bytes(reinterpret_cast<const uint8_t*>(value), length);
    }

    void string(const std::string& value) { text(value.data(), value.size()); }

    std::vector<uint8_t> take() { return std::move(bytes_); }

private:
    std::vector<uint8_t> bytes_;
};

class FixedWriter {
public:
    FixedWriter(uint8_t* output, size_t capacity) : output_(output), capacity_(capacity) {}

    void u8(uint8_t value) { bytes(&value, 1); }

    void u16(uint16_t value)
    {
        uint8_t encoded[2] = {static_cast<uint8_t>(value), static_cast<uint8_t>(value >> 8)};
        bytes(encoded, sizeof(encoded));
    }

    void u32(uint32_t value)
    {
        uint8_t encoded[4];
        for (uint8_t shift = 0; shift < 32; shift += 8) {
            encoded[shift / 8] = static_cast<uint8_t>(value >> shift);
        }
        bytes(encoded, sizeof(encoded));
    }

    void bytes(const uint8_t* data, size_t length)
    {
        if (!ok_ || length > capacity_ - size_) {
            ok_ = false;
            return;
        }
        if (length > 0) std::memcpy(output_ + size_, data, length);
        size_ += length;
    }

    void text(const char* value, size_t length)
    {
        if (length > UINT16_MAX) {
            ok_ = false;
            return;
        }
        u16(static_cast<uint16_t>(length));
        bytes(reinterpret_cast<const uint8_t*>(value), length);
    }

    void string(const std::string& value) { text(value.data(), value.size()); }
    bool ok() const { return ok_; }
    size_t size() const { return size_; }

private:
    uint8_t* output_;
    size_t capacity_;
    size_t size_ = 0;
    bool ok_ = true;
};

class Reader {
public:
    Reader(const uint8_t* begin, const uint8_t* end) : cursor_(begin), end_(end) {}

    bool u8(uint8_t& value)
    {
        if (cursor_ >= end_) return false;
        value = *cursor_++;
        return true;
    }

    bool u16(uint16_t& value)
    {
        if (static_cast<size_t>(end_ - cursor_) < 2) return false;
        value = static_cast<uint16_t>(cursor_[0]) |
                static_cast<uint16_t>(static_cast<uint16_t>(cursor_[1]) << 8);
        cursor_ += 2;
        return true;
    }

    bool u32(uint32_t& value)
    {
        if (static_cast<size_t>(end_ - cursor_) < 4) return false;
        value = static_cast<uint32_t>(cursor_[0]) |
                (static_cast<uint32_t>(cursor_[1]) << 8) |
                (static_cast<uint32_t>(cursor_[2]) << 16) |
                (static_cast<uint32_t>(cursor_[3]) << 24);
        cursor_ += 4;
        return true;
    }

    bool i32(int& value)
    {
        uint32_t raw = 0;
        if (!u32(raw)) return false;
        value = static_cast<int>(static_cast<int32_t>(raw));
        return true;
    }

    bool string(std::string& value, size_t maxBytes)
    {
        uint16_t length = 0;
        if (!u16(length) || length > maxBytes || static_cast<size_t>(end_ - cursor_) < length) {
            return false;
        }
        if (std::memchr(cursor_, 0, length) != nullptr) return false;
        value.assign(reinterpret_cast<const char*>(cursor_), length);
        cursor_ += length;
        return true;
    }

    bool atEnd() const { return cursor_ == end_; }

private:
    const uint8_t* cursor_;
    const uint8_t* end_;
};

bool validUtf8(const std::string& value)
{
    for (size_t i = 0; i < value.size();) {
        const uint8_t ch = static_cast<uint8_t>(value[i]);
        if (ch <= 0x7FU) {
            ++i;
            continue;
        }
        size_t extra = 0;
        uint32_t codepoint = 0;
        if ((ch & 0xE0U) == 0xC0U) {
            // C0/C1 are never valid UTF-8 lead bytes: both encode an
            // overlong two-byte sequence, and C1 must not be accepted as a
            // permissive Latin-1 control byte.
            if (ch <= 0xC1U) return false;
            extra = 1;
            codepoint = ch & 0x1FU;
            if (codepoint == 0) return false;
        } else if ((ch & 0xF0U) == 0xE0U) {
            extra = 2;
            codepoint = ch & 0x0FU;
        } else if ((ch & 0xF8U) == 0xF0U) {
            extra = 3;
            codepoint = ch & 0x07U;
        } else {
            return false;
        }
        if (i + extra >= value.size()) return false;
        for (size_t j = 1; j <= extra; ++j) {
            const uint8_t tail = static_cast<uint8_t>(value[i + j]);
            if ((tail & 0xC0U) != 0x80U) return false;
            codepoint = (codepoint << 6) | (tail & 0x3FU);
        }
        if ((extra == 2 && codepoint < 0x800U) ||
            (extra == 3 && codepoint < 0x10000U) || codepoint > 0x10FFFFU ||
            (codepoint >= 0xD800U && codepoint <= 0xDFFFU)) {
            return false;
        }
        i += extra + 1;
    }
    return true;
}

bool bounded(const std::string& value, size_t maxBytes, bool controls = true)
{
    if (value.size() > maxBytes || value.find('\0') != std::string::npos || !validUtf8(value)) return false;
    if (controls) {
        if (!std::all_of(value.begin(), value.end(), [](unsigned char ch) {
                return ch >= 0x20U && ch != 0x7FU;
            })) return false;
    }
    return true;
}

bool hostnameValid(const std::string& value)
{
    if (value.empty() || value.size() > MAX_HOSTNAME_LENGTH ||
        value.front() == '-' || value.back() == '-') return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-';
    });
}

bool wifiPasswordValid(const std::string& value)
{
    if (value.empty()) return true;
    if (value.size() < 8 || value.size() > MAX_WIFI_PASSWORD_BYTES) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return ch >= 0x20U && ch <= 0x7EU;
    });
}

bool digits(const std::string& value, size_t minLength, size_t maxLength)
{
    if (value.size() < minLength || value.size() > maxLength) return false;
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) { return ch >= '0' && ch <= '9'; });
}

bool txPowerValid(uint8_t value)
{
    return value == 8 || value == 20 || value == 28 || value == 34 || value == 44 ||
           value == 52 || value == 56 || value == 60 || value == 66 || value == 72 || value == 80;
}

void syncLegacyMirrors(IdfConfig& value)
{
    value.mdnsHost = value.hostname;
    value.hbEnabled = value.heartbeatEnable;
    if (!value.webAccounts[0].username.empty()) value.webUser = value.webAccounts[0].username;
    if (!value.webAccounts[0].password.empty()) value.webPass = value.webAccounts[0].password;
}

IdfConfig defaults()
{
    IdfConfig value;
    value.roamingEnabled = false;
    value.webAccounts[0].username = IDF_DEFAULT_WEB_USER;
    value.webAccounts[0].password = IDF_DEFAULT_WEB_PASS;
    value.hostname = "sms";
    value.mdnsHost = value.hostname;
    value.heartbeatEnable = true;
    value.heartbeatInterval = DEFAULT_HEARTBEAT_INTERVAL_HOURS;
    value.hbEnabled = value.heartbeatEnable;
    value.kaTrafficKB = DEFAULT_KEEPALIVE_TRAFFIC_KB;
    value.hbHour = 9;
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        char name[24];
        snprintf(name, sizeof(name), "Channel %d", i + 1);
        value.pushChannels[i].name = name;
    }
    return value;
}

bool semanticallyValid(const IdfConfig& value, bool portable = false)
{
    if (value.smtpPort < 1 || value.smtpPort > 65535 || value.networkMode < NETWORK_MODE_WIFI_ONLY ||
        value.networkMode > NETWORK_MODE_MIX || value.heartbeatInterval < MIN_HEARTBEAT_INTERVAL_HOURS ||
        value.heartbeatInterval > MAX_HEARTBEAT_INTERVAL_HOURS ||
        (!portable && !txPowerValid(value.wifiTxPowerQuarterDbm)) ||
        value.kaIntervalDays < 1 || value.kaIntervalDays > 3650 || value.kaAction > 3 ||
        value.kaTrafficKB < MIN_KEEPALIVE_TRAFFIC_KB || value.kaTrafficKB > MAX_KEEPALIVE_TRAFFIC_KB ||
        value.tzOffsetMin < -720 || value.tzOffsetMin > 840 || value.rebootHour < 0 || value.rebootHour > 23 ||
        value.smsHealthHour < 0 || value.smsHealthHour > 23) {
        return false;
    }
    if ((!portable && (value.deviceName.empty() || !bounded(value.deviceName, MAX_DEVICE_NAME_BYTES) ||
        !hostnameValid(value.hostname))) ||
        (value.notificationLocale != NOTIFICATION_LOCALE_ZH_TW &&
         value.notificationLocale != NOTIFICATION_LOCALE_ZH_CN &&
         value.notificationLocale != NOTIFICATION_LOCALE_EN)) {
        return false;
    }
    if (!bounded(value.notificationLocale, MAX_NOTIFICATION_LOCALE_BYTES) ||
        !bounded(value.smtpServer, MAX_SMTP_SERVER_BYTES) || !bounded(value.smtpUser, MAX_SMTP_USER_BYTES) ||
        !bounded(value.smtpPass, MAX_SMTP_PASSWORD_BYTES) || !bounded(value.smtpSendTo, MAX_SMTP_RECIPIENT_BYTES) ||
        !bounded(value.adminPhone, MAX_ADMIN_PHONE_BYTES) || !bounded(value.numberBlackList, MAX_BLACKLIST_BYTES, false) ||
        !bounded(value.forwardRules, MAX_FORWARD_RULES_BYTES, false) || !bounded(value.ntpServer, MAX_NTP_SERVER_BYTES) ||
        !bounded(value.apn, MAX_APN_BYTES) || !bounded(value.operatorPlmn, MAX_OPERATOR_PLMN_BYTES) ||
        (!portable && !bounded(value.phoneNumber, MAX_PHONE_NUMBER_BYTES))) {
        return false;
    }
    for (int i = 0; !portable && i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        if (!bounded(value.webAccounts[i].username, MAX_WEB_USERNAME_BYTES) ||
            !bounded(value.webAccounts[i].password, MAX_WEB_PASSWORD_BYTES)) return false;
    }
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        const IdfPushChannel& channel = value.pushChannels[i];
        if (channel.type < PUSH_TYPE_POST_JSON || channel.type > PUSH_TYPE_NTFY ||
            !bounded(channel.name, MAX_PUSH_NAME_BYTES) ||
            !bounded(channel.url, MAX_PUSH_URL_BYTES) || !bounded(channel.key1, MAX_PUSH_KEY1_BYTES) ||
            !bounded(channel.key2, MAX_PUSH_KEY2_BYTES) || !bounded(channel.titleTemplate, MAX_TITLE_TEMPLATE_BYTES) ||
            !bounded(channel.bodyTemplate, MAX_BODY_TEMPLATE_BYTES, false) ||
            !bounded(channel.customBody, MAX_CUSTOM_BODY_BYTES, false)) return false;
        const bool invalidTemplates = channel.type == PUSH_TYPE_CUSTOM
                                          ? (!channel.titleTemplate.empty() || !channel.bodyTemplate.empty())
                                          : !channel.customBody.empty();
        if (channel.titleTemplate.find('\r') != std::string::npos ||
            channel.titleTemplate.find('\n') != std::string::npos || invalidTemplates) {
            return false;
        }
    }
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        const IdfWifiNetwork& profile = value.wifiNetworks[i];
        if (!bounded(profile.ssid, MAX_WIFI_SSID_BYTES) || !wifiPasswordValid(profile.pass) ||
            (profile.ssid.empty() && !profile.pass.empty())) return false;
    }
    for (int i = 0; !portable && i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        const IdfSimCredential& item = value.simCredentials[i];
        if (!item.iccid.empty() && !digits(item.iccid, 15, MAX_SIM_ICCID_BYTES)) return false;
        if (!item.pin.empty() && !digits(item.pin, 4, MAX_SIM_PIN_BYTES)) return false;
        if (!item.puk.empty() && !digits(item.puk, 8, MAX_SIM_PUK_BYTES)) return false;
        if (item.pinMaxAttempts < 1 || item.pinMaxAttempts > 2 || item.pukMaxAttempts < 1 ||
            item.pukMaxAttempts > 5 || item.pinFailedAttempts > item.pinMaxAttempts ||
            item.pukFailedAttempts > item.pukMaxAttempts) return false;
        for (int j = 0; j < i; ++j) {
            if (!item.iccid.empty() && item.iccid == value.simCredentials[j].iccid) return false;
        }
    }
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        const IdfSchedTask& task = value.schedTasks[i];
        if (!bounded(task.name, MAX_SCHEDULE_NAME_BYTES) ||
            (!portable && !bounded(task.profile, MAX_SCHEDULE_PROFILE_BYTES)) ||
            !bounded(task.target, MAX_SCHEDULE_TARGET_BYTES) || !bounded(task.payload, MAX_SCHEDULE_PAYLOAD_BYTES) ||
            task.intervalDays < 1 || task.intervalDays > 3650 || task.action > 3) return false;
    }
    return true;
}

void writeHeader(std::vector<uint8_t>& blob, uint16_t schema, uint32_t generation, size_t payloadOffset)
{
    auto put16 = [&blob](size_t offset, uint16_t value) {
        blob[offset] = static_cast<uint8_t>(value);
        blob[offset + 1] = static_cast<uint8_t>(value >> 8);
    };
    auto put32 = [&blob](size_t offset, uint32_t value) {
        for (uint8_t shift = 0; shift < 32; shift += 8) blob[offset + shift / 8] = static_cast<uint8_t>(value >> shift);
    };
    put32(0, kConfigMagic);
    put16(4, schema);
    put16(6, 0);
    put32(8, generation);
    put32(12, static_cast<uint32_t>(blob.size() - payloadOffset));
    put32(16, crc32(blob.data() + payloadOffset, blob.size() - payloadOffset));
}

void writeHeader(uint8_t* blob, size_t blobSize, uint16_t schema, uint32_t generation,
                 size_t payloadOffset)
{
    auto put16 = [blob](size_t offset, uint16_t value) {
        blob[offset] = static_cast<uint8_t>(value);
        blob[offset + 1] = static_cast<uint8_t>(value >> 8);
    };
    auto put32 = [blob](size_t offset, uint32_t value) {
        for (uint8_t shift = 0; shift < 32; shift += 8) {
            blob[offset + shift / 8] = static_cast<uint8_t>(value >> shift);
        }
    };
    put32(0, kConfigMagic);
    put16(4, schema);
    put16(6, 0);
    put32(8, generation);
    put32(12, static_cast<uint32_t>(blobSize - payloadOffset));
    put32(16, crc32(blob + payloadOffset, blobSize - payloadOffset));
}

void writeMarker(std::vector<uint8_t>& marker, uint16_t schema, uint32_t generation,
                 uint32_t blobLength, uint32_t blobCrc)
{
    (void)schema;
    marker.assign(kMarkerBytes, 0);
    auto put32 = [&marker](size_t offset, uint32_t value) {
        for (uint8_t shift = 0; shift < 32; shift += 8) marker[offset + shift / 8] = static_cast<uint8_t>(value >> shift);
    };
    put32(0, kMarkerMagic);
    put32(4, generation);
    put32(8, blobLength);
    put32(12, blobCrc);
    put32(16, crc32(marker.data(), kMarkerBytes - 4));
}

bool readMarker(const std::vector<uint8_t>& marker, uint16_t& schema, uint32_t& generation,
                uint32_t& blobLength, uint32_t& blobCrc)
{
    if (marker.size() != kMarkerBytes) return false;
    auto get32 = [&marker](size_t offset) {
        return static_cast<uint32_t>(marker[offset]) | (static_cast<uint32_t>(marker[offset + 1]) << 8) |
               (static_cast<uint32_t>(marker[offset + 2]) << 16) |
               (static_cast<uint32_t>(marker[offset + 3]) << 24);
    };
    if (get32(0) != kMarkerMagic || get32(16) != crc32(marker.data(), kMarkerBytes - 4)) return false;
    schema = 0;
    generation = get32(4);
    blobLength = get32(8);
    blobCrc = get32(12);
    return true;
}

bool readLegacyString(nvs_handle_t nvs, const char* key, std::string& value, size_t maxBytes)
{
    size_t length = 0;
    esp_err_t err = nvs_get_str(nvs, key, nullptr, &length);
    if (err == ESP_ERR_NVS_NOT_FOUND) return true;
    if (err != ESP_OK || length == 0 || length - 1 > maxBytes) return false;
    std::string result(length, '\0');
    if (nvs_get_str(nvs, key, result.data(), &length) != ESP_OK) return false;
    result.resize(length > 0 ? length - 1 : 0);
    if (!bounded(result, maxBytes, false)) return false;
    value = std::move(result);
    return true;
}

bool legacyStringPresent(nvs_handle_t nvs, const char* key, bool& present)
{
    size_t length = 0;
    const esp_err_t err = nvs_get_str(nvs, key, nullptr, &length);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        present = false;
        return true;
    }
    present = err == ESP_OK;
    return present && length > 0;
}

bool overlayLegacyWifiProfile(nvs_handle_t nvs, IdfConfig& value, int index,
                              const char* ssidKey, const char* passwordKey, bool alias)
{
    bool ssidPresent = false;
    bool passwordPresent = false;
    if (!legacyStringPresent(nvs, ssidKey, ssidPresent) ||
        !legacyStringPresent(nvs, passwordKey, passwordPresent)) return false;
    if (alias && !ssidPresent) return true;
    if (!ssidPresent && !passwordPresent) return true;
    std::string ssid;
    std::string password;
    if (!readLegacyString(nvs, ssidKey, ssid, MAX_WIFI_SSID_BYTES) ||
        !readLegacyString(nvs, passwordKey, password, MAX_WIFI_PASSWORD_BYTES)) return false;
    if (ssid.empty() && password.empty()) return true;
    if (!bounded(ssid, MAX_WIFI_SSID_BYTES) || !wifiPasswordValid(password) ||
        (ssid.empty() && !password.empty())) return false;
    value.wifiNetworks[index] = {std::move(ssid), std::move(password)};
    return true;
}

bool readLegacyI32(nvs_handle_t nvs, const char* key, int& value, int fallback)
{
    int32_t result = 0;
    esp_err_t err = nvs_get_i32(nvs, key, &result);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        value = fallback;
        return true;
    }
    if (err != ESP_OK || result < std::numeric_limits<int>::min() || result > std::numeric_limits<int>::max()) return false;
    value = static_cast<int>(result);
    return true;
}

bool readLegacyU8(nvs_handle_t nvs, const char* key, uint8_t& value, uint8_t fallback)
{
    uint8_t result = 0;
    esp_err_t err = nvs_get_u8(nvs, key, &result);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        value = fallback;
        return true;
    }
    if (err != ESP_OK) return false;
    value = result;
    return true;
}

bool readLegacyBool(nvs_handle_t nvs, const char* key, bool& value, bool fallback)
{
    uint8_t result = 0;
    esp_err_t err = nvs_get_u8(nvs, key, &result);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        value = fallback;
        return true;
    }
    if (err != ESP_OK || result > 1) return false;
    value = result != 0;
    return true;
}

bool readLegacyI32Alias(nvs_handle_t nvs, const char* currentKey, const char* legacyKey,
                        int& value, int fallback)
{
    int32_t result = 0;
    const esp_err_t err = nvs_get_i32(nvs, currentKey, &result);
    if (err == ESP_ERR_NVS_NOT_FOUND) return readLegacyI32(nvs, legacyKey, value, fallback);
    if (err != ESP_OK || result < std::numeric_limits<int>::min() ||
        result > std::numeric_limits<int>::max()) return false;
    value = static_cast<int>(result);
    return true;
}

bool readLegacyBoolAlias(nvs_handle_t nvs, const char* currentKey, const char* legacyKey,
                         bool& value, bool fallback)
{
    uint8_t result = 0;
    const esp_err_t err = nvs_get_u8(nvs, currentKey, &result);
    if (err == ESP_ERR_NVS_NOT_FOUND) return readLegacyBool(nvs, legacyKey, value, fallback);
    if (err != ESP_OK || result > 1) return false;
    value = result != 0;
    return true;
}

bool readLegacyU32Alias(nvs_handle_t nvs, const char* currentKey, const char* legacyKey,
                        uint32_t& value, uint32_t fallback)
{
    uint32_t result = 0;
    esp_err_t err = nvs_get_u32(nvs, currentKey, &result);
    if (err == ESP_ERR_NVS_NOT_FOUND) err = nvs_get_u32(nvs, legacyKey, &result);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        value = fallback;
        return true;
    }
    if (err != ESP_OK) return false;
    value = result;
    return true;
}

bool readLegacyConnectivity(nvs_handle_t nvs, IdfConfig& value)
{
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        char ssidKey[20];
        char passwordKey[20];
        snprintf(ssidKey, sizeof(ssidKey), i == 0 ? "wifiSsid" : "wifi%dSsid", i);
        snprintf(passwordKey, sizeof(passwordKey), i == 0 ? "wifiPass" : "wifi%dPass", i);
        // Slot 0 shares wifiPass with the develop alias wifiSSID; defer an
        // otherwise orphaned password until that alias is checked below.
        if (!overlayLegacyWifiProfile(nvs, value, i, ssidKey, passwordKey, i == 0)) return false;
    }
    if (!overlayLegacyWifiProfile(nvs, value, 0, "wifiSSID", "wifiPass", true) ||
        !overlayLegacyWifiProfile(nvs, value, 1, "wifiSSID2", "wifiPass2", true)) return false;

    int networkMode = value.networkMode;
    if (!readLegacyI32(nvs, "networkMode", networkMode, value.networkMode) ||
        networkMode < NETWORK_MODE_WIFI_ONLY || networkMode > NETWORK_MODE_MIX) return false;
    value.networkMode = networkMode;

    bool heartbeatEnable = value.heartbeatEnable;
    if (!readLegacyBool(nvs, "heartbeatEnable", heartbeatEnable, value.heartbeatEnable)) return false;
    value.heartbeatEnable = heartbeatEnable;
    value.hbEnabled = heartbeatEnable;

    int heartbeatInterval = value.heartbeatInterval;
    if (!readLegacyI32(nvs, "heartbeatInterval", heartbeatInterval, value.heartbeatInterval) ||
        heartbeatInterval < MIN_HEARTBEAT_INTERVAL_HOURS ||
        heartbeatInterval > MAX_HEARTBEAT_INTERVAL_HOURS) return false;
    value.heartbeatInterval = heartbeatInterval;
    return true;
}

bool overlayLegacyConnectivity(IdfConfig& value)
{
    nvs_handle_t nvs = 0;
    const esp_err_t err = nvs_open("sms_config", NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) return true;
    if (err != ESP_OK) return false;

    const bool ok = readLegacyConnectivity(nvs, value);
    nvs_close(nvs);
    return ok;
}

bool loadLegacy(IdfConfig& value, bool& existed)
{
    value = defaults();
    nvs_handle_t nvs = 0;
    esp_err_t err = nvs_open("sms_config", NVS_READONLY, &nvs);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        existed = false;
        if (WIFI_SSID[0]) {
            value.wifiNetworks[0].ssid = WIFI_SSID;
            value.wifiNetworks[0].pass = WIFI_PASS;
            value.wifiFromFallback = true;
        }
        return semanticallyValid(value);
    }
    if (err != ESP_OK) return false;
    existed = true;

    bool ok = true;
    auto str = [&](const char* key, std::string& out, size_t maxBytes) {
        if (ok) ok = readLegacyString(nvs, key, out, maxBytes);
    };
    auto integer = [&](const char* key, int& out, int fallback) {
        if (ok) ok = readLegacyI32(nvs, key, out, fallback);
    };
    auto byte = [&](const char* key, uint8_t& out, uint8_t fallback) {
        if (ok) ok = readLegacyU8(nvs, key, out, fallback);
    };
    auto boolean = [&](const char* key, bool& out, bool fallback) {
        if (ok) ok = readLegacyBool(nvs, key, out, fallback);
    };

    if (ok) ok = readLegacyConnectivity(nvs, value);
    byte("wifiTxPwr", value.wifiTxPowerQuarterDbm, 34);
    integer("smtpPort", value.smtpPort, 465);
    str("smtpServer", value.smtpServer, MAX_SMTP_SERVER_BYTES);
    str("smtpUser", value.smtpUser, MAX_SMTP_USER_BYTES);
    str("smtpPass", value.smtpPass, MAX_SMTP_PASSWORD_BYTES);
    str("smtpSendTo", value.smtpSendTo, MAX_SMTP_RECIPIENT_BYTES);
    str("adminPhone", value.adminPhone, MAX_ADMIN_PHONE_BYTES);
    str("numBlkList", value.numberBlackList, MAX_BLACKLIST_BYTES);
    str("fwdRules", value.forwardRules, MAX_FORWARD_RULES_BYTES);
    std::string remark;
    str("remark", remark, MAX_DEVICE_NAME_BYTES);
    if (!remark.empty() && bounded(remark, MAX_DEVICE_NAME_BYTES)) value.deviceName = remark;

    bool hasAccountList = false;
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        char key[28];
        bool present = false;
        snprintf(key, sizeof(key), "account%duser", i);
        if (!legacyStringPresent(nvs, key, present)) ok = false;
        hasAccountList = hasAccountList || present;
    }
    if (hasAccountList) {
        for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
            value.webAccounts[i] = IdfWebAccount();
            char key[28];
            snprintf(key, sizeof(key), "account%duser", i);
            str(key, value.webAccounts[i].username, MAX_WEB_USERNAME_BYTES);
            snprintf(key, sizeof(key), "account%dpass", i);
            str(key, value.webAccounts[i].password, MAX_WEB_PASSWORD_BYTES);
        }
    } else {
        str("webUser", value.webAccounts[0].username, MAX_WEB_USERNAME_BYTES);
        str("webPass", value.webAccounts[0].password, MAX_WEB_PASSWORD_BYTES);
    }
    if (!hasAccountList) {
        if (value.webAccounts[0].username.empty()) value.webAccounts[0].username = IDF_DEFAULT_WEB_USER;
        if (value.webAccounts[0].password.empty()) value.webAccounts[0].password = IDF_DEFAULT_WEB_PASS;
    }
    boolean("emailEn", value.emailEnabled, true);
    boolean("pushEn", value.pushEnabled, true);
    if (ok) ok = readLegacyBoolAlias(nvs, "kaEn", "kaEnable", value.kaEnabled, false);
    if (ok) ok = readLegacyI32Alias(nvs, "kaDays", "kaIntervalDays", value.kaIntervalDays, 175);
    integer("kaTraffic", value.kaTrafficKB, DEFAULT_KEEPALIVE_TRAFFIC_KB);
    byte("kaAct", value.kaAction, 1);
    str("kaTarget", value.kaTarget, MAX_KEEPALIVE_TARGET_BYTES);
    str("kaUrl", value.kaUrl, MAX_KEEPALIVE_URL_BYTES);
    str("kaProfile", value.kaProfile, MAX_KEEPALIVE_PROFILE_BYTES);
    if (ok) ok = readLegacyU32Alias(nvs, "kaLast", "kaBaseDate", value.kaLastTime, value.kaLastTime);
    integer("tzMin", value.tzOffsetMin, 480);
    boolean("roamEn", value.roamingEnabled, false);
    str("apn", value.apn, MAX_APN_BYTES);
    str("opPlmn", value.operatorPlmn, MAX_OPERATOR_PLMN_BYTES);
    str("phoneNum", value.phoneNumber, MAX_PHONE_NUMBER_BYTES);
    str("ntpSrv", value.ntpServer, MAX_NTP_SERVER_BYTES);
    str("mdnsHost", value.hostname, MAX_HOSTNAME_LENGTH);
    boolean("rbEn", value.rebootEnabled, false);
    integer("rbHour", value.rebootHour, 4);
    boolean("hbEn", value.heartbeatEnable, value.heartbeatEnable);
    int oldHeartbeatHour = value.hbHour;
    integer("hbHour", oldHeartbeatHour, 9);
    value.hbHour = oldHeartbeatHour;
    boolean("smsHlthEn", value.smsHealthEnabled, false);
    integer("smsHlthHr", value.smsHealthHour, 10);
    boolean("smsHlthNt", value.smsHealthNotify, true);
    boolean("netLed", value.netLedEnabled, true);
    boolean("callNotify", value.callNotifyEnabled, true);

    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        char key[24];
        snprintf(key, sizeof(key), "sim%dIccid", i); str(key, value.simCredentials[i].iccid, MAX_SIM_ICCID_BYTES);
        snprintf(key, sizeof(key), "sim%dPin", i); str(key, value.simCredentials[i].pin, MAX_SIM_PIN_BYTES);
        snprintf(key, sizeof(key), "sim%dPuk", i); str(key, value.simCredentials[i].puk, MAX_SIM_PUK_BYTES);
        snprintf(key, sizeof(key), "sim%dPinMax", i); byte(key, value.simCredentials[i].pinMaxAttempts, 1);
        snprintf(key, sizeof(key), "sim%dPukMax", i); byte(key, value.simCredentials[i].pukMaxAttempts, 1);
        snprintf(key, sizeof(key), "sim%dPinFail", i); byte(key, value.simCredentials[i].pinFailedAttempts, 0);
        snprintf(key, sizeof(key), "sim%dPukFail", i); byte(key, value.simCredentials[i].pukFailedAttempts, 0);
    }
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        char prefix[16];
        snprintf(prefix, sizeof(prefix), "push%d", i);
        char key[28];
        auto readPushString = [&](const char* suffix, std::string& target, size_t maxBytes) {
            snprintf(key, sizeof(key), "%s%s", prefix, suffix);
            str(key, target, maxBytes);
        };
        IdfPushChannel& channel = value.pushChannels[i];
        snprintf(key, sizeof(key), "%sen", prefix); boolean(key, channel.enabled, false);
        snprintf(key, sizeof(key), "%stype", prefix); byte(key, channel.type, 1);
        readPushString("url", channel.url, MAX_PUSH_URL_BYTES);
        readPushString("name", channel.name, MAX_PUSH_NAME_BYTES);
        readPushString("k1", channel.key1, MAX_PUSH_KEY1_BYTES);
        readPushString("k2", channel.key2, MAX_PUSH_KEY2_BYTES);
        readPushString("title", channel.titleTemplate, MAX_TITLE_TEMPLATE_BYTES);
        readPushString("bodyTemplate", channel.bodyTemplate, MAX_BODY_TEMPLATE_BYTES);
        readPushString("body", channel.customBody, MAX_CUSTOM_BODY_BYTES);
        if (channel.type != PUSH_TYPE_CUSTOM) channel.customBody.clear();
    }
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        char key[24];
        auto readTaskString = [&](const char* suffix, std::string& target, size_t maxBytes) {
            snprintf(key, sizeof(key), "st%d%s", i, suffix);
            str(key, target, maxBytes);
        };
        IdfSchedTask& task = value.schedTasks[i];
        snprintf(key, sizeof(key), "st%dEn", i); boolean(key, task.enabled, false);
        readTaskString("Name", task.name, MAX_SCHEDULE_NAME_BYTES);
        readTaskString("Prof", task.profile, MAX_SCHEDULE_PROFILE_BYTES);
        snprintf(key, sizeof(key), "st%dBack", i); boolean(key, task.switchBack, true);
        snprintf(key, sizeof(key), "st%dDays", i); integer(key, task.intervalDays, 30);
        snprintf(key, sizeof(key), "st%dAct", i); byte(key, task.action, 0);
        readTaskString("Tgt", task.target, MAX_SCHEDULE_TARGET_BYTES);
        readTaskString("Pay", task.payload, MAX_SCHEDULE_PAYLOAD_BYTES);
        uint32_t last = task.lastRun;
        snprintf(key, sizeof(key), "st%dLast", i);
        uint32_t value32 = 0;
        esp_err_t lastErr = nvs_get_u32(nvs, key, &value32);
        if (lastErr == ESP_OK) last = value32;
        else if (lastErr != ESP_ERR_NVS_NOT_FOUND) ok = false;
        task.lastRun = last;
    }
    boolean("dataEn", value.dataEnabled, false);
    std::string oldHttpUrl;
    bool oldBark = false;
    str("httpUrl", oldHttpUrl, MAX_PUSH_URL_BYTES);
    boolean("barkMode", oldBark, false);
    if (!oldHttpUrl.empty() && !value.pushChannels[0].enabled) {
        value.pushChannels[0].enabled = true;
        value.pushChannels[0].url = oldHttpUrl;
        value.pushChannels[0].type = oldBark ? PUSH_TYPE_BARK : PUSH_TYPE_POST_JSON;
    }
    nvs_close(nvs);
    syncLegacyMirrors(value);
    return ok && semanticallyValid(value);
}

bool decodeString(Reader& reader, std::string& value, size_t maxBytes) { return reader.string(value, maxBytes); }

bool decodePush(Reader& reader, IdfPushChannel& channel, bool legacyV1, uint8_t maxType,
                bool wideType = false)
{
    uint8_t enabled = 0;
    uint32_t type = 0;
    if (!reader.u8(enabled) || enabled > 1) return false;
    if (wideType) {
        if (!reader.u32(type) || type > maxType) return false;
    } else {
        uint8_t narrowType = 0;
        if (!reader.u8(narrowType) || narrowType > maxType) return false;
        type = narrowType;
    }
    channel.enabled = enabled != 0;
    channel.type = static_cast<uint8_t>(type);
    if (!wideType && channel.type == PUSH_TYPE_NONE) channel.type = PUSH_TYPE_POST_JSON;
    if (!decodeString(reader, channel.name, MAX_PUSH_NAME_BYTES) ||
        !decodeString(reader, channel.url, MAX_PUSH_URL_BYTES) ||
        !decodeString(reader, channel.key1, MAX_PUSH_KEY1_BYTES) ||
        !decodeString(reader, channel.key2, MAX_PUSH_KEY2_BYTES)) return false;
    if (legacyV1) {
        if (!decodeString(reader, channel.customBody, MAX_CUSTOM_BODY_BYTES)) return false;
        channel.titleTemplate.clear();
        channel.bodyTemplate.clear();
    } else if (!decodeString(reader, channel.titleTemplate, MAX_TITLE_TEMPLATE_BYTES) ||
               !decodeString(reader, channel.bodyTemplate, MAX_BODY_TEMPLATE_BYTES) ||
               !decodeString(reader, channel.customBody, MAX_CUSTOM_BODY_BYTES)) {
        return false;
    }
    if (legacyV1 && channel.type != PUSH_TYPE_CUSTOM) channel.customBody.clear();
    return true;
}

bool decodeV1(Reader& reader, IdfConfig& value)
{
    value = defaults();
    uint32_t port = 0;
    if (!reader.u32(port) || port > std::numeric_limits<int>::max()) return false;
    value.smtpPort = static_cast<int>(port);
    if (!decodeString(reader, value.smtpServer, MAX_SMTP_SERVER_BYTES) ||
        !decodeString(reader, value.smtpUser, MAX_SMTP_USER_BYTES) ||
        !decodeString(reader, value.smtpPass, MAX_SMTP_PASSWORD_BYTES) ||
        !decodeString(reader, value.smtpSendTo, MAX_SMTP_RECIPIENT_BYTES) ||
        !decodeString(reader, value.adminPhone, MAX_ADMIN_PHONE_BYTES) ||
        !decodeString(reader, value.numberBlackList, MAX_BLACKLIST_BYTES)) return false;
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        if (!decodeString(reader, value.webAccounts[i].username, MAX_WEB_USERNAME_BYTES) ||
            !decodeString(reader, value.webAccounts[i].password, MAX_WEB_PASSWORD_BYTES)) return false;
    }
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        if (!decodePush(reader, value.pushChannels[i], true, PUSH_TYPE_TELEGRAM)) return false;
    }
    syncLegacyMirrors(value);
    return semanticallyValid(value);
}

bool decodeV2Common(Reader& reader, IdfConfig& value, uint8_t maxType)
{
    value = defaults();
    uint32_t port = 0;
    if (!reader.u32(port) || port > std::numeric_limits<int>::max()) return false;
    value.smtpPort = static_cast<int>(port);
    if (!decodeString(reader, value.deviceName, MAX_DEVICE_NAME_BYTES) ||
        !decodeString(reader, value.hostname, MAX_HOSTNAME_LENGTH) ||
        !decodeString(reader, value.notificationLocale, MAX_NOTIFICATION_LOCALE_BYTES) ||
        !decodeString(reader, value.smtpServer, MAX_SMTP_SERVER_BYTES) ||
        !decodeString(reader, value.smtpUser, MAX_SMTP_USER_BYTES) ||
        !decodeString(reader, value.smtpPass, MAX_SMTP_PASSWORD_BYTES) ||
        !decodeString(reader, value.smtpSendTo, MAX_SMTP_RECIPIENT_BYTES) ||
        !decodeString(reader, value.adminPhone, MAX_ADMIN_PHONE_BYTES) ||
        !decodeString(reader, value.numberBlackList, MAX_BLACKLIST_BYTES)) return false;
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        if (!decodeString(reader, value.webAccounts[i].username, MAX_WEB_USERNAME_BYTES) ||
            !decodeString(reader, value.webAccounts[i].password, MAX_WEB_PASSWORD_BYTES)) return false;
    }
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        if (!decodePush(reader, value.pushChannels[i], false, maxType)) return false;
    }
    syncLegacyMirrors(value);
    return semanticallyValid(value);
}

bool decodeV4(Reader& reader, IdfConfig& value)
{
    if (!decodeV2Common(reader, value, PUSH_TYPE_NTFY)) return false;
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        if (!decodeString(reader, value.wifiNetworks[i].ssid, MAX_WIFI_SSID_BYTES) ||
            !decodeString(reader, value.wifiNetworks[i].pass, MAX_WIFI_PASSWORD_BYTES)) return false;
    }
    uint8_t mode = 0;
    uint8_t enabled = 0;
    uint32_t interval = 0;
    if (!reader.u8(mode) || !reader.u8(enabled) || !reader.u32(interval) || mode > NETWORK_MODE_MIX ||
        enabled > 1 || interval > std::numeric_limits<int>::max()) return false;
    value.networkMode = mode;
    value.heartbeatEnable = enabled != 0;
    value.heartbeatInterval = static_cast<int>(interval);
    syncLegacyMirrors(value);
    return semanticallyValid(value);
}

bool decodeV5(Reader& reader, IdfConfig& value)
{
    value = defaults();
    uint32_t raw = 0;
    if (!reader.u32(raw) || raw > std::numeric_limits<int>::max()) return false;
    value.smtpPort = static_cast<int>(raw);
    if (!decodeString(reader, value.deviceName, MAX_DEVICE_NAME_BYTES) ||
        !decodeString(reader, value.hostname, MAX_HOSTNAME_LENGTH) ||
        !decodeString(reader, value.notificationLocale, MAX_NOTIFICATION_LOCALE_BYTES) ||
        !decodeString(reader, value.smtpServer, MAX_SMTP_SERVER_BYTES) ||
        !decodeString(reader, value.smtpUser, MAX_SMTP_USER_BYTES) ||
        !decodeString(reader, value.smtpPass, MAX_SMTP_PASSWORD_BYTES) ||
        !decodeString(reader, value.smtpSendTo, MAX_SMTP_RECIPIENT_BYTES) ||
        !decodeString(reader, value.adminPhone, MAX_ADMIN_PHONE_BYTES) ||
        !decodeString(reader, value.numberBlackList, MAX_BLACKLIST_BYTES)) return false;
    uint8_t count = 0;
    if (!reader.u8(count) || count != IDF_MAX_WEB_ACCOUNTS) return false;
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        if (!decodeString(reader, value.webAccounts[i].username, MAX_WEB_USERNAME_BYTES) ||
            !decodeString(reader, value.webAccounts[i].password, MAX_WEB_PASSWORD_BYTES)) return false;
    }
    if (!reader.u8(count) || count != IDF_MAX_PUSH_CHANNELS) return false;
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        if (!decodePush(reader, value.pushChannels[i], false, PUSH_TYPE_NTFY, true)) return false;
    }
    if (!reader.u8(count) || count != IDF_MAX_WIFI_NETWORKS) return false;
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        if (!decodeString(reader, value.wifiNetworks[i].ssid, MAX_WIFI_SSID_BYTES) ||
            !decodeString(reader, value.wifiNetworks[i].pass, MAX_WIFI_PASSWORD_BYTES)) return false;
    }
    if (!reader.u32(raw) || raw > NETWORK_MODE_MIX) return false;
    value.networkMode = static_cast<int>(raw);
    if (!reader.u8(count) || count > 1) return false;
    value.heartbeatEnable = count != 0;
    if (!reader.u32(raw) || raw > std::numeric_limits<int>::max()) return false;
    value.heartbeatInterval = static_cast<int>(raw);
    auto readBool = [&reader](bool& target) {
        uint8_t byte = 0;
        if (!reader.u8(byte) || byte > 1) return false;
        target = byte != 0;
        return true;
    };
    if (!reader.u32(raw) || raw > 255 || !txPowerValid(static_cast<uint8_t>(raw))) return false;
    value.wifiTxPowerQuarterDbm = static_cast<uint8_t>(raw);
    if (!readBool(value.emailEnabled) || !readBool(value.pushEnabled) ||
        !decodeString(reader, value.forwardRules, MAX_FORWARD_RULES_BYTES) || !readBool(value.kaEnabled) ||
        !reader.u32(raw) || raw > std::numeric_limits<int>::max()) return false;
    value.kaIntervalDays = static_cast<int>(raw);
    if (!reader.u32(raw) || raw > 255) return false;
    value.kaAction = static_cast<uint8_t>(raw);
    if (!decodeString(reader, value.kaTarget, MAX_KEEPALIVE_TARGET_BYTES) ||
        !decodeString(reader, value.kaUrl, MAX_KEEPALIVE_URL_BYTES) ||
        !decodeString(reader, value.kaProfile, MAX_KEEPALIVE_PROFILE_BYTES) || !reader.u32(value.kaLastTime) ||
        !reader.i32(value.tzOffsetMin) || !decodeString(reader, value.ntpServer, MAX_NTP_SERVER_BYTES) ||
        !readBool(value.rebootEnabled) || !reader.u32(raw) || raw > std::numeric_limits<int>::max()) return false;
    value.rebootHour = static_cast<int>(raw);
    if (!readBool(value.smsHealthEnabled) || !reader.u32(raw) || raw > std::numeric_limits<int>::max()) return false;
    value.smsHealthHour = static_cast<int>(raw);
    if (!readBool(value.smsHealthNotify) || !readBool(value.netLedEnabled) || !readBool(value.callNotifyEnabled) ||
        !readBool(value.dataEnabled) || !readBool(value.roamingEnabled) ||
        !decodeString(reader, value.apn, MAX_APN_BYTES) || !decodeString(reader, value.operatorPlmn, MAX_OPERATOR_PLMN_BYTES) ||
        !decodeString(reader, value.phoneNumber, MAX_PHONE_NUMBER_BYTES)) return false;
    if (!reader.u8(count) || count != IDF_MAX_SIM_CREDENTIALS) return false;
    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        IdfSimCredential& item = value.simCredentials[i];
        if (!decodeString(reader, item.iccid, MAX_SIM_ICCID_BYTES) || !decodeString(reader, item.pin, MAX_SIM_PIN_BYTES) ||
            !decodeString(reader, item.puk, MAX_SIM_PUK_BYTES) || !reader.u32(raw) || raw > 255) return false;
        item.pinMaxAttempts = static_cast<uint8_t>(raw);
        if (!reader.u32(raw) || raw > 255) return false;
        item.pukMaxAttempts = static_cast<uint8_t>(raw);
        if (!reader.u32(raw) || raw > 255) return false;
        item.pinFailedAttempts = static_cast<uint8_t>(raw);
        if (!reader.u32(raw) || raw > 255) return false;
        item.pukFailedAttempts = static_cast<uint8_t>(raw);
    }
    if (!reader.u8(count) || count != IDF_MAX_SCHED_TASKS) return false;
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        IdfSchedTask& task = value.schedTasks[i];
        if (!readBool(task.enabled) || !decodeString(reader, task.name, MAX_SCHEDULE_NAME_BYTES) ||
            !decodeString(reader, task.profile, MAX_SCHEDULE_PROFILE_BYTES) || !readBool(task.switchBack) ||
            !reader.u32(raw) || raw > std::numeric_limits<int>::max()) return false;
        task.intervalDays = static_cast<int>(raw);
        if (!reader.u32(raw) || raw > 255) return false;
        task.action = static_cast<uint8_t>(raw);
        if (!decodeString(reader, task.target, MAX_SCHEDULE_TARGET_BYTES) ||
            !decodeString(reader, task.payload, MAX_SCHEDULE_PAYLOAD_BYTES) || !reader.u32(task.lastRun)) return false;
    }
    syncLegacyMirrors(value);
    return semanticallyValid(value);
}

bool decodeV6(Reader& reader, IdfConfig& value)
{
    if (!decodeV5(reader, value)) return false;
    uint32_t raw = 0;
    if (!reader.u32(raw) || raw < MIN_KEEPALIVE_TRAFFIC_KB || raw > MAX_KEEPALIVE_TRAFFIC_KB) return false;
    value.kaTrafficKB = static_cast<int>(raw);
    return semanticallyValid(value);
}

DecodeResult decodeBlob(const uint8_t* blob, size_t length, IdfConfig& value,
                        uint16_t& schema, uint32_t& generation)
{
    if (!blob || length < kHeaderBytes || length > MAX_CONFIG_BLOB_SIZE) return DecodeResult::Invalid;
    auto get16 = [blob](size_t offset) {
        return static_cast<uint16_t>(blob[offset]) | static_cast<uint16_t>(blob[offset + 1] << 8);
    };
    auto get32 = [blob](size_t offset) {
        return static_cast<uint32_t>(blob[offset]) | (static_cast<uint32_t>(blob[offset + 1]) << 8) |
               (static_cast<uint32_t>(blob[offset + 2]) << 16) |
               (static_cast<uint32_t>(blob[offset + 3]) << 24);
    };
    if (get32(0) != kConfigMagic) return DecodeResult::Invalid;
    schema = get16(4);
    generation = get32(8);
    const uint32_t payloadLength = get32(12);
    if (payloadLength != length - kHeaderBytes ||
        get32(16) != crc32(blob + kHeaderBytes, payloadLength)) return DecodeResult::Invalid;
    if (schema > CONFIG_SCHEMA_VERSION) return DecodeResult::Unsupported;
    if (schema == 0) return DecodeResult::Invalid;
    Reader reader(blob + kHeaderBytes, blob + length);
    bool ok = schema == 1 ? decodeV1(reader, value) :
              schema == 2 ? decodeV2Common(reader, value, PUSH_TYPE_TELEGRAM) :
              schema == 3 ? decodeV2Common(reader, value, PUSH_TYPE_NTFY) :
              schema == 4 ? decodeV4(reader, value) :
              schema == 5 ? decodeV5(reader, value) : decodeV6(reader, value);
    return ok && reader.atEnd() ? DecodeResult::Valid : DecodeResult::Invalid;
}

bool blobEnvelopeValid(const uint8_t* blob, size_t length, uint16_t expectedSchema,
                       uint32_t expectedGeneration)
{
    if (!blob || length < kHeaderBytes || length > MAX_CONFIG_BLOB_SIZE) return false;
    auto get16 = [blob](size_t offset) {
        return static_cast<uint16_t>(blob[offset]) | static_cast<uint16_t>(blob[offset + 1] << 8);
    };
    auto get32 = [blob](size_t offset) {
        return static_cast<uint32_t>(blob[offset]) | (static_cast<uint32_t>(blob[offset + 1]) << 8) |
               (static_cast<uint32_t>(blob[offset + 2]) << 16) |
               (static_cast<uint32_t>(blob[offset + 3]) << 24);
    };
    const uint32_t payloadLength = get32(12);
    return get32(0) == kConfigMagic && get16(4) == expectedSchema && get16(6) == 0 &&
           get32(8) == expectedGeneration && payloadLength == length - kHeaderBytes &&
           get32(16) == crc32(blob + kHeaderBytes, payloadLength);
}

DecodeResult decodeBlob(const std::vector<uint8_t>& blob, IdfConfig& value,
                        uint16_t& schema, uint32_t& generation)
{
    return decodeBlob(blob.data(), blob.size(), value, schema, generation);
}

template <typename OutputWriter>
void encodeV5Fields(const IdfConfig& value, OutputWriter& writer, bool portable, bool includeTraffic = false)
{
    writer.u32(static_cast<uint32_t>(value.smtpPort));
    if (portable) {
        writer.text(PORTABLE_DEVICE_NAME, sizeof(PORTABLE_DEVICE_NAME) - 1);
        writer.text(PORTABLE_HOSTNAME, sizeof(PORTABLE_HOSTNAME) - 1);
    } else {
        writer.string(value.deviceName);
        writer.string(value.hostname);
    }
    writer.string(value.notificationLocale);
    writer.string(value.smtpServer);
    writer.string(value.smtpUser);
    writer.string(value.smtpPass);
    writer.string(value.smtpSendTo);
    writer.string(value.adminPhone);
    writer.string(value.numberBlackList);
    writer.u8(IDF_MAX_WEB_ACCOUNTS);
    for (const IdfWebAccount& account : value.webAccounts) {
        if (portable) {
            writer.text("", 0);
            writer.text("", 0);
        } else {
            writer.string(account.username);
            writer.string(account.password);
        }
    }
    writer.u8(IDF_MAX_PUSH_CHANNELS);
    for (const IdfPushChannel& channel : value.pushChannels) {
        writer.u8(channel.enabled ? 1 : 0);
        writer.u32(channel.type);
        writer.string(channel.name);
        writer.string(channel.url);
        writer.string(channel.key1);
        writer.string(channel.key2);
        writer.string(channel.titleTemplate);
        writer.string(channel.bodyTemplate);
        writer.string(channel.customBody);
    }
    writer.u8(IDF_MAX_WIFI_NETWORKS);
    for (const IdfWifiNetwork& profile : value.wifiNetworks) {
        writer.string(profile.ssid);
        writer.string(profile.pass);
    }
    writer.u32(static_cast<uint32_t>(value.networkMode));
    writer.u8(value.heartbeatEnable ? 1 : 0);
    writer.u32(static_cast<uint32_t>(value.heartbeatInterval));
    writer.u32(portable ? WIFI_TX_POWER_8_5DBM : value.wifiTxPowerQuarterDbm);
    writer.u8(value.emailEnabled ? 1 : 0);
    writer.u8(value.pushEnabled ? 1 : 0);
    writer.string(value.forwardRules);
    writer.u8(value.kaEnabled ? 1 : 0);
    writer.u32(static_cast<uint32_t>(value.kaIntervalDays));
    writer.u32(value.kaAction);
    writer.string(value.kaTarget);
    writer.string(value.kaUrl);
    if (portable) writer.text("", 0);
    else writer.string(value.kaProfile);
    writer.u32(portable ? 0 : value.kaLastTime);
    writer.u32(static_cast<uint32_t>(value.tzOffsetMin));
    writer.string(value.ntpServer);
    writer.u8(value.rebootEnabled ? 1 : 0);
    writer.u32(static_cast<uint32_t>(value.rebootHour));
    writer.u8(value.smsHealthEnabled ? 1 : 0);
    writer.u32(static_cast<uint32_t>(value.smsHealthHour));
    writer.u8(value.smsHealthNotify ? 1 : 0);
    writer.u8(value.netLedEnabled ? 1 : 0);
    writer.u8(value.callNotifyEnabled ? 1 : 0);
    writer.u8(value.dataEnabled ? 1 : 0);
    writer.u8(!portable && value.roamingEnabled ? 1 : 0);
    writer.string(value.apn);
    writer.string(value.operatorPlmn);
    if (portable) writer.text("", 0);
    else writer.string(value.phoneNumber);
    writer.u8(IDF_MAX_SIM_CREDENTIALS);
    for (const IdfSimCredential& item : value.simCredentials) {
        if (portable) {
            writer.text("", 0);
            writer.text("", 0);
            writer.text("", 0);
            writer.u32(1);
            writer.u32(1);
            writer.u32(0);
            writer.u32(0);
        } else {
            writer.string(item.iccid);
            writer.string(item.pin);
            writer.string(item.puk);
            writer.u32(item.pinMaxAttempts);
            writer.u32(item.pukMaxAttempts);
            writer.u32(item.pinFailedAttempts);
            writer.u32(item.pukFailedAttempts);
        }
    }
    writer.u8(IDF_MAX_SCHED_TASKS);
    for (const IdfSchedTask& task : value.schedTasks) {
        writer.u8(task.enabled ? 1 : 0);
        writer.string(task.name);
        if (portable) writer.text("", 0);
        else writer.string(task.profile);
        writer.u8(task.switchBack ? 1 : 0);
        writer.u32(static_cast<uint32_t>(task.intervalDays));
        writer.u32(task.action);
        writer.string(task.target);
        writer.string(task.payload);
        writer.u32(portable ? 0 : task.lastRun);
    }
    if (includeTraffic) writer.u32(static_cast<uint32_t>(value.kaTrafficKB));
}

bool encodeV5(const IdfConfig& value, uint32_t generation, std::vector<uint8_t>& blob)
{
    if (!semanticallyValid(value)) return false;
    Writer writer;
    encodeV5Fields(value, writer, false);
    std::vector<uint8_t> payload = writer.take();
    if (payload.size() + kHeaderBytes > MAX_CONFIG_BLOB_SIZE) return false;
    blob.assign(kHeaderBytes, 0);
    blob.insert(blob.end(), payload.begin(), payload.end());
    writeHeader(blob, 5, generation, kHeaderBytes);
    return true;
}

bool encodeV6(const IdfConfig& value, uint32_t generation, std::vector<uint8_t>& blob)
{
    if (!semanticallyValid(value)) return false;
    Writer writer;
    encodeV5Fields(value, writer, false, true);
    std::vector<uint8_t> payload = writer.take();
    if (payload.size() + kHeaderBytes > MAX_CONFIG_BLOB_SIZE) return false;
    blob.assign(kHeaderBytes, 0);
    blob.insert(blob.end(), payload.begin(), payload.end());
    writeHeader(blob, CONFIG_SCHEMA_VERSION, generation, kHeaderBytes);
    return true;
}

bool generationNewer(uint32_t left, uint32_t right)
{
    return static_cast<int32_t>(left - right) > 0;
}

esp_err_t ensurePartition()
{
    if (s_partitionReady) return ESP_OK;
    esp_err_t err = nvs_flash_init_partition(kPartition);
    // appcfg contains the only recoverable copy of user configuration.  A
    // NVS format/space error must fail closed; erasing here would silently
    // destroy both rollback slots and force defaults.
    if (err == ESP_OK) s_partitionReady = true;
    return err;
}

esp_err_t readBlob(nvs_handle_t nvs, const char* key, std::vector<uint8_t>& blob, bool& present)
{
    size_t length = 0;
    esp_err_t err = nvs_get_blob(nvs, key, nullptr, &length);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        present = false;
        return ESP_OK;
    }
    present = true;
    if (err != ESP_OK || length < kHeaderBytes || length > MAX_CONFIG_BLOB_SIZE) return ESP_ERR_INVALID_SIZE;
    blob.resize(length);
    return nvs_get_blob(nvs, key, blob.data(), &length);
}

esp_err_t readMarkerBlob(nvs_handle_t nvs, const char* key, std::vector<uint8_t>& marker, bool& present)
{
    size_t length = 0;
    esp_err_t err = nvs_get_blob(nvs, key, nullptr, &length);
    if (err == ESP_ERR_NVS_NOT_FOUND) {
        present = false;
        return ESP_OK;
    }
    present = true;
    if (err != ESP_OK || length != kMarkerBytes) return ESP_ERR_INVALID_SIZE;
    marker.resize(length);
    return nvs_get_blob(nvs, key, marker.data(), &length);
}

Slot readSlot(nvs_handle_t nvs, int index)
{
    Slot slot;
    std::vector<uint8_t> blob;
    esp_err_t blobErr = readBlob(nvs, kBlobKeys[index], blob, slot.blobPresent);
    std::vector<uint8_t> marker;
    esp_err_t markerErr = readMarkerBlob(nvs, kMarkerKeys[index], marker, slot.markerPresent);
    if (blobErr != ESP_OK || markerErr != ESP_OK) {
        slot.hardInvalid = (slot.blobPresent && blobErr != ESP_OK) ||
                           (slot.markerPresent && markerErr != ESP_OK);
        return slot;
    }
    if (slot.blobPresent && !slot.markerPresent) {
        std::unique_ptr<IdfConfig> decodedValue(new (std::nothrow) IdfConfig);
        if (!decodedValue) {
            slot.hardInvalid = true;
            return slot;
        }
        DecodeResult decoded = decodeBlob(blob, *decodedValue, slot.schema, slot.generation);
        slot.resumableBlob = decoded == DecodeResult::Valid && slot.schema == CONFIG_SCHEMA_VERSION;
        slot.hardInvalid = !slot.resumableBlob;
        return slot;
    }
    if (slot.markerPresent && !slot.blobPresent) {
        slot.hardInvalid = true;
        return slot;
    }
    if (!slot.blobPresent) return slot;
    uint16_t markerSchema = 0;
    uint32_t markerGeneration = 0;
    uint32_t markerLength = 0;
    uint32_t markerCrc = 0;
    if (!readMarker(marker, markerSchema, markerGeneration, markerLength, markerCrc)) {
        slot.hardInvalid = true;
        return slot;
    }
    std::unique_ptr<IdfConfig> decodedValue(new (std::nothrow) IdfConfig);
    if (!decodedValue) {
        slot.hardInvalid = true;
        return slot;
    }
    DecodeResult decoded = decodeBlob(blob, *decodedValue, slot.schema, slot.generation);
    // The marker has no schema field in the shipped MRK2 layout.  Authenticate
    // its generation/length/CRC against the CFG2 header and payload before
    // treating even a future schema as a committed slot.
    if (markerGeneration != slot.generation || markerLength != blob.size() ||
        markerCrc != crc32(blob.data(), blob.size())) {
        slot.hardInvalid = true;
        return slot;
    }
    if (decoded == DecodeResult::Unsupported) {
        slot.unsupported = true;
        return slot;
    }
    if (decoded != DecodeResult::Valid) {
        slot.hardInvalid = true;
        return slot;
    }
    slot.valid = true;
    return slot;
}

bool selectSlots(nvs_handle_t nvs, Slot* slots, int& active, uint32_t& generation, bool& anyCommittedInvalid,
                 bool& anyUnsupported, bool& anyData)
{
    slots[0] = readSlot(nvs, 0);
    slots[1] = readSlot(nvs, 1);
    anyCommittedInvalid = false;
    anyUnsupported = false;
    anyData = slots[0].blobPresent || slots[0].markerPresent || slots[1].blobPresent || slots[1].markerPresent;

    const bool have0 = slots[0].valid;
    const bool have1 = slots[1].valid;
    if (have0 || have1) {
        // A valid committed generation always wins over a corrupt or
        // incomplete sibling.  Only a marker-authenticated future generation
        // newer than that winner blocks startup.
        active = !have0 ? 1 : !have1 ? 0 :
                 (generationNewer(slots[1].generation, slots[0].generation) ? 1 : 0);
        generation = slots[active].generation;
        bool haveUnsupported = false;
        uint32_t unsupportedGeneration = 0;
        for (int i = 0; i < 2; ++i) {
            if (slots[i].unsupported &&
                (!haveUnsupported || generationNewer(slots[i].generation, unsupportedGeneration))) {
                haveUnsupported = true;
                unsupportedGeneration = slots[i].generation;
            }
        }
        anyUnsupported = haveUnsupported && generationNewer(unsupportedGeneration, generation);
        if (anyUnsupported) active = -1;
        return true;
    }

    // With no valid slot, an authenticated future schema is more actionable
    // than generic corruption.  Otherwise fail closed instead of silently
    // restoring defaults over data that was present.
    anyUnsupported = slots[0].unsupported || slots[1].unsupported;
    // Any present-but-unselectable slot is a committed storage failure.  The
    // only path that may create defaults is a genuinely empty appcfg
    // partition (anyData == false).
    anyCommittedInvalid = !anyUnsupported && anyData;
    if (anyCommittedInvalid || anyUnsupported) {
        active = -1;
        generation = 0;
        return true;
    }
    active = -1;
    generation = 0;
    return true;
}

bool resumableInitialMigration(const Slot* slots, uint8_t state)
{
    return state == CONFIG_STATE_MIGRATING && slots[0].resumableBlob && !slots[0].markerPresent &&
           !slots[0].hardInvalid && !slots[0].unsupported && !slots[1].blobPresent &&
           !slots[1].markerPresent && !slots[1].hardInvalid && !slots[1].unsupported;
}

esp_err_t readSlotValue(nvs_handle_t nvs, int index, IdfConfig& out, uint16_t& schema, uint32_t& generation)
{
    std::vector<uint8_t> blob;
    bool present = false;
    esp_err_t err = readBlob(nvs, kBlobKeys[index], blob, present);
    if (err != ESP_OK) return err;
    if (!present) return ESP_ERR_NVS_NOT_FOUND;
    const DecodeResult result = decodeBlob(blob, out, schema, generation);
    return result == DecodeResult::Valid ? ESP_OK :
           result == DecodeResult::Unsupported ? ESP_ERR_NOT_SUPPORTED : ESP_ERR_INVALID_STATE;
}

esp_err_t openStorage(nvs_open_mode_t mode, nvs_handle_t& nvs)
{
    esp_err_t err = ensurePartition();
    if (err != ESP_OK) return err;
    return nvs_open_from_partition(kPartition, kNamespace, mode, &nvs);
}

esp_err_t saveState(nvs_handle_t nvs, uint8_t state)
{
    esp_err_t err = nvs_set_u8(nvs, kStateKey, state);
    if (err == ESP_OK) err = nvs_commit(nvs);
    return err;
}

}  // namespace

void idf_config_storage_factory_reset(IdfConfig& out)
{
    out = defaults();
}

esp_err_t idf_config_storage_encode_portable(const IdfConfig& source, uint8_t* output,
                                             size_t capacity, size_t* written)
{
    if (written) *written = 0;
    if (!output || !written) return ESP_ERR_INVALID_ARG;
    const size_t usableCapacity = std::min(capacity, MAX_CONFIG_BLOB_SIZE);
    if (capacity < kHeaderBytes) {
        std::memset(output, 0, usableCapacity);
        return ESP_ERR_INVALID_SIZE;
    }
    if (!semanticallyValid(source, true)) {
        std::memset(output, 0, usableCapacity);
        return ESP_ERR_INVALID_ARG;
    }

    const size_t payloadCapacity = usableCapacity - kHeaderBytes;
    FixedWriter writer(output + kHeaderBytes, payloadCapacity);
    encodeV5Fields(source, writer, true, true);
    if (!writer.ok()) {
        std::memset(output, 0, usableCapacity);
        return ESP_ERR_INVALID_SIZE;
    }
    const size_t total = kHeaderBytes + writer.size();
    writeHeader(output, total, CONFIG_SCHEMA_VERSION, 0, kHeaderBytes);
    *written = total;
    return ESP_OK;
}

IdfPortableConfigStatus idf_config_storage_decode_portable(const uint8_t* bytes, size_t length,
                                                           const IdfConfig& target,
                                                           IdfConfig& output)
{
    IdfConfig decoded;
    uint16_t schema = 0;
    uint32_t generation = 0;
    const DecodeResult result = decodeBlob(bytes, length, decoded, schema, generation);
    if (result == DecodeResult::Unsupported) return IdfPortableConfigStatus::UnsupportedVersion;
    if (result != DecodeResult::Valid || generation != 0) return IdfPortableConfigStatus::Invalid;

    if (schema < 4) {
        for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) decoded.wifiNetworks[i] = target.wifiNetworks[i];
        decoded.networkMode = target.networkMode;
        decoded.heartbeatEnable = target.heartbeatEnable;
        decoded.heartbeatInterval = target.heartbeatInterval;
    }
    if (schema < 5) {
        decoded.emailEnabled = target.emailEnabled;
        decoded.pushEnabled = target.pushEnabled;
        decoded.forwardRules = target.forwardRules;
        decoded.kaEnabled = target.kaEnabled;
        decoded.kaIntervalDays = target.kaIntervalDays;
        decoded.kaAction = target.kaAction;
        decoded.kaTarget = target.kaTarget;
        decoded.kaUrl = target.kaUrl;
        decoded.tzOffsetMin = target.tzOffsetMin;
        decoded.ntpServer = target.ntpServer;
        decoded.rebootEnabled = target.rebootEnabled;
        decoded.rebootHour = target.rebootHour;
        decoded.smsHealthEnabled = target.smsHealthEnabled;
        decoded.smsHealthHour = target.smsHealthHour;
        decoded.smsHealthNotify = target.smsHealthNotify;
        decoded.netLedEnabled = target.netLedEnabled;
        decoded.callNotifyEnabled = target.callNotifyEnabled;
        decoded.dataEnabled = target.dataEnabled;
        decoded.apn = target.apn;
        decoded.operatorPlmn = target.operatorPlmn;
        for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) decoded.schedTasks[i] = target.schedTasks[i];
    }
    if (schema < 6) decoded.kaTrafficKB = target.kaTrafficKB;

    decoded.deviceName = target.deviceName;
    decoded.hostname = target.hostname;
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) decoded.webAccounts[i] = target.webAccounts[i];
    decoded.wifiTxPowerQuarterDbm = target.wifiTxPowerQuarterDbm;
    decoded.kaProfile = target.kaProfile;
    decoded.kaLastTime = target.kaLastTime;
    decoded.roamingEnabled = target.roamingEnabled;
    decoded.phoneNumber = target.phoneNumber;
    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        decoded.simCredentials[i] = target.simCredentials[i];
    }
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        decoded.schedTasks[i].profile = target.schedTasks[i].profile;
        decoded.schedTasks[i].lastRun = target.schedTasks[i].lastRun;
    }
    syncLegacyMirrors(decoded);
    if (!semanticallyValid(decoded)) return IdfPortableConfigStatus::Invalid;
    output = std::move(decoded);
    return IdfPortableConfigStatus::Ok;
}

esp_err_t idf_config_storage_save(const IdfConfig& candidate)
{
    std::vector<uint8_t> blob;
    nvs_handle_t nvs = 0;
    bool nvsOpen = false;
    try {
    esp_err_t err = openStorage(NVS_READWRITE, nvs);
    if (err != ESP_OK) return err;
    nvsOpen = true;
    std::unique_ptr<Slot[]> slots(new (std::nothrow) Slot[2]);
    if (!slots) {
        nvs_close(nvs);
        return ESP_ERR_NO_MEM;
    }
    int active = -1;
    uint32_t generation = 0;
    bool invalid = false;
    bool unsupported = false;
    bool anyData = false;
    selectSlots(nvs, slots.get(), active, generation, invalid, unsupported, anyData);
    (void)anyData;
    uint8_t state = 0;
    esp_err_t stateErr = nvs_get_u8(nvs, kStateKey, &state);
    if (stateErr != ESP_OK && stateErr != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        return stateErr;
    }
    const bool resumable = active < 0 && resumableInitialMigration(slots.get(), state);
    if (invalid && !resumable) {
        nvs_close(nvs);
        return ESP_ERR_INVALID_STATE;
    }
    if (unsupported) {
        nvs_close(nvs);
        return ESP_ERR_NOT_SUPPORTED;
    }
    if (s_activeSlot >= 0 && active < 0) {
        active = s_activeSlot;
        generation = s_activeGeneration;
    }
    const int target = active < 0 ? 0 : active == 0 ? 1 : 0;
    const uint32_t nextGeneration = generation + 1U;
    if (!encodeV6(candidate, nextGeneration, blob)) {
        nvs_close(nvs);
        return ESP_ERR_INVALID_ARG;
    }
    const uint32_t expectedBlobLength = static_cast<uint32_t>(blob.size());
    const uint32_t expectedBlobCrc = crc32(blob.data(), blob.size());
    std::vector<uint8_t> marker;
    writeMarker(marker, CONFIG_SCHEMA_VERSION, nextGeneration, expectedBlobLength, expectedBlobCrc);
    // The inactive slot may still carry its previous marker.  Remove it in a
    // separate commit before replacing the blob so a power cut between blob
    // and marker commits leaves an incomplete slot, never a mismatched
    // committed pair that would poison the still-valid active slot.
    err = nvs_erase_key(nvs, kMarkerKeys[target]);
    if (err == ESP_ERR_NVS_NOT_FOUND) err = ESP_OK;
    if (err == ESP_OK) err = nvs_commit(nvs);
    if (err == ESP_OK) err = nvs_set_blob(nvs, kBlobKeys[target], blob.data(), blob.size());
    if (err == ESP_OK) err = nvs_commit(nvs);
    if (err == ESP_OK) {
        // Reuse the encode allocation for readback. No allocation may occur
        // after the first NVS mutation, so bad_alloc cannot strand a new slot.
        bool present = false;
        err = readBlob(nvs, kBlobKeys[target], blob, present);
        if (err == ESP_OK && (!present || blob.size() != expectedBlobLength ||
                              crc32(blob.data(), blob.size()) != expectedBlobCrc ||
                              !blobEnvelopeValid(blob.data(), blob.size(), CONFIG_SCHEMA_VERSION,
                                                 nextGeneration))) {
            err = ESP_ERR_INVALID_STATE;
        }
    }
    std::vector<uint8_t>().swap(blob);
    if (err == ESP_OK) {
        err = nvs_set_blob(nvs, kMarkerKeys[target], marker.data(), marker.size());
        if (err == ESP_OK) err = nvs_set_u8(nvs, kStateKey, CONFIG_STATE_READY);
        if (err == ESP_OK) err = nvs_commit(nvs);
        if (err == ESP_OK) {
            uint8_t checkedMarker[kMarkerBytes] = {};
            size_t checkedLength = sizeof(checkedMarker);
            err = nvs_get_blob(nvs, kMarkerKeys[target], checkedMarker, &checkedLength);
            if (err == ESP_OK &&
                (checkedLength != marker.size() ||
                 std::memcmp(checkedMarker, marker.data(), marker.size()) != 0)) {
                err = ESP_ERR_INVALID_STATE;
            }
        }
    }
    nvs_close(nvs);
    nvsOpen = false;
    if (err == ESP_OK) {
        s_activeSlot = target;
        s_activeGeneration = nextGeneration;
    }
    return err;
    } catch (const std::bad_alloc&) {
        if (nvsOpen) nvs_close(nvs);
        return ESP_ERR_NO_MEM;
    }
}

esp_err_t idf_config_storage_load(IdfConfig& out, IdfConfigLoadStatus* status)
{
    if (status) *status = IdfConfigLoadStatus::Unknown;
    nvs_handle_t nvs = 0;
    bool nvsOpen = false;
    try {
    esp_err_t err = openStorage(NVS_READWRITE, nvs);
    if (err != ESP_OK) {
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return err;
    }
    nvsOpen = true;
    std::unique_ptr<Slot[]> slots(new (std::nothrow) Slot[2]);
    if (!slots) {
        nvs_close(nvs);
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return ESP_ERR_NO_MEM;
    }
    int active = -1;
    uint32_t generation = 0;
    bool invalid = false;
    bool unsupported = false;
    bool anyData = false;
    selectSlots(nvs, slots.get(), active, generation, invalid, unsupported, anyData);
    uint8_t state = 0;
    esp_err_t stateErr = nvs_get_u8(nvs, kStateKey, &state);
    if (stateErr != ESP_OK && stateErr != ESP_ERR_NVS_NOT_FOUND) {
        nvs_close(nvs);
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return stateErr;
    }
    const bool resumable = active < 0 && resumableInitialMigration(slots.get(), state);
    if (unsupported) {
        nvs_close(nvs);
        if (status) *status = IdfConfigLoadStatus::UnsupportedSchema;
        return ESP_ERR_NOT_SUPPORTED;
    }
    if ((invalid && !resumable) || (anyData && active < 0 && !resumable)) {
        nvs_close(nvs);
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return ESP_ERR_INVALID_STATE;
    }
    if (active >= 0) {
        uint16_t activeSchema = 0;
        uint32_t activeGeneration = 0;
        err = readSlotValue(nvs, active, out, activeSchema, activeGeneration);
        if (err != ESP_OK) {
            nvs_close(nvs);
            if (status) *status = err == ESP_ERR_NOT_SUPPORTED ? IdfConfigLoadStatus::UnsupportedSchema
                                                                 : IdfConfigLoadStatus::StorageError;
            return err;
        }
        if (activeSchema <= 3 && !overlayLegacyConnectivity(out)) {
            nvs_close(nvs);
            if (status) *status = IdfConfigLoadStatus::StorageError;
            return ESP_ERR_INVALID_STATE;
        }
        s_activeSlot = active;
        s_activeGeneration = activeGeneration;
        if (state != CONFIG_STATE_READY && saveState(nvs, CONFIG_STATE_READY) != ESP_OK) {
            nvs_close(nvs);
            if (status) *status = IdfConfigLoadStatus::StorageError;
            return ESP_ERR_INVALID_STATE;
        }
        const bool migrated = activeSchema < CONFIG_SCHEMA_VERSION;
        nvs_close(nvs);
        nvsOpen = false;
        if (migrated) {
            err = idf_config_storage_save(out);
            if (err != ESP_OK) {
                if (status) *status = IdfConfigLoadStatus::StorageError;
                return err;
            }
            if (status) *status = IdfConfigLoadStatus::Migrated;
        } else if (status) {
            *status = IdfConfigLoadStatus::Loaded;
        }
        return ESP_OK;
    }
    if (state != 0 && state != CONFIG_STATE_MIGRATING) {
        nvs_close(nvs);
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return ESP_ERR_INVALID_STATE;
    }
    if (state != CONFIG_STATE_MIGRATING && saveState(nvs, CONFIG_STATE_MIGRATING) != ESP_OK) {
        nvs_close(nvs);
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return ESP_ERR_INVALID_STATE;
    }
    nvs_close(nvs);
    nvsOpen = false;

    bool existed = false;
    if (!loadLegacy(out, existed)) {
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return ESP_ERR_INVALID_STATE;
    }
    err = idf_config_storage_save(out);
    if (err != ESP_OK) {
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return err;
    }
    if (status) *status = existed ? IdfConfigLoadStatus::Migrated : IdfConfigLoadStatus::FirstBoot;
    return ESP_OK;
    } catch (const std::bad_alloc&) {
        if (nvsOpen) nvs_close(nvs);
        if (status) *status = IdfConfigLoadStatus::StorageError;
        return ESP_ERR_NO_MEM;
    }
}
