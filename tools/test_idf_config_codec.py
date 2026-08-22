#!/usr/bin/env python3
"""Compile and exercise the real config codec without an ESP-IDF install."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


ESP_ERR_H = r"""#pragma once
#include <stdint.h>
typedef int32_t esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NO_MEM 0x101
#define ESP_ERR_INVALID_ARG 0x102
#define ESP_ERR_INVALID_SIZE 0x103
#define ESP_ERR_INVALID_STATE 0x104
#define ESP_ERR_NOT_SUPPORTED 0x105
#define ESP_ERR_TIMEOUT 0x106
#define ESP_ERR_NOT_FOUND 0x107
#define ESP_ERR_NVS_NOT_FOUND 0x1102
#define ESP_ERR_NVS_TYPE_MISMATCH 0x1103
#define ESP_ERR_NVS_NO_FREE_PAGES 0x110d
#define ESP_ERR_NVS_NEW_VERSION_FOUND 0x110e
static inline const char* esp_err_to_name(esp_err_t) { return "stub"; }
"""

ESP_LOG_H = r"""#pragma once
#define ESP_LOGE(...) do { } while (0)
#define ESP_LOGW(...) do { } while (0)
#define ESP_LOGI(...) do { } while (0)
"""

NVS_H = r"""#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef uintptr_t nvs_handle_t;
typedef enum { NVS_READONLY = 0, NVS_READWRITE = 1 } nvs_open_mode_t;
esp_err_t nvs_open(const char*, nvs_open_mode_t, nvs_handle_t*);
esp_err_t nvs_open_from_partition(const char*, const char*, nvs_open_mode_t, nvs_handle_t*);
void nvs_close(nvs_handle_t);
esp_err_t nvs_commit(nvs_handle_t);
esp_err_t nvs_erase_key(nvs_handle_t, const char*);
esp_err_t nvs_get_blob(nvs_handle_t, const char*, void*, size_t*);
esp_err_t nvs_set_blob(nvs_handle_t, const char*, const void*, size_t);
esp_err_t nvs_get_str(nvs_handle_t, const char*, char*, size_t*);
esp_err_t nvs_get_i32(nvs_handle_t, const char*, int32_t*);
esp_err_t nvs_get_u32(nvs_handle_t, const char*, uint32_t*);
esp_err_t nvs_get_u8(nvs_handle_t, const char*, uint8_t*);
esp_err_t nvs_set_u8(nvs_handle_t, const char*, uint8_t);
"""

NVS_FLASH_H = r"""#pragma once
#include "esp_err.h"
esp_err_t nvs_flash_init_partition(const char*);
esp_err_t nvs_flash_erase_partition(const char*);
"""


HOST_TEST_CPP = r"""#include <algorithm>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <new>
#include <string>
#include <unordered_map>
#include <vector>

// Include the production translation unit so this test invokes its internal
// Writer/Reader, version decoders, header/marker checks, and slot generation
// arithmetic rather than a parallel model.
#include "idf_config_storage.cpp"
#define static_assert(...)
#include "idf_config.cpp"
#undef static_assert

static int check_number = 0;
static bool reject_allocations = false;
static int fail_allocation_after = -1;

void* operator new(std::size_t size) {
    if (reject_allocations) std::abort();
    if (fail_allocation_after == 0) throw std::bad_alloc();
    if (fail_allocation_after > 0) --fail_allocation_after;
    void* value = std::malloc(size);
    if (!value) std::abort();
    return value;
}

void* operator new[](std::size_t size) {
    if (reject_allocations) std::abort();
    if (fail_allocation_after == 0) throw std::bad_alloc();
    if (fail_allocation_after > 0) --fail_allocation_after;
    void* value = std::malloc(size);
    if (!value) std::abort();
    return value;
}

static void require(bool condition) {
    ++check_number;
    if (!condition) {
        std::fprintf(stderr, "codec check %d failed\n", check_number);
        std::abort();
    }
}

struct FakeStore {
    std::vector<uint8_t> blobs[2];
    std::vector<uint8_t> markers[2];
    bool state_present = false;
    uint8_t state = 0;
};

static FakeStore* fake_store = nullptr;
static bool fake_legacy_open = false;
static std::unordered_map<std::string, std::string> fake_legacy_strings;
static std::unordered_map<std::string, int32_t> fake_legacy_i32;
static std::unordered_map<std::string, uint8_t> fake_legacy_u8;
static std::unordered_map<std::string, uint32_t> fake_legacy_u32;

SemaphoreHandle_t xSemaphoreCreateMutex() { return reinterpret_cast<void*>(1); }
int xSemaphoreTake(SemaphoreHandle_t, uint32_t) { return pdTRUE; }
int xSemaphoreGive(SemaphoreHandle_t) { return pdTRUE; }
void idf_log_line(const char*) {}
void idf_logf(const char*, ...) {}

esp_err_t nvs_open(const char* namespace_name, nvs_open_mode_t, nvs_handle_t* handle) {
    if (fake_legacy_open && std::strcmp(namespace_name, "sms_config") == 0) {
        if (handle) *handle = 2;
        return ESP_OK;
    }
    return ESP_ERR_NVS_NOT_FOUND;
}

void nvs_close(nvs_handle_t) {}

esp_err_t nvs_get_str(nvs_handle_t, const char* key, char* data, size_t* length) {
    if (!length) return ESP_ERR_INVALID_ARG;
    const auto it = fake_legacy_strings.find(key);
    if (it == fake_legacy_strings.end()) return ESP_ERR_NVS_NOT_FOUND;
    const size_t required = it->second.size() + 1;
    if (!data) {
        *length = required;
        return ESP_OK;
    }
    if (*length < required) return ESP_ERR_INVALID_SIZE;
    std::memcpy(data, it->second.c_str(), required);
    *length = required;
    return ESP_OK;
}

esp_err_t nvs_get_i32(nvs_handle_t, const char* key, int32_t* value) {
    if (!value) return ESP_ERR_INVALID_ARG;
    const auto it = fake_legacy_i32.find(key);
    if (it == fake_legacy_i32.end()) {
        return fake_legacy_u8.count(key) ? ESP_ERR_NVS_TYPE_MISMATCH : ESP_ERR_NVS_NOT_FOUND;
    }
    *value = it->second;
    return ESP_OK;
}

esp_err_t nvs_get_u8(nvs_handle_t handle, const char* key, uint8_t* value) {
    if (!value) return ESP_ERR_INVALID_ARG;
    if (handle == 1 && std::strcmp(key, "state") == 0) {
        if (!fake_store || !fake_store->state_present) return ESP_ERR_NVS_NOT_FOUND;
        *value = fake_store->state;
        return ESP_OK;
    }
    const auto it = fake_legacy_u8.find(key);
    if (it == fake_legacy_u8.end()) {
        return fake_legacy_i32.count(key) ? ESP_ERR_NVS_TYPE_MISMATCH : ESP_ERR_NVS_NOT_FOUND;
    }
    *value = it->second;
    return ESP_OK;
}

esp_err_t nvs_get_u32(nvs_handle_t, const char* key, uint32_t* value) {
    if (!value) return ESP_ERR_INVALID_ARG;
    const auto it = fake_legacy_u32.find(key);
    if (it == fake_legacy_u32.end()) return ESP_ERR_NVS_NOT_FOUND;
    *value = it->second;
    return ESP_OK;
}

esp_err_t nvs_get_blob(nvs_handle_t, const char* key, void* data, size_t* length) {
    if (!fake_store || !length) return ESP_ERR_INVALID_ARG;
    const bool marker = std::strncmp(key, "mark", 4) == 0;
    const int index = key[3] == 'A' || key[4] == 'A' ? 0 : 1;
    const std::vector<uint8_t>& value = marker ? fake_store->markers[index] : fake_store->blobs[index];
    if (value.empty()) return ESP_ERR_NVS_NOT_FOUND;
    if (!data) {
        *length = value.size();
        return ESP_OK;
    }
    if (*length < value.size()) return ESP_ERR_INVALID_SIZE;
    std::memcpy(data, value.data(), value.size());
    *length = value.size();
    return ESP_OK;
}

esp_err_t nvs_open_from_partition(const char*, const char*, nvs_open_mode_t, nvs_handle_t* handle) {
    if (!fake_store || !handle) return ESP_ERR_INVALID_ARG;
    *handle = 1;
    return ESP_OK;
}

esp_err_t nvs_commit(nvs_handle_t) { return ESP_OK; }

esp_err_t nvs_erase_key(nvs_handle_t, const char* key) {
    if (!fake_store) return ESP_ERR_INVALID_ARG;
    const int index = key[4] == 'A' ? 0 : 1;
    if (fake_store->markers[index].empty()) return ESP_ERR_NVS_NOT_FOUND;
    fake_store->markers[index].clear();
    return ESP_OK;
}

esp_err_t nvs_set_blob(nvs_handle_t, const char* key, const void* data, size_t length) {
    if (!fake_store || !data) return ESP_ERR_INVALID_ARG;
    const bool marker = std::strncmp(key, "mark", 4) == 0;
    const int index = key[3] == 'A' || key[4] == 'A' ? 0 : 1;
    std::vector<uint8_t>& target = marker ? fake_store->markers[index] : fake_store->blobs[index];
    target.assign(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + length);
    return ESP_OK;
}

esp_err_t nvs_set_u8(nvs_handle_t handle, const char* key, uint8_t value) {
    if (!fake_store || handle != 1 || std::strcmp(key, "state") != 0) return ESP_ERR_INVALID_ARG;
    fake_store->state_present = true;
    fake_store->state = value;
    return ESP_OK;
}

esp_err_t nvs_flash_init_partition(const char*) { return ESP_OK; }
esp_err_t nvs_flash_erase_partition(const char*) { return ESP_ERR_NOT_SUPPORTED; }

static void install_pair(FakeStore& store, int index, const std::vector<uint8_t>& blob, uint32_t generation) {
    store.blobs[index] = blob;
    writeMarker(store.markers[index], CONFIG_SCHEMA_VERSION, generation,
                static_cast<uint32_t>(blob.size()), crc32(blob.data(), blob.size()));
}

int main() {
    IdfConfig factory;
    idf_config_storage_factory_reset(factory);
    require(factory.webAccounts[0].username == IDF_DEFAULT_WEB_USER);
    require(factory.webAccounts[0].password == IDF_DEFAULT_WEB_PASS);
    require(!factory.roamingEnabled);
    const char* default_channel_names[IDF_MAX_PUSH_CHANNELS] = {
        "Channel 1", "Channel 2", "Channel 3", "Channel 4", "Channel 5",
    };
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        require(factory.pushChannels[i].name == default_channel_names[i]);
    }

    IdfConfig reset_target = defaults();
    reset_target.smtpServer = "preserved";
    fail_allocation_after = 0;
    bool reset_oom = false;
    try {
        idf_config_storage_factory_reset(reset_target);
    } catch (const std::bad_alloc&) {
        reset_oom = true;
    }
    fail_allocation_after = -1;
    require(reset_oom && reset_target.smtpServer == "preserved");
    idf_config_storage_factory_reset(reset_target);
    require(reset_target.pushChannels[0].name == default_channel_names[0]);

    fake_legacy_open = true;
    fake_legacy_strings["wifiSSID"] = "develop-wifi";
    fake_legacy_strings["wifiPass"] = "develop-pass";
    fake_legacy_strings["wifiSSID2"] = "develop-wifi-2";
    fake_legacy_strings["wifiPass2"] = "develop-pass-2";
    fake_legacy_strings["wifi4Ssid"] = "standard-wifi-5";
    fake_legacy_strings["wifi4Pass"] = "standard-pass-5";
    fake_legacy_strings["account0user"] = "legacy-admin";
    fake_legacy_strings["account0pass"] = "legacy-secret";
    fake_legacy_strings["account9user"] = "legacy-operator";
    fake_legacy_strings["account9pass"] = "operator-secret";
    fake_legacy_strings["remark"] = "Migrated Device";
    fake_legacy_i32["networkMode"] = NETWORK_MODE_MIX;
    fake_legacy_i32["heartbeatInterval"] = 24;
    fake_legacy_u8["heartbeatEnable"] = 0;
    fake_legacy_u8["kaEnable"] = 0;
    fake_legacy_i32["kaIntervalDays"] = 60;
    fake_legacy_i32["kaTraffic"] = 1;
    fake_legacy_u32["kaBaseDate"] = 1700000000;
    fake_legacy_i32["tzMin"] = -300;
    IdfConfig legacy_config;
    bool legacy_existed = false;
    require(loadLegacy(legacy_config, legacy_existed));
    require(legacy_existed);
    require(legacy_config.wifiNetworks[0].ssid == "develop-wifi" && legacy_config.wifiNetworks[1].ssid == "develop-wifi-2");
    require(legacy_config.wifiNetworks[4].ssid == "standard-wifi-5");
    require(legacy_config.webAccounts[9].username == "legacy-operator");
    require(legacy_config.deviceName == "Migrated Device");
    require(legacy_config.networkMode == NETWORK_MODE_MIX && !legacy_config.heartbeatEnable &&
            legacy_config.heartbeatInterval == 24);
    require(!legacy_config.kaEnabled && legacy_config.kaIntervalDays == 60 &&
            legacy_config.kaTrafficKB == 1 && legacy_config.kaLastTime == 1700000000);
    require(legacy_config.tzOffsetMin == -300);
    std::vector<uint8_t> migrated_tz_blob;
    require(encodeV6(legacy_config, 1, migrated_tz_blob));
    IdfConfig migrated_tz_config;
    uint16_t migrated_tz_schema = 0;
    uint32_t migrated_tz_generation = 0;
    require(decodeBlob(migrated_tz_blob, migrated_tz_config, migrated_tz_schema,
                       migrated_tz_generation) == DecodeResult::Valid);
    require(migrated_tz_schema == CONFIG_SCHEMA_VERSION &&
            migrated_tz_config.tzOffsetMin == -300);
    IdfConfig overlay = defaults();
    require(overlayLegacyConnectivity(overlay));
    require(overlay.wifiNetworks[0].ssid == "develop-wifi" &&
            overlay.wifiNetworks[4].ssid == "standard-wifi-5" &&
            overlay.networkMode == NETWORK_MODE_MIX && !overlay.heartbeatEnable &&
            overlay.heartbeatInterval == 24);

    IdfConfig wrong_bool_type;
    bool wrong_bool_existed = false;
    fake_legacy_i32.erase("tzMin");
    fake_legacy_u8["tzMin"] = 1;
    require(!loadLegacy(wrong_bool_type, wrong_bool_existed));
    fake_legacy_u8.erase("tzMin");
    fake_legacy_i32["tzMin"] = 841;
    require(!loadLegacy(wrong_bool_type, wrong_bool_existed));
    fake_legacy_i32["tzMin"] = -300;

    fake_legacy_i32["emailEn"] = 1;
    require(!loadLegacy(wrong_bool_type, wrong_bool_existed));
    fake_legacy_i32.erase("emailEn");
    fake_legacy_u8["emailEn"] = 2;
    require(!loadLegacy(wrong_bool_type, wrong_bool_existed));
    fake_legacy_u8.erase("emailEn");
    fake_legacy_i32["heartbeatInterval"] = MAX_HEARTBEAT_INTERVAL_HOURS + 1;
    require(!overlayLegacyConnectivity(overlay));
    fake_legacy_i32["heartbeatInterval"] = 24;
    fake_legacy_open = false;
    fake_legacy_strings.clear();
    fake_legacy_i32.clear();
    fake_legacy_u8.clear();
    fake_legacy_u32.clear();

    IdfConfig original = defaults();
    original.deviceName = "測試設備";
    original.hostname = "edge-01";
    original.notificationLocale = NOTIFICATION_LOCALE_EN;
    original.webAccounts[1].username = "operator";
    original.webAccounts[1].password = "operator-password";
    original.pushChannels[0].enabled = true;
    original.pushChannels[0].type = PUSH_TYPE_CUSTOM;
    original.pushChannels[0].customBody = "{message}";
    original.wifiNetworks[0].ssid = "ssid-01";
    original.wifiNetworks[0].pass = "password";
    original.roamingEnabled = false;
    original.wifiTxPowerQuarterDbm = WIFI_TX_POWER_20DBM;
    original.kaProfile = "source-profile";
    original.kaLastTime = 123456;
    original.kaTrafficKB = 1234;
    original.phoneNumber = "+886900000001";
    original.simCredentials[0].iccid = "898600000000000000001";
    original.simCredentials[0].pin = "1234";
    original.schedTasks[0].profile = "source-schedule-profile";
    original.schedTasks[0].lastRun = 654321;
    require(semanticallyValid(original));

    uint8_t portable_storage[MAX_CONFIG_BLOB_SIZE] = {};
    size_t portable_size = 0;
    require(idf_config_storage_encode_portable(original, portable_storage,
                                               sizeof(portable_storage), &portable_size) == ESP_OK);
    std::vector<uint8_t> portable(portable_storage, portable_storage + portable_size);
    require(portable.size() >= kHeaderBytes);
    require(portable[8] == 0 && portable[9] == 0 && portable[10] == 0 && portable[11] == 0);
    auto does_not_contain = [&portable](const std::string& secret) {
        return std::search(portable.begin(), portable.end(), secret.begin(), secret.end()) == portable.end();
    };
    for (const std::string& local : {
             original.deviceName, original.hostname, original.webAccounts[1].username,
             original.webAccounts[1].password, original.kaProfile, original.phoneNumber,
             original.simCredentials[0].iccid, original.simCredentials[0].pin,
             original.schedTasks[0].profile,
         }) {
        require(does_not_contain(local));
    }
    s_config = original;
    uint8_t public_portable_storage[MAX_CONFIG_BLOB_SIZE] = {};
    size_t public_portable_size = 0;
    reject_allocations = true;
    require(idf_config_export_portable(public_portable_storage,
                                       sizeof(public_portable_storage),
                                       &public_portable_size) == ESP_OK);
    reject_allocations = false;
    require(public_portable_size == portable_size &&
            std::memcmp(public_portable_storage, portable_storage, portable_size) == 0);

    IdfConfig portable_target = defaults();
    portable_target.deviceName = "Target device";
    portable_target.hostname = "target-device";
    portable_target.webAccounts[0] = {"target-admin", "target-password"};
    portable_target.wifiNetworks[0] = {"target-wifi", "target-password"};
    portable_target.networkMode = NETWORK_MODE_4G_ONLY;
    portable_target.heartbeatEnable = false;
    portable_target.heartbeatInterval = 88;
    portable_target.wifiTxPowerQuarterDbm = WIFI_TX_POWER_5DBM;
    portable_target.kaProfile = "target-profile";
    portable_target.kaLastTime = 987654;
    portable_target.roamingEnabled = true;
    portable_target.phoneNumber = "+886900000099";
    portable_target.simCredentials[0].iccid = "898600000000000000099";
    portable_target.simCredentials[0].pin = "9999";
    portable_target.schedTasks[0].profile = "target-schedule-profile";
    portable_target.schedTasks[0].lastRun = 456789;
    IdfConfig portable_decoded;
    require(idf_config_storage_decode_portable(portable.data(), portable.size(), portable_target,
                                               portable_decoded) == IdfPortableConfigStatus::Ok);
    require(portable_decoded.smtpServer == original.smtpServer);
    require(portable_decoded.wifiNetworks[0].ssid == original.wifiNetworks[0].ssid);
    require(portable_decoded.deviceName == portable_target.deviceName);
    require(portable_decoded.hostname == portable_target.hostname);
    require(portable_decoded.webAccounts[0].username == portable_target.webAccounts[0].username);
    require(portable_decoded.wifiTxPowerQuarterDbm == portable_target.wifiTxPowerQuarterDbm);
    require(portable_decoded.kaProfile == portable_target.kaProfile);
    require(portable_decoded.kaLastTime == portable_target.kaLastTime);
    require(portable_decoded.kaTrafficKB == original.kaTrafficKB);
    require(portable_decoded.roamingEnabled == portable_target.roamingEnabled);
    require(portable_decoded.phoneNumber == portable_target.phoneNumber);
    require(portable_decoded.simCredentials[0].iccid == portable_target.simCredentials[0].iccid);
    require(portable_decoded.schedTasks[0].profile == portable_target.schedTasks[0].profile);
    require(portable_decoded.schedTasks[0].lastRun == portable_target.schedTasks[0].lastRun);

    IdfConfig decode_output = defaults();
    decode_output.smtpServer = "unchanged";
    const uint8_t malformed_portable[kHeaderBytes] = {};
    fail_allocation_after = 0;
    bool decode_oom = false;
    try {
        (void)idf_config_storage_decode_portable(malformed_portable, sizeof(malformed_portable),
                                                 portable_target, decode_output);
    } catch (const std::bad_alloc&) {
        decode_oom = true;
    }
    fail_allocation_after = -1;
    require(decode_oom && decode_output.smtpServer == "unchanged");

    std::vector<uint8_t> portable_nonzero_generation = portable;
    writeHeader(portable_nonzero_generation, CONFIG_SCHEMA_VERSION, 1, kHeaderBytes);
    require(idf_config_storage_decode_portable(portable_nonzero_generation.data(),
                                               portable_nonzero_generation.size(), portable_target,
                                               portable_decoded) == IdfPortableConfigStatus::Invalid);
    std::vector<uint8_t> portable_corrupt = portable;
    portable_corrupt.back() ^= 1;
    require(idf_config_storage_decode_portable(portable_corrupt.data(), portable_corrupt.size(),
                                               portable_target, portable_decoded) ==
            IdfPortableConfigStatus::Invalid);
    std::vector<uint8_t> portable_future = portable;
    writeHeader(portable_future, CONFIG_SCHEMA_VERSION + 1, 0, kHeaderBytes);
    require(idf_config_storage_decode_portable(portable_future.data(), portable_future.size(),
                                               portable_target, portable_decoded) ==
            IdfPortableConfigStatus::UnsupportedVersion);

    IdfConfig readable = defaults();
    readable.numberBlackList = "+886\t123\n+886456";
    readable.forwardRules = "^09\t=>\n08";
    readable.pushChannels[0].type = PUSH_TYPE_CUSTOM;
    readable.pushChannels[0].customBody = "line one\nline two\t{message}";
    readable.pushChannels[1].bodyTemplate = "body line one\nbody line two\t{message}";
    require(semanticallyValid(readable));
    IdfConfig invalid_type = readable;
    invalid_type.pushChannels[0].type = 0;
    require(!semanticallyValid(invalid_type));
    IdfConfig invalid_c1 = readable;
    invalid_c1.deviceName = std::string("bad\xC1\x81", 5);
    require(!semanticallyValid(invalid_c1));

    std::vector<uint8_t> v5_blob;
    std::vector<uint8_t> blob;
    require(encodeV5(original, 42, v5_blob));
    require(encodeV6(original, 42, blob));
    require(blob.size() == v5_blob.size() + sizeof(uint32_t));
    require(std::equal(v5_blob.begin() + kHeaderBytes, v5_blob.end(), blob.begin() + kHeaderBytes));
    IdfConfig decoded;
    uint16_t schema = 0;
    uint32_t generation = 0;
    Reader direct_reader(v5_blob.data() + kHeaderBytes, v5_blob.data() + v5_blob.size());
    IdfConfig direct_decoded;
    bool direct_ok = decodeV5(direct_reader, direct_decoded);
    require(direct_ok && direct_reader.atEnd() && semanticallyValid(direct_decoded));
    require(decodeBlob(blob, decoded, schema, generation) == DecodeResult::Valid);
    require(schema == CONFIG_SCHEMA_VERSION && generation == 42);
    require(decoded.deviceName == original.deviceName);
    require(decoded.hostname == original.hostname);
    require(decoded.notificationLocale == original.notificationLocale);
    require(decoded.webAccounts[1].username == "operator");
    require(decoded.pushChannels[0].customBody == "{message}");
    require(decoded.wifiNetworks[0].pass == "password");
    require(!decoded.roamingEnabled);

    require(encodeV5(defaults(), 43, v5_blob));
    require(decodeBlob(v5_blob, decoded, schema, generation) == DecodeResult::Valid);
    require(schema == 5 && generation == 43 && decoded.kaTrafficKB == DEFAULT_KEEPALIVE_TRAFFIC_KB);
    writeHeader(v5_blob, 5, 0, kHeaderBytes);
    portable_target.kaTrafficKB = 4321;
    require(idf_config_storage_decode_portable(v5_blob.data(), v5_blob.size(), portable_target,
                                               portable_decoded) == IdfPortableConfigStatus::Ok);
    require(portable_decoded.kaTrafficKB == portable_target.kaTrafficKB);

    std::vector<uint8_t> bad_crc = blob;
    bad_crc.back() ^= 0x01;
    require(decodeBlob(bad_crc, decoded, schema, generation) == DecodeResult::Invalid);
    std::vector<uint8_t> bad_length = blob;
    bad_length[12] ^= 0x01;
    require(decodeBlob(bad_length, decoded, schema, generation) == DecodeResult::Invalid);
    std::vector<uint8_t> future = blob;
    future[4] = static_cast<uint8_t>(CONFIG_SCHEMA_VERSION + 1);
    require(decodeBlob(future, decoded, schema, generation) == DecodeResult::Unsupported);

    IdfConfig invalid = original;
    invalid.wifiNetworks[0].ssid.assign(MAX_WIFI_SSID_BYTES + 1, 'x');
    require(!encodeV6(invalid, 43, blob));
    IdfConfig invalid_traffic = original;
    invalid_traffic.kaTrafficKB = MAX_KEEPALIVE_TRAFFIC_KB + 1;
    require(!encodeV6(invalid_traffic, 43, blob));

    IdfConfig maximum = defaults();
    maximum.deviceName.assign(MAX_DEVICE_NAME_BYTES, 'D');
    maximum.hostname.assign(MAX_HOSTNAME_LENGTH, 'h');
    maximum.notificationLocale = NOTIFICATION_LOCALE_EN;
    maximum.smtpServer.assign(MAX_SMTP_SERVER_BYTES, 's');
    maximum.smtpUser.assign(MAX_SMTP_USER_BYTES, 'u');
    maximum.smtpPass.assign(MAX_SMTP_PASSWORD_BYTES, 'p');
    maximum.smtpSendTo.assign(MAX_SMTP_RECIPIENT_BYTES, 'r');
    maximum.adminPhone.assign(MAX_ADMIN_PHONE_BYTES, '1');
    maximum.numberBlackList.assign(MAX_BLACKLIST_BYTES, 'b');
    maximum.forwardRules.assign(MAX_FORWARD_RULES_BYTES, 'f');
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        maximum.webAccounts[i].username.assign(MAX_WEB_USERNAME_BYTES, 'a');
        maximum.webAccounts[i].password.assign(MAX_WEB_PASSWORD_BYTES, 'q');
    }
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        maximum.pushChannels[i].type = PUSH_TYPE_CUSTOM;
        maximum.pushChannels[i].name.assign(MAX_PUSH_NAME_BYTES, 'n');
        maximum.pushChannels[i].url.assign(MAX_PUSH_URL_BYTES, 'U');
        maximum.pushChannels[i].key1.assign(MAX_PUSH_KEY1_BYTES, '1');
        maximum.pushChannels[i].key2.assign(MAX_PUSH_KEY2_BYTES, '2');
        maximum.pushChannels[i].customBody.assign(MAX_CUSTOM_BODY_BYTES, 'c');
    }
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        maximum.wifiNetworks[i].ssid.assign(MAX_WIFI_SSID_BYTES, 'w');
        maximum.wifiNetworks[i].pass.assign(MAX_WIFI_PASSWORD_BYTES, 'P');
    }
    maximum.networkMode = NETWORK_MODE_MIX;
    maximum.heartbeatInterval = MAX_HEARTBEAT_INTERVAL_HOURS;
    maximum.wifiTxPowerQuarterDbm = WIFI_TX_POWER_20DBM;
    maximum.kaIntervalDays = 3650;
    maximum.kaAction = 3;
    maximum.kaTarget.assign(MAX_KEEPALIVE_TARGET_BYTES, 't');
    maximum.kaUrl.assign(MAX_KEEPALIVE_URL_BYTES, 'u');
    maximum.kaProfile.assign(MAX_KEEPALIVE_PROFILE_BYTES, 'k');
    maximum.kaTrafficKB = MAX_KEEPALIVE_TRAFFIC_KB;
    maximum.tzOffsetMin = 840;
    maximum.ntpServer.assign(MAX_NTP_SERVER_BYTES, 'n');
    maximum.rebootHour = 23;
    maximum.smsHealthHour = 23;
    maximum.apn.assign(MAX_APN_BYTES, 'a');
    maximum.operatorPlmn.assign(MAX_OPERATOR_PLMN_BYTES, 'o');
    maximum.phoneNumber.assign(MAX_PHONE_NUMBER_BYTES, '9');
    for (int i = 0; i < IDF_MAX_SIM_CREDENTIALS; ++i) {
        maximum.simCredentials[i].iccid = std::string(21, '8') + static_cast<char>('0' + i);
        maximum.simCredentials[i].pin.assign(MAX_SIM_PIN_BYTES, '1');
        maximum.simCredentials[i].puk.assign(MAX_SIM_PUK_BYTES, '2');
        maximum.simCredentials[i].pinMaxAttempts = 2;
        maximum.simCredentials[i].pukMaxAttempts = 5;
        maximum.simCredentials[i].pinFailedAttempts = 2;
        maximum.simCredentials[i].pukFailedAttempts = 5;
    }
    for (int i = 0; i < IDF_MAX_SCHED_TASKS; ++i) {
        maximum.schedTasks[i].name.assign(MAX_SCHEDULE_NAME_BYTES, 'N');
        maximum.schedTasks[i].profile.assign(MAX_SCHEDULE_PROFILE_BYTES, 'P');
        maximum.schedTasks[i].target.assign(MAX_SCHEDULE_TARGET_BYTES, 'T');
        maximum.schedTasks[i].payload.assign(MAX_SCHEDULE_PAYLOAD_BYTES, 'Y');
        maximum.schedTasks[i].intervalDays = 3650;
        maximum.schedTasks[i].action = 3;
    }
    require(semanticallyValid(maximum));
    std::vector<uint8_t> maximum_blob;
    require(encodeV6(maximum, 44, maximum_blob));
    require(maximum_blob.size() <= MAX_CONFIG_BLOB_SIZE);
    size_t maximum_portable_size = 0;
    require(idf_config_storage_encode_portable(maximum, portable_storage,
                                               sizeof(portable_storage),
                                               &maximum_portable_size) == ESP_OK);
    require(maximum_portable_size <= MAX_CONFIG_BLOB_SIZE);
    s_config = maximum;
    size_t public_maximum_size = 0;
    reject_allocations = true;
    require(idf_config_export_portable(public_portable_storage,
                                       sizeof(public_portable_storage),
                                       &public_maximum_size) == ESP_OK);
    reject_allocations = false;
    require(public_maximum_size == maximum_portable_size);
    const std::string live_smtp_before_failure = s_config.smtpServer;
    size_t rejected_size = 123;
    require(idf_config_export_portable(public_portable_storage,
                                       public_maximum_size - 1,
                                       &rejected_size) == ESP_ERR_INVALID_SIZE);
    require(rejected_size == 0);
    require(std::all_of(public_portable_storage,
                        public_portable_storage + public_maximum_size - 1,
                        [](uint8_t value) { return value == 0; }));
    std::vector<uint8_t> live_after_failure;
    require(encodeV6(s_config, 44, live_after_failure));
    require(live_after_failure == maximum_blob &&
            s_config.smtpServer == live_smtp_before_failure);
    require(idf_config_export_portable(nullptr, sizeof(public_portable_storage),
                                       &rejected_size) == ESP_ERR_INVALID_ARG);
    require(idf_config_export_portable(public_portable_storage,
                                       sizeof(public_portable_storage), nullptr) == ESP_ERR_INVALID_ARG);

    std::vector<uint8_t> marker;
    writeMarker(marker, CONFIG_SCHEMA_VERSION, 42, static_cast<uint32_t>(blob.size()),
                crc32(blob.data(), blob.size()));
    uint16_t marker_schema = 0;
    uint32_t marker_generation = 0;
    uint32_t marker_length = 0;
    uint32_t marker_crc = 0;
    require(readMarker(marker, marker_schema, marker_generation, marker_length, marker_crc));
    require(marker.size() == 20);
    require(marker_schema == 0 && marker_generation == 42);
    require(marker_length == blob.size() && marker_crc == crc32(blob.data(), blob.size()));
    marker[16] ^= 0x01;
    require(!readMarker(marker, marker_schema, marker_generation, marker_length, marker_crc));
    require(generationNewer(1, 0));
    require(generationNewer(0, UINT32_MAX));

    // Build the immutable v1 payload shape and verify migration defaults.
    Writer legacy;
    legacy.u32(465);
    legacy.string("smtp.example");
    legacy.string("legacy-user");
    legacy.string("legacy-pass");
    legacy.string("ops@example");
    legacy.string("+886900000000");
    legacy.string("legacy-blacklist");
    for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
        legacy.string(i == 0 ? "legacy-admin" : "");
        legacy.string(i == 0 ? "legacy-secret" : "");
    }
    for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
        legacy.u8(i == 0 ? 1 : 0);
        legacy.u8(i == 1 ? PUSH_TYPE_NONE : PUSH_TYPE_POST_JSON);
        legacy.string("legacy-channel");
        legacy.string(i == 0 ? "https://push.example" : "");
        legacy.string("");
        legacy.string("");
        legacy.string(i == 1 ? "stale-v1-body" : "");
    }
    std::vector<uint8_t> v1(kHeaderBytes, 0);
    std::vector<uint8_t> legacy_payload = legacy.take();
    v1.insert(v1.end(), legacy_payload.begin(), legacy_payload.end());
    writeHeader(v1, 1, 9, kHeaderBytes);
    require(decodeBlob(v1, decoded, schema, generation) == DecodeResult::Valid);
    require(schema == 1 && generation == 9);
    require(decoded.webAccounts[0].username == "legacy-admin");
    require(decoded.hostname == "sms");
    require(!decoded.roamingEnabled);
    require(decoded.pushChannels[1].customBody.empty());
    require(decoded.pushChannels[1].type == PUSH_TYPE_POST_JSON);

    writeHeader(v1, 1, 0, kHeaderBytes);
    portable_target.emailEnabled = false;
    portable_target.forwardRules = "target-forward-rule";
    portable_target.kaEnabled = true;
    portable_target.dataEnabled = true;
    portable_target.apn = "target-apn";
    require(idf_config_storage_decode_portable(v1.data(), v1.size(), portable_target,
                                               portable_decoded) == IdfPortableConfigStatus::Ok);
    require(portable_decoded.smtpServer == "smtp.example");
    require(portable_decoded.deviceName == portable_target.deviceName);
    require(portable_decoded.webAccounts[0].username == portable_target.webAccounts[0].username);
    require(portable_decoded.wifiNetworks[0].ssid == portable_target.wifiNetworks[0].ssid);
    require(portable_decoded.emailEnabled == portable_target.emailEnabled);
    require(portable_decoded.forwardRules == portable_target.forwardRules);
    require(portable_decoded.kaEnabled == portable_target.kaEnabled);
    require(portable_decoded.dataEnabled == portable_target.dataEnabled);
    require(portable_decoded.apn == portable_target.apn);

    auto append_common_v2_payload = [](Writer& writer, uint8_t push_type, bool zero_slot = false,
                                       bool stale_body = false) {
        writer.u32(465);
        writer.string("v2-device");
        writer.string("sms-v2");
        writer.string(NOTIFICATION_LOCALE_ZH_TW);
        writer.string("smtp.example");
        writer.string("legacy-user");
        writer.string("legacy-pass");
        writer.string("ops@example");
        writer.string("+886900000000");
        writer.string("");
        for (int i = 0; i < IDF_MAX_WEB_ACCOUNTS; ++i) {
            writer.string(i == 0 ? "v2-admin" : "");
            writer.string(i == 0 ? "v2-secret" : "");
        }
        for (int i = 0; i < IDF_MAX_PUSH_CHANNELS; ++i) {
            writer.u8(i == 0 ? 1 : 0);
            writer.u8(zero_slot && i == 1 ? PUSH_TYPE_NONE : push_type);
            writer.string("legacy-channel");
            writer.string(i == 0 ? "https://push.example" : "");
            writer.string("");
            writer.string("");
            writer.string("");
            writer.string("");
            writer.string(stale_body && i == 1 ? "stale-v2-body" : "");
        }
    };

    for (uint16_t old_schema : {static_cast<uint16_t>(2), static_cast<uint16_t>(3)}) {
        Writer common;
        append_common_v2_payload(common, old_schema == 2 ? PUSH_TYPE_TELEGRAM : PUSH_TYPE_NTFY, true);
        std::vector<uint8_t> old_blob(kHeaderBytes, 0);
        std::vector<uint8_t> common_payload = common.take();
        old_blob.insert(old_blob.end(), common_payload.begin(), common_payload.end());
        writeHeader(old_blob, old_schema, old_schema, kHeaderBytes);
        require(decodeBlob(old_blob, decoded, schema, generation) == DecodeResult::Valid);
        require(schema == old_schema && generation == old_schema);
        require(decoded.deviceName == "v2-device");
        require(decoded.webAccounts[0].username == "v2-admin");
        require(decoded.pushChannels[0].type == (old_schema == 2 ? PUSH_TYPE_TELEGRAM : PUSH_TYPE_NTFY));
        require(decoded.pushChannels[1].titleTemplate.empty());
        require(decoded.pushChannels[1].bodyTemplate.empty());
        require(decoded.pushChannels[1].customBody.empty());
        require(decoded.pushChannels[1].type == PUSH_TYPE_POST_JSON);
        require(!decoded.roamingEnabled);

        writeHeader(old_blob, old_schema, 0, kHeaderBytes);
        require(idf_config_storage_decode_portable(old_blob.data(), old_blob.size(), portable_target,
                                                   portable_decoded) == IdfPortableConfigStatus::Ok);
        require(portable_decoded.smtpServer == "smtp.example");
        require(portable_decoded.deviceName == portable_target.deviceName);
        require(portable_decoded.webAccounts[0].username == portable_target.webAccounts[0].username);
        require(portable_decoded.wifiNetworks[0].ssid == portable_target.wifiNetworks[0].ssid);
        require(portable_decoded.networkMode == portable_target.networkMode);
        require(portable_decoded.emailEnabled == portable_target.emailEnabled);
        require(portable_decoded.kaEnabled == portable_target.kaEnabled);
    }

    Writer malformed_v2_payload;
    append_common_v2_payload(malformed_v2_payload, PUSH_TYPE_TELEGRAM, false, true);
    std::vector<uint8_t> malformed_v2(kHeaderBytes, 0);
    std::vector<uint8_t> malformed_v2_bytes = malformed_v2_payload.take();
    malformed_v2.insert(malformed_v2.end(), malformed_v2_bytes.begin(), malformed_v2_bytes.end());
    writeHeader(malformed_v2, 2, 20, kHeaderBytes);
    require(decodeBlob(malformed_v2, decoded, schema, generation) == DecodeResult::Invalid);

    Writer v4_payload;
    append_common_v2_payload(v4_payload, PUSH_TYPE_NTFY, true);
    for (int i = 0; i < IDF_MAX_WIFI_NETWORKS; ++i) {
        v4_payload.string(i == 0 ? "wifi-v4" : "");
        v4_payload.string(i == 0 ? "password" : "");
    }
    v4_payload.u8(NETWORK_MODE_MIX);
    v4_payload.u8(0);
    v4_payload.u32(12);
    std::vector<uint8_t> v4(kHeaderBytes, 0);
    std::vector<uint8_t> v4_bytes = v4_payload.take();
    v4.insert(v4.end(), v4_bytes.begin(), v4_bytes.end());
    writeHeader(v4, 4, 40, kHeaderBytes);
    require(decodeBlob(v4, decoded, schema, generation) == DecodeResult::Valid);
    require(schema == 4 && generation == 40);
    require(decoded.wifiNetworks[0].ssid == "wifi-v4");
    require(decoded.networkMode == NETWORK_MODE_MIX && !decoded.heartbeatEnable);
    require(decoded.heartbeatInterval == 12);
    require(decoded.pushChannels[1].type == PUSH_TYPE_POST_JSON);
    require(!decoded.roamingEnabled);

    writeHeader(v4, 4, 0, kHeaderBytes);
    require(idf_config_storage_decode_portable(v4.data(), v4.size(), portable_target,
                                               portable_decoded) == IdfPortableConfigStatus::Ok);
    require(portable_decoded.deviceName == portable_target.deviceName);
    require(portable_decoded.webAccounts[0].username == portable_target.webAccounts[0].username);
    require(portable_decoded.wifiNetworks[0].ssid == "wifi-v4");
    require(portable_decoded.networkMode == NETWORK_MODE_MIX);
    require(!portable_decoded.heartbeatEnable && portable_decoded.heartbeatInterval == 12);
    require(portable_decoded.emailEnabled == portable_target.emailEnabled);
    require(portable_decoded.forwardRules == portable_target.forwardRules);
    require(portable_decoded.kaEnabled == portable_target.kaEnabled);
    require(portable_decoded.dataEnabled == portable_target.dataEnabled);
    require(portable_decoded.apn == portable_target.apn);

    // Exercise the production slot selector against a tiny NVS shim.  A
    // damaged/incomplete sibling must not hide a valid prior; an authenticated
    // future schema is ignored when older, but blocks when newer.
    IdfConfig slot_value = defaults();
    std::vector<uint8_t> slot_blob;
    require(encodeV6(slot_value, 10, slot_blob));
    FakeStore store;
    fake_store = &store;
    FakeStore allocation_failure_store;
    fake_store = &allocation_failure_store;
    fail_allocation_after = 1;
    require(idf_config_storage_save(slot_value) == ESP_ERR_NO_MEM);
    fail_allocation_after = -1;
    require(!allocation_failure_store.state_present &&
            allocation_failure_store.blobs[0].empty() &&
            allocation_failure_store.blobs[1].empty() &&
            allocation_failure_store.markers[0].empty() &&
            allocation_failure_store.markers[1].empty());
    fake_store = &store;
    install_pair(store, 0, slot_blob, 10);
    store.blobs[1] = {0x01, 0x02, 0x03};
    store.markers[1] = store.markers[0];
    Slot slots[2];
    int active = -1;
    uint32_t selected_generation = 0;
    bool committed_invalid = false;
    bool unsupported = false;
    bool any_data = false;
    require(selectSlots(0, slots, active, selected_generation, committed_invalid, unsupported, any_data));
    require(active == 0 && selected_generation == 10 && !committed_invalid && !unsupported);

    store.blobs[1].clear();
    store.markers[1] = store.markers[0];
    require(selectSlots(0, slots, active, selected_generation, committed_invalid, unsupported, any_data));
    require(active == 0 && !committed_invalid && !unsupported);

    store.blobs[0].clear();
    store.markers[0].clear();
    store.blobs[1] = {0x01, 0x02, 0x03};
    store.markers[1].clear();
    require(selectSlots(0, slots, active, selected_generation, committed_invalid, unsupported, any_data));
    require(active == -1 && committed_invalid && !unsupported);

    std::vector<uint8_t> older_future = slot_blob;
    older_future[4] = static_cast<uint8_t>(CONFIG_SCHEMA_VERSION + 1);
    writeHeader(older_future, static_cast<uint16_t>(CONFIG_SCHEMA_VERSION + 1), 9, kHeaderBytes);
    install_pair(store, 0, slot_blob, 10);
    install_pair(store, 1, older_future, 9);
    require(selectSlots(0, slots, active, selected_generation, committed_invalid, unsupported, any_data));
    require(active == 0 && !unsupported);

    std::vector<uint8_t> newer_future = slot_blob;
    newer_future[4] = static_cast<uint8_t>(CONFIG_SCHEMA_VERSION + 1);
    writeHeader(newer_future, static_cast<uint16_t>(CONFIG_SCHEMA_VERSION + 1), 11, kHeaderBytes);
    install_pair(store, 1, newer_future, 11);
    require(selectSlots(0, slots, active, selected_generation, committed_invalid, unsupported, any_data));
    require(active == -1 && unsupported);

    std::vector<uint8_t> wrap_supported = slot_blob;
    writeHeader(wrap_supported, CONFIG_SCHEMA_VERSION, UINT32_MAX, kHeaderBytes);
    install_pair(store, 0, wrap_supported, UINT32_MAX);
    std::vector<uint8_t> wrap_future = newer_future;
    writeHeader(wrap_future, static_cast<uint16_t>(CONFIG_SCHEMA_VERSION + 1), 0, kHeaderBytes);
    install_pair(store, 1, wrap_future, 0);
    require(selectSlots(0, slots, active, selected_generation, committed_invalid, unsupported, any_data));
    require(active == -1 && unsupported);

    // The first appcfg write has no rollback slot.  A cut after its blob commit
    // leaves state=MIGRATING plus blob-only cfgA; load must rebuild and commit
    // defaults.  Marker-only and malformed committed pairs are not protocol
    // residues and must remain fail-closed.
    FakeStore migration_store;
    fake_store = &migration_store;
    migration_store.state_present = true;
    migration_store.state = CONFIG_STATE_MIGRATING;
    require(encodeV6(defaults(), 1, migration_store.blobs[0]));
    s_partitionReady = false;
    s_activeSlot = -1;
    s_activeGeneration = 0;
    IdfConfig recovered;
    IdfConfigLoadStatus load_status = IdfConfigLoadStatus::Unknown;
    require(idf_config_storage_load(recovered, &load_status) == ESP_OK);
    require(load_status == IdfConfigLoadStatus::FirstBoot && !migration_store.markers[0].empty());

    FakeStore marker_only_store;
    fake_store = &marker_only_store;
    marker_only_store.state_present = true;
    marker_only_store.state = CONFIG_STATE_MIGRATING;
    writeMarker(marker_only_store.markers[0], CONFIG_SCHEMA_VERSION, 1, 100, 200);
    s_activeSlot = -1;
    require(idf_config_storage_load(recovered, &load_status) == ESP_ERR_INVALID_STATE);

    FakeStore malformed_store;
    fake_store = &malformed_store;
    malformed_store.state_present = true;
    malformed_store.state = CONFIG_STATE_MIGRATING;
    require(encodeV6(defaults(), 1, malformed_store.blobs[0]));
    writeMarker(malformed_store.markers[0], CONFIG_SCHEMA_VERSION, 1,
                static_cast<uint32_t>(malformed_store.blobs[0].size()), 0);
    s_activeSlot = -1;
    require(idf_config_storage_load(recovered, &load_status) == ESP_ERR_INVALID_STATE);
    return 0;
}
"""


class IdfConfigCodecTest(unittest.TestCase):
    def test_production_codec_round_trip_and_faults(self) -> None:
        compiler = shutil.which("g++")
        if compiler is None:
            self.fail("g++ is required for the production codec host check")
        with tempfile.TemporaryDirectory(prefix="idf-config-codec-") as temp_dir:
            temp = Path(temp_dir)
            (temp / "esp_err.h").write_text(ESP_ERR_H, encoding="utf-8")
            (temp / "esp_log.h").write_text(ESP_LOG_H, encoding="utf-8")
            (temp / "nvs.h").write_text(NVS_H, encoding="utf-8")
            (temp / "nvs_flash.h").write_text(NVS_FLASH_H, encoding="utf-8")
            (temp / "freertos").mkdir()
            (temp / "freertos" / "FreeRTOS.h").write_text(
                "#pragma once\n#include <stdint.h>\n#define pdTRUE 1\n#define portMAX_DELAY UINT32_MAX\n",
                encoding="utf-8",
            )
            (temp / "freertos" / "semphr.h").write_text(
                "#pragma once\n#include <stdint.h>\ntypedef void* SemaphoreHandle_t;\n"
                "SemaphoreHandle_t xSemaphoreCreateMutex();\n"
                "int xSemaphoreTake(SemaphoreHandle_t, uint32_t);\n"
                "int xSemaphoreGive(SemaphoreHandle_t);\n",
                encoding="utf-8",
            )
            (temp / "idf_log.h").write_text(
                "#pragma once\nvoid idf_log_line(const char*);\nvoid idf_logf(const char*, ...);\n",
                encoding="utf-8",
            )
            source = temp / "idf_config_codec_host.cpp"
            source.write_text(HOST_TEST_CPP, encoding="utf-8")
            binary = temp / "idf_config_codec_host"
            compile = [
                compiler,
                "-std=c++17",
                "-fexceptions",
                "-O0",
                "-ffunction-sections",
                "-fdata-sections",
                "-Werror",
                "-Wno-unused-function",
                "-Wno-unused-variable",
                "-Wl,--gc-sections",
                "-I",
                str(temp),
                "-I",
                str(ROOT / "components/idf_config"),
                "-I",
                str(ROOT / "components/idf_config/include"),
                str(source),
                "-o",
                str(binary),
            ]
            subprocess.run(compile, cwd=ROOT, check=True)
            subprocess.run([str(binary)], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
