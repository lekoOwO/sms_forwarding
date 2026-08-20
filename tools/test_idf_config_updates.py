#!/usr/bin/env python3
"""Compile and exercise public config updates without an ESP-IDF install."""

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
#define ESP_ERR_NOT_FOUND 0x105
#define ESP_ERR_TIMEOUT 0x106
#define ESP_ERR_NOT_SUPPORTED 0x107
static inline const char* esp_err_to_name(esp_err_t) { return "stub"; }
"""

ESP_LOG_H = r"""#pragma once
#define ESP_LOGE(...) do { } while (0)
#define ESP_LOGW(...) do { } while (0)
#define ESP_LOGI(...) do { } while (0)
"""

FREERTOS_H = r"""#pragma once
#include <stdint.h>
#define pdTRUE 1
#define portMAX_DELAY UINT32_MAX
"""

SEMPHR_H = r"""#pragma once
#include <stdint.h>
typedef void* SemaphoreHandle_t;
SemaphoreHandle_t xSemaphoreCreateMutex();
int xSemaphoreTake(SemaphoreHandle_t, uint32_t);
int xSemaphoreGive(SemaphoreHandle_t);
"""

IDF_LOG_H = r"""#pragma once
void idf_log_line(const char*);
void idf_logf(const char*, ...);
"""

HOST_CPP = r"""#include <cstdio>
#include <cstdlib>
#include <new>

#define static_assert(...)
#include "idf_config.cpp"
#undef static_assert

static int save_count = 0;
static IdfConfig saved;
static esp_err_t save_result = ESP_OK;
static IdfPortableConfigStatus portable_decode_status = IdfPortableConfigStatus::Invalid;
static IdfConfig portable_decoded;
static IdfConfig portable_encoded;
static esp_err_t portable_encode_result = ESP_OK;
static int semaphore_take_result = pdTRUE;
static int semaphore_depth = 0;
static bool throw_storage_load = false;
static bool throw_storage_save = false;
static bool throw_portable_decode = false;
static bool throw_next_allocation = false;

void* operator new(std::size_t size) {
    if (throw_next_allocation) {
        throw_next_allocation = false;
        throw std::bad_alloc();
    }
    void* value = std::malloc(size);
    if (!value) throw std::bad_alloc();
    return value;
}

void* operator new[](std::size_t size) {
    if (throw_next_allocation) {
        throw_next_allocation = false;
        throw std::bad_alloc();
    }
    void* value = std::malloc(size);
    if (!value) throw std::bad_alloc();
    return value;
}

SemaphoreHandle_t xSemaphoreCreateMutex() { return reinterpret_cast<void*>(1); }
int xSemaphoreTake(SemaphoreHandle_t, uint32_t) {
    if (semaphore_take_result == pdTRUE) ++semaphore_depth;
    return semaphore_take_result;
}
int xSemaphoreGive(SemaphoreHandle_t) { --semaphore_depth; return pdTRUE; }
void idf_log_line(const char*) {}
void idf_logf(const char*, ...) {}

esp_err_t idf_config_storage_load(IdfConfig&, IdfConfigLoadStatus*) {
    if (throw_storage_load) throw std::bad_alloc();
    return ESP_ERR_INVALID_STATE;
}
esp_err_t idf_config_storage_save(const IdfConfig& value) {
    if (throw_storage_save) throw std::bad_alloc();
    ++save_count;
    saved = value;
    return save_result;
}
void idf_config_storage_factory_reset(IdfConfig& out) { out = IdfConfig(); }
esp_err_t idf_config_storage_encode_portable(const IdfConfig& source, uint8_t* output,
                                             size_t capacity, size_t* written) {
    if (!output || !written) return ESP_ERR_INVALID_ARG;
    *written = 0;
    if (portable_encode_result != ESP_OK) return portable_encode_result;
    if (capacity < 4) return ESP_ERR_INVALID_SIZE;
    portable_encoded = source;
    std::memcpy(output, "CFG2", 4);
    *written = 4;
    return ESP_OK;
}
IdfPortableConfigStatus idf_config_storage_decode_portable(const uint8_t*, size_t,
                                                           const IdfConfig&, IdfConfig& output) {
    if (throw_portable_decode) throw std::bad_alloc();
    if (portable_decode_status == IdfPortableConfigStatus::Ok) output = portable_decoded;
    return portable_decode_status;
}

static void require(bool condition) {
    if (!condition) std::abort();
}

static void reset() {
    s_config = IdfConfig();
    s_config.wifiNetworks[1] = {"untouched", "untouched-pass"};
    s_config.wifiNetworks[2] = {"old-name", "old-password"};
    save_count = 0;
    save_result = ESP_OK;
    portable_decode_status = IdfPortableConfigStatus::Invalid;
    portable_decoded = IdfConfig();
    portable_encoded = IdfConfig();
    portable_encode_result = ESP_OK;
    semaphore_take_result = pdTRUE;
    semaphore_depth = 0;
    throw_storage_load = false;
    throw_storage_save = false;
    throw_portable_decode = false;
    throw_next_allocation = false;
}

int run_config_tests() {
    reset();
    require(idf_config_save_wifi_profile(2, "old-name", "", false, true) == ESP_OK);
    require(save_count == 1 && saved.wifiNetworks[2].pass == "old-password");
    require(saved.wifiNetworks[1].ssid == "untouched");

    reset();
    require(idf_config_save_wifi_profile(2, "new-name", "", false, true) == ESP_ERR_INVALID_ARG);
    require(save_count == 0);

    reset();
    require(idf_config_save_wifi_profile(2, "new-name", "new-password", false, false) == ESP_OK);
    require(saved.wifiNetworks[2].ssid == "new-name" && saved.wifiNetworks[2].pass == "new-password");
    require(saved.wifiNetworks[1].ssid == "untouched");

    reset();
    require(idf_config_save_wifi_profile(2, "open-network", "ignored", true, true) == ESP_OK);
    require(saved.wifiNetworks[2].ssid == "open-network" && saved.wifiNetworks[2].pass.empty());

    reset();
    require(idf_config_save_wifi_profile(2, "", "ignored", false, true) == ESP_OK);
    require(saved.wifiNetworks[2].ssid.empty() && saved.wifiNetworks[2].pass.empty());
    require(saved.wifiNetworks[1].ssid == "untouched");

    reset();
    require(idf_config_save_wifi_profile(-1, "x", "password", false, false) == ESP_ERR_INVALID_ARG);
    require(idf_config_save_wifi_profile(IDF_MAX_WIFI_NETWORKS, "x", "password", false, false) == ESP_ERR_INVALID_ARG);
    require(idf_config_save_wifi_profile(2, "closed", "", false, false) == ESP_ERR_INVALID_ARG);
    require(idf_config_save_wifi_profile(2, "closed", "short", false, false) == ESP_ERR_INVALID_ARG);
    require(save_count == 0);

    reset();
    s_config.smtpServer = "snapshot.example";
    uint8_t portable[4] = {};
    size_t portable_size = 0;
    require(idf_config_export_portable(portable, sizeof(portable), &portable_size) == ESP_OK);
    require(portable_size == sizeof(portable) && std::memcmp(portable, "CFG2", 4) == 0);
    require(portable_encoded.smtpServer == "snapshot.example");
    require(save_count == 0);

    const IdfConfig before_failed_export = s_config;
    portable_size = 99;
    require(idf_config_export_portable(portable, sizeof(portable) - 1, &portable_size) ==
            ESP_ERR_INVALID_SIZE);
    require(portable_size == 0 && s_config.smtpServer == before_failed_export.smtpServer);
    require(idf_config_export_portable(nullptr, sizeof(portable), &portable_size) ==
            ESP_ERR_INVALID_ARG);
    require(idf_config_export_portable(portable, sizeof(portable), nullptr) ==
            ESP_ERR_INVALID_ARG);
    portable_encode_result = ESP_ERR_NO_MEM;
    require(idf_config_export_portable(portable, sizeof(portable), &portable_size) == ESP_ERR_NO_MEM);
    require(portable_size == 0 && s_config.smtpServer == before_failed_export.smtpServer);

    reset();
    s_config.deviceName = "local-device";
    s_config.smtpServer = "before.example";
    portable_decoded = s_config;
    portable_decoded.smtpServer = "restored.example";
    portable_decode_status = IdfPortableConfigStatus::Ok;
    const uint8_t valid[] = {1};
    IdfPortableConfigStatus status = IdfPortableConfigStatus::Invalid;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_OK);
    require(status == IdfPortableConfigStatus::Ok);
    require(save_count == 1 && saved.smtpServer == "restored.example");
    require(s_config.smtpServer == "restored.example" && s_config.deviceName == "local-device");

    reset();
    s_config.smtpServer = "unchanged.example";
    portable_decode_status = IdfPortableConfigStatus::Invalid;
    status = IdfPortableConfigStatus::Ok;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_ERR_INVALID_ARG);
    require(status == IdfPortableConfigStatus::Invalid);
    require(save_count == 0 && s_config.smtpServer == "unchanged.example");

    reset();
    status = IdfPortableConfigStatus::Ok;
    require(idf_config_restore_portable(nullptr, 0, &status) == ESP_ERR_INVALID_ARG);
    require(status == IdfPortableConfigStatus::Invalid);
    status = IdfPortableConfigStatus::Ok;
    require(idf_config_restore_portable(valid, 0, &status) == ESP_ERR_INVALID_ARG);
    require(status == IdfPortableConfigStatus::Invalid && save_count == 0);

    reset();
    s_config.smtpServer = "unchanged.example";
    semaphore_take_result = 0;
    status = IdfPortableConfigStatus::Invalid;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_ERR_TIMEOUT);
    require(status == IdfPortableConfigStatus::Ok);
    require(save_count == 0 && s_config.smtpServer == "unchanged.example");

    reset();
    s_config.smtpServer = "unchanged.example";
    portable_decode_status = IdfPortableConfigStatus::UnsupportedVersion;
    status = IdfPortableConfigStatus::Ok;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_ERR_NOT_SUPPORTED);
    require(status == IdfPortableConfigStatus::UnsupportedVersion);
    require(save_count == 0 && s_config.smtpServer == "unchanged.example");

    reset();
    s_config.smtpServer = "live.example";
    portable_decoded = s_config;
    portable_decoded.smtpServer = "candidate.example";
    portable_decode_status = IdfPortableConfigStatus::Ok;
    save_result = ESP_ERR_INVALID_STATE;
    status = IdfPortableConfigStatus::Invalid;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_ERR_INVALID_STATE);
    require(status == IdfPortableConfigStatus::Ok);
    require(save_count == 1 && saved.smtpServer == "candidate.example");
    require(s_config.smtpServer == "live.example");

    reset();
    s_config.smtpServer = "decode-live.example";
    throw_portable_decode = true;
    status = IdfPortableConfigStatus::Invalid;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_ERR_NO_MEM);
    require(status == IdfPortableConfigStatus::Ok && save_count == 0 && semaphore_depth == 0);
    require(s_config.smtpServer == "decode-live.example");
    throw_portable_decode = false;
    portable_decode_status = IdfPortableConfigStatus::Ok;
    portable_decoded = s_config;
    portable_decoded.smtpServer = "decode-retry.example";
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_OK);
    require(s_config.smtpServer == "decode-retry.example" && semaphore_depth == 0);

    reset();
    s_config.smtpServer = "save-live.example";
    portable_decode_status = IdfPortableConfigStatus::Ok;
    portable_decoded = s_config;
    portable_decoded.smtpServer = "save-candidate.example";
    throw_storage_save = true;
    status = IdfPortableConfigStatus::Invalid;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_ERR_NO_MEM);
    require(status == IdfPortableConfigStatus::Ok && save_count == 0 && semaphore_depth == 0);
    require(s_config.smtpServer == "save-live.example");
    throw_storage_save = false;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_OK);
    require(s_config.smtpServer == "save-candidate.example" && semaphore_depth == 0);

    reset();
    s_config.smtpServer = "begin-live.example";
    throw_next_allocation = true;
    status = IdfPortableConfigStatus::Invalid;
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_ERR_NO_MEM);
    require(status == IdfPortableConfigStatus::Ok && save_count == 0 && semaphore_depth == 0);
    require(s_config.smtpServer == "begin-live.example");
    portable_decode_status = IdfPortableConfigStatus::Ok;
    portable_decoded = s_config;
    portable_decoded.smtpServer = "begin-retry.example";
    require(idf_config_restore_portable(valid, sizeof(valid), &status) == ESP_OK);
    require(s_config.smtpServer == "begin-retry.example" && semaphore_depth == 0);

    reset();
    s_config.smtpServer = "boot-live.example";
    throw_storage_load = true;
    require(idf_config_load() == ESP_ERR_NO_MEM);
    require(idf_config_last_load_status() == IdfConfigLoadStatus::StorageError);
    require(s_config.smtpServer == "boot-live.example" && semaphore_depth == 0);
    return 0;
}
"""


class IdfConfigUpdateTest(unittest.TestCase):
    def test_indexed_wifi_profile_update_contract(self) -> None:
        compiler = shutil.which("g++")
        if compiler is None:
            self.fail("g++ is required for the config update host check")
        with tempfile.TemporaryDirectory(prefix="idf-config-update-") as temp_dir:
            temp = Path(temp_dir)
            (temp / "freertos").mkdir()
            (temp / "esp_err.h").write_text(ESP_ERR_H, encoding="utf-8")
            (temp / "esp_log.h").write_text(ESP_LOG_H, encoding="utf-8")
            (temp / "freertos" / "FreeRTOS.h").write_text(FREERTOS_H, encoding="utf-8")
            (temp / "freertos" / "semphr.h").write_text(SEMPHR_H, encoding="utf-8")
            (temp / "idf_log.h").write_text(IDF_LOG_H, encoding="utf-8")
            source = temp / "idf_config_update_host.cpp"
            source.write_text(HOST_CPP, encoding="utf-8")
            caller = temp / "idf_config_update_caller.cpp"
            caller.write_text(
                "extern int run_config_tests();\nint main() { return run_config_tests(); }\n",
                encoding="utf-8",
            )
            binary = temp / "idf_config_update_host"
            implementation_object = temp / "idf_config_update_host.o"
            caller_object = temp / "idf_config_update_caller.o"
            subprocess.run(
                [
                    compiler, "-std=c++17", "-fexceptions", "-O0", "-ffunction-sections", "-fdata-sections", "-Werror",
                    "-Wno-unused-function", "-Wno-unused-variable",
                    "-I", str(temp), "-I", str(ROOT / "components/idf_config"),
                    "-I", str(ROOT / "components/idf_config/include"), "-c", str(source),
                    "-o", str(implementation_object),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [compiler, "-std=c++17", "-fno-exceptions", "-Werror", "-c", str(caller),
                 "-o", str(caller_object)],
                cwd=ROOT,
                check=True,
            )
            subprocess.run(
                [compiler, "-Wl,--gc-sections", str(implementation_object), str(caller_object),
                 "-o", str(binary)],
                cwd=ROOT,
                check=True,
            )
            subprocess.run([str(binary)], cwd=ROOT, check=True)
            cmake = (ROOT / "components/idf_config/CMakeLists.txt").read_text(encoding="utf-8")
            self.assertIn('target_compile_options(${COMPONENT_LIB} PRIVATE "-fexceptions"', cmake)


if __name__ == "__main__":
    unittest.main()
