#!/usr/bin/env python3
"""Compile and exercise the production bounded CA cache with a fake NVS."""

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
#define ESP_ERR_NOT_FOUND 0x107
#define ESP_ERR_NVS_NOT_FOUND 0x1102
"""

NVS_H = r"""#pragma once
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"
typedef uintptr_t nvs_handle_t;
typedef enum { NVS_READONLY = 0, NVS_READWRITE = 1 } nvs_open_mode_t;
typedef struct {
    size_t used_entries;
    size_t free_entries;
    size_t total_entries;
    size_t namespace_count;
    size_t available_entries;
} nvs_stats_t;
esp_err_t nvs_open_from_partition(const char*, const char*, nvs_open_mode_t, nvs_handle_t*);
void nvs_close(nvs_handle_t);
esp_err_t nvs_commit(nvs_handle_t);
esp_err_t nvs_erase_key(nvs_handle_t, const char*);
esp_err_t nvs_get_blob(nvs_handle_t, const char*, void*, size_t*);
esp_err_t nvs_set_blob(nvs_handle_t, const char*, const void*, size_t);
esp_err_t nvs_get_stats(const char*, nvs_stats_t*);
"""

NVS_FLASH_H = r"""#pragma once
#include "esp_err.h"
esp_err_t nvs_flash_init_partition(const char*);
"""

FREERTOS_H = r"""#pragma once
#include <stdint.h>
typedef int BaseType_t;
typedef uint32_t TickType_t;
typedef void* SemaphoreHandle_t;
typedef struct { uintptr_t opaque; } StaticSemaphore_t;
typedef int portMUX_TYPE;
#define pdTRUE 1
#define pdFALSE 0
#define pdMS_TO_TICKS(value) (value)
#define portMUX_INITIALIZER_UNLOCKED 0
#define taskENTER_CRITICAL(lock) ((void)(lock))
#define taskEXIT_CRITICAL(lock) ((void)(lock))
"""

SEMPHR_H = r"""#pragma once
#include "FreeRTOS.h"
SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t*);
BaseType_t xSemaphoreTake(SemaphoreHandle_t, TickType_t);
BaseType_t xSemaphoreGive(SemaphoreHandle_t);
"""

SHA_H = r"""#pragma once
#include <stddef.h>
int mbedtls_sha256(const unsigned char*, size_t, unsigned char[32], int);
"""

HOST_CPP = r"""#include <algorithm>
#include <array>
#include <condition_variable>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "freertos/semphr.h"
#include "idf_config_ca_store.cpp"

static std::unordered_map<std::string, std::vector<uint8_t>> store;
static size_t available_entries = 4000;
static bool corrupt_cert_readback = false;
static std::mutex api_mutex;
static std::mutex interleave_mutex;
static std::condition_variable interleave_changed;
static int semaphore_take_attempts = 0;
static int reserve_entries = 0;
static bool release_first_install = false;
static bool first_install_done = false;
static bool mutex_create_fails = false;
static bool mutex_take_fails = false;
static thread_local int install_role = 0;

static void require(bool condition) { if (!condition) std::abort(); }

SemaphoreHandle_t xSemaphoreCreateMutexStatic(StaticSemaphore_t*) {
    return mutex_create_fails ? nullptr : reinterpret_cast<SemaphoreHandle_t>(1);
}
BaseType_t xSemaphoreTake(SemaphoreHandle_t handle, TickType_t) {
    {
        std::lock_guard<std::mutex> guard(interleave_mutex);
        ++semaphore_take_attempts;
        interleave_changed.notify_all();
    }
    if (!handle || mutex_take_fails) return pdFALSE;
    api_mutex.lock();
    return pdTRUE;
}
BaseType_t xSemaphoreGive(SemaphoreHandle_t handle) {
    if (!handle) return pdFALSE;
    api_mutex.unlock();
    return pdTRUE;
}

esp_err_t nvs_flash_init_partition(const char*) { return ESP_OK; }
esp_err_t nvs_open_from_partition(const char* partition, const char* name,
                                  nvs_open_mode_t, nvs_handle_t* handle) {
    if (!handle || std::strcmp(partition, "appcfg") || std::strcmp(name, "ca_cache")) {
        return ESP_ERR_INVALID_ARG;
    }
    *handle = 1;
    return ESP_OK;
}
void nvs_close(nvs_handle_t) {}
esp_err_t nvs_commit(nvs_handle_t) { return ESP_OK; }
esp_err_t nvs_get_stats(const char*, nvs_stats_t* stats) {
    if (!stats) return ESP_ERR_INVALID_ARG;
    if (install_role != 0) {
        std::unique_lock<std::mutex> lock(interleave_mutex);
        ++reserve_entries;
        interleave_changed.notify_all();
        if (install_role == 1) {
            interleave_changed.wait(lock, [] { return release_first_install; });
        } else {
            interleave_changed.wait(lock, [] { return first_install_done; });
        }
    }
    *stats = {};
    stats->free_entries = available_entries;
    stats->available_entries = available_entries;
    return ESP_OK;
}
esp_err_t nvs_erase_key(nvs_handle_t, const char* key) {
    return store.erase(key) ? ESP_OK : ESP_ERR_NVS_NOT_FOUND;
}
esp_err_t nvs_set_blob(nvs_handle_t, const char* key, const void* data, size_t length) {
    if (!data || !length) return ESP_ERR_INVALID_ARG;
    const auto* first = static_cast<const uint8_t*>(data);
    store[key] = std::vector<uint8_t>(first, first + length);
    return ESP_OK;
}
esp_err_t nvs_get_blob(nvs_handle_t, const char* key, void* data, size_t* length) {
    if (!length) return ESP_ERR_INVALID_ARG;
    auto found = store.find(key);
    if (found == store.end()) return ESP_ERR_NVS_NOT_FOUND;
    if (!data) { *length = found->second.size(); return ESP_OK; }
    if (*length < found->second.size()) return ESP_ERR_INVALID_SIZE;
    std::memcpy(data, found->second.data(), found->second.size());
    *length = found->second.size();
    if (corrupt_cert_readback && std::strncmp(key, "cert", 4) == 0) {
        static_cast<uint8_t*>(data)[*length - 1] ^= 1;
        corrupt_cert_readback = false;
    }
    return ESP_OK;
}

int mbedtls_sha256(const unsigned char* input, size_t length,
                   unsigned char output[32], int is224) {
    if (!input || !output || is224) return -1;
    uint32_t state = 2166136261u;
    for (size_t i = 0; i < length; ++i) state = (state ^ input[i]) * 16777619u;
    for (size_t i = 0; i < 32; ++i) {
        state = state * 1664525u + 1013904223u + static_cast<uint32_t>(i);
        output[i] = static_cast<uint8_t>(state >> 24);
    }
    return 0;
}

static size_t keys_with_prefix(const char* prefix) {
    return std::count_if(store.begin(), store.end(), [prefix](const auto& item) {
        return item.first.rfind(prefix, 0) == 0;
    });
}

static void reset_fixture() {
    store.clear();
    available_entries = 4000;
    corrupt_cert_readback = false;
    semaphore_take_attempts = 0;
    reserve_entries = 0;
    release_first_install = false;
    first_install_done = false;
    mutex_create_fails = false;
    mutex_take_fails = false;
}

static int run_concurrency() {
    reset_fixture();
    IdfConfigCaStatus status;
    std::vector<uint8_t> output;
    require(idf_config_ca_lookup("https://missing.example", output, &status) == ESP_ERR_NOT_FOUND);
    const uint8_t der1[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    const uint8_t der2[] = {0x30, 0x03, 0x02, 0x01, 0x02};
    esp_err_t first_result = ESP_ERR_INVALID_STATE;
    esp_err_t second_result = ESP_ERR_INVALID_STATE;
    std::thread first([&] {
        install_role = 1;
        first_result = idf_config_ca_install("https://one.example", der1, sizeof(der1), nullptr);
        std::lock_guard<std::mutex> guard(interleave_mutex);
        first_install_done = true;
        interleave_changed.notify_all();
    });
    {
        std::unique_lock<std::mutex> lock(interleave_mutex);
        interleave_changed.wait(lock, [] { return reserve_entries == 1; });
    }
    std::thread second([&] {
        install_role = 2;
        second_result = idf_config_ca_install("https://two.example", der2, sizeof(der2), nullptr);
    });
    {
        std::unique_lock<std::mutex> lock(interleave_mutex);
        interleave_changed.wait(lock, [] {
            return reserve_entries == 2 || semaphore_take_attempts >= 3;
        });
        release_first_install = true;
        interleave_changed.notify_all();
    }
    first.join();
    second.join();
    require(first_result == ESP_OK && second_result == ESP_OK);
    require(idf_config_ca_lookup("https://one.example", output, nullptr) == ESP_OK);
    require(output == std::vector<uint8_t>(der1, der1 + sizeof(der1)));
    require(idf_config_ca_lookup("https://two.example", output, nullptr) == ESP_OK);
    require(output == std::vector<uint8_t>(der2, der2 + sizeof(der2)));
    return 0;
}

static int run_fail_closed() {
    reset_fixture();
    const uint8_t der[] = {0x30, 0x01};
    std::vector<uint8_t> output = {9};
    IdfConfigCaStatus status;
    status.configured = true;
    mutex_create_fails = true;
    require(idf_config_ca_lookup("https://one.example", output, &status) == ESP_ERR_INVALID_STATE);
    require(output.empty() && !status.configured && store.empty());
    mutex_create_fails = false;
    require(idf_config_ca_lookup("https://one.example", output, &status) == ESP_ERR_NOT_FOUND);
    mutex_take_fails = true;
    require(idf_config_ca_install("https://one.example", der, sizeof(der), &status) ==
            ESP_ERR_INVALID_STATE);
    require(!status.configured && store.empty());
    return 0;
}

static int run_baseline() {
    const uint8_t der1[] = {0x30, 0x03, 0x02, 0x01, 0x01};
    const uint8_t der2[] = {0x30, 0x03, 0x02, 0x01, 0x02};
    IdfConfigCaStatus status;
    std::vector<uint8_t> output = {9};

    require(idf_config_ca_lookup("https://missing.example", output, &status) == ESP_ERR_NOT_FOUND);
    require(output.empty() && !status.configured && status.derLength == 0);
    require(idf_config_ca_install("http://bad.example", der1, sizeof(der1), nullptr) == ESP_ERR_INVALID_ARG);
    require(idf_config_ca_install("https://Bad.example", der1, sizeof(der1), nullptr) == ESP_ERR_INVALID_ARG);
    require(idf_config_ca_install("https://bad.example/path", der1, sizeof(der1), nullptr) == ESP_ERR_INVALID_ARG);
    std::vector<uint8_t> oversized(IDF_CONFIG_CA_MAX_DER_BYTES + 1, 1);
    require(idf_config_ca_install("https://one.example", oversized.data(), oversized.size(), nullptr) ==
            ESP_ERR_INVALID_SIZE);
    require(store.empty());

    require(idf_config_ca_install("https://one.example", der1, sizeof(der1), &status) == ESP_OK);
    require(status.configured && status.derLength == sizeof(der1));
    require(keys_with_prefix("cert") == 1 && keys_with_prefix("bind") == 1);
    require(idf_config_ca_lookup("https://one.example", output, &status) == ESP_OK);
    require(output == std::vector<uint8_t>(der1, der1 + sizeof(der1)));

    const auto first_hash = status.sha256;
    require(idf_config_ca_install("https://two.example:8443", der1, sizeof(der1), nullptr) == ESP_OK);
    require(keys_with_prefix("cert") == 1 && keys_with_prefix("bind") == 2);
    require(idf_config_ca_install("https://one.example", der2, sizeof(der2), nullptr) == ESP_OK);
    require(keys_with_prefix("cert") == 2);
    require(idf_config_ca_install("https://two.example:8443", der2, sizeof(der2), &status) == ESP_OK);
    require(keys_with_prefix("cert") == 1 && status.sha256 != first_hash);

    const size_t binding_count = keys_with_prefix("bind");
    corrupt_cert_readback = true;
    require(idf_config_ca_install("https://three.example", der1, sizeof(der1), nullptr) ==
            ESP_ERR_INVALID_STATE);
    require(keys_with_prefix("bind") == binding_count);

    available_entries = 1100;
    require(idf_config_ca_install("https://four.example", der1, sizeof(der1), nullptr) == ESP_ERR_NO_MEM);
    require(keys_with_prefix("bind") == binding_count);

    available_entries = 4000;
    require(idf_config_ca_status("https://two.example:8443", status) == ESP_OK);
    require(status.configured && status.derLength == sizeof(der2));
    return 0;
}

int main(int argc, char** argv) {
    if (argc == 2 && std::strcmp(argv[1], "concurrency") == 0) return run_concurrency();
    if (argc == 2 && std::strcmp(argv[1], "fail-closed") == 0) return run_fail_closed();
    return run_baseline();
}
"""


class IdfConfigCaStoreTest(unittest.TestCase):
    def test_bounded_deduplicated_staged_cache(self) -> None:
        compiler = shutil.which("g++")
        self.assertIsNotNone(compiler, "g++ is required")
        with tempfile.TemporaryDirectory(prefix="idf-config-ca-") as temp_dir:
            temp = Path(temp_dir)
            (temp / "mbedtls").mkdir()
            (temp / "freertos").mkdir()
            (temp / "esp_err.h").write_text(ESP_ERR_H, encoding="utf-8")
            (temp / "nvs.h").write_text(NVS_H, encoding="utf-8")
            (temp / "nvs_flash.h").write_text(NVS_FLASH_H, encoding="utf-8")
            (temp / "freertos" / "FreeRTOS.h").write_text(FREERTOS_H, encoding="utf-8")
            (temp / "freertos" / "semphr.h").write_text(SEMPHR_H, encoding="utf-8")
            (temp / "mbedtls" / "sha256.h").write_text(SHA_H, encoding="utf-8")
            source = temp / "ca_store_host.cpp"
            source.write_text(HOST_CPP, encoding="utf-8")
            binary = temp / "ca_store_host"
            subprocess.run([
                compiler, "-std=c++17", "-fexceptions", "-O0", "-Wall", "-Wextra", "-Werror",
                "-pthread",
                "-I", str(temp),
                "-I", str(ROOT / "components/idf_config"),
                "-I", str(ROOT / "components/idf_config/include"),
                str(source), "-o", str(binary),
            ], cwd=ROOT, check=True)
            subprocess.run([str(binary), "concurrency"], cwd=ROOT, check=True)
            subprocess.run([str(binary), "fail-closed"], cwd=ROOT, check=True)
            subprocess.run([str(binary)], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
