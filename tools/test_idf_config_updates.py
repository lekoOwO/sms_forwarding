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
#define ESP_ERR_INVALID_STATE 0x103
#define ESP_ERR_NOT_FOUND 0x104
#define ESP_ERR_TIMEOUT 0x105
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

#define static_assert(...)
#include "idf_config.cpp"
#undef static_assert

static int save_count = 0;
static IdfConfig saved;

SemaphoreHandle_t xSemaphoreCreateMutex() { return reinterpret_cast<void*>(1); }
int xSemaphoreTake(SemaphoreHandle_t, uint32_t) { return pdTRUE; }
int xSemaphoreGive(SemaphoreHandle_t) { return pdTRUE; }
void idf_log_line(const char*) {}
void idf_logf(const char*, ...) {}

esp_err_t idf_config_storage_load(IdfConfig&, IdfConfigLoadStatus*) { return ESP_ERR_INVALID_STATE; }
esp_err_t idf_config_storage_save(const IdfConfig& value) {
    ++save_count;
    saved = value;
    return ESP_OK;
}
void idf_config_storage_factory_reset(IdfConfig& out) { out = IdfConfig(); }

static void require(bool condition) {
    if (!condition) std::abort();
}

static void reset() {
    s_config = IdfConfig();
    s_config.wifiNetworks[1] = {"untouched", "untouched-pass"};
    s_config.wifiNetworks[2] = {"old-name", "old-password"};
    save_count = 0;
}

int main() {
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
            binary = temp / "idf_config_update_host"
            subprocess.run(
                [
                    compiler, "-std=c++17", "-O0", "-ffunction-sections", "-fdata-sections", "-Werror",
                    "-Wno-unused-function", "-Wno-unused-variable", "-Wl,--gc-sections",
                    "-I", str(temp), "-I", str(ROOT / "components/idf_config"),
                    "-I", str(ROOT / "components/idf_config/include"), str(source), "-o", str(binary),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run([str(binary)], cwd=ROOT, check=True)


if __name__ == "__main__":
    unittest.main()
