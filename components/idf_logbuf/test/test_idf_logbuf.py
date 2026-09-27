#!/usr/bin/env python3
"""Host checks for the non-blocking RAM log path."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]

ESP_ERR_H = r"""#pragma once
#include <stdint.h>
typedef int32_t esp_err_t;
#define ESP_OK 0
#define ESP_ERR_NVS_NO_FREE_PAGES 0x101
#define ESP_ERR_NVS_NEW_VERSION_FOUND 0x102
#define ESP_ERR_INVALID_STATE 0x103
"""

ESP_ATTR_H = r"""#pragma once
#define __NOINIT_ATTR
"""

ESP_SYSTEM_H = r"""#pragma once
typedef int esp_reset_reason_t;
enum {
    ESP_RST_POWERON = 0,
    ESP_RST_EXT,
    ESP_RST_SW,
    ESP_RST_PANIC,
    ESP_RST_INT_WDT,
    ESP_RST_TASK_WDT,
    ESP_RST_WDT,
    ESP_RST_DEEPSLEEP,
    ESP_RST_BROWNOUT,
    ESP_RST_SDIO,
    ESP_RST_USB,
    ESP_RST_JTAG,
    ESP_RST_EFUSE,
    ESP_RST_PWR_GLITCH,
    ESP_RST_CPU_LOCKUP,
};
static inline esp_reset_reason_t esp_reset_reason() { return ESP_RST_POWERON; }
"""

FREERTOS_H = r"""#pragma once
#include <stdint.h>
typedef uint32_t TickType_t;
typedef int BaseType_t;
#define pdTRUE 1
#define pdFALSE 0
#define pdPASS 1
#define portMAX_DELAY UINT32_MAX
#define pdMS_TO_TICKS(value) (value)
"""

SEMPHR_H = r"""#pragma once
#include <stdint.h>
typedef void* SemaphoreHandle_t;
extern bool host_allow_take;
extern uint32_t host_last_take_ticks;
SemaphoreHandle_t xSemaphoreCreateMutex();
int xSemaphoreTake(SemaphoreHandle_t, uint32_t);
int xSemaphoreGive(SemaphoreHandle_t);
"""

TASK_H = r"""#pragma once
#include "freertos/FreeRTOS.h"
typedef void (*TaskFunction_t)(void*);
BaseType_t xTaskCreate(TaskFunction_t, const char*, uint32_t, void*, uint32_t, void*);
void vTaskDelay(TickType_t);
void vTaskDelete(void*);
"""

NVS_H = r"""#pragma once
#include <stddef.h>
#include "esp_err.h"
typedef uint32_t nvs_handle_t;
#define NVS_READONLY 0
#define NVS_READWRITE 1
static inline esp_err_t nvs_open_from_partition(const char*, const char*, int, nvs_handle_t*) { return ESP_ERR_INVALID_STATE; }
static inline esp_err_t nvs_get_blob(nvs_handle_t, const char*, void*, size_t*) { return ESP_ERR_INVALID_STATE; }
static inline esp_err_t nvs_set_blob(nvs_handle_t, const char*, const void*, size_t) { return ESP_ERR_INVALID_STATE; }
static inline esp_err_t nvs_commit(nvs_handle_t) { return ESP_ERR_INVALID_STATE; }
static inline void nvs_close(nvs_handle_t) {}
"""

NVS_FLASH_H = r"""#pragma once
#include "esp_err.h"
static inline esp_err_t nvs_flash_init_partition(const char*) { return ESP_ERR_INVALID_STATE; }
"""

HOST_CPP = r"""#include <cstdlib>
#include <stdint.h>
#include <string>
#include "freertos/semphr.h"
#include "freertos/task.h"

bool host_allow_take = true;
uint32_t host_last_take_ticks = UINT32_MAX;

struct HostMutex {};
static HostMutex host_mutex;
SemaphoreHandle_t xSemaphoreCreateMutex() { return &host_mutex; }
int xSemaphoreTake(SemaphoreHandle_t, uint32_t ticks) {
    host_last_take_ticks = ticks;
    return host_allow_take ? pdTRUE : pdFALSE;
}
int xSemaphoreGive(SemaphoreHandle_t) { return pdTRUE; }
BaseType_t xTaskCreate(TaskFunction_t, const char*, uint32_t, void*, uint32_t, void*) { return pdPASS; }
void vTaskDelay(TickType_t) {}
void vTaskDelete(void*) {}
void idf_util_json_escape_append(std::string&, const std::string&) {}
std::string idf_util_trim_copy(const std::string& value) { return value; }
std::string idf_util_format_epoch_local(uint32_t, int) { return {}; }

#include "idf_log.cpp"

static void require(bool condition) {
    if (!condition) std::abort();
}

int main() {
    require(idf_logf_try("usb_recovery stage=frame_received seq=%u len=%u", 9U, 0U));
    const std::string before = idf_log_text_dump();
    require(before.find("seq=9 len=0") != std::string::npos);

    host_allow_take = false;
    require(!idf_logf_try("dropped"));
    require(host_last_take_ticks == 0);
    host_allow_take = true;
    require(idf_log_text_dump() == before);

    require(idf_logf_try("usb_recovery stage=write_frame seq=%u len=%u result=ESP_OK written=%u",
                         9U, 10U, 19U));
    const std::string after = idf_log_text_dump();
    require(after.find("written=19") != std::string::npos);
    require(after.find("dropped") == std::string::npos);
    return 0;
}
"""


class IdfLogbufTryTest(unittest.TestCase):
    def test_try_log_is_nonblocking_and_preserves_ring_when_locked(self) -> None:
        compiler = shutil.which("g++")
        if compiler is None:
            self.fail("g++ is required for the idf_logbuf host check")
        with tempfile.TemporaryDirectory(prefix="idf-logbuf-try-") as temp_dir:
            temp = Path(temp_dir)
            (temp / "freertos").mkdir()
            (temp / "esp_err.h").write_text(ESP_ERR_H, encoding="utf-8")
            (temp / "esp_attr.h").write_text(ESP_ATTR_H, encoding="utf-8")
            (temp / "esp_system.h").write_text(ESP_SYSTEM_H, encoding="utf-8")
            (temp / "freertos" / "FreeRTOS.h").write_text(FREERTOS_H, encoding="utf-8")
            (temp / "freertos" / "semphr.h").write_text(SEMPHR_H, encoding="utf-8")
            (temp / "freertos" / "task.h").write_text(TASK_H, encoding="utf-8")
            (temp / "nvs.h").write_text(NVS_H, encoding="utf-8")
            (temp / "nvs_flash.h").write_text(NVS_FLASH_H, encoding="utf-8")
            source = temp / "idf_logbuf_try_host.cpp"
            source.write_text(HOST_CPP, encoding="utf-8")
            binary = temp / "idf_logbuf_try_host"
            subprocess.run(
                [
                    compiler,
                    "-std=c++17",
                    "-O0",
                    "-ffunction-sections",
                    "-fdata-sections",
                    "-Werror",
                    "-Wno-unused-function",
                    "-Wno-unused-variable",
                    "-I",
                    str(temp),
                    "-I",
                    str(ROOT / "components/idf_logbuf"),
                    "-I",
                    str(ROOT / "components/idf_logbuf/include"),
                    str(source),
                    "-Wl,--gc-sections",
                    "-o",
                    str(binary),
                ],
                cwd=ROOT,
                check=True,
            )
            subprocess.run([str(binary)], cwd=ROOT, check=True)

    def test_usb_markers_use_try_api_and_are_release_guarded(self) -> None:
        compiler = shutil.which("g++")
        if compiler is None:
            self.fail("g++ is required for the release source check")
        header = (ROOT / "components/idf_logbuf/include/idf_log.h").read_text(encoding="utf-8")
        source = (ROOT / "components/idf_logbuf/idf_log.cpp").read_text(encoding="utf-8")
        usb = (ROOT / "main/usb_recovery.cpp").read_text(encoding="utf-8")
        self.assertIn("bool idf_logf_try(const char* fmt, ...);", header)
        self.assertIn("xSemaphoreTake(s_log_mutex, 0)", source)
        body = source[source.index("bool idf_logf_try"):source.index("std::string idf_log_json_since")]
        self.assertIn("return false;", body)
        marker_lines = [line for line in usb.splitlines() if "usb_recovery stage=" in line]
        self.assertEqual(len(marker_lines), 4)
        self.assertTrue(all("idf_logf_try" in line for line in marker_lines))
        self.assertNotIn("idf_logf(\"usb_recovery stage=", usb)
        self.assertEqual(usb.count("#if SMS_USB_RECOVERY && !FIRMWARE_IS_RELEASE"), 4)
        release = subprocess.run(
            [
                compiler,
                "-E",
                "-P",
                "-DFIRMWARE_IS_RELEASE=1",
                "-DSMS_USB_RECOVERY=0",
                str(ROOT / "main/usb_recovery.cpp"),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
        ).stdout
        self.assertNotIn("usb_recovery stage=", release)
        self.assertNotIn("idf_logf_try", release)


if __name__ == "__main__":
    unittest.main()
