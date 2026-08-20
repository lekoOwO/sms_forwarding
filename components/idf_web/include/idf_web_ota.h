#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "esp_err.h"
#include "idf_web_ota_core.h"

esp_err_t idf_web_ota_init();
IdfWebOtaCode idf_web_ota_start(const std::string& manifest,
                                const uint8_t* signature, size_t signature_size,
                                uint32_t upload_id, uint32_t now_ms);
IdfWebOtaCode idf_web_ota_append(uint32_t upload_id, size_t offset,
                                 const uint8_t* data, size_t size,
                                 uint32_t now_ms, size_t* next_offset);
IdfWebOtaCode idf_web_ota_prepare_finish(uint32_t upload_id);
bool idf_web_ota_cancel_finish(uint32_t upload_id);
bool idf_web_ota_cancel_upload(uint32_t upload_id);
IdfWebOtaCode idf_web_ota_finish(uint32_t upload_id);
bool idf_web_ota_expire(uint32_t now_ms, uint32_t ttl_ms);
bool idf_web_ota_active();
bool idf_web_ota_restart_pending();

// Called by the boot health task. A rollback decision does not return.
esp_err_t idf_web_ota_health_check(bool http_live, bool management_reachable,
                                   bool deadline_expired);
