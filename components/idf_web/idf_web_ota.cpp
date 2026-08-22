#include "idf_web_ota.h"

#include <algorithm>
#include <cstring>
#include <memory>

#include "esp_ota_ops.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "mbedtls/base64.h"
#include "mbedtls/pk.h"
#include "mbedtls/sha256.h"
#include "nvs.h"

namespace {

#ifndef SMS_OTA_TEST_KEY
#define SMS_OTA_TEST_KEY 0
#endif
#if SMS_OTA_TEST_KEY
static constexpr const char* OTA_NAMESPACE = "ota_test_meta";
#else
static constexpr const char* OTA_NAMESPACE = "ota_meta";
#endif
static constexpr const char* KEY_ACCEPTED = "accepted";
static constexpr const char* KEY_PENDING = "pending";
static constexpr const char* KEY_PENDING_ADDRESS = "pendingAddr";

#if SMS_OTA_TEST_KEY
extern const uint8_t ota_public_key_b64_start[] asm("_binary_ota_test_public_key_der_b64_start");
extern const uint8_t ota_public_key_b64_end[] asm("_binary_ota_test_public_key_der_b64_end");
#else
extern const uint8_t ota_public_key_b64_start[] asm("_binary_ota_public_key_der_b64_start");
extern const uint8_t ota_public_key_b64_end[] asm("_binary_ota_public_key_der_b64_end");
#endif

struct RuntimeContext {
    esp_ota_handle_t handle = 0;
    const esp_partition_t* target = nullptr;
    mbedtls_sha256_context hash;
    bool hash_initialized = false;
};

static RuntimeContext s_runtime;
static SemaphoreHandle_t s_mutex = nullptr;
static std::unique_ptr<IdfWebOtaSession> s_session;

bool read_counter(nvs_handle_t handle, const char* key, uint32_t& value)
{
    value = 0;
    const esp_err_t err = nvs_get_u32(handle, key, &value);
    return err == ESP_OK || err == ESP_ERR_NVS_NOT_FOUND;
}

bool load_counters(void*, uint32_t* accepted, uint32_t* pending)
{
    nvs_handle_t handle = 0;
    const esp_err_t opened = nvs_open(OTA_NAMESPACE, NVS_READONLY, &handle);
    if (opened == ESP_ERR_NVS_NOT_FOUND) { *accepted = 0; *pending = 0; return true; }
    if (opened != ESP_OK) return false;
    const bool ok = read_counter(handle, KEY_ACCEPTED, *accepted) &&
                    read_counter(handle, KEY_PENDING, *pending);
    nvs_close(handle);
    return ok;
}

bool verify_signature(void*, const uint8_t* manifest, size_t manifest_size,
                      const uint8_t* signature, size_t signature_size)
{
    uint8_t key_der[96] = {};
    size_t key_size = 0;
    // The linker exposes these as independent extern arrays; cppcheck cannot
    // prove that both symbols belong to the same embedded object.
    const size_t encoded_size = static_cast<size_t>(
        reinterpret_cast<uintptr_t>(ota_public_key_b64_end) -
        reinterpret_cast<uintptr_t>(ota_public_key_b64_start));
    if (mbedtls_base64_decode(key_der, sizeof(key_der), &key_size,
            ota_public_key_b64_start, encoded_size) != 0 || key_size == 0) return false;
    uint8_t digest[32] = {};
    if (mbedtls_sha256(manifest, manifest_size, digest, 0) != 0) {
        std::memset(key_der, 0, sizeof(key_der));
        return false;
    }
    mbedtls_pk_context key;
    mbedtls_pk_init(&key);
    int result = mbedtls_pk_parse_public_key(&key, key_der, key_size);
    if (result == 0) {
        result = mbedtls_pk_verify(&key, MBEDTLS_MD_SHA256, digest, sizeof(digest),
                                   signature, signature_size);
    }
    mbedtls_pk_free(&key);
    std::memset(key_der, 0, sizeof(key_der));
    std::memset(digest, 0, sizeof(digest));
    return result == 0;
}

bool hash_begin(void* raw)
{
    auto& runtime = *static_cast<RuntimeContext*>(raw);
    if (runtime.hash_initialized) mbedtls_sha256_free(&runtime.hash);
    mbedtls_sha256_init(&runtime.hash);
    runtime.hash_initialized = true;
    return mbedtls_sha256_starts(&runtime.hash, 0) == 0;
}

bool hash_update(void* raw, const uint8_t* data, size_t size)
{
    auto& runtime = *static_cast<RuntimeContext*>(raw);
    return runtime.hash_initialized && mbedtls_sha256_update(&runtime.hash, data, size) == 0;
}

bool hash_matches(void* raw, const char* expected_hex)
{
    auto& runtime = *static_cast<RuntimeContext*>(raw);
    uint8_t digest[32] = {};
    if (!runtime.hash_initialized || mbedtls_sha256_finish(&runtime.hash, digest) != 0) return false;
    mbedtls_sha256_free(&runtime.hash);
    runtime.hash_initialized = false;
    unsigned difference = 0;
    for (size_t i = 0; i < sizeof(digest); ++i) {
        const auto nibble = [](char ch) -> unsigned {
            return ch >= '0' && ch <= '9' ? static_cast<unsigned>(ch - '0')
                 : static_cast<unsigned>(ch - 'a' + 10);
        };
        difference |= digest[i] ^ static_cast<uint8_t>((nibble(expected_hex[i * 2]) << 4) |
                                                        nibble(expected_hex[i * 2 + 1]));
    }
    std::memset(digest, 0, sizeof(digest));
    return difference == 0;
}

bool begin_update(void* raw, size_t size, uint32_t* address)
{
    auto& runtime = *static_cast<RuntimeContext*>(raw);
    runtime.target = esp_ota_get_next_update_partition(nullptr);
    if (!runtime.target || esp_ota_begin(runtime.target, size, &runtime.handle) != ESP_OK) {
        runtime.target = nullptr;
        runtime.handle = 0;
        return false;
    }
    *address = runtime.target->address;
    return true;
}

bool write_update(void* raw, const uint8_t* data, size_t size)
{
    auto& runtime = *static_cast<RuntimeContext*>(raw);
    return runtime.handle != 0 && esp_ota_write(runtime.handle, data, size) == ESP_OK;
}

bool finish_update(void* raw)
{
    auto& runtime = *static_cast<RuntimeContext*>(raw);
    if (runtime.handle == 0) return false;
    const esp_ota_handle_t handle = runtime.handle;
    runtime.handle = 0;
    return esp_ota_end(handle) == ESP_OK;
}

void abort_update(void* raw)
{
    auto& runtime = *static_cast<RuntimeContext*>(raw);
    if (runtime.handle != 0) esp_ota_abort(runtime.handle);
    runtime.handle = 0;
    runtime.target = nullptr;
    if (runtime.hash_initialized) {
        mbedtls_sha256_free(&runtime.hash);
        runtime.hash_initialized = false;
    }
}

void clear_pending_metadata(void*)
{
    nvs_handle_t handle = 0;
    if (nvs_open(OTA_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) return;
    nvs_erase_key(handle, KEY_PENDING);
    nvs_erase_key(handle, KEY_PENDING_ADDRESS);
    nvs_commit(handle);
    nvs_close(handle);
}

bool store_pending(void*, uint32_t counter, uint32_t address)
{
    nvs_handle_t handle = 0;
    if (nvs_open(OTA_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) return false;
    bool ok = nvs_set_u32(handle, KEY_PENDING, counter) == ESP_OK &&
              nvs_set_u32(handle, KEY_PENDING_ADDRESS, address) == ESP_OK &&
              nvs_commit(handle) == ESP_OK;
    uint32_t saved_counter = 0, saved_address = 0;
    ok = ok && nvs_get_u32(handle, KEY_PENDING, &saved_counter) == ESP_OK &&
         nvs_get_u32(handle, KEY_PENDING_ADDRESS, &saved_address) == ESP_OK &&
         saved_counter == counter && saved_address == address;
    if (!ok) {
        nvs_erase_key(handle, KEY_PENDING);
        nvs_erase_key(handle, KEY_PENDING_ADDRESS);
        nvs_commit(handle);
    }
    nvs_close(handle);
    return ok;
}

bool set_boot(void* raw, uint32_t address)
{
    auto& runtime = *static_cast<RuntimeContext*>(raw);
    return runtime.target && runtime.target->address == address &&
           esp_ota_set_boot_partition(runtime.target) == ESP_OK;
}

IdfWebOtaPlatform make_platform()
{
    return {&s_runtime, load_counters, verify_signature,
            hash_begin, hash_update, hash_matches,
            begin_update, write_update, finish_update, abort_update,
            store_pending, clear_pending_metadata, set_boot};
}

bool lock(TickType_t ticks = portMAX_DELAY)
{
    return s_mutex && xSemaphoreTake(s_mutex, ticks) == pdTRUE;
}

void unlock() { xSemaphoreGive(s_mutex); }

struct HealthContext { nvs_handle_t handle = 0; };

bool bind_health_pending_address(void* raw, uint32_t address)
{
    const nvs_handle_t handle = static_cast<HealthContext*>(raw)->handle;
    if (nvs_set_u32(handle, KEY_PENDING_ADDRESS, address) != ESP_OK ||
        nvs_commit(handle) != ESP_OK) return false;
    uint32_t readback = 0;
    return nvs_get_u32(handle, KEY_PENDING_ADDRESS, &readback) == ESP_OK && readback == address;
}

bool mark_health_valid(void*)
{
    return esp_ota_mark_app_valid_cancel_rollback() == ESP_OK;
}

bool persist_health_accepted(void* raw, uint32_t target)
{
    const nvs_handle_t handle = static_cast<HealthContext*>(raw)->handle;
    if (target == 0 || nvs_set_u32(handle, KEY_ACCEPTED, target) != ESP_OK ||
        nvs_commit(handle) != ESP_OK) return false;
    uint32_t readback = 0;
    if (nvs_get_u32(handle, KEY_ACCEPTED, &readback) != ESP_OK || readback != target) return false;
    return true;
}

bool clear_health_pending(void* raw)
{
    const nvs_handle_t handle = static_cast<HealthContext*>(raw)->handle;
    const esp_err_t pending_error = nvs_erase_key(handle, KEY_PENDING);
    const esp_err_t address_error = nvs_erase_key(handle, KEY_PENDING_ADDRESS);
    if (!((pending_error == ESP_OK || pending_error == ESP_ERR_NVS_NOT_FOUND) &&
          (address_error == ESP_OK || address_error == ESP_ERR_NVS_NOT_FOUND)) ||
        nvs_commit(handle) != ESP_OK) return false;
    uint32_t ignored = 0;
    return nvs_get_u32(handle, KEY_PENDING, &ignored) == ESP_ERR_NVS_NOT_FOUND &&
           nvs_get_u32(handle, KEY_PENDING_ADDRESS, &ignored) == ESP_ERR_NVS_NOT_FOUND;
}

void rollback_health(void*) { esp_ota_mark_app_invalid_rollback_and_reboot(); }

}  // namespace

esp_err_t idf_web_ota_init()
{
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
    if (!s_mutex) return ESP_ERR_NO_MEM;
    if (!s_session) {
        s_session.reset(new (std::nothrow) IdfWebOtaSession(make_platform()));
        if (!s_session) return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

IdfWebOtaCode idf_web_ota_start(const std::string& manifest,
                                const uint8_t* signature, size_t signature_size,
                                uint32_t upload_id, uint32_t now_ms)
{
    if (!lock()) return IdfWebOtaCode::Busy;
    const IdfWebOtaCode result = s_session->start(manifest, signature, signature_size,
                                                  upload_id, now_ms);
    unlock();
    return result;
}

IdfWebOtaCode idf_web_ota_append(uint32_t upload_id, size_t offset,
                                 const uint8_t* data, size_t size,
                                 uint32_t now_ms, size_t* next_offset)
{
    if (!lock()) return IdfWebOtaCode::Busy;
    const IdfWebOtaCode result = s_session->append(upload_id, offset, data, size,
                                                   now_ms, next_offset);
    unlock();
    return result;
}

IdfWebOtaCode idf_web_ota_prepare_finish(uint32_t upload_id)
{
    if (!lock()) return IdfWebOtaCode::Busy;
    const IdfWebOtaCode result = s_session->prepare_finish(upload_id);
    unlock();
    return result;
}

bool idf_web_ota_cancel_finish(uint32_t upload_id)
{
    if (!lock()) return false;
    const bool result = s_session->cancel_finish(upload_id);
    unlock();
    return result;
}

bool idf_web_ota_cancel_upload(uint32_t upload_id)
{
    if (!lock()) return false;
    const bool result = s_session->cancel_upload(upload_id);
    unlock();
    return result;
}

IdfWebOtaCode idf_web_ota_finish(uint32_t upload_id)
{
    if (!lock()) return IdfWebOtaCode::Busy;
    const IdfWebOtaCode result = s_session->finish(upload_id);
    unlock();
    return result;
}

bool idf_web_ota_expire(uint32_t now_ms, uint32_t ttl_ms)
{
    if (!lock()) return false;
    const bool result = s_session->expire(now_ms, ttl_ms);
    unlock();
    return result;
}

bool idf_web_ota_active()
{
    if (!lock(pdMS_TO_TICKS(100))) return true;
    const bool result = s_session->active();
    unlock();
    return result;
}

bool idf_web_ota_restart_pending()
{
    if (!lock(pdMS_TO_TICKS(100))) return true;
    const bool result = s_session->restart_pending();
    unlock();
    return result;
}

esp_err_t idf_web_ota_health_check(bool http_live, bool management_reachable,
                                   bool deadline_expired)
{
    const esp_partition_t* running = esp_ota_get_running_partition();
    if (!running) return ESP_ERR_INVALID_STATE;
    esp_ota_img_states_t raw_state;
    if (esp_ota_get_state_partition(running, &raw_state) != ESP_OK) return ESP_OK;
    IdfWebOtaImageState state = raw_state == ESP_OTA_IMG_PENDING_VERIFY
        ? IdfWebOtaImageState::PendingVerify
        : raw_state == ESP_OTA_IMG_VALID ? IdfWebOtaImageState::Valid : IdfWebOtaImageState::Other;

    nvs_handle_t handle = 0;
    if (nvs_open(OTA_NAMESPACE, NVS_READWRITE, &handle) != ESP_OK) {
        if (state == IdfWebOtaImageState::PendingVerify) esp_ota_mark_app_invalid_rollback_and_reboot();
        return ESP_FAIL;
    }
    uint32_t accepted = 0, pending = 0, pending_address = 0;
    const bool metadata_ok = read_counter(handle, KEY_ACCEPTED, accepted) &&
        read_counter(handle, KEY_PENDING, pending) &&
        read_counter(handle, KEY_PENDING_ADDRESS, pending_address);
    if (!metadata_ok) {
        nvs_close(handle);
        if (state == IdfWebOtaImageState::PendingVerify) esp_ota_mark_app_invalid_rollback_and_reboot();
        return ESP_FAIL;
    }
    HealthContext context{handle};
    const IdfWebOtaHealthPlatform platform = {
        &context, bind_health_pending_address, mark_health_valid,
        persist_health_accepted, clear_health_pending, rollback_health,
    };
    const IdfWebOtaHealthResult result = idf_web_ota_apply_health(
        state, http_live, management_reachable, deadline_expired,
        accepted, pending, running->address, pending_address, platform);
    nvs_close(handle);
    if (result == IdfWebOtaHealthResult::Waiting) return ESP_ERR_NOT_FINISHED;
    if (result == IdfWebOtaHealthResult::Done) return ESP_OK;
    return ESP_FAIL;
}
