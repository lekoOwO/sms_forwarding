#include "config_backup.h"

#include <ArduinoJson.h>
#include <esp_random.h>
#include <mbedtls/gcm.h>
#include <mbedtls/platform_util.h>
#include <mbedtls/pkcs5.h>
#include <memory>

#include "config.h"
#include "globals.h"
#include "ota_update.h"
#include "web_handlers.h"

static constexpr size_t BACKUP_CHUNK_SIZE = 8192;
static constexpr uint32_t TRANSFER_TTL_MS = 120000;
static constexpr uint32_t DOWNLOAD_TTL_MS = 120000;
static constexpr size_t MIN_PASSPHRASE_BYTES = 12;
static constexpr size_t MAX_PASSPHRASE_BYTES = 128;
static_assert(BACKUP_LITTLE_ENDIAN && BACKUP_AAD_BYTES == BACKUP_HEADER_BYTES,
              "unsupported backup envelope layout");

struct RestoreUpload {
  std::unique_ptr<uint8_t[]> bytes;
  size_t size = 0;
  size_t written = 0;
  uint32_t id = 0;
  uint32_t lastActivity = 0;
  bool finishing = false;
};

struct Download {
  std::unique_ptr<uint8_t[]> bytes;
  size_t size = 0;
  uint32_t id = 0;
  uint32_t expiresAt = 0;
};

struct CryptoWork {
  bool restore = false;
  uint32_t jobId = 0;
  String passphrase;
  Config config;
  std::unique_ptr<uint8_t[]> bytes;
  size_t size = 0;
};

static RestoreUpload upload;
static Download download;
static Config restoredConfig;
static uint32_t nextTransferId = 1;
static SemaphoreHandle_t transferMutex;
static bool cryptoBusy = false;

void initConfigBackup() {
  if (!transferMutex) transferMutex = xSemaphoreCreateMutex();
}

static void zeroString(String& value) {
  if (value.length()) mbedtls_platform_zeroize(const_cast<char*>(value.c_str()), value.length());
  value = "";
}

static void clearCryptoBusy() {
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  cryptoBusy = false;
  xSemaphoreGive(transferMutex);
}

static void allowRestoreRetry() {
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  upload.finishing = false;
  cryptoBusy = false;
  xSemaphoreGive(transferMutex);
}

static String resultJson(bool success, const char* code, uint32_t downloadId = 0) {
  JsonDocument result;
  result["success"] = success;
  result["code"] = code;
  JsonObject data = result["data"].to<JsonObject>();
  if (downloadId) data["exportId"] = downloadId;
  result["detail"] = "";
  String json;
  serializeJson(result, json);
  return json;
}

static void sendResult(int status, bool success, const char* code, uint32_t id = 0,
                       size_t nextOffset = 0) {
  JsonDocument result;
  result["success"] = success;
  result["code"] = code;
  JsonObject data = result["data"].to<JsonObject>();
  if (id) data["uploadId"] = id;
  if (id) data["chunkSize"] = BACKUP_CHUNK_SIZE;
  if (id || nextOffset) data["nextOffset"] = nextOffset;
  result["detail"] = "";
  String json;
  serializeJson(result, json);
  server.sendHeader("Cache-Control", "no-store");
  server.send(status, "application/json", json);
}

static bool validPassphrase(const String& passphrase) {
  return passphrase.length() >= MIN_PASSPHRASE_BYTES && passphrase.length() <= MAX_PASSPHRASE_BYTES;
}

static void write16(uint8_t* output, uint16_t value) {
  output[0] = value;
  output[1] = value >> 8;
}

static void write32(uint8_t* output, uint32_t value) {
  output[0] = value;
  output[1] = value >> 8;
  output[2] = value >> 16;
  output[3] = value >> 24;
}

static uint16_t read16(const uint8_t* input) {
  return input[0] | static_cast<uint16_t>(input[1]) << 8;
}

static uint32_t read32(const uint8_t* input) {
  return input[0] | static_cast<uint32_t>(input[1]) << 8 |
         static_cast<uint32_t>(input[2]) << 16 | static_cast<uint32_t>(input[3]) << 24;
}

static bool deriveKey(const String& passphrase, const uint8_t* salt, uint8_t key[32]) {
  return mbedtls_pkcs5_pbkdf2_hmac_ext(
           MBEDTLS_MD_SHA256, reinterpret_cast<const uint8_t*>(passphrase.c_str()),
           passphrase.length(), salt, BACKUP_SALT_BYTES, BACKUP_KDF_ITERATIONS,
           32, key) == 0;
}

static bool encryptConfig(CryptoWork& work, std::unique_ptr<uint8_t[]>& output,
                          size_t& outputSize) {
  PortableConfigBuffer portable;
  if (!encodePortableConfig(work.config, portable) || portable.length > MAX_CONFIG_BLOB_SIZE) return false;
  outputSize = BACKUP_HEADER_BYTES + portable.length + BACKUP_TAG_BYTES;
  output.reset(new (std::nothrow) uint8_t[outputSize]);
  if (!output) return false;
  uint8_t* header = output.get();
  memcpy(header, BACKUP_ENVELOPE_MAGIC, 8);
  write16(header + 8, BACKUP_ENVELOPE_VERSION);
  header[10] = BACKUP_KDF_ID;
  header[11] = BACKUP_CIPHER_ID;
  write32(header + 12, BACKUP_KDF_ITERATIONS);
  esp_fill_random(header + 16, BACKUP_SALT_BYTES + BACKUP_IV_BYTES);

  uint8_t key[32];
  bool ok = deriveKey(work.passphrase, header + 16, key);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (ok) ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0;
  if (ok) {
    ok = mbedtls_gcm_crypt_and_tag(
           &gcm, MBEDTLS_GCM_ENCRYPT, portable.length, header + 32, BACKUP_IV_BYTES,
           header, BACKUP_AAD_BYTES, portable.bytes.get(), header + BACKUP_HEADER_BYTES,
           BACKUP_TAG_BYTES, header + BACKUP_HEADER_BYTES + portable.length) == 0;
  }
  mbedtls_gcm_free(&gcm);
  mbedtls_platform_zeroize(key, sizeof(key));
  if (portable.bytes) mbedtls_platform_zeroize(portable.bytes.get(), portable.length);
  return ok;
}

static bool decryptConfig(CryptoWork& work, Config& output) {
  if (work.size < BACKUP_HEADER_BYTES + BACKUP_TAG_BYTES ||
      work.size > MAX_ENCRYPTED_CONFIG_BYTES) return false;
  const uint8_t* header = work.bytes.get();
  if (memcmp(header, BACKUP_ENVELOPE_MAGIC, 8) ||
      read16(header + 8) != BACKUP_ENVELOPE_VERSION ||
      header[10] != BACKUP_KDF_ID || header[11] != BACKUP_CIPHER_ID ||
      read32(header + 12) != BACKUP_KDF_ITERATIONS) return false;
  size_t plaintextSize = work.size - BACKUP_HEADER_BYTES - BACKUP_TAG_BYTES;
  if (plaintextSize == 0 || plaintextSize > MAX_CONFIG_BLOB_SIZE) return false;
  std::unique_ptr<uint8_t[]> plaintext(new (std::nothrow) uint8_t[plaintextSize]);
  if (!plaintext) return false;

  uint8_t key[32];
  bool ok = deriveKey(work.passphrase, header + 16, key);
  mbedtls_gcm_context gcm;
  mbedtls_gcm_init(&gcm);
  if (ok) ok = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256) == 0;
  if (ok) {
    ok = mbedtls_gcm_auth_decrypt(
           &gcm, plaintextSize, header + 32, BACKUP_IV_BYTES, header, BACKUP_AAD_BYTES,
           header + BACKUP_HEADER_BYTES + plaintextSize, BACKUP_TAG_BYTES,
           header + BACKUP_HEADER_BYTES, plaintext.get()) == 0;
  }
  if (ok) ok = decodePortableConfig(plaintext.get(), plaintextSize, work.config, output) == PORTABLE_CONFIG_OK;
  mbedtls_gcm_free(&gcm);
  mbedtls_platform_zeroize(key, sizeof(key));
  mbedtls_platform_zeroize(plaintext.get(), plaintextSize);
  return ok;
}

static void applyRestoredConfig() {
  if (!saveConfig(restoredConfig)) {
    clearCryptoBusy();
    sendQueuedActionResult(500, false, "ACTION_CONFIG_RESTORE_SAVE_FAILED");
    return;
  }
  lockRuntimeConfig();
  config = restoredConfig;
  configValid = isConfigValid();
  unlockRuntimeConfig();
  sendQueuedActionResult(200, true, "ACTION_CONFIG_RESTORED");
  clearCryptoBusy();
  scheduleDeviceRestart();
}

static void cryptoTask(void* parameter) {
  std::unique_ptr<CryptoWork> work(static_cast<CryptoWork*>(parameter));
  uint32_t started = millis();
  bool ok = false;
  if (work->restore) {
    Config decoded;
    ok = decryptConfig(*work, decoded);
    if (ok) {
      restoredConfig = decoded;
      resumeDeferredWebJob(work->jobId, applyRestoredConfig);
    } else {
      completeDeferredWebJob(work->jobId, false,
                             resultJson(false, "ACTION_CONFIG_RESTORE_INVALID"));
    }
  } else {
    std::unique_ptr<uint8_t[]> encrypted;
    size_t encryptedSize = 0;
    ok = encryptConfig(*work, encrypted, encryptedSize);
    uint32_t downloadId = 0;
    if (ok) {
      xSemaphoreTake(transferMutex, portMAX_DELAY);
      if (download.bytes) mbedtls_platform_zeroize(download.bytes.get(), download.size);
      download.bytes = std::move(encrypted);
      download.size = encryptedSize;
      download.id = nextTransferId++;
      if (download.id == 0) download.id = nextTransferId++;
      download.expiresAt = millis() + DOWNLOAD_TTL_MS;
      downloadId = download.id;
      xSemaphoreGive(transferMutex);
    }
    completeDeferredWebJob(work->jobId, ok,
                           resultJson(ok, ok ? "ACTION_CONFIG_EXPORT_READY" :
                                               "ACTION_CONFIG_EXPORT_FAILED",
                                      downloadId));
  }
  zeroString(work->passphrase);
  if (work->bytes) mbedtls_platform_zeroize(work->bytes.get(), work->size);
  logCaptureF("Config crypto completed in %lu ms; free heap %u; stack %u\n",
              static_cast<unsigned long>(millis() - started), ESP.getFreeHeap(),
              uxTaskGetStackHighWaterMark(nullptr));
  if (!work->restore || !ok) {
    clearCryptoBusy();
  }
  vTaskDelete(nullptr);
}

static void runConfigExport() {
  String passphrase = webJobArg("passphrase");
  if (!validPassphrase(passphrase)) {
    zeroString(passphrase);
    clearCryptoBusy();
    sendQueuedActionResult(400, false, "ACTION_CONFIG_PASSPHRASE_INVALID");
    return;
  }
  std::unique_ptr<CryptoWork> work(new (std::nothrow) CryptoWork);
  if (!work) {
    zeroString(passphrase);
    clearCryptoBusy();
    sendQueuedActionResult(500, false, "ACTION_CONFIG_EXPORT_FAILED");
    return;
  }
  work->jobId = deferCurrentWebJob();
  work->passphrase = passphrase;
  lockRuntimeConfig();
  work->config = config;
  unlockRuntimeConfig();
  zeroString(passphrase);
  CryptoWork* raw = work.release();
  if (xTaskCreate(cryptoTask, "config-crypto", 8192, raw, 1, nullptr) != pdPASS) {
    zeroString(raw->passphrase);
    uint32_t jobId = raw->jobId;
    delete raw;
    clearCryptoBusy();
    completeDeferredWebJob(jobId, false, resultJson(false, "ACTION_CONFIG_EXPORT_FAILED"));
  }
}

static void runConfigRestore() {
  String passphrase = webJobArg("passphrase");
  if (!validPassphrase(passphrase)) {
    zeroString(passphrase);
    allowRestoreRetry();
    sendQueuedActionResult(400, false, "ACTION_CONFIG_PASSPHRASE_INVALID");
    return;
  }
  std::unique_ptr<CryptoWork> work(new (std::nothrow) CryptoWork);
  if (!work) {
    zeroString(passphrase);
    allowRestoreRetry();
    sendQueuedActionResult(500, false, "ACTION_CONFIG_RESTORE_FAILED");
    return;
  }
  work->restore = true;
  work->jobId = deferCurrentWebJob();
  work->passphrase = passphrase;
  lockRuntimeConfig();
  work->config = config;
  unlockRuntimeConfig();
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  work->bytes = std::move(upload.bytes);
  work->size = upload.size;
  upload = RestoreUpload{};
  xSemaphoreGive(transferMutex);
  zeroString(passphrase);
  CryptoWork* raw = work.release();
  if (xTaskCreate(cryptoTask, "config-crypto", 8192, raw, 1, nullptr) != pdPASS) {
    zeroString(raw->passphrase);
    if (raw->bytes) mbedtls_platform_zeroize(raw->bytes.get(), raw->size);
    uint32_t jobId = raw->jobId;
    delete raw;
    clearCryptoBusy();
    completeDeferredWebJob(jobId, false, resultJson(false, "ACTION_CONFIG_RESTORE_FAILED"));
  }
}

bool configTransferActive() {
  if (!transferMutex) return false;
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  bool active = upload.bytes != nullptr || cryptoBusy;
  xSemaphoreGive(transferMutex);
  return active;
}

void handleConfigExportStart() {
  if (!checkAuth() || !checkCsrf()) return;
  if (deviceRestartPending()) {
    sendResult(409, false, "ACTION_BUSY");
    return;
  }
  String passphrase = server.arg("passphrase");
  if (!validPassphrase(passphrase)) {
    zeroString(passphrase);
    sendResult(400, false, "ACTION_CONFIG_PASSPHRASE_INVALID");
    return;
  }
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  if (cryptoBusy || upload.bytes) {
    xSemaphoreGive(transferMutex);
    zeroString(passphrase);
    sendResult(409, false, "ACTION_BUSY");
    return;
  }
  cryptoBusy = true;
  xSemaphoreGive(transferMutex);
  if (!enqueueWebJob("config-export", runConfigExport, "passphrase", passphrase)) {
    clearCryptoBusy();
  }
  zeroString(passphrase);
}

void handleConfigExportDownload() {
  if (!checkAuth() || !checkCsrf()) return;
  uint32_t id = server.arg("id").toInt();
  std::unique_ptr<uint8_t[]> bytes;
  size_t size = 0;
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  if (!download.bytes || id == 0 || id != download.id) {
    xSemaphoreGive(transferMutex);
    sendResult(404, false, "ACTION_CONFIG_EXPORT_NOT_FOUND");
    return;
  }
  bytes = std::move(download.bytes);
  size = download.size;
  download = Download{};
  xSemaphoreGive(transferMutex);
  server.sendHeader("Cache-Control", "no-store");
  server.sendHeader("Content-Disposition", "attachment; filename=configuration.smscfg");
  server.setContentLength(size);
  server.send(200, CONFIG_MIME_TYPE, "");
  server.sendContent(reinterpret_cast<const char*>(bytes.get()), size);
  mbedtls_platform_zeroize(bytes.get(), size);
}

void handleConfigRestoreStart() {
  if (!checkAuth() || !checkCsrf()) return;
  if (deviceRestartPending()) {
    sendResult(409, false, "ACTION_BUSY");
    return;
  }
  size_t size = server.arg("size").toInt();
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  bool busy = upload.bytes || cryptoBusy;
  xSemaphoreGive(transferMutex);
  if (otaUploadActive()) {
    sendResult(409, false, "ACTION_BUSY");
    return;
  }
  if (busy || webJobsActive() || size < BACKUP_HEADER_BYTES + BACKUP_TAG_BYTES ||
      size > MAX_ENCRYPTED_CONFIG_BYTES) {
    sendResult(409, false, "ACTION_CONFIG_RESTORE_START_FAILED");
    return;
  }
  std::unique_ptr<uint8_t[]> bytes(new (std::nothrow) uint8_t[size]);
  if (!bytes) {
    sendResult(500, false, "ACTION_CONFIG_RESTORE_START_FAILED");
    return;
  }
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  upload.bytes = std::move(bytes);
  upload.size = size;
  upload.id = nextTransferId++;
  if (upload.id == 0) upload.id = nextTransferId++;
  upload.lastActivity = millis();
  uint32_t id = upload.id;
  xSemaphoreGive(transferMutex);
  sendResult(201, true, "ACTION_CONFIG_RESTORE_STARTED", id, 0);
}

void handleConfigRestoreChunk() {
  if (!checkAuth() || !checkCsrf()) return;
  uint32_t id = server.arg("id").toInt();
  size_t offset = server.arg("offset").toInt();
  uint8_t* chunk = nullptr;
  size_t chunkLength = 0;
  if (!decodeBase64RequestChunk(BACKUP_CHUNK_SIZE, chunk, chunkLength)) {
    sendResult(400, false, "ACTION_CONFIG_RESTORE_CHUNK_INVALID");
    return;
  }
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  if (!upload.bytes || upload.finishing || id != upload.id || offset != upload.written ||
      upload.written + chunkLength > upload.size) {
    xSemaphoreGive(transferMutex);
    sendResult(400, false, "ACTION_CONFIG_RESTORE_CHUNK_INVALID");
    return;
  }
  memcpy(upload.bytes.get() + upload.written, chunk, chunkLength);
  upload.written += chunkLength;
  upload.lastActivity = millis();
  size_t nextOffset = upload.written;
  xSemaphoreGive(transferMutex);
  sendResult(200, true, "ACTION_CONFIG_RESTORE_CHUNK_OK", 0, nextOffset);
}

void handleConfigRestoreFinish() {
  if (!checkAuth() || !checkCsrf()) return;
  uint32_t id = server.arg("id").toInt();
  String passphrase = server.arg("passphrase");
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  if (!upload.bytes || upload.finishing || id != upload.id || upload.written != upload.size ||
      !validPassphrase(passphrase)) {
    xSemaphoreGive(transferMutex);
    zeroString(passphrase);
    sendResult(400, false, "ACTION_CONFIG_RESTORE_FINISH_INVALID");
    return;
  }
  upload.finishing = true;
  cryptoBusy = true;
  xSemaphoreGive(transferMutex);
  if (!enqueueWebJob("config-restore", runConfigRestore, "passphrase", passphrase)) {
    allowRestoreRetry();
  }
  zeroString(passphrase);
}

void configBackupTick() {
  xSemaphoreTake(transferMutex, portMAX_DELAY);
  if (upload.bytes && !upload.finishing && millis() - upload.lastActivity > TRANSFER_TTL_MS) {
    mbedtls_platform_zeroize(upload.bytes.get(), upload.size);
    upload = RestoreUpload{};
  }
  if (download.bytes && static_cast<int32_t>(millis() - download.expiresAt) >= 0) {
    mbedtls_platform_zeroize(download.bytes.get(), download.size);
    download = Download{};
  }
  xSemaphoreGive(transferMutex);
}
