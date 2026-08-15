#include "ota_update.h"

#include <ArduinoJson.h>
#include <SHA2Builder.h>
#include <Preferences.h>
#include <Update.h>
#include <esp_ota_ops.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>

#include "globals.h"
#include "config_backup.h"
#include "utf8_validation.h"
#include "web_handlers.h"

static constexpr uint32_t OTA_SESSION_TTL_MS = 120000;
static constexpr size_t OTA_SLOT_SIZE = 0x1E0000;
static constexpr size_t OTA_MAX_MANIFEST_SIZE = 512;
static constexpr size_t OTA_MAX_SIGNATURE_SIZE = 72;

static const uint8_t OTA_PUBLIC_KEY[] = {
  0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02,
  0x01, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, 0x03,
  0x42, 0x00, 0x04, 0x26, 0x55, 0xc4, 0x26, 0x5b, 0x13, 0x83, 0xa0, 0xb5,
  0xaa, 0xd3, 0x26, 0x7d, 0x82, 0x3b, 0x70, 0xe7, 0xe4, 0xb3, 0x96, 0x50,
  0x60, 0x0e, 0x98, 0x63, 0xb5, 0xe0, 0x36, 0x6e, 0x66, 0x13, 0x2c, 0x16,
  0xeb, 0xd6, 0xc4, 0xbf, 0xdd, 0xae, 0x58, 0x0d, 0xd9, 0xac, 0xf9, 0x93,
  0x91, 0x80, 0x27, 0x18, 0x3d, 0x1b, 0x85, 0x88, 0xf8, 0xc5, 0xbe, 0xad,
  0xcc, 0xad, 0x5b, 0xfe, 0xac, 0xc1, 0x61
};

struct OtaSession {
  bool active = false;
  bool finishing = false;
  uint32_t id = 0;
  uint32_t releaseCounter = 0;
  size_t size = 0;
  size_t written = 0;
  uint32_t lastActivity = 0;
  String expectedSha256;
  SHA256Builder sha256;
};

static OtaSession session;
static uint32_t nextUploadId = 1;
static uint32_t restartAt = 0;
static bool restartPending = false;
static SemaphoreHandle_t otaMutex;

void initOtaUpdate() {
  if (!otaMutex) otaMutex = xSemaphoreCreateMutex();
}

static void sendResult(int status, bool success, const char* code,
                       JsonDocument* data = nullptr, const String& detail = "") {
  JsonDocument response;
  response["success"] = success;
  response["code"] = code;
  if (data) response["data"].set(data->as<JsonVariantConst>());
  else response["data"].to<JsonObject>();
  response["detail"] = detail;
  String json;
  serializeJson(response, json);
  server.sendHeader("Cache-Control", "no-store");
  server.send(status, "application/json", json);
}

static bool parseUint32(const String& text, uint32_t& value) {
  if (text.length() == 0 || text.length() > 10) return false;
  uint64_t parsed = 0;
  for (size_t i = 0; i < text.length(); ++i) {
    if (!isDigit(text[i])) return false;
    parsed = parsed * 10 + (text[i] - '0');
    if (parsed > UINT32_MAX) return false;
  }
  value = parsed;
  return true;
}

static bool parseHex(const String& text, uint8_t* output, size_t& outputLength) {
  if ((text.length() & 1) || text.length() == 0 || text.length() / 2 > outputLength) return false;
  outputLength = text.length() / 2;
  for (size_t i = 0; i < outputLength; ++i) {
    char high = text[i * 2];
    char low = text[i * 2 + 1];
    auto nibble = [](char value) -> int {
      if (value >= '0' && value <= '9') return value - '0';
      if (value >= 'a' && value <= 'f') return value - 'a' + 10;
      return -1;
    };
    int a = nibble(high), b = nibble(low);
    if (a < 0 || b < 0) return false;
    output[i] = static_cast<uint8_t>((a << 4) | b);
  }
  return true;
}

static bool validSha256(const String& value) {
  if (value.length() != 64) return false;
  for (size_t i = 0; i < value.length(); ++i) {
    if (!isDigit(value[i]) && (value[i] < 'a' || value[i] > 'f')) return false;
  }
  return true;
}

static bool validVersion(const String& version) {
  if (version.length() == 0 || version.length() > 32) return false;
  for (size_t i = 0; i < version.length(); ++i) {
    char c = version[i];
    if (!isAlphaNumeric(c) && c != '.' && c != '-' && c != '_' && c != '+') return false;
  }
  return true;
}

static bool verifyManifest(const String& manifest, const uint8_t* signature, size_t signatureLength) {
  SHA256Builder digest;
  digest.begin();
  digest.add(reinterpret_cast<const uint8_t*>(manifest.c_str()), manifest.length());
  digest.calculate();
  uint8_t hash[32];
  digest.getBytes(hash);

  mbedtls_pk_context key;
  mbedtls_pk_init(&key);
  int result = mbedtls_pk_parse_public_key(&key, OTA_PUBLIC_KEY, sizeof(OTA_PUBLIC_KEY));
  if (result == 0) {
    result = mbedtls_pk_verify(&key, MBEDTLS_MD_SHA256, hash, sizeof(hash),
                               signature, signatureLength);
  }
  mbedtls_pk_free(&key);
  return result == 0;
}

static uint32_t effectiveReleaseCounter() {
  Preferences metadata;
  if (!metadata.begin("ota_meta", true)) return UINT32_MAX;
  uint32_t accepted = metadata.getUInt("accepted", 0);
  uint32_t pending = metadata.getUInt("pending", 0);
  metadata.end();
  return pending > accepted ? pending : accepted;
}

static void clearPendingMetadata(Preferences& metadata) {
  metadata.remove("pending");
  metadata.remove("pendingAddr");
}

static bool commitAcceptedCounter(Preferences& metadata, uint32_t pending) {
  uint32_t accepted = metadata.getUInt("accepted", 0);
  uint32_t counter = pending > accepted ? pending : accepted;
  if (metadata.putUInt("accepted", counter) != sizeof(uint32_t) ||
      metadata.getUInt("accepted", 0) != counter) return false;
  clearPendingMetadata(metadata);
  return true;
}

static void abortSessionLocked() {
  if (Update.isRunning()) Update.abort();
  session.active = false;
  session.finishing = false;
  session.expectedSha256 = "";
}

bool otaUploadActive() {
  if (!otaMutex) return false;
  xSemaphoreTake(otaMutex, portMAX_DELAY);
  bool active = session.active;
  xSemaphoreGive(otaMutex);
  return active;
}

bool deviceRestartPending() {
  if (!otaMutex) return false;
  xSemaphoreTake(otaMutex, portMAX_DELAY);
  bool pending = restartPending;
  xSemaphoreGive(otaMutex);
  return pending;
}

void scheduleDeviceRestart(uint32_t delayMs) {
  xSemaphoreTake(otaMutex, portMAX_DELAY);
  restartPending = true;
  restartAt = millis() + delayMs;
  xSemaphoreGive(otaMutex);
}

void handleOtaStart() {
  if (!checkAuth() || !checkCsrf()) return;
  xSemaphoreTake(otaMutex, portMAX_DELAY);
  bool uploadActive = session.active;
  xSemaphoreGive(otaMutex);
  if (uploadActive || deviceRestartPending() || configTransferActive() || webJobsActive()) {
    sendResult(409, false, "ACTION_BUSY");
    return;
  }

  String manifest = server.arg("manifest");
  String signatureHex = server.arg("signature");
  if (manifest.length() == 0 || manifest.length() > OTA_MAX_MANIFEST_SIZE ||
      !isValidUtf8Text(manifest.c_str())) {
    sendResult(400, false, "ACTION_OTA_MANIFEST_INVALID");
    return;
  }
  uint8_t signature[OTA_MAX_SIGNATURE_SIZE];
  size_t signatureLength = sizeof(signature);
  if (!parseHex(signatureHex, signature, signatureLength) || signatureLength < 8 ||
      !verifyManifest(manifest, signature, signatureLength)) {
    sendResult(400, false, "ACTION_OTA_SIGNATURE_INVALID");
    return;
  }

  JsonDocument document;
  if (deserializeJson(document, manifest) || document["format"].as<int>() != 1 ||
      document["target"].as<String>() != "esp32c3") {
    sendResult(400, false, "ACTION_OTA_MANIFEST_INVALID");
    return;
  }
  String version = document["version"].as<String>();
  String sha256 = document["sha256"].as<String>();
  uint32_t counter = document["releaseCounter"].as<uint32_t>();
  uint32_t size = document["size"].as<uint32_t>();
  if (!validVersion(version) || !validSha256(sha256) || size == 0 ||
      size > OTA_SLOT_SIZE || counter == 0 || counter <= effectiveReleaseCounter()) {
    sendResult(400, false, "ACTION_OTA_MANIFEST_INVALID");
    return;
  }
  if (!Update.begin(size, U_FLASH)) {
    sendResult(500, false, "ACTION_OTA_BEGIN_FAILED", nullptr, Update.errorString());
    return;
  }

  xSemaphoreTake(otaMutex, portMAX_DELAY);
  session.active = true;
  session.finishing = false;
  session.id = nextUploadId++;
  if (session.id == 0) session.id = nextUploadId++;
  session.releaseCounter = counter;
  session.size = size;
  session.written = 0;
  session.lastActivity = millis();
  session.expectedSha256 = sha256;
  session.sha256.begin();
  uint32_t uploadId = session.id;
  xSemaphoreGive(otaMutex);

  JsonDocument data;
  data["uploadId"] = uploadId;
  data["chunkSize"] = OTA_CHUNK_SIZE;
  data["nextOffset"] = 0;
  sendResult(201, true, "ACTION_OTA_UPLOAD_STARTED", &data);
}

void handleOtaChunk() {
  if (!checkAuth() || !checkCsrf()) return;
  uint32_t id = 0, offset = 0;
  uint8_t* chunk = nullptr;
  size_t chunkLength = 0;
  if (!decodeBase64RequestChunk(OTA_CHUNK_SIZE, chunk, chunkLength)) {
    sendResult(400, false, "ACTION_OTA_CHUNK_INVALID");
    return;
  }
  xSemaphoreTake(otaMutex, portMAX_DELAY);
  if (!session.active || session.finishing || !parseUint32(server.arg("id"), id) ||
      !parseUint32(server.arg("offset"), offset) || id != session.id) {
    xSemaphoreGive(otaMutex);
    sendResult(409, false, "ACTION_OTA_SESSION_INVALID");
    return;
  }
  if (offset != session.written || session.written + chunkLength > session.size) {
    xSemaphoreGive(otaMutex);
    sendResult(400, false, "ACTION_OTA_CHUNK_INVALID");
    return;
  }
  if (Update.write(chunk, chunkLength) != chunkLength) {
    String detail = Update.errorString();
    abortSessionLocked();
    xSemaphoreGive(otaMutex);
    sendResult(500, false, "ACTION_OTA_WRITE_FAILED", nullptr, detail);
    return;
  }
  session.sha256.add(chunk, chunkLength);
  session.written += chunkLength;
  session.lastActivity = millis();
  size_t nextOffset = session.written;
  xSemaphoreGive(otaMutex);
  JsonDocument data;
  data["nextOffset"] = nextOffset;
  sendResult(200, true, "ACTION_OTA_CHUNK_OK", &data);
}

void handleOtaFinish() {
  if (!checkAuth() || !checkCsrf()) return;
  uint32_t id = 0;
  xSemaphoreTake(otaMutex, portMAX_DELAY);
  if (!session.active || session.finishing || !parseUint32(server.arg("id"), id) ||
      id != session.id || session.written != session.size) {
    xSemaphoreGive(otaMutex);
    sendResult(409, false, "ACTION_OTA_SESSION_INVALID");
    return;
  }
  session.finishing = true;
  xSemaphoreGive(otaMutex);
  if (!enqueueWebJob("ota", runOtaFinish, "id", server.arg("id"))) {
    xSemaphoreTake(otaMutex, portMAX_DELAY);
    session.finishing = false;
    xSemaphoreGive(otaMutex);
  }
}

void runOtaFinish() {
  xSemaphoreTake(otaMutex, portMAX_DELAY);
  session.sha256.calculate();
  if (session.sha256.toString() != session.expectedSha256) {
    abortSessionLocked();
    xSemaphoreGive(otaMutex);
    sendQueuedActionResult(400, false, "ACTION_OTA_HASH_INVALID");
    return;
  }
  Preferences metadata;
  if (!metadata.begin("ota_meta", false)) {
    abortSessionLocked();
    xSemaphoreGive(otaMutex);
    sendQueuedActionResult(500, false, "ACTION_OTA_METADATA_FAILED");
    return;
  }
  const esp_partition_t* target = esp_ota_get_next_update_partition(nullptr);
  if (!target || metadata.putUInt("pending", session.releaseCounter) != sizeof(uint32_t) ||
      metadata.putUInt("pendingAddr", target->address) != sizeof(uint32_t) ||
      metadata.getUInt("pending", 0) != session.releaseCounter ||
      metadata.getUInt("pendingAddr", 0) != target->address) {
    clearPendingMetadata(metadata);
    metadata.end();
    abortSessionLocked();
    xSemaphoreGive(otaMutex);
    sendQueuedActionResult(500, false, "ACTION_OTA_METADATA_FAILED");
    return;
  }
  if (!Update.end()) {
    String detail = Update.errorString();
    clearPendingMetadata(metadata);
    metadata.end();
    abortSessionLocked();
    xSemaphoreGive(otaMutex);
    sendQueuedActionResult(500, false, "ACTION_OTA_FINALIZE_FAILED", detail);
    return;
  }
  metadata.end();
  session.active = false;
  session.finishing = false;
  session.expectedSha256 = "";
  restartPending = true;
  restartAt = millis() + 2000;
  xSemaphoreGive(otaMutex);
  sendQueuedActionResult(200, true, "ACTION_OTA_READY");
}

void otaTick() {
  xSemaphoreTake(otaMutex, portMAX_DELAY);
  if (session.active && !session.finishing && millis() - session.lastActivity > OTA_SESSION_TTL_MS) {
    abortSessionLocked();
    logCaptureLn("OTA upload expired");
  }
  bool restart = restartAt && static_cast<int32_t>(millis() - restartAt) >= 0;
  xSemaphoreGive(otaMutex);
  if (restart) ESP.restart();
}

void otaConfirmHealthy(bool healthy) {
  const esp_partition_t* running = esp_ota_get_running_partition();
  esp_ota_img_states_t state;
  if (!running || esp_ota_get_state_partition(running, &state) != ESP_OK) return;

  Preferences metadata;
  bool opened = metadata.begin("ota_meta", false);
  uint32_t pending = opened ? metadata.getUInt("pending", 0) : 0;
  uint32_t pendingAddress = opened ? metadata.getUInt("pendingAddr", 0) : 0;
  if (state == ESP_OTA_IMG_PENDING_VERIFY) {
    if (opened && pending && pendingAddress == 0 &&
        metadata.putUInt("pendingAddr", running->address) == sizeof(uint32_t) &&
        metadata.getUInt("pendingAddr", 0) == running->address) {
      pendingAddress = running->address;
    }
    if (!healthy || !opened || pending == 0 || running->address != pendingAddress) {
      if (opened) metadata.end();
      esp_ota_mark_app_invalid_rollback_and_reboot();
      return;
    }
    if (esp_ota_mark_app_valid_cancel_rollback() != ESP_OK) {
      metadata.end();
      esp_ota_mark_app_invalid_rollback_and_reboot();
      return;
    }
    commitAcceptedCounter(metadata, pending);
  } else if (opened && pending) {
    if (state == ESP_OTA_IMG_VALID && running->address == pendingAddress) {
      commitAcceptedCounter(metadata, pending);
    } else {
      clearPendingMetadata(metadata);
    }
  }
  if (opened) metadata.end();
}
