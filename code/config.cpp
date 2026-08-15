#include "config.h"
#include "web_handlers.h"

#include <memory>
#include <new>
#include <nvs.h>

namespace {

constexpr uint32_t CONFIG_MAGIC = 0x32474643;  // CFG2
constexpr uint16_t CONFIG_SCHEMA_VERSION = 1;
constexpr uint32_t MARKER_MAGIC = 0x324B524D;  // MRK2
constexpr size_t CONFIG_HEADER_SIZE = 20;
constexpr size_t CONFIG_MARKER_SIZE = 20;
constexpr size_t MAX_CONFIG_BLOB_SIZE = 32768;
constexpr size_t MAX_STORED_STRING_SIZE = 8192;
constexpr uint8_t CONFIG_STATE_MIGRATING = 1;
constexpr uint8_t CONFIG_STATE_READY = 2;

const char* const SLOT_BLOBS[] = {"cfgA", "cfgB"};
const char* const SLOT_MARKERS[] = {"markA", "markB"};

int activeSlot = -1;
uint32_t activeGeneration = 0;

struct OwnedBuffer {
  std::unique_ptr<uint8_t[]> bytes;
  size_t length = 0;
};

struct SlotState {
  bool present = false;
  bool valid = false;
  uint32_t generation = 0;
  Config value;
};

uint32_t crc32(const uint8_t* data, size_t length) {
  uint32_t crc = 0xFFFFFFFF;
  for (size_t i = 0; i < length; ++i) {
    crc ^= data[i];
    for (uint8_t bit = 0; bit < 8; ++bit) {
      crc = (crc >> 1) ^ (0xEDB88320U & (0U - (crc & 1U)));
    }
  }
  return ~crc;
}

void writeU16(uint8_t*& cursor, uint16_t value) {
  *cursor++ = value & 0xFF;
  *cursor++ = value >> 8;
}

void writeU32(uint8_t*& cursor, uint32_t value) {
  for (uint8_t shift = 0; shift < 32; shift += 8) *cursor++ = value >> shift;
}

uint16_t readU16(const uint8_t*& cursor) {
  uint16_t value = cursor[0] | (uint16_t(cursor[1]) << 8);
  cursor += 2;
  return value;
}

uint32_t readU32(const uint8_t*& cursor) {
  uint32_t value = 0;
  for (uint8_t shift = 0; shift < 32; shift += 8) value |= uint32_t(*cursor++) << shift;
  return value;
}

bool addStringSize(size_t& size, const String& value) {
  if (value.length() > MAX_STORED_STRING_SIZE || value.length() > UINT16_MAX) return false;
  size += 2 + value.length();
  return size <= MAX_CONFIG_BLOB_SIZE - CONFIG_HEADER_SIZE;
}

bool payloadSize(const Config& value, size_t& size) {
  size = 4;
  if (!addStringSize(size, value.smtpServer) || !addStringSize(size, value.smtpUser) ||
      !addStringSize(size, value.smtpPass) || !addStringSize(size, value.smtpSendTo) ||
      !addStringSize(size, value.adminPhone) || !addStringSize(size, value.numberBlackList)) return false;
  for (int i = 0; i < MAX_WEB_ACCOUNTS; ++i) {
    if (!addStringSize(size, value.webAccounts[i].username) ||
        !addStringSize(size, value.webAccounts[i].password)) return false;
  }
  for (int i = 0; i < MAX_PUSH_CHANNELS; ++i) {
    size += 2;
    const PushChannel& channel = value.pushChannels[i];
    if (!addStringSize(size, channel.name) || !addStringSize(size, channel.url) ||
        !addStringSize(size, channel.key1) || !addStringSize(size, channel.key2) ||
        !addStringSize(size, channel.customBody)) return false;
  }
  return size <= MAX_CONFIG_BLOB_SIZE - CONFIG_HEADER_SIZE;
}

void writeString(uint8_t*& cursor, const String& value) {
  writeU16(cursor, value.length());
  memcpy(cursor, value.c_str(), value.length());
  cursor += value.length();
}

bool readString(const uint8_t*& cursor, const uint8_t* end, String& value) {
  if (end - cursor < 2) return false;
  uint16_t length = readU16(cursor);
  if (length > MAX_STORED_STRING_SIZE || end - cursor < length ||
      memchr(cursor, '\0', length) != nullptr || !value.reserve(length)) return false;
  value = "";
  value.concat(reinterpret_cast<const char*>(cursor), length);
  cursor += length;
  return value.length() == length;
}

bool storageSemanticsValid(const Config& value) {
  if (value.smtpPort < 1 || value.smtpPort > 65535) return false;
  for (int i = 0; i < MAX_PUSH_CHANNELS; ++i) {
    int type = static_cast<int>(value.pushChannels[i].type);
    if (type < PUSH_TYPE_NONE || type > PUSH_TYPE_TELEGRAM) return false;
  }
  return true;
}

bool encodeConfig(const Config& value, uint32_t generation, OwnedBuffer& blob) {
  if (!storageSemanticsValid(value)) return false;
  size_t payloadLength;
  if (!payloadSize(value, payloadLength)) return false;
  blob.length = CONFIG_HEADER_SIZE + payloadLength;
  blob.bytes.reset(new (std::nothrow) uint8_t[blob.length]);
  if (!blob.bytes) return false;

  uint8_t* cursor = blob.bytes.get() + CONFIG_HEADER_SIZE;
  writeU32(cursor, value.smtpPort);
  writeString(cursor, value.smtpServer);
  writeString(cursor, value.smtpUser);
  writeString(cursor, value.smtpPass);
  writeString(cursor, value.smtpSendTo);
  writeString(cursor, value.adminPhone);
  writeString(cursor, value.numberBlackList);
  for (int i = 0; i < MAX_WEB_ACCOUNTS; ++i) {
    writeString(cursor, value.webAccounts[i].username);
    writeString(cursor, value.webAccounts[i].password);
  }
  for (int i = 0; i < MAX_PUSH_CHANNELS; ++i) {
    const PushChannel& channel = value.pushChannels[i];
    *cursor++ = channel.enabled ? 1 : 0;
    *cursor++ = static_cast<uint8_t>(channel.type);
    writeString(cursor, channel.name);
    writeString(cursor, channel.url);
    writeString(cursor, channel.key1);
    writeString(cursor, channel.key2);
    writeString(cursor, channel.customBody);
  }
  if (cursor != blob.bytes.get() + blob.length) return false;

  cursor = blob.bytes.get();
  writeU32(cursor, CONFIG_MAGIC);
  writeU16(cursor, CONFIG_SCHEMA_VERSION);
  writeU16(cursor, 0);
  writeU32(cursor, generation);
  writeU32(cursor, payloadLength);
  writeU32(cursor, crc32(blob.bytes.get() + CONFIG_HEADER_SIZE, payloadLength));
  return true;
}

bool decodeConfig(const uint8_t* bytes, size_t length, Config& value, uint32_t& generation) {
  if (length < CONFIG_HEADER_SIZE || length > MAX_CONFIG_BLOB_SIZE) return false;
  const uint8_t* cursor = bytes;
  if (readU32(cursor) != CONFIG_MAGIC || readU16(cursor) != CONFIG_SCHEMA_VERSION) return false;
  readU16(cursor);
  generation = readU32(cursor);
  uint32_t payloadLength = readU32(cursor);
  uint32_t payloadCrc = readU32(cursor);
  if (payloadLength != length - CONFIG_HEADER_SIZE ||
      crc32(bytes + CONFIG_HEADER_SIZE, payloadLength) != payloadCrc) return false;

  const uint8_t* end = bytes + length;
  if (end - cursor < 4) return false;
  value.smtpPort = readU32(cursor);
  if (!readString(cursor, end, value.smtpServer) || !readString(cursor, end, value.smtpUser) ||
      !readString(cursor, end, value.smtpPass) || !readString(cursor, end, value.smtpSendTo) ||
      !readString(cursor, end, value.adminPhone) || !readString(cursor, end, value.numberBlackList)) return false;
  for (int i = 0; i < MAX_WEB_ACCOUNTS; ++i) {
    if (!readString(cursor, end, value.webAccounts[i].username) ||
        !readString(cursor, end, value.webAccounts[i].password)) return false;
  }
  for (int i = 0; i < MAX_PUSH_CHANNELS; ++i) {
    if (end - cursor < 2) return false;
    uint8_t enabled = *cursor++;
    uint8_t type = *cursor++;
    if (enabled > 1 || type > PUSH_TYPE_TELEGRAM) return false;
    PushChannel& channel = value.pushChannels[i];
    channel.enabled = enabled == 1;
    channel.type = static_cast<PushType>(type);
    if (!readString(cursor, end, channel.name) || !readString(cursor, end, channel.url) ||
        !readString(cursor, end, channel.key1) || !readString(cursor, end, channel.key2) ||
        !readString(cursor, end, channel.customBody)) return false;
  }
  return cursor == end && storageSemanticsValid(value);
}

void encodeMarker(uint8_t marker[CONFIG_MARKER_SIZE], uint32_t generation,
                  uint32_t blobLength, uint32_t blobCrc) {
  uint8_t* cursor = marker;
  writeU32(cursor, MARKER_MAGIC);
  writeU32(cursor, generation);
  writeU32(cursor, blobLength);
  writeU32(cursor, blobCrc);
  writeU32(cursor, crc32(marker, CONFIG_MARKER_SIZE - 4));
}

bool readSlot(int slot, SlotState& state) {
  const char* blobKey = SLOT_BLOBS[slot];
  const char* markerKey = SLOT_MARKERS[slot];
  bool hasBlob = preferences.isKey(blobKey);
  bool hasMarker = preferences.isKey(markerKey);
  state.present = hasBlob || hasMarker;
  if (!hasBlob || !hasMarker) return true;

  size_t markerLength = preferences.getBytesLength(markerKey);
  size_t blobLength = preferences.getBytesLength(blobKey);
  if (markerLength != CONFIG_MARKER_SIZE || blobLength < CONFIG_HEADER_SIZE ||
      blobLength > MAX_CONFIG_BLOB_SIZE) return true;

  uint8_t marker[CONFIG_MARKER_SIZE];
  if (preferences.getBytes(markerKey, marker, sizeof(marker)) != sizeof(marker)) return true;
  const uint8_t* markerCursor = marker;
  if (readU32(markerCursor) != MARKER_MAGIC) return true;
  uint32_t markerGeneration = readU32(markerCursor);
  uint32_t markedLength = readU32(markerCursor);
  uint32_t markedCrc = readU32(markerCursor);
  uint32_t markerCrc = readU32(markerCursor);
  if (markedLength != blobLength || markerCrc != crc32(marker, CONFIG_MARKER_SIZE - 4)) return true;

  OwnedBuffer blob;
  blob.length = blobLength;
  blob.bytes.reset(new (std::nothrow) uint8_t[blobLength]);
  if (!blob.bytes || preferences.getBytes(blobKey, blob.bytes.get(), blobLength) != blobLength ||
      markedCrc != crc32(blob.bytes.get(), blobLength)) return true;
  uint32_t decodedGeneration;
  if (!decodeConfig(blob.bytes.get(), blobLength, state.value, decodedGeneration) ||
      decodedGeneration != markerGeneration) return true;
  state.generation = decodedGeneration;
  state.valid = true;
  return true;
}

bool generationNewer(uint32_t left, uint32_t right) {
  return static_cast<int32_t>(left - right) > 0;
}

void setDefaults(Config& value) {
  value.smtpPort = 465;
  value.webAccounts[0].username = DEFAULT_WEB_USER;
  value.webAccounts[0].password = DEFAULT_WEB_PASS;
  for (int i = 1; i < MAX_WEB_ACCOUNTS; ++i) {
    value.webAccounts[i].username = "";
    value.webAccounts[i].password = "";
  }
  for (int i = 0; i < MAX_PUSH_CHANNELS; ++i) {
    value.pushChannels[i].enabled = false;
    value.pushChannels[i].type = PUSH_TYPE_POST_JSON;
    value.pushChannels[i].name = "Channel " + String(i + 1);
  }
}

enum LegacyStatus { LEGACY_OK, LEGACY_ABSENT, LEGACY_ERROR };

LegacyStatus loadLegacyConfig(Config& value) {
  nvs_handle_t handle;
  esp_err_t openResult = nvs_open("sms_config", NVS_READONLY, &handle);
  if (openResult == ESP_ERR_NVS_NOT_FOUND) {
    setDefaults(value);
    return LEGACY_ABSENT;
  }
  if (openResult != ESP_OK) return LEGACY_ERROR;
  nvs_close(handle);
  if (!preferences.begin("sms_config", true)) return LEGACY_ERROR;

  value.smtpServer = preferences.getString("smtpServer", "");
  value.smtpPort = preferences.getInt("smtpPort", 465);
  value.smtpUser = preferences.getString("smtpUser", "");
  value.smtpPass = preferences.getString("smtpPass", "");
  value.smtpSendTo = preferences.getString("smtpSendTo", "");
  value.adminPhone = preferences.getString("adminPhone", "");
  bool hasAccountList = preferences.isKey("account0user");
  for (int i = 0; i < MAX_WEB_ACCOUNTS; ++i) {
    String prefix = "account" + String(i);
    if (i == 0 && !hasAccountList) {
      value.webAccounts[i].username = preferences.getString("webUser", DEFAULT_WEB_USER);
      value.webAccounts[i].password = preferences.getString("webPass", DEFAULT_WEB_PASS);
    } else {
      value.webAccounts[i].username = preferences.getString((prefix + "user").c_str(), "");
      value.webAccounts[i].password = preferences.getString((prefix + "pass").c_str(), "");
    }
  }
  value.numberBlackList = preferences.getString("numBlkList", "");
  for (int i = 0; i < MAX_PUSH_CHANNELS; ++i) {
    String prefix = "push" + String(i);
    PushChannel& channel = value.pushChannels[i];
    channel.enabled = preferences.getBool((prefix + "en").c_str(), false);
    channel.type = static_cast<PushType>(preferences.getUChar((prefix + "type").c_str(), PUSH_TYPE_POST_JSON));
    channel.url = preferences.getString((prefix + "url").c_str(), "");
    channel.name = preferences.getString((prefix + "name").c_str(), "Channel " + String(i + 1));
    channel.key1 = preferences.getString((prefix + "k1").c_str(), "");
    channel.key2 = preferences.getString((prefix + "k2").c_str(), "");
    channel.customBody = preferences.getString((prefix + "body").c_str(), "");
  }
  String oldHttpUrl = preferences.getString("httpUrl", "");
  if (oldHttpUrl.length() > 0 && !value.pushChannels[0].enabled) {
    value.pushChannels[0].enabled = true;
    value.pushChannels[0].url = oldHttpUrl;
    value.pushChannels[0].type = preferences.getUChar("barkMode", 0) != 0 ? PUSH_TYPE_BARK : PUSH_TYPE_POST_JSON;
    value.pushChannels[0].name = "Migrated channel";
  }
  preferences.end();
  return storageSemanticsValid(value) ? LEGACY_OK : LEGACY_ERROR;
}

bool openConfigStorage() {
  return preferences.begin("config", false, "appcfg");
}

bool setConfigState(uint8_t state) {
  if (!openConfigStorage()) return false;
  bool ok = preferences.putUChar("state", state) == 1;
  preferences.end();
  return ok;
}

}  // namespace

bool saveConfig(const Config& candidate) {
  uint32_t generation = activeGeneration + 1;
  OwnedBuffer blob;
  if (!encodeConfig(candidate, generation, blob) || !openConfigStorage()) {
    logCaptureLn("Failed to save configuration");
    return false;
  }

  int targetSlot = activeSlot == 0 ? 1 : 0;
  uint32_t blobCrc = crc32(blob.bytes.get(), blob.length);
  bool ok = preferences.putBytes(SLOT_BLOBS[targetSlot], blob.bytes.get(), blob.length) == blob.length;
  SlotState staged;
  if (ok) {
    // The old marker deliberately remains until the new blob has been read back.
    size_t storedLength = preferences.getBytesLength(SLOT_BLOBS[targetSlot]);
    OwnedBuffer stored;
    stored.length = storedLength;
    stored.bytes.reset(new (std::nothrow) uint8_t[storedLength]);
    uint32_t checkedGeneration = 0;
    Config checked;
    ok = storedLength == blob.length && stored.bytes &&
         preferences.getBytes(SLOT_BLOBS[targetSlot], stored.bytes.get(), storedLength) == storedLength &&
         crc32(stored.bytes.get(), storedLength) == blobCrc &&
         decodeConfig(stored.bytes.get(), storedLength, checked, checkedGeneration) &&
         checkedGeneration == generation;
  }
  if (ok) {
    uint8_t marker[CONFIG_MARKER_SIZE];
    encodeMarker(marker, generation, blob.length, blobCrc);
    ok = preferences.putBytes(SLOT_MARKERS[targetSlot], marker, sizeof(marker)) == sizeof(marker);
  }
  if (ok) ok = readSlot(targetSlot, staged) && staged.valid && staged.generation == generation;
  preferences.end();

  if (!ok) {
    logCaptureLn("Failed to save configuration: new slot was not committed");
    return false;
  }
  activeSlot = targetSlot;
  activeGeneration = generation;
  logCaptureLn("Configuration saved");
  return true;
}

ConfigLoadStatus loadConfig() {
  activeSlot = -1;
  activeGeneration = 0;
  if (!openConfigStorage()) {
    logCaptureLn("Failed to load configuration: could not open appcfg NVS");
    return CONFIG_LOAD_STORAGE_ERROR;
  }

  SlotState slots[2];
  readSlot(0, slots[0]);
  readSlot(1, slots[1]);
  uint8_t storageState = preferences.getUChar("state", 0);
  bool hasValidSlot = slots[0].valid || slots[1].valid;
  bool stateOk = true;
  if (hasValidSlot && storageState != CONFIG_STATE_READY) {
    stateOk = preferences.putUChar("state", CONFIG_STATE_READY) == 1;
  }
  preferences.end();
  if (hasValidSlot) {
    if (!stateOk) {
      logCaptureLn("Failed to load configuration: could not commit storage state");
      return CONFIG_LOAD_STORAGE_ERROR;
    }
    int selected = !slots[0].valid ? 1 : !slots[1].valid ? 0 :
                   (generationNewer(slots[1].generation, slots[0].generation) ? 1 : 0);
    config = slots[selected].value;
    activeSlot = selected;
    activeGeneration = slots[selected].generation;
    logCaptureLn("Configuration loaded");
    return CONFIG_LOAD_OK;
  }
  bool hasSlotData = slots[0].present || slots[1].present;
  bool canMigrate = storageState == CONFIG_STATE_MIGRATING ||
                    (storageState == 0 && !hasSlotData);
  if (!canMigrate) {
    logCaptureLn("Failed to load configuration: both configuration slots are invalid");
    return CONFIG_LOAD_STORAGE_ERROR;
  }

  if (storageState != CONFIG_STATE_MIGRATING &&
      !setConfigState(CONFIG_STATE_MIGRATING)) {
    logCaptureLn("Failed to migrate configuration: could not commit migration state");
    return CONFIG_LOAD_STORAGE_ERROR;
  }

  Config legacy;
  LegacyStatus legacyStatus = loadLegacyConfig(legacy);
  if (legacyStatus == LEGACY_ERROR || !saveConfig(legacy) ||
      !setConfigState(CONFIG_STATE_READY)) {
    logCaptureLn("Failed to migrate configuration");
    return CONFIG_LOAD_STORAGE_ERROR;
  }
  config = legacy;
  logCaptureLn(legacyStatus == LEGACY_ABSENT ? "Initial configuration created" : "Legacy configuration migrated");
  return legacyStatus == LEGACY_ABSENT ? CONFIG_LOAD_FIRST_BOOT : CONFIG_LOAD_OK;
}

bool isPushChannelValid(const PushChannel& ch) {
  if (!ch.enabled) return false;
  if (ch.url.indexOf('\r') >= 0 || ch.url.indexOf('\n') >= 0 ||
      ch.key1.indexOf('\r') >= 0 || ch.key1.indexOf('\n') >= 0 ||
      ch.key2.indexOf('\r') >= 0 || ch.key2.indexOf('\n') >= 0) return false;
  switch (ch.type) {
    case PUSH_TYPE_POST_JSON:
    case PUSH_TYPE_BARK:
    case PUSH_TYPE_GET:
    case PUSH_TYPE_DINGTALK:
    case PUSH_TYPE_FEISHU:
    case PUSH_TYPE_CUSTOM:
      return ch.url.length() > 0;
    case PUSH_TYPE_PUSHPLUS:
    case PUSH_TYPE_SERVERCHAN:
      return ch.key1.length() > 0;
    case PUSH_TYPE_GOTIFY:
      return ch.url.length() > 0 && ch.key1.length() > 0;
    case PUSH_TYPE_TELEGRAM:
      return ch.key1.length() > 0 && ch.key2.length() > 0;
    default:
      return false;
  }
}

bool isConfigValid() {
  bool emailValid = config.smtpServer.length() > 0 && config.smtpUser.length() > 0 &&
                    config.smtpPass.length() > 0 && config.smtpSendTo.length() > 0;
  for (int i = 0; i < MAX_PUSH_CHANNELS; ++i) {
    if (isPushChannelValid(config.pushChannels[i])) return true;
  }
  return emailValid;
}

String getDeviceUrl() {
  return "http://" + WiFi.localIP().toString() + "/";
}
