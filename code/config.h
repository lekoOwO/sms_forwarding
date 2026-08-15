#ifndef CONFIG_H
#define CONFIG_H

#include "globals.h"

#include <memory>

enum ConfigLoadStatus {
  CONFIG_LOAD_OK,
  CONFIG_LOAD_FIRST_BOOT,
  CONFIG_LOAD_STORAGE_ERROR,
};

enum PortableConfigStatus {
  PORTABLE_CONFIG_OK,
  PORTABLE_CONFIG_INVALID,
  PORTABLE_CONFIG_UNSUPPORTED_VERSION,
};

struct PortableConfigBuffer {
  std::unique_ptr<uint8_t[]> bytes;
  size_t length = 0;
};

bool saveConfig(const Config& candidate);
ConfigLoadStatus loadConfig();
bool encodePortableConfig(const Config& value, PortableConfigBuffer& output);
PortableConfigStatus decodePortableConfig(const uint8_t* bytes, size_t length,
                                          const Config& target, Config& output);
bool isPushChannelValid(const PushChannel& ch);
bool isConfigSemanticallyValid(const Config& value);
bool isConfigValid();
String getDeviceUrl();

#endif
