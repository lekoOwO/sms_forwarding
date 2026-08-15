#ifndef CONFIG_H
#define CONFIG_H

#include "globals.h"

enum ConfigLoadStatus {
  CONFIG_LOAD_OK,
  CONFIG_LOAD_FIRST_BOOT,
  CONFIG_LOAD_STORAGE_ERROR,
};

bool saveConfig(const Config& candidate);
ConfigLoadStatus loadConfig();
bool isPushChannelValid(const PushChannel& ch);
bool isConfigValid();
String getDeviceUrl();

#endif
