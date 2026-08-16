#pragma once

#if __has_include("wifi_config.local.h")
#include "wifi_config.local.h"
#else
#define WIFI_SSID "your_wifi_ssid"
#define WIFI_PASS "your_wifi_password"
#endif
