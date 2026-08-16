#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "config_schema_generated.h"

struct IdfPushTemplateValues {
    std::string sender;
    std::string message;
    std::string timestamp;
    std::string device;
    std::string localNumber;
    std::string ip;
    std::string hostname;
    std::string wifi;
};

enum class IdfPushNetworkDecision : uint8_t {
    Wifi,
    Defer,
    Unsupported,
};

bool idf_push_utf8_valid(const std::string& value);
bool idf_push_render_template(const std::string& source, const IdfPushTemplateValues& values,
                              size_t max_bytes, bool header, std::string& output);
bool idf_push_render_sms_notification(const std::string& locale,
                                      const std::string& title_template,
                                      const std::string& body_template,
                                      const IdfPushTemplateValues& values,
                                      std::string& title, std::string& body);
bool idf_push_network_uses_wifi(NetworkMode mode, bool wifi_connected);
IdfPushNetworkDecision idf_push_select_network(NetworkMode mode, bool wifi_connected);
size_t idf_push_utf8_codepoint_count(const std::string& value, size_t limit);
