#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

#include "config_schema_generated.h"
#include "idf_modem_https.h"

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
    Cellular,
    Unsupported,
};

struct IdfPushTestJobState {
    static constexpr size_t MAX_CLEANUP_MESSAGE = 96;

    bool pending = false;
    bool running = false;
    bool done = false;
    bool success = false;
    int64_t nextUs = 0;
    int64_t deadlineUs = 0;
    std::string message;
    std::string cleanupMessage;
    IdfModemHttpsDiagnosticReason failureReason = IdfModemHttpsDiagnosticReason::none;
    IdfModemHttpsDiagnosticReason cleanupReason = IdfModemHttpsDiagnosticReason::none;
    bool resetNeeded = false;
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
void idf_push_complete_test_job(IdfPushTestJobState& job, bool success,
                                std::string message, std::string cleanup_message,
                                IdfModemHttpsDiagnosticReason failure_reason =
                                    IdfModemHttpsDiagnosticReason::none,
                                IdfModemHttpsDiagnosticReason cleanup_reason =
                                    IdfModemHttpsDiagnosticReason::none,
                                bool reset_needed = false);
std::string idf_push_serialize_test_status(const IdfPushTestJobState& job,
                                           bool include_cleanup);
