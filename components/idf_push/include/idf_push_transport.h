#pragma once

#include <cstddef>
#include <array>
#include <cstdint>
#include <string>
#include <vector>

#include "idf_config.h"
#include "idf_modem_https.h"
#include "idf_push_core.h"

struct IdfPushHttpRequest {
    std::string url;
    std::string method = "POST";
    std::string contentType = "application/json";
    std::string headerName;
    std::string headerValue;
    std::string body;
    std::vector<uint8_t> rootCertificateDer;
    std::array<uint8_t, 32> rootCertificateSha256{};
};

struct IdfPushTransportResult {
    static constexpr size_t MAX_MESSAGE = 96;
    int error = -1;
    int httpStatus = -1;
    int mhttpError = -1;
    bool ok = false;
    std::string message;
    std::string cleanupMessage;
    IdfModemHttpsDiagnosticReason failureReason = IdfModemHttpsDiagnosticReason::none;
    IdfModemHttpsDiagnosticReason cleanupReason = IdfModemHttpsDiagnosticReason::none;
    IdfModemHttpsFailureResponseReason failureResponseReason =
        IdfModemHttpsFailureResponseReason::unknown;
    bool failureResponseReasonAvailable = false;
    IdfModemHttpsParseReason failureParseReason = IdfModemHttpsParseReason::none;
    IdfModemHttpsParseReason cleanupParseReason = IdfModemHttpsParseReason::none;
    IdfModemHttpsParseShape failureParseShape{};
    IdfModemHttpsParseShape cleanupParseShape{};
    bool cleanupRequiresReset = false;
    IdfPushTransportPath transportPath = IdfPushTransportPath::None;
    bool dispatchAttempted = false;
    IdfHttpsFailureStage failureStage = IdfHttpsFailureStage::none;
};

using IdfPushWifiRequest = int (*)(const IdfPushHttpRequest& request, int& statusCode);
using IdfPushCellularPost = int (*)(const IdfModemHttpsPostRequest& request,
                                    IdfModemHttpsPostResult& result);

bool idf_push_build_gotify_request(const IdfPushChannel& channel,
                                   const std::string& title, const std::string& message,
                                   IdfPushHttpRequest& request);
bool idf_push_dispatch_request(const IdfPushHttpRequest& request,
                               IdfPushNetworkDecision network,
                               const IdfConfigStatusView& config,
                               IdfPushWifiRequest wifi_request,
                               IdfPushCellularPost cellular_post,
                               IdfPushTransportResult& result);
