#pragma once

#include <cstddef>
#include <string>

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
};

struct IdfPushTransportResult {
    static constexpr size_t MAX_MESSAGE = 96;
    int error = -1;
    int httpStatus = -1;
    bool ok = false;
    std::string message;
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
