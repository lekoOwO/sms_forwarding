#include "idf_push_transport.h"

#include <algorithm>
#include <cctype>

namespace {

std::string json_escape(const std::string& value)
{
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char ch : value) {
        switch (ch) {
            case '\\': out += "\\\\"; break;
            case '"': out += "\\\""; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (ch < 0x20) {
                    static constexpr char hex[] = "0123456789abcdef";
                    out += "\\u00";
                    out += hex[ch >> 4];
                    out += hex[ch & 0x0f];
                } else {
                    out += static_cast<char>(ch);
                }
        }
    }
    return out;
}

std::string url_encode(const std::string& value)
{
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    out.reserve(value.size() * 3);
    for (unsigned char ch : value) {
        if (std::isalnum(ch) != 0) out += static_cast<char>(ch);
        else if (ch == ' ') out += '+';
        else {
            out += '%';
            out += hex[ch >> 4];
            out += hex[ch & 0x0f];
        }
    }
    return out;
}

bool http_status_valid(int status)
{
    return status >= 100 && status <= 599;
}

}  // namespace

bool idf_push_build_gotify_request(const IdfPushChannel& channel,
                                   const std::string& title, const std::string& message,
                                   IdfPushHttpRequest& request)
{
    if (channel.type != PUSH_TYPE_GOTIFY || channel.url.empty() || channel.key1.empty()) return false;
    request = IdfPushHttpRequest();
    request.url = channel.url;
    if (request.url.back() != '/') request.url += '/';
    request.url += "message?token=" + url_encode(channel.key1);
    request.body = "{\"title\":\"" + json_escape(title) + "\",\"message\":\"" +
                   json_escape(message) + "\",\"priority\":5}";
    return true;
}

bool idf_push_dispatch_request(const IdfPushHttpRequest& request,
                               IdfPushNetworkDecision network,
                               const IdfConfigStatusView& config,
                               IdfPushWifiRequest wifi_request,
                               IdfPushCellularPost cellular_post,
                               IdfPushTransportResult& result)
{
    result = IdfPushTransportResult();
    if (network == IdfPushNetworkDecision::Wifi) {
        result.transportPath = IdfPushTransportPath::Wifi;
        if (!wifi_request) {
            result.failureStage = IdfHttpsFailureStage::preflight;
            return false;
        }
        result.dispatchAttempted = true;
        result.error = wifi_request(request, result.httpStatus);
        result.ok = result.error == 0 && result.httpStatus >= 200 && result.httpStatus < 300;
        if (result.ok) {
            result.failureStage = IdfHttpsFailureStage::none;
        } else if (http_status_valid(result.httpStatus) &&
                   (result.httpStatus < 200 || result.httpStatus >= 300)) {
            result.failureStage = IdfHttpsFailureStage::http;
        } else {
            result.failureStage = result.error == 0 ? IdfHttpsFailureStage::response
                                                    : IdfHttpsFailureStage::modem;
        }
        return result.ok;
    }
    if (network != IdfPushNetworkDecision::Cellular) {
        result.failureStage = IdfHttpsFailureStage::preflight;
        return false;
    }
    result.transportPath = IdfPushTransportPath::Cellular;
    if (request.method != "POST") {
        result.failureStage = IdfHttpsFailureStage::request;
        return false;
    }
    if (!cellular_post) {
        result.failureStage = IdfHttpsFailureStage::preflight;
        return false;
    }

    IdfModemHttpsPostRequest cellular_request;
    cellular_request.url = request.url;
    cellular_request.body = request.body;
    cellular_request.contentType = request.contentType;
    cellular_request.headerName = request.headerName;
    cellular_request.headerValue = request.headerValue;
    cellular_request.apn = config.apn;
    cellular_request.dataEnabled = config.dataEnabled;
    cellular_request.rootCertificateDer = request.rootCertificateDer;
    cellular_request.rootCertificateSha256 = request.rootCertificateSha256;
    if (cellular_request.rootCertificateDer.empty()) {
        result.message = "Cellular CA is not provisioned";
        result.failureStage = IdfHttpsFailureStage::ca;
        return false;
    }
    IdfModemHttpsPostResult cellular_result;
    result.dispatchAttempted = true;
    result.error = cellular_post(cellular_request, cellular_result);
    result.httpStatus = cellular_result.httpStatus;
    result.mhttpError = cellular_result.mhttpError;
    result.message.assign(cellular_result.message.data(),
                          std::min(cellular_result.message.size(), IdfPushTransportResult::MAX_MESSAGE));
    result.cleanupMessage.assign(
        cellular_result.cleanupMessage.data(),
        std::min(cellular_result.cleanupMessage.size(), IdfPushTransportResult::MAX_MESSAGE));
    result.failureReason = cellular_result.failureReason;
    result.cleanupReason = cellular_result.cleanupReason;
    result.failureResponseReason = cellular_result.failureResponseReason;
    result.failureResponseReasonAvailable = cellular_result.failureResponseReasonAvailable;
    result.failureParseReason = cellular_result.failureParseReason;
    result.cleanupParseReason = cellular_result.cleanupParseReason;
    if (result.failureReason == IdfModemHttpsDiagnosticReason::response_invalid) {
        result.failureParseShape = cellular_result.failureParseShape;
    }
    if (result.cleanupReason == IdfModemHttpsDiagnosticReason::response_invalid) {
        result.cleanupParseShape = cellular_result.cleanupParseShape;
    }
    result.cleanupRequiresReset = cellular_result.cleanupRequiresReset;
    result.failureStage = cellular_result.failureStage;
    if (result.message == "HTTPS modem request failed" && result.mhttpError >= 0) {
        result.message += " (code " + std::to_string(result.mhttpError) + ")";
    }
    result.ok = result.error == 0 && cellular_result.ok &&
                result.httpStatus >= 200 && result.httpStatus < 300;
    if (result.ok) {
        result.failureStage = IdfHttpsFailureStage::none;
    } else if (http_status_valid(result.httpStatus) &&
               (result.httpStatus < 200 || result.httpStatus >= 300)) {
        result.failureStage = IdfHttpsFailureStage::http;
    } else if (result.failureStage == IdfHttpsFailureStage::none) {
        result.failureStage = result.error == 0 ? IdfHttpsFailureStage::response
                                                : IdfHttpsFailureStage::modem;
    }
    return result.ok;
}
