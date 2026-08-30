#!/usr/bin/env python3
import subprocess
import tempfile
from pathlib import Path


ROOT = Path(__file__).resolve().parents[3]
PUSH = ROOT / "components/idf_push"


def main() -> None:
    harness = r'''
#include <cassert>
#include <string>
#include <string_view>
#include <type_traits>
#include <utility>

#include "idf_push_core.h"
#include "idf_push_transport.h"

static IdfModemHttpsPostRequest captured_request;
static int modem_calls = 0;
static int modem_status = 204;
static int modem_error = -1;
static bool modem_ok = true;
static std::string modem_message = "HTTPS TLS context 1 has no pre-provisioned certificate";
static std::string modem_cleanup_message;

template <typename T, typename = void>
struct CleanupMessageAccessor {
    static void set(T&, const std::string&) {}
    static std::string_view get(const T&) { return {}; }
};

template <typename T>
struct CleanupMessageAccessor<T, std::void_t<decltype(std::declval<T&>().cleanupMessage)>> {
    static void set(T& result, const std::string& message) { result.cleanupMessage = message; }
    static std::string_view get(const T& result) { return result.cleanupMessage; }
};

static int fake_modem_post(const IdfModemHttpsPostRequest& request,
                           IdfModemHttpsPostResult& result) {
    captured_request = request;
    ++modem_calls;
    result.httpStatus = modem_status;
    result.mhttpError = modem_error;
    result.ok = modem_ok;
    result.message = modem_message;
    CleanupMessageAccessor<IdfModemHttpsPostResult>::set(result, modem_cleanup_message);
    return 0;
}

int main() {
    assert(idf_push_select_network(NETWORK_MODE_4G_ONLY, true) ==
           IdfPushNetworkDecision::Cellular);
    assert(idf_push_select_network(NETWORK_MODE_4G_ONLY, false) ==
           IdfPushNetworkDecision::Cellular);
    assert(idf_push_select_network(NETWORK_MODE_MIX, false) ==
           IdfPushNetworkDecision::Cellular);
    assert(idf_push_select_network(NETWORK_MODE_MIX, true) ==
           IdfPushNetworkDecision::Wifi);

    IdfPushChannel gotify;
    gotify.type = PUSH_TYPE_GOTIFY;
    gotify.url = "https://gotify.example/base";
    gotify.key1 = "tok en/+";
    IdfPushHttpRequest request;
    assert(idf_push_build_gotify_request(gotify, "Alert \"1\"", "line\nbody", request));
    assert(request.url == "https://gotify.example/base/message?token=tok+en%2F%2B");
    assert(request.method == "POST");
    assert(request.contentType == "application/json");
    assert(request.body == "{\"title\":\"Alert \\\"1\\\"\",\"message\":\"line\\nbody\",\"priority\":5}");

    IdfConfigStatusView config;
    config.apn = "internet";
    config.dataEnabled = true;
    request.headerName = "X-Device";
    request.headerValue = "sms-forwarder";
    request.rootCertificateDer = {'D', 'E', 'R'};
    request.rootCertificateSha256.fill(0xab);
    IdfPushTransportResult transport;
    assert(idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                     nullptr, fake_modem_post, transport));
    assert(modem_calls == 1);
    assert(captured_request.url == request.url);
    assert(captured_request.body == request.body);
    assert(captured_request.contentType == "application/json");
    assert(captured_request.headerName == "X-Device");
    assert(captured_request.headerValue == "sms-forwarder");
    assert(captured_request.apn == "internet");
    assert(captured_request.dataEnabled);
    assert(captured_request.rootCertificateDer == request.rootCertificateDer);
    assert(captured_request.rootCertificateSha256 == request.rootCertificateSha256);
    assert(transport.httpStatus == 204);
    assert(transport.ok);
    assert(CleanupMessageAccessor<IdfPushTransportResult>::get(transport).empty());

    modem_status = 503;
    modem_error = 4;
    modem_message = "HTTPS modem request failed";
    assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                      nullptr, fake_modem_post, transport));
    assert(!transport.ok);
    assert(transport.mhttpError == 4);
    assert(transport.message == "HTTPS modem request failed (code 4)");
    modem_error = -1;
    modem_message = "HTTPS TLS context 1 has no pre-provisioned certificate";
    assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                      nullptr, fake_modem_post, transport));
    assert(transport.mhttpError == -1);
    assert(transport.message == "HTTPS TLS context 1 has no pre-provisioned certificate");
    modem_message = "HTTPS modem connected-state poll failed";
    assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                      nullptr, fake_modem_post, transport));
    assert(transport.message == "HTTPS modem connected-state poll failed");
    for (const char* message : {
             "HTTPS modem initial query command failed",
             "HTTPS modem initial query response invalid",
             "HTTPS modem stale socket close command failed",
             "HTTPS modem stale socket close response invalid",
             "HTTPS modem post-close query command failed",
             "HTTPS modem post-close query response invalid",
         }) {
        modem_message = message;
        assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                          nullptr, fake_modem_post, transport));
        assert(transport.message == message);
    }
    modem_message.assign(200, 'x');
    assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                      nullptr, fake_modem_post, transport));
    assert(transport.message.size() == IdfPushTransportResult::MAX_MESSAGE);
    modem_status = 200;
    modem_ok = false;
    modem_message = "HTTPS request write failed";
    modem_cleanup_message = "HTTPS cleanup socket close failed";
    assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                      nullptr, fake_modem_post, transport));
    assert(!transport.ok);
    assert(transport.httpStatus == 200);
    assert(transport.message == "HTTPS request write failed");
    assert(CleanupMessageAccessor<IdfPushTransportResult>::get(transport) ==
           "HTTPS cleanup socket close failed");

    modem_cleanup_message.assign(200, 'y');
    assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                      nullptr, fake_modem_post, transport));
    assert(CleanupMessageAccessor<IdfPushTransportResult>::get(transport).size() ==
           IdfPushTransportResult::MAX_MESSAGE);

    modem_status = 204;
    modem_ok = true;
    modem_message = "HTTPS POST succeeded";
    modem_cleanup_message.clear();
    assert(idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                     nullptr, fake_modem_post, transport));
    assert(CleanupMessageAccessor<IdfPushTransportResult>::get(transport).empty());

    request.method = "GET";
    const int calls_before_get = modem_calls;
    assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                      nullptr, fake_modem_post, transport));
    assert(modem_calls == calls_before_get);

    request.method = "POST";
    request.rootCertificateDer.clear();
    const int calls_before_missing_ca = modem_calls;
    assert(!idf_push_dispatch_request(request, IdfPushNetworkDecision::Cellular, config,
                                      nullptr, fake_modem_post, transport));
    assert(modem_calls == calls_before_missing_ca);
    assert(transport.message == "Cellular CA is not provisioned");
}
'''
    with tempfile.TemporaryDirectory() as temp_dir:
        Path(temp_dir, "esp_err.h").write_text("using esp_err_t = int;\n")
        harness_path = Path(temp_dir) / "cellular_dispatch_test.cpp"
        binary_path = Path(temp_dir) / "cellular_dispatch_test"
        harness_path.write_text(harness)
        subprocess.run(
            [
                "g++", "-std=c++17", "-Wall", "-Wextra", "-Werror",
                f"-I{temp_dir}",
                f"-I{PUSH / 'include'}", f"-I{ROOT / 'components/idf_config/include'}",
                f"-I{ROOT / 'components/idf_modem/include'}",
                f"-I{ROOT / 'components/idf_logbuf/include'}",
                str(ROOT / "components/idf_logbuf/idf_util.cpp"),
                str(PUSH / "idf_push_core.cpp"), str(PUSH / "idf_push_transport.cpp"),
                str(harness_path), "-o", str(binary_path),
            ],
            check=True,
        )
        subprocess.run([str(binary_path)], check=True)


if __name__ == "__main__":
    main()
