#include "idf_modem_https.h"
#include "idf_modem_registration.h"

#include <algorithm>
#include <cassert>
#include <string>
#include <vector>

static IdfModemHttpsPostRequest request_fixture()
{
    IdfModemHttpsPostRequest request;
    request.url = "https://push.example.test/api/notify?source=sms";
    request.body = std::string("{\"message\":\"line\n\r\0\x1f\"}", 22);
    request.contentType = "application/json";
    request.headerName = "X-Device";
    request.headerValue = "forwarder";
    request.apn = "  internet  ";
    return request;
}

struct OwnerTransportFixture {
    enum class StaleFailure { none, modem_error, transport_failure };
    enum class FailureStage {
        none,
        auth,
        cert_bind,
        encoding,
        negotime,
        version,
        ignorestamp,
        ignoreverify,
        create,
        timeout,
        ssl,
    };

    std::vector<std::string> writes;
    std::string raw_body;
    bool prompt_seen = false;
    bool cleanup_ok = true;
    bool abandoned = false;
    bool request_expired = false;
    bool first_cleanup_timeout = false;
    bool second_cleanup_timeout = false;
    StaleFailure stale_failure = StaleFailure::none;
    bool short_setup_write = false;
    bool non_2xx_response = false;
    std::string cert_response;
    FailureStage fail_stage = FailureStage::none;
    IdfModemHttpsPostResult last_result;

    static IdfModemHttpsCommandResult send_command(
        void* context, std::string_view command, std::string& response,
        std::string_view raw_payload, bool cleanup, bool tolerate_modem_error);
    static IdfModemHttpsCommandResult wait_response(
        void* context, uint8_t http_id, IdfModemHttpsPostResult& result);

    bool run(const IdfModemHttpsPostRequest& request, std::string_view model,
             int cereg_stat, std::string_view cert_response)
    {
        if (abandoned || !idf_modem_https_model_allowed(model) ||
            !idf_modem_data_activation_allowed(cereg_stat)) {
            return false;
        }
        this->cert_response.assign(cert_response.data(), cert_response.size());
        IdfModemHttpsCallbacks callbacks{this, &send_command, &wait_response};
        IdfModemHttpsPostResult result;
        const bool ok = idf_modem_https_run_post(request, callbacks, result) ==
                        IdfModemHttpsRunResult::ok;
        last_result = result;
        return ok;
    }
};

IdfModemHttpsCommandResult OwnerTransportFixture::send_command(
    void* context, std::string_view command, std::string& response,
    std::string_view raw_payload, bool cleanup, bool tolerate_modem_error)
{
    auto& fixture = *static_cast<OwnerTransportFixture*>(context);
    response.clear();
    fixture.writes.emplace_back(command);
    if (command.rfind("AT+MHTTPCONTENT=", 0) == 0) {
        fixture.prompt_seen = true;
        fixture.raw_body.assign(raw_payload.data(), raw_payload.size());
    }
    if (!cleanup && command == "AT+MHTTPDEL=0") {
        if (fixture.stale_failure == OwnerTransportFixture::StaleFailure::transport_failure) {
            return IdfModemHttpsCommandResult::failed;
        }
        if (fixture.stale_failure == OwnerTransportFixture::StaleFailure::modem_error) {
            assert(tolerate_modem_error);
            return IdfModemHttpsCommandResult::modem_error;
        }
    }
    if (!cleanup && fixture.short_setup_write &&
        command == "AT+MHTTPCFG=\"ssl\",7,1,1") {
        return IdfModemHttpsCommandResult::failed;
    }
    const auto fail = [&](OwnerTransportFixture::FailureStage stage) {
        return fixture.fail_stage == stage;
    };
    if (fail(OwnerTransportFixture::FailureStage::auth) &&
        command == "AT+MSSLCFG=\"auth\",1,1") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::cert_bind) &&
        command == "AT+MSSLCFG=\"cert\",1,\"root-ca.pem\"") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::encoding) &&
        command == "AT+MSSLCFG=\"encoding\",1,2") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::negotime) &&
        command == "AT+MSSLCFG=\"negotime\",1,60") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::version) &&
        command == "AT+MSSLCFG=\"version\",1,3") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::ignorestamp) &&
        command == "AT+MSSLCFG=\"ignorestamp\",1,0") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::ignoreverify) &&
        command == "AT+MSSLCFG=\"ignoreverify\",1,0") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::create) &&
        command == idf_modem_https_create_command("push.example.test")) return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::timeout) &&
        command == "AT+MHTTPCFG=\"timeout\",7,30") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::ssl) &&
        command == "AT+MHTTPCFG=\"ssl\",7,1,1") return IdfModemHttpsCommandResult::failed;
    if (cleanup && command == "AT+MHTTPTERM=7" && fixture.first_cleanup_timeout) {
        return IdfModemHttpsCommandResult::timeout;
    }
    if (cleanup && command == "AT+MHTTPDEL=7" && fixture.second_cleanup_timeout) {
        return IdfModemHttpsCommandResult::timeout;
    }
    if (cleanup && !fixture.cleanup_ok) return IdfModemHttpsCommandResult::failed;
    if (command == idf_modem_https_cert_query_command()) response = fixture.cert_response;
    if (command == idf_modem_https_create_command("push.example.test")) {
        response = "+MHTTPCREATE: 7\r\nOK\r\n";
    }
    return IdfModemHttpsCommandResult::ok;
}

IdfModemHttpsCommandResult OwnerTransportFixture::wait_response(
    void* context, uint8_t http_id, IdfModemHttpsPostResult& result)
{
    auto& fixture = *static_cast<OwnerTransportFixture*>(context);
    if (fixture.request_expired) return IdfModemHttpsCommandResult::timeout;
    if (fixture.non_2xx_response) {
        result.httpStatus = 503;
        result.message = "HTTPS POST returned a non-2xx status";
        return IdfModemHttpsCommandResult::failed;
    }
    IdfModemHttpsUrcParser parser(http_id);
    for (const std::string_view chunk : {
             std::string_view("+MHTTPURC: \"header\",7,204,0\r\n"),
             std::string_view("+MHTTPURC: \"content\",7,5,5,0\r\nhello"),
         }) {
        parser.feed(chunk);
    }
    result = parser.result();
    if (!parser.complete() || parser.failed()) return IdfModemHttpsCommandResult::failed;
    return IdfModemHttpsCommandResult::ok;
}

static std::vector<std::string> expected_writes()
{
    return {
        "AT+CGDCONT=1,\"IP\",\"internet\"",
        "AT+CGACT=1,1",
        "AT+MHTTPDEL=0",
        "AT+MHTTPDEL=1",
        "AT+MHTTPDEL=2",
        "AT+MHTTPDEL=3",
        "AT+MSSLCFG=\"cert\",1",
        "AT+MSSLCFG=\"cert\",1,\"root-ca.pem\"",
        "AT+MSSLCFG=\"auth\",1,1",
        "AT+MSSLCFG=\"encoding\",1,2",
        "AT+MSSLCFG=\"negotime\",1,60",
        "AT+MSSLCFG=\"version\",1,3",
        "AT+MSSLCFG=\"ignorestamp\",1,0",
        "AT+MSSLCFG=\"ignoreverify\",1,0",
        "AT+MHTTPCREATE=\"https://push.example.test\"",
        "AT+MHTTPCFG=\"ssl\",7,1,1",
        "AT+MHTTPCFG=\"timeout\",7,30",
        "AT+MHTTPCFG=\"header\",7,1",
        "AT+MHTTPHEADER=7,1,30,\"Content-Type: application/json\"",
        "AT+MHTTPHEADER=7,0,19,\"X-Device: forwarder\"",
        "AT+MHTTPCONTENT=7,0,22",
        "AT+MHTTPREQUEST=7,2,0,2F6170692F6E6F746966793F736F757263653D736D73",
        "AT+MHTTPTERM=7",
        "AT+MHTTPDEL=7",
        "AT+CGACT=0,1",
    };
}

static void feed_fragmented_success()
{
    IdfModemHttpsUrcParser parser(7);
    for (const std::string_view chunk : {
             std::string_view("+MHTTPURC: \"header\",7,204"),
             std::string_view(",0\r\n+CMT: \"+886900000\",145\r\n0011"),
             std::string_view("2233445566778899AABBCCDDEEFF\r\nRING\r\n"),
             std::string_view("+CLIP: \"+886911111\",145\r\n+CEREG: 1,1\r\n"),
             std::string_view("+MHTTPURC: \"content\",7,5,5,2\r\nhe"),
             std::string_view("+MHTTPURC: \"content\",7,5,5,3\r\nllo"),
             std::string_view("+MHTTPURC: \"content\",7,5,5,0\r\n"),
         }) {
        parser.feed(chunk);
    }
    assert(parser.complete());
    assert(!parser.failed());
    assert(parser.result().httpStatus == 204);
    assert(parser.result().expectedResponseBytes == 5);
    assert(parser.result().responseBytes == 5);
    assert(parser.urcs().find("+CMT:") != std::string::npos);
    assert(parser.urcs().find("00112233445566778899AABBCCDDEEFF") != std::string::npos);
    assert(parser.urcs().find("RING") != std::string::npos);
    assert(parser.urcs().find("+CLIP:") != std::string::npos);
    assert(parser.urcs().find("+CEREG:") != std::string::npos);
    assert(parser.urcs().find("hello") == std::string::npos);

    IdfModemHttpsUrcParser error_parser(7);
    error_parser.feed("+MHTTPURC: \"err\",7,4\r\n");
    assert(error_parser.complete());
    assert(error_parser.failed());
    assert(error_parser.result().mhttpError == 4);

    IdfModemHttpsUrcParser non_2xx(7);
    non_2xx.feed("+MHTTPURC: \"header\",7,503,0\r\n");
    non_2xx.feed("+MHTTPURC: \"content\",7,0,0,0\r\n");
    assert(non_2xx.complete());
    assert(!idf_modem_https_status_success(non_2xx.result().httpStatus));

    IdfModemHttpsUrcParser timeout(7);
    assert(!timeout.complete());
}

int main()
{
    const IdfModemHttpsPostRequest request = request_fixture();
    const std::string cert_response =
        "+MSSLCFG: \"cert\",1,\"root-ca.pem\"\r\nOK\r\n";

    OwnerTransportFixture owner;
    assert(owner.run(request, "ML307A", 1, cert_response));
    assert(owner.writes == expected_writes());
    assert(owner.prompt_seen);
    assert(owner.raw_body == request.body);
    assert(owner.raw_body.find('\x1a') == std::string::npos);
    assert(idf_modem_https_content_command(7, IDF_MODEM_HTTPS_POST_MAX_BODY) ==
           "AT+MHTTPCONTENT=7,0,4096");

    IdfModemHttpsPostRequest empty_body = request;
    empty_body.body.clear();
    OwnerTransportFixture empty;
    assert(!empty.run(empty_body, "ML307A", 1, cert_response));
    assert(empty.writes.empty());
    assert(idf_modem_https_timeout_command(7, 1001) ==
           "AT+MHTTPCFG=\"timeout\",7,2");
    assert(idf_modem_https_timeout_command(7, IDF_MODEM_HTTPS_POST_MAX_TIMEOUT_MS) ==
           "AT+MHTTPCFG=\"timeout\",7,90");

    const std::pair<OwnerTransportFixture::FailureStage, const char*> tls_failures[] = {
        {OwnerTransportFixture::FailureStage::auth, "HTTPS TLS auth failed"},
        {OwnerTransportFixture::FailureStage::cert_bind, "HTTPS TLS certificate binding failed"},
        {OwnerTransportFixture::FailureStage::encoding, "HTTPS TLS encoding failed"},
        {OwnerTransportFixture::FailureStage::negotime, "HTTPS TLS negotiation timeout failed"},
        {OwnerTransportFixture::FailureStage::version, "HTTPS TLS version failed"},
        {OwnerTransportFixture::FailureStage::ignorestamp, "HTTPS TLS timestamp check failed"},
        {OwnerTransportFixture::FailureStage::ignoreverify, "HTTPS TLS certificate verification failed"},
        {OwnerTransportFixture::FailureStage::create, "HTTPS connection creation failed"},
        {OwnerTransportFixture::FailureStage::timeout, "HTTPS HTTP timeout configuration failed"},
        {OwnerTransportFixture::FailureStage::ssl, "HTTPS SSL binding failed"},
    };
    for (const auto& failure : tls_failures) {
        OwnerTransportFixture failed_tls;
        failed_tls.fail_stage = failure.first;
        assert(!failed_tls.run(request, "ML307A", 1, cert_response));
        assert(failed_tls.last_result.message == failure.second);
        assert(failed_tls.writes.back() == "AT+CGACT=0,1");
    }

    OwnerTransportFixture cleanup_failure;
    cleanup_failure.cleanup_ok = false;
    assert(!cleanup_failure.run(request, "ML307A", 1, cert_response));
    assert(cleanup_failure.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture expired;
    expired.request_expired = true;
    assert(!expired.run(request, "ML307A", 1, cert_response));
    assert(expired.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture cleanup_timeout;
    cleanup_timeout.request_expired = true;
    cleanup_timeout.first_cleanup_timeout = true;
    assert(!cleanup_timeout.run(request, "ML307A", 1, cert_response));
    assert(cleanup_timeout.writes[cleanup_timeout.writes.size() - 3] == "AT+MHTTPTERM=7");
    assert(cleanup_timeout.writes[cleanup_timeout.writes.size() - 2] == "AT+MHTTPDEL=7");
    assert(cleanup_timeout.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture second_cleanup_timeout;
    second_cleanup_timeout.request_expired = true;
    second_cleanup_timeout.second_cleanup_timeout = true;
    assert(!second_cleanup_timeout.run(request, "ML307A", 1, cert_response));
    assert(second_cleanup_timeout.writes[second_cleanup_timeout.writes.size() - 3] ==
           "AT+MHTTPTERM=7");
    assert(second_cleanup_timeout.writes[second_cleanup_timeout.writes.size() - 2] ==
           "AT+MHTTPDEL=7");
    assert(second_cleanup_timeout.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture stale_error;
    stale_error.stale_failure = OwnerTransportFixture::StaleFailure::modem_error;
    assert(stale_error.run(request, "ML307A", 1, cert_response));
    assert(stale_error.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture stale_transport;
    stale_transport.stale_failure = OwnerTransportFixture::StaleFailure::transport_failure;
    assert(!stale_transport.run(request, "ML307A", 1, cert_response));
    assert(stale_transport.writes.back() == "AT+CGACT=0,1");
    assert(std::find(stale_transport.writes.begin(), stale_transport.writes.end(),
                     "AT+MHTTPCREATE=\"https://push.example.test\"") ==
           stale_transport.writes.end());

    OwnerTransportFixture short_setup;
    short_setup.short_setup_write = true;
    assert(!short_setup.run(request, "ML307A", 1, cert_response));
    assert(short_setup.writes.back() == "AT+CGACT=0,1");
    assert(std::find(short_setup.writes.begin(), short_setup.writes.end(),
                     "AT+MHTTPCFG=\"ssl\",7,1,1") != short_setup.writes.end());
    assert(!short_setup.prompt_seen);
    assert(std::find(short_setup.writes.begin(), short_setup.writes.end(),
                     "AT+MHTTPREQUEST=7,2,0,2F6170692F6E6F746966793F736F757263653D736D73") ==
           short_setup.writes.end());

    OwnerTransportFixture no_certificate;
    assert(!no_certificate.run(request, "ML307A", 1, "OK\r\n"));
    assert(no_certificate.writes.back() == "AT+CGACT=0,1");
    assert(std::find(no_certificate.writes.begin(), no_certificate.writes.end(),
                     "AT+MHTTPCREATE=\"https://push.example.test\"") ==
           no_certificate.writes.end());

    OwnerTransportFixture non_2xx;
    non_2xx.non_2xx_response = true;
    assert(!non_2xx.run(request, "ML307A", 1, cert_response));
    assert(non_2xx.writes.back() == "AT+CGACT=0,1");

    for (const std::string_view model : {std::string_view(), std::string_view("ML307Y"),
                                         std::string_view("unknown")}) {
        OwnerTransportFixture blocked;
        assert(!blocked.run(request, model, 1, cert_response));
        assert(blocked.writes.empty());
    }
    for (const int stat : {0, 5, 11, -1}) {
        OwnerTransportFixture blocked;
        assert(!blocked.run(request, "ML307A", stat, cert_response));
        assert(blocked.writes.empty());
    }
    OwnerTransportFixture abandoned;
    abandoned.abandoned = true;
    assert(!abandoned.run(request, "ML307A", 1, cert_response));
    assert(abandoned.writes.empty());

    IdfModemHttpsPostRequest oversized = request;
    std::string error;
    oversized.body.assign(IDF_MODEM_HTTPS_POST_MAX_BODY + 1, 'x');
    assert(!idf_modem_https_validate_request(oversized, error));
    oversized = request;
    oversized.url.assign(IDF_MODEM_HTTPS_POST_MAX_URL + 1, 'x');
    assert(!idf_modem_https_validate_request(oversized, error));
    oversized = request;
    oversized.headerValue.assign(IDF_MODEM_HTTPS_POST_MAX_HEADER_VALUE + 1, 'x');
    assert(!idf_modem_https_validate_request(oversized, error));

    feed_fragmented_success();
    return 0;
}
