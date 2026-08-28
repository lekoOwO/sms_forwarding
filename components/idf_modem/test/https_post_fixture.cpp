#include "idf_modem_https.h"
#include "idf_modem_query_filter.h"
#include "idf_modem_registration.h"

#include <algorithm>
#include <cassert>
#include <fstream>
#include <iterator>
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
    request.rootCertificateDer = {'D', 'E', 'R'};
    request.rootCertificateSha256.fill(0xab);
    return request;
}

static const std::string certificate_name =
    "ca_abababababababababababababababababababababababababababab.pem";
static const std::string certificate_pem =
    "-----BEGIN CERTIFICATE-----\nREVS\n-----END CERTIFICATE-----\n";
static constexpr int64_t fixture_epoch = 1704067200;
static const std::string clock_set_command =
    "AT+CCLK=\"24/01/01,00:00:00+00\"";
static constexpr std::string_view clock_error =
    "HTTPS modem clock synchronization failed";
static_assert(3 + 56 + 4 <= IDF_MODEM_HTTPS_CERT_NAME_MAX);

struct OwnerTransportFixture {
    enum class StaleFailure { none, modem_error, transport_failure };
    enum class FailureStage {
        none,
        cert_list,
        cert_write,
        cert_prompt,
        cert_read,
        clock_set,
        clock_set_timeout,
        clock_readback,
        clock_readback_timeout,
        auth,
        cert_bind,
        encoding,
        negotime,
        version,
        ignorestamp,
        ignoreverify,
        ciphersuite,
        session,
        create,
        timeout,
        ssl,
    };

    std::vector<std::string> writes;
    std::string raw_body;
    std::string raw_certificate;
    bool body_prompt_seen = false;
    bool cert_prompt_seen = false;
    bool cert_present = true;
    bool cert_length_mismatch = false;
    bool cert_readback_mismatch = false;
    bool cleanup_ok = true;
    bool abandoned = false;
    bool request_expired = false;
    bool omit_clock_callback = false;
    int64_t epoch = fixture_epoch;
    std::string clock_readback = "+CCLK: \"24/01/01,00:00:00+00\"\r\nOK\r\n";
    bool clock_set_seen = false;
    bool first_cleanup_timeout = false;
    bool second_cleanup_timeout = false;
    StaleFailure stale_failure = StaleFailure::none;
    bool short_setup_write = false;
    bool non_2xx_response = false;
    std::string pinned_certificate;
    FailureStage fail_stage = FailureStage::none;
    IdfModemHttpsRunResult last_run_result = IdfModemHttpsRunResult::invalid_request;
    IdfModemHttpsPostResult last_result;

    static IdfModemHttpsCommandResult send_command(
        void* context, std::string_view command, std::string& response,
        std::string_view raw_payload, bool cleanup, bool tolerate_modem_error);
    static IdfModemHttpsCommandResult wait_response(
        void* context, uint8_t http_id, IdfModemHttpsPostResult& result);
    static int64_t current_epoch(void* context);

    bool run(const IdfModemHttpsPostRequest& request, std::string_view model,
             int cereg_stat)
    {
        if (abandoned || !idf_modem_https_model_allowed(model) ||
            !idf_modem_data_activation_allowed(cereg_stat)) {
            return false;
        }
        pinned_certificate = certificate_pem;
        const IdfModemHttpsGetEpoch clock = omit_clock_callback ? nullptr : &current_epoch;
        IdfModemHttpsCallbacks callbacks{this, &send_command, &wait_response, clock};
        IdfModemHttpsPostResult result;
        last_run_result = idf_modem_https_run_post(request, callbacks, result);
        const bool ok = last_run_result == IdfModemHttpsRunResult::ok;
        last_result = result;
        return ok;
    }
};

int64_t OwnerTransportFixture::current_epoch(void* context)
{
    return static_cast<OwnerTransportFixture*>(context)->epoch;
}

IdfModemHttpsCommandResult OwnerTransportFixture::send_command(
    void* context, std::string_view command, std::string& response,
    std::string_view raw_payload, bool cleanup, bool tolerate_modem_error)
{
    auto& fixture = *static_cast<OwnerTransportFixture*>(context);
    response.clear();
    fixture.writes.emplace_back(command);
    if (command.rfind("AT+MHTTPCONTENT=", 0) == 0) {
        fixture.body_prompt_seen = true;
        fixture.raw_body.assign(raw_payload.data(), raw_payload.size());
    }
    const std::string cert_write =
        "AT+MSSLCERTWR=\"" + certificate_name +
        "\",0," + std::to_string(fixture.pinned_certificate.size());
    if (command == cert_write) {
        fixture.cert_prompt_seen = true;
        fixture.raw_certificate.assign(raw_payload.data(), raw_payload.size());
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
    if (fail(OwnerTransportFixture::FailureStage::cert_list) &&
        command == "AT+MSSLLIST=1") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::cert_write) &&
        command == cert_write) return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::cert_prompt) &&
        command == cert_write) return IdfModemHttpsCommandResult::timeout;
    if (fail(OwnerTransportFixture::FailureStage::cert_read) &&
        command == "AT+MSSLCERTRD=\"" + certificate_name + "\"") {
        return IdfModemHttpsCommandResult::failed;
    }
    if (command.rfind("AT+CCLK=\"", 0) == 0) {
        fixture.clock_set_seen = true;
        if (fail(OwnerTransportFixture::FailureStage::clock_set)) {
            return IdfModemHttpsCommandResult::failed;
        }
        if (fail(OwnerTransportFixture::FailureStage::clock_set_timeout)) {
            return IdfModemHttpsCommandResult::timeout;
        }
        response = "OK\r\n";
    }
    if (command == "AT+CCLK?") {
        if (fail(OwnerTransportFixture::FailureStage::clock_readback)) {
            return IdfModemHttpsCommandResult::failed;
        }
        if (fail(OwnerTransportFixture::FailureStage::clock_readback_timeout)) {
            return IdfModemHttpsCommandResult::timeout;
        }
        response = fixture.clock_readback;
    }
    if (fail(OwnerTransportFixture::FailureStage::auth) &&
        command == "AT+MSSLCFG=\"auth\",1,1") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::cert_bind) &&
        command == idf_modem_https_cert_bind_command(certificate_name)) {
        return IdfModemHttpsCommandResult::failed;
    }
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
    if (fail(OwnerTransportFixture::FailureStage::ciphersuite) &&
        command == "AT+MSSLCFG=\"ciphersuite\",1,0") return IdfModemHttpsCommandResult::failed;
    if (fail(OwnerTransportFixture::FailureStage::session) &&
        command == "AT+MSSLCFG=\"session\",1,0") return IdfModemHttpsCommandResult::failed;
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
    if (command == "AT+MSSLLIST=1") {
        if (fixture.cert_present) {
            const size_t listed_length = fixture.pinned_certificate.size() +
                                         (fixture.cert_length_mismatch ? 1U : 0U);
            response = "+MSSLLIST: \"" + certificate_name +
                       "\"," + std::to_string(listed_length) + "\r\nOK\r\n";
        } else {
            response = "OK\r\n";
        }
    }
    if (command == "AT+MSSLCERTRD=\"" + certificate_name + "\"") {
        std::string readback = fixture.pinned_certificate;
        if (fixture.cert_readback_mismatch && !readback.empty()) readback[0] ^= 1;
        response = "+MSSLCERTRD: " + std::to_string(readback.size()) + "," + readback +
                   "\r\nOK\r\n";
    }
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
             std::string_view("+MHTTPURC: \"header\",7,200,19,X-Test: forward\r\n\r\n"),
             std::string_view("+MHTTPURC: \"content\",7,5,5,5,hello"),
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
        clock_set_command,
        "AT+CCLK?",
        "AT+MSSLLIST=1",
        "AT+MSSLCERTRD=\"" + certificate_name + "\"",
        "AT+CGDCONT=1,\"IP\",\"internet\"",
        "AT+CGACT=1,1",
        "AT+MHTTPDEL=0",
        "AT+MHTTPDEL=1",
        "AT+MHTTPDEL=2",
        "AT+MHTTPDEL=3",
        "AT+MSSLCFG=\"cert\",1,\"" + certificate_name + "\"",
        "AT+MSSLCFG=\"auth\",1,1",
        "AT+MSSLCFG=\"encoding\",1,2",
        "AT+MSSLCFG=\"negotime\",1,60",
        "AT+MSSLCFG=\"version\",1,3",
        "AT+MSSLCFG=\"ignorestamp\",1,0",
        "AT+MSSLCFG=\"ignoreverify\",1,0",
        "AT+MSSLCFG=\"ciphersuite\",1,0",
        "AT+MSSLCFG=\"session\",1,0",
        "AT+MHTTPCREATE=\"https://push.example.test\"",
        "AT+MHTTPCFG=\"ssl\",7,1,1",
        "AT+MHTTPCFG=\"timeout\",7,30",
        "AT+MHTTPHEADER=7,1,30,\"Content-Type: application/json\"",
        "AT+MHTTPHEADER=7,0,19,\"X-Device: forwarder\"",
        "AT+MHTTPCONTENT=7,0,22",
        "AT+MHTTPREQUEST=7,2,0,\"/api/notify?source=sms\"",
        "AT+MHTTPTERM=7",
        "AT+MHTTPDEL=7",
        "AT+CGACT=0,1",
    };
}

static void assert_no_network_or_secret_wire(const OwnerTransportFixture& fixture)
{
    for (const std::string& write : fixture.writes) {
        assert(write.rfind("AT+CGACT", 0) != 0);
        assert(write.rfind("AT+MHTTP", 0) != 0);
        assert(write.find("forwarder") == std::string::npos);
    }
}

static void feed_fragmented_success()
{
    IdfModemHttpsUrcParser parser(7);
    const std::string wire =
        "+MHTTPURC: \"header\",7,200,19,X-Test: forward\r\n\r\n"
        "+CMT: \"+886900000\",145\r\n00112233445566778899AABBCCDDEEFF\r\n"
        "RING\r\n+CLIP: \"+886911111\",145\r\n+CEREG: 1,1\r\n"
        "+MHTTPURC: \"content\",7,5,2,2,he"
        "+MHTTPURC: \"content\",7,5,5,3,llo";
    for (size_t offset = 0, fragment = 1; offset < wire.size(); fragment = fragment % 3 + 1) {
        const size_t count = std::min(fragment, wire.size() - offset);
        parser.feed(std::string_view(wire).substr(offset, count));
        offset += count;
    }
    assert(parser.complete());
    assert(!parser.failed());
    assert(parser.result().httpStatus == 200);
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
    non_2xx.feed("+MHTTPURC: \"header\",7,503,0,");
    non_2xx.feed("+MHTTPURC: \"content\",7,0,0,0,");
    assert(non_2xx.complete());
    assert(!idf_modem_https_status_success(non_2xx.result().httpStatus));

    IdfModemHttpsUrcParser timeout(7);
    assert(!timeout.complete());
}

static void filter_interleaved_clock_response()
{
    IdfModemQueryResponseFilter filter("AT+CCLK?", "+CCLK:", "", false);
    const std::string input =
        "+CEREG: 1,1\r\n+CMT: \"+886900000\",145\r\n"
        "00112233445566778899AABBCCDDEEFF\r\n"
        "+CCLK: \"24/01/01,00:00:00+00\"\r\n"
        "+CCLK: \"24/01/01,00:00:01+00\"\r\nOK\r\n";
    filter.feed(input.data(), input.size());
    filter.flush_pending();
    assert(filter.response() ==
           "+CCLK: \"24/01/01,00:00:00+00\"\r\n"
           "+CCLK: \"24/01/01,00:00:01+00\"\r\nOK\r\n");
    assert(filter.urcs().find("+CEREG:") != std::string::npos);
    assert(filter.urcs().find("+CMT:") != std::string::npos);
    assert(filter.urcs().find("00112233445566778899AABBCCDDEEFF") != std::string::npos);
}

int main()
{
    const IdfModemHttpsPostRequest request = request_fixture();
    assert(certificate_name.rfind("ca_", 0) == 0);
    assert(certificate_name.size() == 63);

    OwnerTransportFixture owner;
    assert(owner.run(request, "ML307A", 1));
    assert(owner.writes == expected_writes());
    assert(std::count(owner.writes.begin(), owner.writes.end(),
                      "AT+MSSLCFG=\"ciphersuite\",1,0") == 1);
    assert(std::count(owner.writes.begin(), owner.writes.end(),
                      "AT+MSSLCFG=\"session\",1,0") == 1);
    assert(!owner.cert_prompt_seen);
    assert(owner.body_prompt_seen);
    assert(owner.raw_body == request.body);
    assert(owner.raw_body.find('\x1a') == std::string::npos);
    assert(owner.clock_set_seen);
    assert(idf_modem_https_content_command(7, IDF_MODEM_HTTPS_POST_MAX_BODY) ==
           "AT+MHTTPCONTENT=7,0,4096");

    IdfModemHttpsPostRequest missing_root = request;
    missing_root.rootCertificateDer.clear();
    OwnerTransportFixture no_root;
    assert(!no_root.run(missing_root, "ML307A", 1));
    assert(no_root.writes.empty());
    assert(!no_root.body_prompt_seen);

    IdfModemHttpsPostRequest empty_body = request;
    empty_body.body.clear();
    OwnerTransportFixture empty;
    assert(!empty.run(empty_body, "ML307A", 1));
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
        {OwnerTransportFixture::FailureStage::ciphersuite, "HTTPS TLS cipher suite failed"},
        {OwnerTransportFixture::FailureStage::session, "HTTPS TLS session reset failed"},
        {OwnerTransportFixture::FailureStage::create, "HTTPS connection creation failed"},
        {OwnerTransportFixture::FailureStage::timeout, "HTTPS HTTP timeout configuration failed"},
        {OwnerTransportFixture::FailureStage::ssl, "HTTPS SSL binding failed"},
    };
    for (const auto& failure : tls_failures) {
        OwnerTransportFixture failed_tls;
        failed_tls.fail_stage = failure.first;
        assert(!failed_tls.run(request, "ML307A", 1));
        assert(failed_tls.last_result.message == failure.second);
        assert(failed_tls.writes.back() == "AT+CGACT=0,1");
    }

    OwnerTransportFixture cleanup_failure;
    cleanup_failure.cleanup_ok = false;
    assert(!cleanup_failure.run(request, "ML307A", 1));
    assert(cleanup_failure.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture expired;
    expired.request_expired = true;
    assert(!expired.run(request, "ML307A", 1));
    assert(expired.writes.back() == "AT+CGACT=0,1");

    for (const int64_t invalid_epoch : {int64_t(-1), int64_t(0), int64_t(2145916800)}) {
        OwnerTransportFixture invalid_time;
        invalid_time.epoch = invalid_epoch;
        assert(!invalid_time.run(request, "ML307A", 1));
        assert(invalid_time.writes.empty());
        assert(invalid_time.last_result.message == clock_error);
    }

    for (const std::string_view invalid_readback : {
             std::string_view("+CCLK: \"24/01/02,00:00:00+00\"\r\nOK\r\n"),
             std::string_view("+CCLK: \"24/01/01,00:00:00+08\"\r\nOK\r\n"),
             std::string_view("+CCLK: \"24/01/01,00:00:00+00\"\r\n"),
             std::string_view("+CCLK: \"24/01/01,00:00:00+00\"\r\n"
                              "+CCLK: \"24/01/01,00:00:01+00\"\r\nOK\r\n"),
             std::string_view("+CCLK: \"24/02/30,00:00:00+00\"\r\nOK\r\n"),
         }) {
        OwnerTransportFixture invalid_clock;
        invalid_clock.clock_readback = invalid_readback;
        assert(!invalid_clock.run(request, "ML307A", 1));
        assert(invalid_clock.writes ==
               std::vector<std::string>({clock_set_command, "AT+CCLK?"}));
        assert(invalid_clock.last_result.message == clock_error);
    }

    OwnerTransportFixture clock_set_failure;
    clock_set_failure.fail_stage = OwnerTransportFixture::FailureStage::clock_set;
    assert(!clock_set_failure.run(request, "ML307A", 1));
    assert(clock_set_failure.writes == std::vector<std::string>({clock_set_command}));
    assert(clock_set_failure.last_run_result == IdfModemHttpsRunResult::command_failed);
    assert(clock_set_failure.last_result.message == clock_error);

    OwnerTransportFixture clock_set_timeout;
    clock_set_timeout.fail_stage = OwnerTransportFixture::FailureStage::clock_set_timeout;
    assert(!clock_set_timeout.run(request, "ML307A", 1));
    assert(clock_set_timeout.writes == std::vector<std::string>({clock_set_command}));
    assert(clock_set_timeout.last_run_result == IdfModemHttpsRunResult::timed_out);
    assert(clock_set_timeout.last_result.message == clock_error);

    OwnerTransportFixture clock_readback_failure;
    clock_readback_failure.fail_stage = OwnerTransportFixture::FailureStage::clock_readback;
    assert(!clock_readback_failure.run(request, "ML307A", 1));
    assert(clock_readback_failure.writes ==
           std::vector<std::string>({clock_set_command, "AT+CCLK?"}));
    assert(clock_readback_failure.last_run_result == IdfModemHttpsRunResult::command_failed);
    assert(clock_readback_failure.last_result.message == clock_error);

    OwnerTransportFixture clock_readback_timeout;
    clock_readback_timeout.fail_stage = OwnerTransportFixture::FailureStage::clock_readback_timeout;
    assert(!clock_readback_timeout.run(request, "ML307A", 1));
    assert(clock_readback_timeout.writes ==
           std::vector<std::string>({clock_set_command, "AT+CCLK?"}));
    assert(clock_readback_timeout.last_run_result == IdfModemHttpsRunResult::timed_out);
    assert(clock_readback_timeout.last_result.message == clock_error);

    for (const std::string_view drift : {
             std::string_view("+CCLK: \"23/12/31,23:59:55+00\"\r\nOK\r\n"),
             std::string_view("+CCLK: \"24/01/01,00:00:05+00\"\r\nOK\r\n"),
         }) {
        OwnerTransportFixture accepted_drift;
        accepted_drift.clock_readback = drift;
        assert(accepted_drift.run(request, "ML307A", 1));
    }
    OwnerTransportFixture rejected_drift;
    rejected_drift.clock_readback = "+CCLK: \"24/01/01,00:00:06+00\"\r\nOK\r\n";
    assert(!rejected_drift.run(request, "ML307A", 1));
    assert(rejected_drift.writes ==
           std::vector<std::string>({clock_set_command, "AT+CCLK?"}));
    assert(rejected_drift.last_result.message == clock_error);

    OwnerTransportFixture last_cclk_second;
    last_cclk_second.epoch = 2145916799;
    last_cclk_second.clock_readback = "+CCLK: \"37/12/31,23:59:59+00\"\r\nOK\r\n";
    assert(last_cclk_second.run(request, "ML307A", 1));
    assert(last_cclk_second.writes[0] == "AT+CCLK=\"37/12/31,23:59:59+00\"");

    OwnerTransportFixture null_clock;
    null_clock.omit_clock_callback = true;
    assert(!null_clock.run(request, "ML307A", 1));
    assert(null_clock.writes.empty());
    assert(null_clock.last_run_result == IdfModemHttpsRunResult::invalid_request);

    OwnerTransportFixture cleanup_timeout;
    cleanup_timeout.request_expired = true;
    cleanup_timeout.first_cleanup_timeout = true;
    assert(!cleanup_timeout.run(request, "ML307A", 1));
    assert(cleanup_timeout.writes[cleanup_timeout.writes.size() - 3] == "AT+MHTTPTERM=7");
    assert(cleanup_timeout.writes[cleanup_timeout.writes.size() - 2] == "AT+MHTTPDEL=7");
    assert(cleanup_timeout.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture second_cleanup_timeout;
    second_cleanup_timeout.request_expired = true;
    second_cleanup_timeout.second_cleanup_timeout = true;
    assert(!second_cleanup_timeout.run(request, "ML307A", 1));
    assert(second_cleanup_timeout.writes[second_cleanup_timeout.writes.size() - 3] ==
           "AT+MHTTPTERM=7");
    assert(second_cleanup_timeout.writes[second_cleanup_timeout.writes.size() - 2] ==
           "AT+MHTTPDEL=7");
    assert(second_cleanup_timeout.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture stale_error;
    stale_error.stale_failure = OwnerTransportFixture::StaleFailure::modem_error;
    assert(stale_error.run(request, "ML307A", 1));
    assert(stale_error.writes.back() == "AT+CGACT=0,1");

    OwnerTransportFixture stale_transport;
    stale_transport.stale_failure = OwnerTransportFixture::StaleFailure::transport_failure;
    assert(!stale_transport.run(request, "ML307A", 1));
    assert(stale_transport.writes.back() == "AT+CGACT=0,1");
    assert(std::find(stale_transport.writes.begin(), stale_transport.writes.end(),
                     "AT+MHTTPCREATE=\"https://push.example.test\"") ==
           stale_transport.writes.end());

    OwnerTransportFixture short_setup;
    short_setup.short_setup_write = true;
    assert(!short_setup.run(request, "ML307A", 1));
    assert(short_setup.writes.back() == "AT+CGACT=0,1");
    assert(std::find(short_setup.writes.begin(), short_setup.writes.end(),
                     "AT+MHTTPCFG=\"ssl\",7,1,1") != short_setup.writes.end());
    assert(!short_setup.body_prompt_seen);
    assert(std::find(short_setup.writes.begin(), short_setup.writes.end(),
                     "AT+MHTTPREQUEST=7,2,0,\"/api/notify?source=sms\"") ==
           short_setup.writes.end());

    OwnerTransportFixture no_certificate;
    no_certificate.cert_present = false;
    assert(no_certificate.run(request, "ML307A", 1));
    assert(no_certificate.writes[2] == "AT+MSSLLIST=1");
    assert(no_certificate.writes[3] ==
           "AT+MSSLCERTWR=\"" + certificate_name + "\",0," +
               std::to_string(certificate_pem.size()));
    assert(no_certificate.writes[4] ==
           "AT+MSSLCERTRD=\"" + certificate_name + "\"");
    assert(no_certificate.cert_prompt_seen);
    assert(no_certificate.raw_certificate == certificate_pem);
    assert(no_certificate.raw_certificate.find('\x1a') == std::string::npos);

    for (const auto failure : {OwnerTransportFixture::FailureStage::cert_list,
                               OwnerTransportFixture::FailureStage::cert_write,
                               OwnerTransportFixture::FailureStage::cert_prompt,
                               OwnerTransportFixture::FailureStage::cert_read}) {
        OwnerTransportFixture failed_certificate;
        failed_certificate.cert_present =
            failure != OwnerTransportFixture::FailureStage::cert_write &&
            failure != OwnerTransportFixture::FailureStage::cert_prompt;
        failed_certificate.fail_stage = failure;
        assert(!failed_certificate.run(request, "ML307A", 1));
        assert(failed_certificate.last_run_result ==
               (failure == OwnerTransportFixture::FailureStage::cert_prompt
                    ? IdfModemHttpsRunResult::timed_out
                    : IdfModemHttpsRunResult::command_failed));
        assert_no_network_or_secret_wire(failed_certificate);
    }
    OwnerTransportFixture listed_mismatch;
    listed_mismatch.cert_length_mismatch = true;
    assert(!listed_mismatch.run(request, "ML307A", 1));
    assert_no_network_or_secret_wire(listed_mismatch);
    assert(!listed_mismatch.cert_prompt_seen);

    OwnerTransportFixture readback_mismatch;
    readback_mismatch.cert_readback_mismatch = true;
    assert(!readback_mismatch.run(request, "ML307A", 1));
    assert_no_network_or_secret_wire(readback_mismatch);

    OwnerTransportFixture non_2xx;
    non_2xx.non_2xx_response = true;
    assert(!non_2xx.run(request, "ML307A", 1));
    assert(non_2xx.writes.back() == "AT+CGACT=0,1");

    for (const std::string_view model : {std::string_view(), std::string_view("ML307Y"),
                                         std::string_view("unknown")}) {
        OwnerTransportFixture blocked;
        assert(!blocked.run(request, model, 1));
        assert(blocked.writes.empty());
    }
    for (const int stat : {0, 5, 11, -1}) {
        OwnerTransportFixture blocked;
        assert(!blocked.run(request, "ML307A", stat));
        assert(blocked.writes.empty());
    }
    OwnerTransportFixture abandoned;
    abandoned.abandoned = true;
    assert(!abandoned.run(request, "ML307A", 1));
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
    oversized = request;
    oversized.url = "https://push.example.test/\xE9\x80\x9A\xE7\x9F\xA5";
    assert(!idf_modem_https_validate_request(oversized, error));

    feed_fragmented_success();
    filter_interleaved_clock_response();
    return 0;
}
