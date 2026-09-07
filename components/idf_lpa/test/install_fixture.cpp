#include "idf_lpa_install.h"
#include "idf_lpa_es9_transport.h"
#include "idf_esim_lpa.h"
#include "idf_esim_codec.h"

#include <algorithm>
#include <array>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <new>
#include <string>
#include <vector>

using Bytes = std::vector<uint8_t>;
static constexpr char kActivation[] = "LPA:1$edge.example$ABC-012";
static constexpr char kHost[] = "edge.example";
static int64_t now_us = 1000000;
int64_t esp_timer_get_time() { return now_us; }

static void* confirmation_storage = nullptr;
static size_t confirmation_capacity = 0;
static bool confirmation_wiped = false;

void* operator new(size_t size)
{
    void* storage = std::malloc(size);
    if (!storage) std::abort();
    return storage;
}

void operator delete(void* storage) noexcept
{
    if (storage && storage == confirmation_storage) {
        const auto* bytes = static_cast<const unsigned char*>(storage);
        for (size_t index = 0; index < confirmation_capacity; ++index) assert(bytes[index] == 0);
        confirmation_storage = nullptr;
        confirmation_wiped = true;
    }
    std::free(storage);
}

void operator delete(void* storage, size_t) noexcept { operator delete(storage); }

static Bytes join(std::initializer_list<Bytes> parts)
{
    Bytes out;
    for (const auto& part : parts) out.insert(out.end(), part.begin(), part.end());
    return out;
}

static Bytes tlv(std::initializer_list<uint8_t> tag, const Bytes& value)
{
    Bytes out(tag);
    if (value.size() < 128U) out.push_back(static_cast<uint8_t>(value.size()));
    else if (value.size() < 256U) {
        out.push_back(0x81);
        out.push_back(static_cast<uint8_t>(value.size()));
    } else {
        out.push_back(0x82);
        out.push_back(static_cast<uint8_t>(value.size() >> 8));
        out.push_back(static_cast<uint8_t>(value.size()));
    }
    out.insert(out.end(), value.begin(), value.end());
    return out;
}

static Bytes text_bytes(std::string_view value) { return Bytes(value.begin(), value.end()); }
static Bytes seq(std::initializer_list<Bytes> fields) { return tlv({0x30}, join(fields)); }
static const Bytes kTransaction = {0x01, 0x02};
static const Bytes kChallenge(16, 0x11);
static const Bytes kServerChallenge(16, 0x22);
static const Bytes kCertificate = seq({tlv({0x02}, {0x01})});
static const Bytes kSignature = tlv({0x5F, 0x37}, {0xAA, 0xBB});

static std::string base64(const Bytes& value)
{
    std::string out;
    LpaRspError error;
    assert(idf_lpa_rsp_base64_encode(value.data(), value.size(), out, error));
    return out;
}

static Bytes pir(const Bytes& transaction, uint8_t number = 1,
                 std::string_view host = kHost, bool installed = true)
{
    const Bytes metadata = tlv({0xBF, 0x2F}, join({
        tlv({0x80}, {number}), tlv({0x81}, {0x07, 0x80}),
        tlv({0x0C}, text_bytes(host)),
        tlv({0x5A}, {0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0xF4})}));
    const Bytes result = installed ? tlv({0xA0}, join({
        tlv({0x4F}, {1, 2, 3, 4, 5}), tlv({0x04}, {0x90, 0x00})})) :
        tlv({0xA1}, join({tlv({0x02}, {0x05}), tlv({0x02}, {0x01})}));
    return tlv({0xBF, 0x37}, join({tlv({0xBF, 0x27}, join({
        tlv({0x80}, transaction), metadata, tlv({0x06}, {0x2B, 6, 1, 4, 1}),
        tlv({0xA2}, result)})), kSignature}));
}

struct Fixture {
    bool require_cc = false;
    bool bad_challenge = false;
    bool wrong_client_transaction = false;
    bool download_failure = false;
    bool notification_failure = false;
    bool removal_failure = false;
    bool rejected_install = false;
    bool wrong_pir_transaction = false;
    bool card_failure = false;
    bool policy_rules = false;
    bool consent_accepted = true;
    bool cancel_card_failure = false;
    bool cancel_http_failure = false;
    bool wrong_cancel_transaction = false;
    bool callback_late = false;
    bool observe_confirmation_wipe = false;
    esp_err_t callback_error = ESP_OK;
    std::string code = "654321";
    Bytes pending;
    Bytes auth_response;
    Bytes prepare_response;
    Bytes cancel_response;
    std::vector<std::string> events;
    std::vector<IdfLpaInstallStage> stages;
    std::vector<uint32_t> removed;
    int confirmations = 0;
    int downloads = 0;
    int notifications = 0;
    std::vector<uint8_t> cancellations;
} g;

static std::string field(std::string_view json, const char* key)
{
    std::string out;
    LpaRspError error;
    assert(idf_lpa_rsp_json_get_string(json, key, out, error));
    return out;
}

static Bytes binary_field(std::string_view json, const char* key)
{
    Bytes out;
    LpaRspError error;
    assert(idf_lpa_rsp_base64_decode(field(json, key), out, error));
    return out;
}

esp_err_t idf_modem_get_imei(std::string& out, uint32_t timeout_ms)
{
    assert(timeout_ms > 0 && timeout_ms <= 5000);
    g.events.push_back("imei");
    out = "860000000000001";
    return ESP_OK;
}

esp_err_t idf_esim_lpa_retrieve_notifications(Bytes& out, size_t& offset,
                                             size_t& length, std::string&)
{
    g.events.push_back("pending");
    out = tlv({0xBF, 0x2B}, tlv({0xA0}, g.pending));
    size_t pos = 0;
    idf_esim_internal::TlvSpan outer, list;
    std::string message;
    assert(idf_esim_internal::parse_tlv_span(out, out.size(), pos, outer, message));
    pos = outer.valueOffset;
    assert(idf_esim_internal::parse_tlv_span(out, out.size(), pos, list, message));
    offset = list.valueOffset;
    length = list.valueLength;
    return ESP_OK;
}

esp_err_t idf_esim_lpa_get_auth_material(Bytes& info, std::array<uint8_t, 16>& challenge,
                                        std::string& message)
{
    g.events.push_back("material");
    if (g.card_failure) { message = "private card detail"; return ESP_FAIL; }
    info = tlv({0xBF, 0x20}, tlv({0x82}, {2, 2, 0}));
    std::copy(kChallenge.begin(), kChallenge.end(), challenge.begin());
    return ESP_OK;
}

esp_err_t idf_esim_lpa_authenticate_server(const Bytes& request, Bytes& out, std::string&)
{
    g.events.push_back("authenticate_card");
    size_t pos = 0;
    idf_esim_internal::TlvSpan root, child;
    std::string message;
    assert(idf_esim_internal::parse_tlv_span(request, request.size(), pos, root, message));
    pos = root.valueOffset;
    for (size_t index = 0; index < 5; ++index)
        assert(idf_esim_internal::parse_tlv_span(request, request.size(), pos, child, message));
    assert(pos == request.size());
    const Bytes context(request.begin() + child.offset, request.end());
    const Bytes signed1 = seq({tlv({0x80}, kTransaction), tlv({0x83}, text_bytes(kHost)),
        tlv({0x84}, kServerChallenge), tlv({0xBF, 0x22}, tlv({0x82}, {2, 2, 0})), context});
    out = tlv({0xBF, 0x38}, tlv({0xA0}, join({signed1, kSignature,
                                            kCertificate, kCertificate})));
    g.auth_response = out;
    return ESP_OK;
}

esp_err_t idf_esim_lpa_prepare_download(const Bytes& request, Bytes& out, std::string&)
{
    g.events.push_back("prepare_card");
    idf_esim_internal::Tlv root;
    std::string message;
    assert(idf_esim_internal::parse_tlv(request, root, message));
    assert(root.children.size() == (g.require_cc ? 4U : 3U));
    if (g.require_cc && g.code == "654321") {
        const Bytes expected_hash = {0xEF, 0x01, 0x2A, 0x3C, 0xA6, 0xD3, 0x7A, 0x38,
            0xDC, 0xA7, 0x7D, 0x91, 0x2C, 0x6A, 0x93, 0xAA, 0xCF, 0x81, 0x32, 0xFA,
            0x5D, 0xAA, 0x40, 0x40, 0x15, 0x9E, 0xEA, 0x68, 0xD1, 0xD1, 0xA0, 0xB5};
        assert(root.children[2].tag == Bytes{0x04} && root.children[2].value == expected_hash);
    }
    out = tlv({0xBF, 0x21}, tlv({0xA0}, join({seq({
        tlv({0x80}, kTransaction), tlv({0x5F, 0x49}, {1, 2, 3})}), kSignature})));
    g.prepare_response = out;
    return ESP_OK;
}

esp_err_t idf_esim_lpa_remove_notification(uint32_t number, std::string&)
{
    g.events.push_back("remove");
    g.removed.push_back(number);
    return g.removal_failure ? ESP_FAIL : ESP_OK;
}

esp_err_t idf_esim_lpa_cancel_session(const Bytes& request, Bytes& out, std::string&)
{
    g.events.push_back("cancel_card");
    idf_esim_internal::Tlv root;
    std::string message;
    assert(idf_esim_internal::parse_tlv(request, root, message));
    assert(root.tag == Bytes({0xBF, 0x41}) && root.children.size() == 2);
    assert(root.children[0].tag == Bytes{0x80} && root.children[0].value == kTransaction);
    assert(root.children[1].tag == Bytes{0x81} && root.children[1].value.size() == 1);
    const uint8_t reason = root.children[1].value[0];
    assert(reason == 1 || reason == 2);
    g.cancellations.push_back(reason);
    if (g.cancel_card_failure) return ESP_FAIL;
    out = tlv({0xBF, 0x41}, tlv({0xA0}, join({seq({
        tlv({0x80}, g.wrong_cancel_transaction ? Bytes{0x77} : kTransaction),
        tlv({0x81}, {0x2B, 6, 1, 4, 1}), tlv({0x82}, {reason})}), kSignature})));
    g.cancel_response = out;
    return ESP_OK;
}

bool idf_lpa_es9_post_json(IdfLpaEs9Operation op, std::string_view host,
                          std::string_view request, std::string& response,
                          IdfLpaEs9TransportError& error)
{
    assert(host == kHost);
    error = IdfLpaEs9TransportError::none;
    response.clear();
    const std::string status = R"({"header":{"functionExecutionStatus":{"status":"Executed-Success"}},)";
    if (op == IdfLpaEs9Operation::cancel_session) {
        g.events.push_back("cancel_http");
        assert(field(request, "transactionId") == "0102");
        assert(binary_field(request, "cancelSessionResponse") == g.cancel_response);
        if (g.cancel_http_failure) {
            error = IdfLpaEs9TransportError::transport;
            return false;
        }
        response = R"({"header":{"functionExecutionStatus":{"status":"Executed-Success"}}})";
        return true;
    }
    if (op == IdfLpaEs9Operation::initiate_authentication) {
        g.events.push_back("initiate");
        assert(request == R"({"euiccChallenge":"EREREREREREREREREREREQ==","euiccInfo1":"vyAFggMCAgA=","smdpAddress":"edge.example"})");
        const Bytes signed1 = seq({tlv({0x80}, kTransaction),
            tlv({0x81}, g.bad_challenge ? Bytes(16, 0xEE) : kChallenge),
            tlv({0x83}, text_bytes(kHost)), tlv({0x84}, kServerChallenge)});
        response = status + "\"transactionId\":\"0102\",\"serverSigned1\":\"" + base64(signed1) +
            "\",\"serverSignature1\":\"" + base64(kSignature) +
            "\",\"euiccCiPKIdToBeUsed\":\"" + base64(tlv({0x04}, Bytes(20, 0xAA))) +
            "\",\"serverCertificate\":\"" + base64(kCertificate) + "\"}";
        return true;
    }
    if (op == IdfLpaEs9Operation::authenticate_client) {
        g.events.push_back("authenticate_client");
        assert(field(request, "transactionId") == "0102");
        assert(binary_field(request, "authenticateServerResponse") == g.auth_response);
        const Bytes signed2 = seq({tlv({0x80}, kTransaction),
                                    tlv({0x01}, {uint8_t(g.require_cc ? 0xFF : 0)})});
        const Bytes metadata = tlv({0xBF, 0x25}, join({
            tlv({0x5A}, {0x98, 0x88, 0x12, 0x32, 0x54, 0x76, 0x98, 0x10, 0x32, 0xF4}),
            tlv({0x91}, text_bytes("Carrier")), tlv({0x92}, text_bytes("Travel")),
            g.policy_rules ? join({tlv({0xB7}, tlv({0x80}, {0x42, 0xF6, 0x18})),
                                   tlv({0x99}, {0x07, 0x80})}) : Bytes{}}));
        response = status + "\"transactionId\":\"" + (g.wrong_client_transaction ? "0103" : "0102") +
            "\",\"profileMetadata\":\"" + base64(metadata) +
            "\",\"smdpSigned2\":\"" + base64(signed2) +
            "\",\"smdpSignature2\":\"" + base64(kSignature) +
            "\",\"smdpCertificate\":\"" + base64(kCertificate) + "\"}";
        return true;
    }
    assert(op == IdfLpaEs9Operation::handle_notification);
    g.events.push_back("notify");
    ++g.notifications;
    const Bytes pending = binary_field(request, "pendingNotification");
    assert(pending == pir(kTransaction, 1, kHost, !g.rejected_install) ||
           pending == pir({0x77}, 9));
    if (g.notification_failure) {
        response = "private server detail";
        error = IdfLpaEs9TransportError::transport;
        return false;
    }
    return true;
}

bool idf_lpa_es9_get_bound_profile_package(std::string_view host,
    std::string_view request, std::string_view transaction,
    const LpaRspProfileMetadata& expected_metadata, Bytes& result,
    std::string&, IdfLpaEs9TransportError& error)
{
    g.events.push_back("download");
    ++g.downloads;
    assert(host == kHost && transaction == "0102");
    assert(expected_metadata.profile_name == "Travel" &&
           expected_metadata.service_provider_name == "Carrier" && !expected_metadata.has_policy_rules);
    assert(field(request, "transactionId") == "0102");
    assert(binary_field(request, "prepareDownloadResponse") == g.prepare_response);
    if (g.download_failure) {
        error = IdfLpaEs9TransportError::timeout;
        return false;
    }
    result = pir(g.wrong_pir_transaction ? Bytes{0x01, 0x03} : kTransaction,
                 1, kHost, !g.rejected_install);
    error = IdfLpaEs9TransportError::none;
    return true;
}

static esp_err_t confirmation(void*, const LpaRspProfileMetadata& metadata,
                              bool cc_required, uint32_t timeout, bool& accepted, std::string& out)
{
    assert(timeout > 0 && timeout <= 300000U);
    assert(metadata.profile_name == "Travel" && metadata.service_provider_name == "Carrier");
    assert(!metadata.has_policy_rules && cc_required == g.require_cc);
    ++g.confirmations;
    accepted = g.consent_accepted;
    if (g.callback_late) now_us += (int64_t(timeout) + 1) * 1000;
    if (g.observe_confirmation_wipe) {
        out.assign(128, 'S');
        out.resize(g.code.size());
        std::copy(g.code.begin(), g.code.end(), out.begin());
        confirmation_storage = out.data();
        confirmation_capacity = out.capacity();
        confirmation_wiped = false;
    } else out = cc_required ? g.code : "";
    return g.callback_error;
}

static void progress(void*, IdfLpaInstallStage stage) { g.stages.push_back(stage); }

static IdfLpaInstallResult run(esp_err_t expected, IdfLpaConfirmationCallback callback = confirmation)
{
    IdfLpaInstallResult result;
    const esp_err_t actual = idf_lpa_install_profile(kActivation, callback, progress, nullptr, result);
    if (actual != expected)
        std::fprintf(stderr, "install expected=%d actual=%d code=%s\n", expected, actual,
                     idf_lpa_install_error_name(result.error));
    assert(actual == expected);
    return result;
}

static void reset() { g = {}; now_us = 1000000; }

static void successful_install_requires_metadata_consent_without_enabling()
{
    reset();
    const auto result = run(ESP_OK);
    assert(result.installed && !result.notification_pending && result.error == IdfLpaInstallError::none);
    assert(g.confirmations == 1 && g.downloads == 1 && g.notifications == 1);
    assert(g.removed == std::vector<uint32_t>{1});
    assert(g.events == std::vector<std::string>({"pending", "imei", "material", "initiate",
        "authenticate_card", "authenticate_client", "prepare_card", "download", "notify", "remove"}));
    assert(g.stages.back() == IdfLpaInstallStage::completed);
}

static void confirmation_is_required_once_and_expires_before_card_download()
{
    reset(); g.require_cc = true;
    assert(run(ESP_OK).installed && g.confirmations == 1);
    for (int kind = 0; kind < 4; ++kind) {
        reset(); g.require_cc = true;
        if (kind == 0) g.callback_error = ESP_ERR_TIMEOUT;
        if (kind == 1) g.callback_late = true;
        if (kind == 2) g.code = std::string(129, 'X');
        if (kind == 3) g.code = "bad\ncode";
        const auto result = run(kind < 2 ? ESP_ERR_TIMEOUT : ESP_ERR_INVALID_ARG);
        assert(!result.installed && g.confirmations == 1 && g.downloads == 0);
        assert(std::find(g.events.begin(), g.events.end(), "prepare_card") == g.events.end());
        assert(result.error == (kind < 2 ? IdfLpaInstallError::confirmation_timeout :
                                          IdfLpaInstallError::confirmation_invalid));
        assert(g.cancellations == std::vector<uint8_t>{uint8_t(kind < 2 ? 2 : 1)});
        assert(g.events.back() == "cancel_http");
    }
    reset(); g.require_cc = true;
    assert(run(ESP_ERR_INVALID_STATE, nullptr).error == IdfLpaInstallError::confirmation_required);
    assert(g.downloads == 0);
    reset(); g.require_cc = true; g.code.assign(128, 'X');
    assert(run(ESP_OK).installed);
    for (bool timeout : {false, true}) {
        reset(); g.require_cc = true; g.observe_confirmation_wipe = true;
        g.callback_error = timeout ? ESP_ERR_TIMEOUT : ESP_OK;
        run(timeout ? ESP_ERR_TIMEOUT : ESP_OK);
        assert(confirmation_wiped && confirmation_storage == nullptr);
    }
}

static void consent_decline_and_policy_restrictions_postpone_without_terminating_order()
{
    reset(); g.consent_accepted = false;
    assert(run(ESP_FAIL).error == IdfLpaInstallError::postponed);
    assert(g.confirmations == 1 && g.downloads == 0 && g.cancellations == std::vector<uint8_t>{1});
    reset(); g.policy_rules = true;
    assert(run(ESP_ERR_NOT_SUPPORTED).error == IdfLpaInstallError::policy_rules_unsupported);
    assert(g.confirmations == 0 && g.downloads == 0 && g.cancellations == std::vector<uint8_t>{1});
    reset();
    assert(run(ESP_ERR_INVALID_STATE, nullptr).error == IdfLpaInstallError::confirmation_required);
    assert(g.downloads == 0 && g.cancellations == std::vector<uint8_t>{1});
    for (int failure = 0; failure < 3; ++failure) {
        reset(); g.consent_accepted = false;
        g.cancel_card_failure = failure == 0;
        g.cancel_http_failure = failure == 1;
        g.wrong_cancel_transaction = failure == 2;
        assert(run(ESP_FAIL).error == IdfLpaInstallError::cancellation_failed);
        assert(g.cancellations.size() == 1 && g.downloads == 0 && !g.notifications);
        assert(g.events.back() == (failure == 1 ? "cancel_http" : "cancel_card"));
    }
}

static void rejects_unbound_protocol_before_card_side_effects()
{
    reset(); g.bad_challenge = true;
    assert(run(ESP_ERR_INVALID_RESPONSE).error == IdfLpaInstallError::protocol);
    assert(std::find(g.events.begin(), g.events.end(), "authenticate_card") == g.events.end());
    reset(); g.wrong_client_transaction = true;
    assert(run(ESP_ERR_INVALID_RESPONSE).error == IdfLpaInstallError::protocol);
    assert(g.downloads == 0 && g.confirmations == 0);
}

static void installation_result_survives_notification_failures()
{
    for (bool removal : {false, true}) {
        reset(); g.notification_failure = !removal; g.removal_failure = removal;
        const auto result = run(ESP_OK);
        assert(result.installed && result.notification_pending);
        assert(result.error == IdfLpaInstallError::notification_pending);
        assert(g.downloads == 1 && g.removed.size() == size_t(removal));
    }
    reset(); g.rejected_install = true;
    const auto rejected = run(ESP_FAIL);
    assert(!rejected.installed && !rejected.notification_pending);
    assert(rejected.error == IdfLpaInstallError::installation_failed);
    assert(g.notifications == 1 && g.removed == std::vector<uint32_t>{1});
    for (bool wrong_result : {false, true}) {
        reset(); g.download_failure = !wrong_result; g.wrong_pir_transaction = wrong_result;
        const auto uncertain = run(ESP_FAIL);
        assert(!uncertain.installed && uncertain.error == IdfLpaInstallError::installation_uncertain);
        assert(g.downloads == 1 && g.notifications == 0 && g.removed.empty());
        assert(g.cancellations.empty());
    }
}

static void recovers_same_host_only_and_blocks_new_auth_until_acknowledged()
{
    reset(); g.pending = join({pir({0x88}, 8, "other.example"), pir({0x77}, 9)});
    assert(run(ESP_OK).installed);
    assert(g.removed == std::vector<uint32_t>({9, 1}));
    assert(g.events[0] == "pending" && g.events[1] == "notify" && g.events[2] == "remove");
    reset(); g.pending = pir({0x77}, 9); g.notification_failure = true;
    const auto pending = run(ESP_FAIL);
    assert(!pending.installed && pending.notification_pending && g.removed.empty());
    assert(g.events == std::vector<std::string>({"pending", "notify"}));
    reset(); g.pending = {0xBF, 0x37, 0x04, 0x00};
    assert(run(ESP_ERR_INVALID_RESPONSE).error == IdfLpaInstallError::protocol);
    assert(g.events == std::vector<std::string>{"pending"});
    reset();
    for (size_t index = 0; index < 17; ++index) {
        const Bytes entry = pir({0x77}, 9);
        g.pending.insert(g.pending.end(), entry.begin(), entry.end());
    }
    assert(run(ESP_ERR_INVALID_RESPONSE).error == IdfLpaInstallError::protocol);
    assert(g.notifications == 0 && g.downloads == 0);
}

int main()
{
    IdfLpaInstallResult result;
    assert(idf_lpa_install_profile("invalid", nullptr, nullptr, nullptr, result) ==
           ESP_ERR_INVALID_ARG);
    assert(result.error == IdfLpaInstallError::invalid_activation);
    assert(g.events.empty());
    for (const char* activation : {"LPA:1$edge.example$ABC-012$1.2.3", "1$edge.example$ABC-012$$1"}) {
        assert(idf_lpa_install_profile(activation, nullptr, nullptr, nullptr, result) == ESP_ERR_NOT_SUPPORTED);
        assert(result.error == IdfLpaInstallError::unsupported_activation_options && g.events.empty());
    }
    assert(idf_lpa_install_profile("LPA:1$edge.example$abc-012", nullptr, nullptr, nullptr, result) ==
           ESP_ERR_INVALID_ARG);
    assert(result.error == IdfLpaInstallError::invalid_activation && g.events.empty());
    successful_install_requires_metadata_consent_without_enabling();
    confirmation_is_required_once_and_expires_before_card_download();
    consent_decline_and_policy_restrictions_postpone_without_terminating_order();
    rejects_unbound_protocol_before_card_side_effects();
    installation_result_survives_notification_failures();
    recovers_same_host_only_and_blocks_new_auth_until_acknowledged();
}
