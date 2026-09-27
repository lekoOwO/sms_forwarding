#include "idf_lpa_install.h"

#include <array>
#include <initializer_list>
#include <utility>
#include <vector>

#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "idf_esim_codec.h"
#include "idf_esim_lpa.h"
#include "idf_lpa_activation_code.h"
#include "idf_lpa_es9_transport.h"
#include "idf_log.h"
#include "idf_modem.h"

namespace {

using Bytes = std::vector<uint8_t>;
constexpr size_t kMaxPendingNotifications = 16U;

struct PendingNotification {
    size_t offset = 0U;
    size_t length = 0U;
    uint32_t sequence = 0U;
    std::string address;
};

int compare_ascii_ci(std::string_view left, std::string_view right) noexcept
{
    const size_t common = left.size() < right.size() ? left.size() : right.size();
    for (size_t index = 0U; index < common; ++index) {
        unsigned char left_byte = static_cast<unsigned char>(left[index]);
        unsigned char right_byte = static_cast<unsigned char>(right[index]);
        if (left_byte >= static_cast<unsigned char>('a') &&
            left_byte <= static_cast<unsigned char>('z')) {
            left_byte = static_cast<unsigned char>(left_byte - 'a' + 'A');
        }
        if (right_byte >= static_cast<unsigned char>('a') &&
            right_byte <= static_cast<unsigned char>('z')) {
            right_byte = static_cast<unsigned char>(right_byte - 'a' + 'A');
        }
        if (left_byte != right_byte) return left_byte < right_byte ? -1 : 1;
    }
    if (left.size() == right.size()) return 0;
    return left.size() < right.size() ? -1 : 1;
}

void zero_bytes(void* storage, size_t length)
{
    volatile uint8_t* bytes = static_cast<volatile uint8_t*>(storage);
    while (length-- != 0U) *bytes++ = 0;
}

template <typename Container>
void clear_sensitive(Container& value)
{
    if (value.size() < value.capacity()) value.resize(value.capacity(), 0);
    zero_bytes(value.data(), value.size());
    value.clear();
}

template <typename Container>
void release_sensitive(Container& value)
{
    clear_sensitive(value);
    Container empty;
    value.swap(empty);
}

// 仅保存当前阶段所需资料；TLS 前释放已经完成的 DER/JSON 副本。
struct InstallData {
    std::string imei, transaction, text, text2, request_json, response_json;
    std::string notification_host, confirmation, safe_message;
    Bytes first, second, third, fourth, request, response, forwarded, pending;
    std::array<uint8_t, 16> challenge{}, transaction_bytes{};
    std::array<uint8_t, 32> hash_cc{};
    size_t transaction_size = 0;
    LpaRspProfileMetadata metadata;
    LpaRspError rsp_error = LpaRspError::none;
    IdfLpaEs9TransportError transport_error = IdfLpaEs9TransportError::none;

    void release_objects()
    {
        release_sensitive(first);
        release_sensitive(second);
        release_sensitive(third);
        release_sensitive(fourth);
    }

    ~InstallData()
    {
        for (auto* value : {&imei, &transaction, &text, &text2, &request_json,
                            &response_json, &notification_host, &confirmation, &safe_message,
                            &metadata.profile_name, &metadata.service_provider_name})
            clear_sensitive(*value);
        for (auto* value : {&first, &second, &third, &fourth, &request, &response,
                            &forwarded, &pending})
            clear_sensitive(*value);
        zero_bytes(challenge.data(), challenge.size());
        zero_bytes(transaction_bytes.data(), transaction_bytes.size());
        zero_bytes(hash_cc.data(), hash_cc.size());
    }
};

class DownloadDiagnosticsGuard final {
public:
    explicit DownloadDiagnosticsGuard(const IdfLpaInstallResult& result)
        : result_(result)
    {
        free_heap_at_start = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        minimum_monitor_started =
            heap_caps_monitor_local_minimum_free_size_start() == ESP_OK;
    }

    ~DownloadDiagnosticsGuard()
    {
        if (minimum_monitor_started) {
            minimum_free_heap = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
            (void)heap_caps_monitor_local_minimum_free_size_stop();
        }
        free_heap_at_end = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        if (minimum_monitor_started) {
            idf_logf("eSIM download resources: result=%s bppEncodedBytes=%u "
                     "bppDecodedBytes=%u freeHeapAtStart=%u minimumFreeHeap=%u "
                     "freeHeapAtEnd=%u",
                     idf_lpa_install_error_name(result_.error),
                     static_cast<unsigned>(bpp_encoded_chars),
                     static_cast<unsigned>(bpp_decoded_bytes),
                     static_cast<unsigned>(free_heap_at_start),
                     static_cast<unsigned>(minimum_free_heap),
                     static_cast<unsigned>(free_heap_at_end));
        } else {
            idf_logf("eSIM download resources: result=%s bppEncodedBytes=%u "
                     "bppDecodedBytes=%u freeHeapAtStart=%u minimumFreeHeap=n/a "
                     "freeHeapAtEnd=%u",
                     idf_lpa_install_error_name(result_.error),
                     static_cast<unsigned>(bpp_encoded_chars),
                     static_cast<unsigned>(bpp_decoded_bytes),
                     static_cast<unsigned>(free_heap_at_start),
                     static_cast<unsigned>(free_heap_at_end));
        }
    }

    DownloadDiagnosticsGuard(const DownloadDiagnosticsGuard&) = delete;
    DownloadDiagnosticsGuard& operator=(const DownloadDiagnosticsGuard&) = delete;

    std::size_t bpp_encoded_chars = 0U;
    std::size_t bpp_decoded_bytes = 0U;

private:
    const IdfLpaInstallResult& result_;
    std::size_t free_heap_at_start = 0U;
    std::size_t minimum_free_heap = 0U;
    std::size_t free_heap_at_end = 0U;
    bool minimum_monitor_started = false;
};

esp_err_t fail(IdfLpaInstallResult& result, IdfLpaInstallError error, esp_err_t code)
{
    result.error = error;
    return code;
}

// 所有 value 均来自已验证的主机名、交易十六进制或 base64；不接收自由文本。
bool make_request(InstallData& data,
                  std::initializer_list<std::pair<std::string_view, std::string_view>> fields)
{
    clear_sensitive(data.request_json);
    size_t size = 2;
    for (const auto& field : fields) size += field.first.size() + field.second.size() + 6U;
    if (size > IDF_LPA_ES9_MAX_JSON_BYTES) return false;
    data.request_json.reserve(size);
    data.request_json.push_back('{');
    for (const auto& field : fields) {
        if (data.request_json.size() > 1U) data.request_json.push_back(',');
        data.request_json.push_back('"');
        data.request_json.append(field.first);
        data.request_json.append("\":\"");
        data.request_json.append(field.second);
        data.request_json.push_back('"');
    }
    data.request_json.push_back('}');
    return true;
}

bool post(InstallData& data, IdfLpaEs9Operation operation, std::string_view host)
{
    release_sensitive(data.response_json);
    const bool ok = idf_lpa_es9_post_json(operation, host, data.request_json,
                                         data.response_json, data.transport_error);
    release_sensitive(data.request_json);
    return ok;
}

bool binary_field(InstallData& data, const char* name, Bytes& value)
{
    clear_sensitive(data.text);
    const bool ok = idf_lpa_rsp_json_get_string(data.response_json, name, data.text,
                                               data.rsp_error) &&
        idf_lpa_rsp_base64_decode(data.text, value, data.rsp_error);
    release_sensitive(data.text);
    return ok;
}

bool encoded(InstallData& data, const uint8_t* bytes, size_t size, std::string& out)
{
    clear_sensitive(out);
    return idf_lpa_rsp_base64_encode(bytes, size, out, data.rsp_error);
}

bool notification(InstallData& data, const uint8_t* bytes, size_t size, uint32_t number)
{
    if (!encoded(data, bytes, size, data.text) ||
        !make_request(data, {{"pendingNotification", data.text}})) return false;
    release_sensitive(data.text);
    if (!post(data, IdfLpaEs9Operation::handle_notification, data.notification_host)) return false;
    // 仅在服务器确认成功后移除；失败时让 eUICC 保留可重试的通知。
    return idf_esim_lpa_remove_notification(number, data.safe_message) == ESP_OK;
}

bool cancel_session(InstallData& data, std::string_view host, LpaRspCancelReason reason)
{
    // 只在 BPP 前调用；保留载入可能已发生时的结果不确定性，不终止付费订单。
    data.release_objects();
    release_sensitive(data.request);
    release_sensitive(data.response);
    release_sensitive(data.forwarded);
    release_sensitive(data.response_json);
    release_sensitive(data.confirmation);
    zero_bytes(data.hash_cc.data(), data.hash_cc.size());
    if (!idf_lpa_rsp_build_cancel_session_request(data.transaction_bytes.data(),
            data.transaction_size, reason, data.request, data.rsp_error) ||
        idf_esim_lpa_cancel_session(data.request, data.response, data.safe_message) != ESP_OK)
        return false;
    release_sensitive(data.request);
    if (!idf_lpa_rsp_parse_cancel_session_response(data.response.data(), data.response.size(),
            data.transaction_bytes.data(), data.transaction_size, reason, data.forwarded,
            data.rsp_error) ||
        !encoded(data, data.forwarded.data(), data.forwarded.size(), data.text) ||
        !make_request(data, {{"transactionId", data.transaction}, {"cancelSessionResponse", data.text}}))
        return false;
    release_sensitive(data.response);
    release_sensitive(data.forwarded);
    release_sensitive(data.text);
    if (!post(data, IdfLpaEs9Operation::cancel_session, host)) return false;
    bool success = false;
    return idf_lpa_rsp_parse_status(data.response_json, success, data.rsp_error,
                                    "CancelSession") && success;
}

esp_err_t recover_notifications(InstallData& data, std::string_view host,
                                 IdfLpaInstallResult& result)
{
    size_t offset = 0, length = 0;
    if (idf_esim_lpa_retrieve_notifications(data.pending, offset, length,
                                            data.safe_message) != ESP_OK)
        return fail(result, IdfLpaInstallError::card, ESP_FAIL);
    if (offset > data.pending.size() || length > data.pending.size() - offset)
        return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
    const size_t end = offset + length;
    size_t count = 0;
    size_t position = offset;
    idf_esim_internal::TlvSpan entry;
    // 先检查整个列表的边界和数量，避免开始一个没有合理上限的重试批次。
    while (position < end) {
        if (++count > kMaxPendingNotifications ||
            !idf_esim_internal::parse_tlv_span(data.pending, end, position, entry,
                                                data.safe_message))
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
    }

    std::vector<PendingNotification> notifications;
    notifications.reserve(count);
    position = offset;
    while (position < end) {
        if (!idf_esim_internal::parse_tlv_span(data.pending, end, position, entry,
                                               data.safe_message))
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
        bool installed = false;
        uint32_t number = 0;
        LpaRspNotificationOperation operation = LpaRspNotificationOperation::install;
        std::string address;
        if (!idf_lpa_rsp_parse_pending_notification(
                data.pending.data() + entry.offset, entry.encoded_length(), installed, number,
                address, operation, data.rsp_error)) {
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
        }
        (void)installed;
        (void)operation;
        notifications.push_back(PendingNotification{entry.offset, entry.encoded_length(),
                                                     number, std::move(address)});
    }

    auto notification_less = [](const PendingNotification& left,
                                const PendingNotification& right) {
        const int address_order = compare_ascii_ci(left.address, right.address);
        return address_order != 0 ? address_order < 0 : left.sequence < right.sequence;
    };
    // 卡片待处理列表很小；插入排序不引入额外分配，也固定同主机的序号顺序。
    for (size_t index = 1U; index < notifications.size(); ++index) {
        PendingNotification current = std::move(notifications[index]);
        size_t insert_at = index;
        while (insert_at > 0U && notification_less(current, notifications[insert_at - 1U])) {
            notifications[insert_at] = std::move(notifications[insert_at - 1U]);
            --insert_at;
        }
        notifications[insert_at] = std::move(current);
    }
    for (size_t index = 1U; index < notifications.size(); ++index) {
        if (notifications[index - 1U].sequence == notifications[index].sequence &&
            compare_ascii_ci(notifications[index - 1U].address,
                             notifications[index].address) == 0) {
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
        }
    }

    esp_err_t current_host_error = ESP_OK;
    std::string current_host_message;
    size_t group_begin = 0U;
    while (group_begin < notifications.size()) {
        size_t group_end = group_begin + 1U;
        while (group_end < notifications.size() &&
               compare_ascii_ci(notifications[group_begin].address,
                                notifications[group_end].address) == 0) {
            ++group_end;
        }
        esp_err_t group_error = ESP_OK;
        for (size_t index = group_begin; index < group_end; ++index) {
            const PendingNotification& pending_notification = notifications[index];
            data.notification_host = pending_notification.address;
            clear_sensitive(data.safe_message);
            if (!notification(data, data.pending.data() + pending_notification.offset,
                              pending_notification.length, pending_notification.sequence)) {
                group_error = ESP_FAIL;
                break;
            }
        }
        if (group_error != ESP_OK &&
            compare_ascii_ci(notifications[group_begin].address, host) == 0) {
            result.notification_pending = true;
            current_host_error = group_error;
            current_host_message = data.safe_message;
        }
        // 其他 SM-DP+ 的失败只延后该主机群组；继续处理独立群组。
        group_begin = group_end;
    }
    release_sensitive(data.pending);
    release_sensitive(data.response_json);
    if (current_host_error != ESP_OK) {
        if (!current_host_message.empty()) data.safe_message = current_host_message;
        return fail(result, IdfLpaInstallError::notification_pending, current_host_error);
    }
    return ESP_OK;
}

} // namespace

esp_err_t idf_lpa_install_profile(std::string_view activation_code,
                                   IdfLpaConfirmationCallback confirmation,
                                   IdfLpaProgressCallback progress,
                                   void* context,
                                   IdfLpaInstallResult& result)
{
    result = {};
    const auto stage = [&](IdfLpaInstallStage current) { if (progress) progress(context, current); };
    stage(IdfLpaInstallStage::validating);
    LpaActivationCode parsed;
    if (!idf_lpa_parse_activation_code(activation_code, parsed))
        return fail(result, IdfLpaInstallError::invalid_activation, ESP_ERR_INVALID_ARG);
    LpaRspError matching_id_error = LpaRspError::none;
    if (!idf_lpa_rsp_validate_matching_id(parsed.matching_id(), matching_id_error))
        return fail(result, IdfLpaInstallError::invalid_activation, ESP_ERR_INVALID_ARG);
    DownloadDiagnosticsGuard diagnostics_guard(result);
    InstallData data;
    stage(IdfLpaInstallStage::recovering_notifications);
    esp_err_t error = recover_notifications(data, parsed.smdp_host(), result);
    if (error != ESP_OK) return error;
    if (idf_modem_get_imei(data.imei, 3000U) != ESP_OK)
        return fail(result, IdfLpaInstallError::identity_unavailable, ESP_FAIL);
    stage(IdfLpaInstallStage::authenticating);
    if (idf_esim_lpa_get_auth_material(data.first, data.challenge, data.safe_message) != ESP_OK)
        return fail(result, IdfLpaInstallError::card, ESP_FAIL);
    if (!encoded(data, data.challenge.data(), data.challenge.size(), data.text) ||
        !encoded(data, data.first.data(), data.first.size(), data.text2) ||
        !make_request(data, {{"euiccChallenge", data.text}, {"euiccInfo1", data.text2},
                             {"smdpAddress", parsed.smdp_host()}}))
        return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
    data.release_objects();
    release_sensitive(data.text);
    release_sensitive(data.text2);
    if (!post(data, IdfLpaEs9Operation::initiate_authentication, parsed.smdp_host()))
        return fail(result, IdfLpaInstallError::server, ESP_FAIL);
    bool success = false;
    if (!idf_lpa_rsp_parse_status(data.response_json, success, data.rsp_error,
                                  "InitiateAuthentication") || !success ||
        !idf_lpa_rsp_json_get_string(data.response_json, "transactionId", data.transaction,
                                      data.rsp_error) ||
        !idf_lpa_rsp_decode_transaction_id(data.transaction, data.transaction_bytes,
                                            data.transaction_size, data.rsp_error) ||
        !binary_field(data, "serverSigned1", data.first) ||
        !binary_field(data, "serverSignature1", data.second) ||
        !binary_field(data, "euiccCiPKIdToBeUsed", data.third) ||
        !binary_field(data, "serverCertificate", data.fourth) ||
        !idf_lpa_rsp_validate_server_signed1(data.first.data(), data.first.size(),
            data.transaction_bytes.data(), data.transaction_size, data.challenge,
            parsed.smdp_host(), data.rsp_error) ||
        !idf_lpa_rsp_build_authenticate_server_request(data.first, data.second, data.third,
            data.fourth, parsed.matching_id(), data.imei, Bytes{0x30, 0x00}, data.request,
            data.rsp_error))
        return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
    // 未有设备无线能力证据时使用空 OPTIONAL SEQUENCE，不虚构支持的 release。
    data.release_objects();
    release_sensitive(data.imei);
    release_sensitive(data.response_json);
    bool bpp_started = false;
    const auto authenticated_install = [&]() -> esp_err_t {
        if (idf_esim_lpa_authenticate_server(data.request, data.response, data.safe_message) != ESP_OK)
            return fail(result, IdfLpaInstallError::card, ESP_FAIL);
        if (!idf_lpa_rsp_parse_authenticate_server_response(data.response.data(), data.response.size(),
                data.request, data.forwarded, data.rsp_error) ||
            !encoded(data, data.forwarded.data(), data.forwarded.size(), data.text) ||
            !make_request(data, {{"transactionId", data.transaction},
                                 {"authenticateServerResponse", data.text}}))
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
        release_sensitive(data.request);
        release_sensitive(data.response);
        release_sensitive(data.forwarded);
        release_sensitive(data.text);
        if (!post(data, IdfLpaEs9Operation::authenticate_client, parsed.smdp_host()))
            return fail(result, IdfLpaInstallError::server, ESP_FAIL);
        if (!idf_lpa_rsp_parse_status(data.response_json, success, data.rsp_error,
                                      "AuthenticateClient") || !success ||
            !idf_lpa_rsp_json_get_string(data.response_json, "transactionId", data.text,
                                          data.rsp_error) ||
            !idf_lpa_rsp_transaction_id_matches(data.text, data.transaction_bytes.data(),
                                                 data.transaction_size, data.rsp_error) ||
            !binary_field(data, "profileMetadata", data.first) ||
            !idf_lpa_rsp_parse_profile_metadata(data.first.data(), data.first.size(),
                                                 data.metadata, data.rsp_error))
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
        release_sensitive(data.first);
        bool confirmation_required = false;
        if (!binary_field(data, "smdpSigned2", data.first) ||
            !binary_field(data, "smdpSignature2", data.second) ||
            !binary_field(data, "smdpCertificate", data.third) ||
            !idf_lpa_rsp_parse_smdp_signed2(data.first.data(), data.first.size(),
                data.transaction_bytes.data(), data.transaction_size,
                confirmation_required, data.rsp_error))
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
        release_sensitive(data.response_json);
        if (data.metadata.has_policy_rules)
            return fail(result, IdfLpaInstallError::policy_rules_unsupported, ESP_ERR_NOT_SUPPORTED);
        if (!confirmation)
            return fail(result, IdfLpaInstallError::confirmation_required, ESP_ERR_INVALID_STATE);
        stage(IdfLpaInstallStage::awaiting_confirmation);
        const int64_t deadline = esp_timer_get_time() +
            static_cast<int64_t>(IDF_LPA_INSTALL_CONFIRMATION_TIMEOUT_MS) * 1000;
        bool accepted = false;
        error = confirmation(context, data.metadata, confirmation_required,
            IDF_LPA_INSTALL_CONFIRMATION_TIMEOUT_MS, accepted, data.confirmation);
        if (error == ESP_ERR_TIMEOUT || esp_timer_get_time() >= deadline)
            return fail(result, IdfLpaInstallError::confirmation_timeout, ESP_ERR_TIMEOUT);
        if (error != ESP_OK)
            return fail(result, IdfLpaInstallError::confirmation_invalid, ESP_ERR_INVALID_ARG);
        if (!accepted) return fail(result, IdfLpaInstallError::postponed, ESP_FAIL);
        if (confirmation_required && !idf_lpa_rsp_compute_hash_cc(data.confirmation,
                data.transaction_bytes.data(), data.transaction_size, data.hash_cc, data.rsp_error))
            return fail(result, IdfLpaInstallError::confirmation_invalid, ESP_ERR_INVALID_ARG);
        release_sensitive(data.confirmation);
        stage(IdfLpaInstallStage::preparing);
        if (!idf_lpa_rsp_build_prepare_download_request(data.first, data.second, data.third,
                confirmation_required ? &data.hash_cc : nullptr, data.request, data.rsp_error))
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
        data.release_objects();
        zero_bytes(data.hash_cc.data(), data.hash_cc.size());
        if (idf_esim_lpa_prepare_download(data.request, data.response, data.safe_message) != ESP_OK)
            return fail(result, IdfLpaInstallError::card, ESP_FAIL);
        release_sensitive(data.request);
        if (!idf_lpa_rsp_parse_prepare_download_response(data.response.data(), data.response.size(),
                data.transaction_bytes.data(), data.transaction_size, data.forwarded, data.rsp_error) ||
            !encoded(data, data.forwarded.data(), data.forwarded.size(), data.text) ||
            !make_request(data, {{"transactionId", data.transaction}, {"prepareDownloadResponse", data.text}}))
            return fail(result, IdfLpaInstallError::protocol, ESP_ERR_INVALID_RESPONSE);
        release_sensitive(data.response);
        release_sensitive(data.forwarded);
        release_sensitive(data.text);
        stage(IdfLpaInstallStage::downloading);
        bpp_started = true;
        if (!idf_lpa_es9_get_bound_profile_package(parsed.smdp_host(), data.request_json,
                data.transaction, data.metadata, data.response, data.safe_message,
                data.transport_error, &diagnostics_guard.bpp_encoded_chars,
                &diagnostics_guard.bpp_decoded_bytes))
            return fail(result, IdfLpaInstallError::installation_uncertain, ESP_FAIL);
        release_sensitive(data.metadata.profile_name);
        release_sensitive(data.metadata.service_provider_name);
        release_sensitive(data.request_json);
        uint32_t number = 0;
        if (!idf_lpa_rsp_parse_profile_installation_notification(data.response.data(), data.response.size(),
                data.transaction_bytes.data(), data.transaction_size, parsed.smdp_host(),
                result.installed, number, data.notification_host, data.rsp_error))
            return fail(result, IdfLpaInstallError::installation_uncertain, ESP_FAIL);
        stage(IdfLpaInstallStage::notifying);
        result.notification_pending = !notification(data, data.response.data(), data.response.size(), number);
        result.error = result.installed ? (result.notification_pending ? IdfLpaInstallError::notification_pending :
                                                                        IdfLpaInstallError::none) :
                                          IdfLpaInstallError::installation_failed;
        stage(IdfLpaInstallStage::completed);
        return result.installed ? ESP_OK : ESP_FAIL;
    };
    error = authenticated_install();
    if (error != ESP_OK && !bpp_started &&
        !cancel_session(data, parsed.smdp_host(), error == ESP_ERR_TIMEOUT ?
            LpaRspCancelReason::timeout : LpaRspCancelReason::postponed))
        return fail(result, IdfLpaInstallError::cancellation_failed, ESP_FAIL);
    return error;
}

const char* idf_lpa_install_error_name(IdfLpaInstallError error) noexcept
{
    switch (error) {
    case IdfLpaInstallError::none: return "none";
    case IdfLpaInstallError::invalid_activation: return "invalid_activation";
    case IdfLpaInstallError::unsupported_activation_options: return "unsupported_activation_options";
    case IdfLpaInstallError::identity_unavailable: return "identity_unavailable";
    case IdfLpaInstallError::card: return "card";
    case IdfLpaInstallError::server: return "server";
    case IdfLpaInstallError::protocol: return "protocol";
    case IdfLpaInstallError::confirmation_required: return "confirmation_required";
    case IdfLpaInstallError::confirmation_invalid: return "confirmation_invalid";
    case IdfLpaInstallError::confirmation_timeout: return "confirmation_timeout";
    case IdfLpaInstallError::postponed: return "postponed";
    case IdfLpaInstallError::policy_rules_unsupported: return "policy_rules_unsupported";
    case IdfLpaInstallError::cancellation_failed: return "cancellation_failed";
    case IdfLpaInstallError::notification_pending: return "notification_pending";
    case IdfLpaInstallError::installation_failed: return "installation_failed";
    case IdfLpaInstallError::installation_uncertain: return "installation_uncertain";
    }
    return "unknown";
}
