#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>

#include "esp_err.h"
#include "idf_lpa_rsp.h"

constexpr std::size_t IDF_LPA_INSTALL_MAX_ACTIVATION_BYTES = 516U;
constexpr std::uint32_t IDF_LPA_INSTALL_CONFIRMATION_TIMEOUT_MS = 5U * 60U * 1000U;

enum class IdfLpaInstallStage : std::uint8_t {
    validating,
    recovering_notifications,
    authenticating,
    awaiting_confirmation,
    preparing,
    downloading,
    notifying,
    completed,
};

enum class IdfLpaInstallError : std::uint8_t {
    none,
    invalid_activation,
    unsupported_activation_options,
    identity_unavailable,
    card,
    server,
    protocol,
    confirmation_required,
    confirmation_invalid,
    confirmation_timeout,
    postponed,
    policy_rules_unsupported,
    cancellation_failed,
    notification_pending,
    installation_failed,
    installation_uncertain,
};

struct IdfLpaInstallResult {
    bool installed = false;
    bool notification_pending = false;
    IdfLpaInstallError error = IdfLpaInstallError::none;
};

// 每次下载都须确认 metadata；必须在 timeout_ms 内返回，未接受时只延期订单。
// 服务器要求确认码时，成功需移交最多 IDF_LPA_RSP_MAX_CONFIRMATION_BYTES 个可打印 ASCII 字节，
// 调用方必须清除自身副本；协调器会清除接管的字符串。
using IdfLpaConfirmationCallback = esp_err_t (*)(void* context,
                                                 const LpaRspProfileMetadata& metadata,
                                                 bool confirmation_code_required,
                                                 std::uint32_t timeout_ms,
                                                 bool& accepted,
                                                 std::string& confirmation_code);
using IdfLpaProgressCallback = void (*)(void* context, IdfLpaInstallStage stage);

const char* idf_lpa_install_error_name(IdfLpaInstallError error) noexcept;

// 同步操作，由现有后台任务保证独占准入；不在用户等待或 HTTPS 期间持有卡片锁。
// 使用现有各阶段预算及有界确认等待，不宣称统一硬性总时限。不会自动启用 profile。
// installed=true 时通知失败仍返回 ESP_OK，notification_pending 提示后续重试通知。
// installation_uncertain 表示卡片可能已变更，不能据此自动重用激活码。
esp_err_t idf_lpa_install_profile(std::string_view activation_code,
                                   IdfLpaConfirmationCallback confirmation,
                                   IdfLpaProgressCallback progress,
                                   void* context,
                                   IdfLpaInstallResult& result);
