#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "esp_err.h"
#include "idf_lpa_rsp.h"

constexpr std::size_t IDF_LPA_BPP_MAX_ENCODED_BYTES = 1536U * 1024U;
constexpr std::size_t IDF_LPA_BPP_MAX_DECODED_BYTES = 1024U * 1024U;
constexpr std::size_t IDF_LPA_BPP_MAX_SEGMENT_BYTES = 30U * 1024U;
constexpr std::size_t IDF_LPA_BPP_MAX_ELEMENTS = 4096U;
constexpr std::size_t IDF_LPA_BPP_BLOCK_BYTES = 120U;
constexpr std::size_t IDF_LPA_BPP_MAX_CARD_SEGMENT_BYTES =
    IDF_LPA_BPP_MAX_SEGMENT_BYTES;
constexpr std::size_t IDF_LPA_BPP_MAX_METADATA_WIRE_BYTES = 16U * 1024U;

// 解析一個 SGP.22 GetBoundProfilePackage response；header 與 transactionId 可交換，
// 但 boundProfilePackage 必須最後出現。只將已驗證的 BPP segment 寫入具體 eUICC
// LPA session，絕不啟用 profile。A1/88 在有界緩衝內重組、核對已同意的
// 名稱/供應商且沒有 PPR 後才原樣送出；不支援帶 PPR 的 expected_metadata。
// feed() 執行期間輸入區塊必須保持有效。
class IdfLpaBppStream final {
public:
    IdfLpaBppStream(std::string_view expected_transaction_id,
                     const LpaRspProfileMetadata& expected_metadata) noexcept;
    ~IdfLpaBppStream();

    IdfLpaBppStream(const IdfLpaBppStream&) = delete;
    IdfLpaBppStream& operator=(const IdfLpaBppStream&) = delete;
    IdfLpaBppStream(IdfLpaBppStream&&) = delete;
    IdfLpaBppStream& operator=(IdfLpaBppStream&&) = delete;

    esp_err_t feed(const char* data, std::size_t length, std::string& safe_message);
    esp_err_t feed(std::string_view chunk, std::string& safe_message)
    {
        return feed(chunk.data(), chunk.size(), safe_message);
    }

    // 每次失敗都會安全清除 installation_result，message 不包含伺服器文字。
    esp_err_t finish(std::vector<std::uint8_t>& installation_result,
                     std::string& safe_message);

    // 停止卡片 I/O 並安全清除 parser 擁有的 BPP 狀態；可重複呼叫，方便所有錯誤路徑共用。
    void abort() noexcept;

#ifdef IDF_LPA_BPP_TESTING
    bool test_sensitive_storage_is_zero() const noexcept;
    std::size_t test_cleanup_count() const noexcept;
#endif

private:
    class Impl;
    Impl* impl_;
};
