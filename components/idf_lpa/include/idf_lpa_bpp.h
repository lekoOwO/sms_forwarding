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

// 解析一個 SGP.22 GetBoundProfilePackage response；root 欄位可按服務端順序出現，
// 包括 boundProfilePackage 早於 header/status/transactionId。BPP segment 會串流寫入
// 具體 eUICC LPA session；最後一個 card block 會等完整 JSON envelope 驗證後才送出，
// 絕不啟用 profile。若先前 segment 已送出而尾端欄位驗證失敗，呼叫方必須將安裝視為
// 不確定，不可安全重試。A1/88 在有界緩衝內重組、核對已同意的名稱/供應商且沒有 PPR
// 後才原樣送出；不支援帶 PPR 的 expected_metadata。feed() 執行期間輸入區塊必須保持有效。
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

    // Diagnostic counters for the current response; only bounded non-sensitive totals survive cleanup.
    std::size_t encoded_bpp_chars() const noexcept;
    std::size_t decoded_bpp_bytes() const noexcept;

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
