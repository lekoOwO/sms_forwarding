#pragma once

#include <array>
#include <stddef.h>
#include <stdint.h>

#include <string>
#include <vector>

#include "esp_err.h"

// 读取认证所需的 eUICC 信息和 challenge；BF22 只作本次会话的能力前置检查。
esp_err_t idf_esim_lpa_get_auth_material(std::vector<uint8_t>& euicc_info1,
                                         std::array<uint8_t, 16>& challenge,
                                         std::string& safe_message);

// 发送受控的 AuthenticateServer BF38 数据对象，不开放任意 raw APDU。
esp_err_t idf_esim_lpa_authenticate_server(const std::vector<uint8_t>& request,
                                           std::vector<uint8_t>& response,
                                           std::string& safe_message);

// 发送受控的 PrepareDownload BF21 数据对象。
esp_err_t idf_esim_lpa_prepare_download(const std::vector<uint8_t>& request,
                                        std::vector<uint8_t>& response,
                                        std::string& safe_message);

// 检索 eUICC 中的待发送通知，并返回 A0 列表的 value 范围。
esp_err_t idf_esim_lpa_retrieve_notifications(std::vector<uint8_t>& encoded_response,
                                              size_t& list_offset,
                                              size_t& list_length,
                                              std::string& safe_message);

// 按序号移除一条通知，并校验卡侧业务状态。
esp_err_t idf_esim_lpa_remove_notification(uint32_t sequence_number,
                                           std::string& safe_message);

// 一个 BPP segment 的卡侧会话；会话不可复制，区块序号在发送前检查为单字节范围。
class IdfEsimLpaBppSession {
public:
    IdfEsimLpaBppSession();
    IdfEsimLpaBppSession(const IdfEsimLpaBppSession&) = delete;
    IdfEsimLpaBppSession& operator=(const IdfEsimLpaBppSession&) = delete;
    IdfEsimLpaBppSession(IdfEsimLpaBppSession&& other) noexcept;
    IdfEsimLpaBppSession& operator=(IdfEsimLpaBppSession&& other) noexcept;
    ~IdfEsimLpaBppSession();

    esp_err_t begin_segment(std::string& safe_message);
    esp_err_t write_block(const uint8_t* data,
                          size_t length,
                          bool last,
                          uint16_t block_number,
                          std::vector<uint8_t>& response,
                          std::string& safe_message);
    void close();

private:
    void* impl_;
};
