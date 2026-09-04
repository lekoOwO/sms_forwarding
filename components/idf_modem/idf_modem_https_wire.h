#pragma once

#include "idf_modem_https.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace idf_modem_https_wire {

inline constexpr size_t kResponseMax = 16384;
inline constexpr size_t kLineMax = 12288;
inline constexpr size_t kSendMax = 1460;
inline constexpr size_t kReadMax = 4096;
inline constexpr size_t kHttpHeaderMax = 4096;
inline constexpr size_t kHttpBodyMax = 65536;

enum class MipStateDisposition : uint8_t {
    invalid,
    initial,
    connected,
    connecting,
    closed,
};

bool scan_frame(std::string_view response, std::string_view command,
                std::vector<std::string_view>& body,
                IdfModemHttpsParseReason* reason = nullptr,
                IdfModemHttpsParseShape* shape = nullptr,
                uint8_t* command_echo_count = nullptr,
                bool* ignored_auxiliary_seen = nullptr);
bool parse_cfg_response(std::string_view response, std::string_view command,
                        std::string_view parameter, uint8_t& first, uint8_t& second,
                        bool& has_second);
bool parse_mip_state(std::string_view response, std::string_view command,
                     std::string_view expected, uint8_t& cid,
                     IdfModemHttpsParseReason* reason = nullptr,
                     IdfModemHttpsParseShape* shape = nullptr);
MipStateDisposition classify_mip_state(std::string_view response,
                                       std::string_view command,
                                       uint8_t expected_cid,
                                       IdfModemHttpsParseReason* reason = nullptr,
                                       IdfModemHttpsParseShape* shape = nullptr);
bool parse_mip_open(std::string_view response, std::string_view command,
                    uint8_t expected_cid, bool& present);
bool parse_mip_urc(std::string_view line, uint32_t& received, uint32_t& total,
                   uint8_t& state, bool& disconnected);
bool parse_cgdccont(std::string_view response, std::string_view command, uint8_t cid,
                    std::string* apn = nullptr, std::string* profile = nullptr);
bool build_cgdccont_command(uint8_t cid, std::string_view apn, std::string& command);
bool parse_cgact(std::string_view response, std::string_view command, uint8_t cid,
                bool& active);
bool parse_result(std::string_view response, std::string_view command,
                  std::string_view prefix, uint8_t expected_cid, uint32_t& value,
                  IdfModemHttpsParseReason* reason = nullptr,
                  IdfModemHttpsParseShape* shape = nullptr);
bool parse_mip_close_result(std::string_view response, std::string_view command,
                            uint8_t expected_cid, uint32_t& value,
                            IdfModemHttpsParseReason* reason = nullptr,
                            IdfModemHttpsParseShape* shape = nullptr,
                            bool* requires_confirmation = nullptr);
bool parse_read(std::string_view response, std::string_view command, uint8_t cid,
                uint32_t& unread, std::vector<uint8_t>& data, bool& remote_closed,
                IdfModemHttpsParseReason* reason = nullptr,
                IdfModemHttpsParseShape* shape = nullptr,
                bool* no_data = nullptr);
std::string hex_encode(const uint8_t* bytes, size_t length);

class MipOpenLatch {
public:
    void begin();
    bool feed(std::string_view bytes);
    bool finish();
    void reset();
    bool active() const { return active_; }
    bool connected() const { return connected_; }
    bool nonfatal() const { return !failed_; }

private:
    bool consume_line(std::string_view line);

    std::string carry_;
    bool active_ = false;
    bool connected_ = false;
    bool failed_ = false;
    bool success_seen_ = false;
};

class HttpResponse {
public:
    bool feed(const uint8_t* bytes, size_t length, IdfModemHttpsPostResult& result);
    bool finish_eof(IdfModemHttpsPostResult& result);
    bool complete() const { return complete_; }
    size_t header_bytes() const { return header_bytes_; }

private:
    bool parse_header(size_t body_start, IdfModemHttpsPostResult& result);

    std::string header_;
    size_t header_bytes_ = 0;
    size_t response_bytes_ = 0;
    size_t body_bytes_ = 0;
    bool has_content_length_ = false;
    bool header_complete_ = false;
    bool complete_ = false;
};

}  // namespace idf_modem_https_wire
