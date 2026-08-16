#include "idf_push_core.h"

#include <array>
#include <utility>

static size_t utf8_char_length(const unsigned char* data, size_t remaining)
{
    if (remaining == 0) return 0;
    const unsigned char first = data[0];
    if (first < 0x80) return 1;
    if (first >= 0xC2 && first <= 0xDF) {
        return remaining >= 2 && data[1] >= 0x80 && data[1] <= 0xBF ? 2 : 0;
    }
    if (first >= 0xE0 && first <= 0xEF) {
        if (remaining < 3 || data[2] < 0x80 || data[2] > 0xBF) return 0;
        if (first == 0xE0) return data[1] >= 0xA0 && data[1] <= 0xBF ? 3 : 0;
        if (first == 0xED) return data[1] >= 0x80 && data[1] <= 0x9F ? 3 : 0;
        return data[1] >= 0x80 && data[1] <= 0xBF ? 3 : 0;
    }
    if (first >= 0xF0 && first <= 0xF4) {
        if (remaining < 4 || data[2] < 0x80 || data[2] > 0xBF ||
            data[3] < 0x80 || data[3] > 0xBF) return 0;
        if (first == 0xF0) return data[1] >= 0x90 && data[1] <= 0xBF ? 4 : 0;
        if (first == 0xF4) return data[1] >= 0x80 && data[1] <= 0x8F ? 4 : 0;
        return data[1] >= 0x80 && data[1] <= 0xBF ? 4 : 0;
    }
    return 0;
}

bool idf_push_utf8_valid(const std::string& value)
{
    size_t pos = 0;
    while (pos < value.size()) {
        size_t length = utf8_char_length(
            reinterpret_cast<const unsigned char*>(value.data() + pos), value.size() - pos);
        if (length == 0) return false;
        pos += length;
    }
    return true;
}

bool idf_push_render_template(const std::string& source, const IdfPushTemplateValues& values,
                              size_t max_bytes, bool header, std::string& output)
{
    const std::array<std::pair<const char*, const std::string*>, 10> replacements = {{
        {"{sender}", &values.sender},
        {"{message}", &values.message},
        {"{timestamp}", &values.timestamp},
        {"{device}", &values.device},
        {"{localNumber}", &values.localNumber},
        {"{ip}", &values.ip},
        {"{hostname}", &values.hostname},
        {"{wifi}", &values.wifi},
        {"{receiver}", &values.localNumber},
        {"{local_number}", &values.localNumber},
    }};
    if (!idf_push_utf8_valid(source)) return false;
    for (const auto& replacement : replacements) {
        if (!idf_push_utf8_valid(*replacement.second)) return false;
    }

    output.clear();
    output.reserve(source.size() < max_bytes ? source.size() : max_bytes);
    for (size_t pos = 0; pos < source.size();) {
        const std::string* value = nullptr;
        size_t token_length = 0;
        if (source[pos] == '{') {
            for (const auto& replacement : replacements) {
                token_length = std::char_traits<char>::length(replacement.first);
                if (source.compare(pos, token_length, replacement.first) == 0) {
                    value = replacement.second;
                    break;
                }
            }
        }
        if (value) {
            if (value->size() > max_bytes - output.size()) return false;
            output += *value;
            pos += token_length;
        } else {
            if (output.size() == max_bytes) return false;
            output += source[pos++];
        }
    }
    if (!idf_push_utf8_valid(output)) return false;
    if (header) {
        for (unsigned char ch : output) {
            if (ch < 0x20 || ch == 0x7F) return false;
        }
    }
    return true;
}

bool idf_push_render_sms_notification(const std::string& locale,
                                      const std::string& title_template,
                                      const std::string& body_template,
                                      const IdfPushTemplateValues& values,
                                      std::string& title, std::string& body)
{
    const char* default_title = "來自 {sender} 的簡訊";
    const char* default_body = "裝置：{device}\n寄件者：{sender}\n時間：{timestamp}\n內容：{message}";
    if (locale == NOTIFICATION_LOCALE_EN) {
        default_title = "SMS from {sender}";
        default_body = "Device: {device}\nSender: {sender}\nTime: {timestamp}\nMessage: {message}";
    } else if (locale == NOTIFICATION_LOCALE_ZH_CN) {
        default_title = "来自 {sender} 的短信";
        default_body = "设备：{device}\n发件人：{sender}\n时间：{timestamp}\n内容：{message}";
    }
    const std::string& title_source = title_template.empty() ? std::string(default_title) : title_template;
    const std::string& body_source = body_template.empty() ? std::string(default_body) : body_template;
    return idf_push_render_template(title_source, values, MAX_RENDERED_TITLE_BYTES, true, title) &&
           idf_push_render_template(body_source, values, MAX_RENDERED_BODY_BYTES, false, body);
}

bool idf_push_network_uses_wifi(NetworkMode mode, bool wifi_connected)
{
    return idf_push_select_network(mode, wifi_connected) == IdfPushNetworkDecision::Wifi;
}

IdfPushNetworkDecision idf_push_select_network(NetworkMode mode, bool wifi_connected)
{
    if (mode == NETWORK_MODE_4G_ONLY) return IdfPushNetworkDecision::Unsupported;
    if (mode == NETWORK_MODE_WIFI_ONLY || mode == NETWORK_MODE_MIX) {
        return wifi_connected ? IdfPushNetworkDecision::Wifi : IdfPushNetworkDecision::Defer;
    }
    return IdfPushNetworkDecision::Unsupported;
}

size_t idf_push_utf8_codepoint_count(const std::string& value, size_t limit)
{
    size_t pos = 0;
    size_t count = 0;
    while (pos < value.size()) {
        size_t length = utf8_char_length(
            reinterpret_cast<const unsigned char*>(value.data() + pos), value.size() - pos);
        if (length == 0 || ++count > limit) return limit + 1;
        pos += length;
    }
    return count;
}
