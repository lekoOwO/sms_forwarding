#include "idf_push_cellular.h"

#include <algorithm>
#include <cctype>

namespace {

bool canonical_https_origin(const std::string& url, std::string& origin)
{
    constexpr char prefix[] = "https://";
    if (url.compare(0, sizeof(prefix) - 1, prefix) != 0) return false;
    const size_t authority_start = sizeof(prefix) - 1;
    const size_t authority_end = url.find_first_of("/?#", authority_start);
    std::string authority = url.substr(authority_start, authority_end - authority_start);
    if (authority.empty() || authority.find('@') != std::string::npos) return false;
    std::transform(authority.begin(), authority.end(), authority.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    if (authority.back() == '.') authority.pop_back();
    if (authority.empty()) return false;
    if (authority.size() > 4 && authority.compare(authority.size() - 4, 4, ":443") == 0) {
        authority.resize(authority.size() - 4);
    }
    if (authority.empty()) return false;
    origin = std::string(prefix) + authority;
    return true;
}

std::string inherited_url(const IdfPushChannel& channel)
{
    if (!channel.url.empty()) return channel.url;
    if (channel.type == PUSH_TYPE_PUSHPLUS) return "https://www.pushplus.plus/send";
    if (channel.type == PUSH_TYPE_SERVERCHAN) return "https://sctapi.ftqq.com/";
    if (channel.type == PUSH_TYPE_TELEGRAM) return "https://api.telegram.org";
    return {};
}

}  // namespace

bool idf_push_prepare_cellular_target(const IdfPushChannel& channel,
                                      IdfPushCellularTarget& target)
{
    target = {};
    if (!channel.enabled || !channel.cellularEnabled) return false;
    target.effectiveUrl = channel.cellularUrl.empty() ? inherited_url(channel)
                                                       : channel.cellularUrl;
    if (!canonical_https_origin(target.effectiveUrl, target.canonicalOrigin)) {
        target = {};
        return false;
    }
    return true;
}
