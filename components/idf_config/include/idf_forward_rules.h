#pragma once

#include <string>
#include <cstdint>
#include <utility>
#include <vector>

// Mark CSV explicitly; unmarked settings retain the legacy Tab semantics.
inline constexpr char IDF_FORWARD_CSV_PREFIX[] = "#!forward-rules-csv-v1\n";
struct IdfForwardRule {
    std::string type, pattern, action, enabled;
    size_t line = 1;
};
struct IdfForwardDecision {
    bool matched = false;
    bool drop = false;
    uint32_t chMask = 0;
    bool email = false;
    size_t line = 0;
};

inline std::string idf_forward_trim(const std::string& value)
{
    const auto first = value.find_first_not_of(" \t\r\n\f\v");
    if (first == std::string::npos) return {};
    return value.substr(first, value.find_last_not_of(" \t\r\n\f\v") - first + 1);
}

inline bool idf_forward_parse(const std::string& text, std::vector<IdfForwardRule>& rows,
                              size_t& error_line, std::string& error)
{
    rows.clear(); error.clear(); error_line = 0;
    const bool csv = text.compare(0, sizeof(IDF_FORWARD_CSV_PREFIX) - 1, IDF_FORWARD_CSV_PREFIX) == 0;
    size_t pos = csv ? sizeof(IDF_FORWARD_CSV_PREFIX) - 1 : 0, line = 1;
    auto fail = [&](size_t at, const char* reason) { error_line = at; error = reason; return false; };
    while (pos < text.size()) {
        const size_t start = line;
        if (!csv) {
            size_t end = text.find('\n', pos);
            if (end == std::string::npos) end = text.size();
            const std::string raw = idf_forward_trim(text.substr(pos, end - pos));
            pos = end + (end < text.size()); ++line;
            const size_t a = raw.find('\t'), b = a == std::string::npos ? a : raw.find('\t', a + 1);
            if (b == std::string::npos) continue;
            const size_t c = raw.find('\t', b + 1);
            rows.push_back({raw.substr(0, a), raw.substr(a + 1, b - a - 1),
                raw.substr(b + 1, c == std::string::npos ? c : c - b - 1),
                c == std::string::npos ? "1" : idf_forward_trim(raw.substr(c + 1)), start});
            continue;
        }
        if (text[pos] == '\n') { ++pos; ++line; continue; }
        if (text[pos] == '\r' && pos + 1 < text.size() && text[pos + 1] == '\n') { pos += 2; ++line; continue; }
        std::vector<std::string> fields;
        bool more = true;
        while (more) {
            std::string value;
            if (pos < text.size() && text[pos] == '"') {
                ++pos; bool closed = false;
                while (pos < text.size()) {
                    const char ch = text[pos++];
                    if (ch == '"') {
                        if (pos < text.size() && text[pos] == '"') { value += '"'; ++pos; }
                        else { closed = true; break; }
                    } else { value += ch; if (ch == '\n') ++line; }
                }
                if (!closed) return fail(start, "quotes");
            } else {
                while (pos < text.size() && text[pos] != ',' && text[pos] != '\n' && text[pos] != '\r') {
                    if (text[pos] == '"') return fail(start, "quotes");
                    value += text[pos++];
                }
            }
            fields.push_back(std::move(value));
            if (fields.size() > 4) return fail(start, "columns");
            if (pos == text.size()) more = false;
            else if (text[pos] == ',') ++pos;
            else if (text[pos] == '\n') { ++pos; ++line; more = false; }
            else if (text[pos] == '\r' && pos + 1 < text.size() && text[pos + 1] == '\n') { pos += 2; ++line; more = false; }
            else return fail(start, "quotes");
        }
        if (fields.size() < 3) return fail(start, "columns");
        if (fields[0] != "kw" && fields[0] != "from" && fields[0] != "re") return fail(start, "type");
        const std::string enabled = fields.size() == 3 || fields[3].empty() ? "1" : fields[3];
        if (enabled != "0" && enabled != "1") return fail(start, "enabled");
        size_t offset = 0;
        while (offset < fields[2].size()) {
            const size_t end = fields[2].find(',', offset);
            const std::string action = idf_forward_trim(fields[2].substr(offset, end == std::string::npos ? end : end - offset));
            if (action != "drop" && action != "email" && action != "1" && action != "2" && action != "3" && action != "4" && action != "5") return fail(start, "action");
            if (end == std::string::npos) break;
            offset = end + 1;
            if (offset == fields[2].size()) return fail(start, "action");
        }
        rows.push_back({fields[0], fields[1], fields[2], enabled, start});
    }
    return true;
}
