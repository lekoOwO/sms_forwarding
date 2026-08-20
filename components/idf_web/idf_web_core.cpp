#include "idf_web_core.h"

#include <algorithm>
#include <cstring>
#include <cctype>
#include <iterator>
#include <new>
#include <vector>

bool idf_web_constant_time_equal(const char* actual, size_t actual_len,
                                 const std::string& expected)
{
    size_t length = actual_len > expected.size() ? actual_len : expected.size();
    unsigned char difference = actual_len == expected.size() ? 0 : 1;
    for (size_t i = 0; i < length; ++i) {
        unsigned char left = i < actual_len ? static_cast<unsigned char>(actual[i]) : 0;
        unsigned char right = i < expected.size() ? static_cast<unsigned char>(expected[i]) : 0;
        difference |= left ^ right;
    }
    return difference == 0;
}

bool idf_web_ap_auth_bypass(bool ap_mode, bool ap_local, const char* uri)
{
    if (!ap_mode || !ap_local || !uri) return false;
    const size_t path_len = strcspn(uri, "?");
    static const char* const allowed[] = {"/wifiscan", "/wificonfig", "/apstatus"};
    return std::any_of(std::begin(allowed), std::end(allowed), [uri, path_len](const char* path) {
        return strlen(path) == path_len && strncmp(uri, path, path_len) == 0;
    });
}

bool idf_web_ap_csrf_bypass(bool ap_mode, bool ap_local, const char* uri, const char* token)
{
    return ap_mode && ap_local && uri && token && strcmp(uri, "/wificonfig") == 0 &&
           strcmp(token, "1") == 0;
}

bool idf_web_at_command_allowed(const std::string& input)
{
    if (input.empty() || input.size() > 256 || input.find_first_of("\r\n") != std::string::npos) {
        return false;
    }
    size_t begin = 0;
    while (begin < input.size() && std::isspace(static_cast<unsigned char>(input[begin]))) ++begin;
    size_t end = input.size();
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1]))) --end;
    std::string cmd = input.substr(begin, end - begin);
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), [](char ch) {
        return static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    });
    if (cmd.compare(0, 2, "AT") != 0) return false;
    return cmd.compare(0, 3, "ATD") != 0 && cmd != "ATO" &&
           cmd.compare(0, 7, "AT+CMGS") != 0 && cmd.compare(0, 7, "AT+CMGW") != 0 &&
           cmd.compare(0, 9, "AT+CGDATA") != 0 && cmd.compare(0, 7, "AT+CMUX") != 0 &&
           cmd.find("CIPSEND") == std::string::npos && cmd.find("QISEND") == std::string::npos &&
           cmd.find("CASEND") == std::string::npos;
}

static int hex_value(char ch)
{
    if (ch >= '0' && ch <= '9') return ch - '0';
    if (ch >= 'a' && ch <= 'f') return ch - 'a' + 10;
    if (ch >= 'A' && ch <= 'F') return ch - 'A' + 10;
    return -1;
}

bool idf_web_valid_utf8_text(const std::string& value)
{
    for (size_t i = 0; i < value.size();) {
        const unsigned char first = static_cast<unsigned char>(value[i]);
        if (first == 0 || (first < 0x20 && first != '\t' && first != '\n' && first != '\r') ||
            first == 0x7f) return false;
        size_t continuation = 0;
        uint32_t codepoint = 0;
        if (first < 0x80) { ++i; continue; }
        if ((first & 0xe0) == 0xc0) { continuation = 1; codepoint = first & 0x1f; }
        else if ((first & 0xf0) == 0xe0) { continuation = 2; codepoint = first & 0x0f; }
        else if ((first & 0xf8) == 0xf0) { continuation = 3; codepoint = first & 0x07; }
        else return false;
        if (i + continuation >= value.size()) return false;
        for (size_t j = 1; j <= continuation; ++j) {
            const unsigned char next = static_cast<unsigned char>(value[i + j]);
            if ((next & 0xc0) != 0x80) return false;
            codepoint = (codepoint << 6) | (next & 0x3f);
        }
        if ((continuation == 1 && codepoint < 0x80) ||
            (continuation == 2 && codepoint < 0x800) ||
            (continuation == 3 && codepoint < 0x10000) ||
            (codepoint >= 0xd800 && codepoint <= 0xdfff) || codepoint > 0x10ffff) return false;
        i += continuation + 1;
    }
    return true;
}

static bool decode_component(const char* data, size_t len, std::string& out)
{
    out.clear();
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        const char ch = data[i];
        if (ch == '+') out.push_back(' ');
        else if (ch == '%') {
            if (i + 2 >= len) return false;
            const int hi = hex_value(data[i + 1]);
            const int lo = hex_value(data[i + 2]);
            if (hi < 0 || lo < 0) return false;
            out.push_back(static_cast<char>((hi << 4) | lo));
            i += 2;
        } else out.push_back(ch);
    }
    return idf_web_valid_utf8_text(out);
}

IdfWebFormDecodeResult idf_web_decode_form(const std::string& body, size_t max_fields)
{
    IdfWebFormDecodeResult result;
    size_t pos = 0;
    while (pos <= body.size()) {
        const size_t amp_found = body.find('&', pos);
        const size_t amp = amp_found == std::string::npos ? body.size() : amp_found;
        size_t eq = body.find('=', pos);
        if (eq == std::string::npos || eq > amp) eq = amp;
        std::string key;
        std::string value;
        if (!decode_component(body.data() + pos, eq - pos, key) ||
            (eq < amp && !decode_component(body.data() + eq + 1, amp - eq - 1, value))) return result;
        if (!key.empty()) {
            if (result.fields.size() >= max_fields) {
                result.too_many_fields = true;
                return result;
            }
            result.fields.emplace_back(std::move(key), std::move(value));
        }
        if (amp == body.size()) break;
        pos = amp + 1;
    }
    result.valid = true;
    return result;
}

IdfWebOwnedJobInput idf_web_own_job_input(const char* type, const char* payload,
                                          size_t payload_size)
{
    IdfWebOwnedJobInput input;
    if (type) input.type = type;
    if (payload && payload_size) input.payload.assign(payload, payload_size);
    return input;
}

template <typename Buffer>
static void secure_clear(Buffer& value)
{
    volatile unsigned char* bytes = reinterpret_cast<volatile unsigned char*>(value.data());
    for (size_t i = 0; i < value.size(); ++i) bytes[i] = 0;
    value.clear();
    value.shrink_to_fit();
}

void idf_web_secure_clear(std::string& value) { secure_clear(value); }
void idf_web_secure_clear(std::vector<uint8_t>& value) { secure_clear(value); }

void idf_web_secure_clear(IdfWebOwnedBytes& value)
{
    volatile uint8_t* bytes = value.data.get();
    for (size_t i = 0; i < value.capacity; ++i) bytes[i] = 0;
    value.data.reset();
    value.size = 0;
    value.capacity = 0;
}

bool idf_web_allocate_owned_bytes(IdfWebOwnedBytes& value, size_t size,
                                  IdfWebByteAllocator allocator)
{
    idf_web_secure_clear(value);
    if (size == 0) return false;
    std::unique_ptr<uint8_t[]> storage(
        allocator ? allocator(size) : new (std::nothrow) uint8_t[size]);
    if (!storage) return false;
    value.data = std::move(storage);
    value.capacity = size;
    return true;
}

bool idf_web_finalize_owned_bytes(IdfWebOwnedBytes& value, size_t written,
                                  size_t maximum)
{
    if (!value.data || written == 0 || written > maximum || written > value.capacity) {
        idf_web_secure_clear(value);
        return false;
    }
    value.size = written;
    return true;
}

void idf_web_transfer_clear(IdfWebTransfer& transfer)
{
    idf_web_secure_clear(transfer.bytes);
    transfer = IdfWebTransfer();
}

bool idf_web_transfer_expire(IdfWebTransfer& transfer, uint32_t now_ms, uint32_t ttl_ms)
{
    if (transfer.mode == IdfWebTransferMode::None || transfer.expected_size == 0 ||
        now_ms - transfer.started_ms < ttl_ms) {
        return false;
    }
    idf_web_transfer_clear(transfer);
    return true;
}

bool idf_web_transfer_start(IdfWebTransfer& transfer, IdfWebTransferMode mode,
                            uint32_t id, size_t expected_size, uint32_t now_ms,
                            IdfWebByteAllocator allocator)
{
    if (transfer.mode != IdfWebTransferMode::None || mode == IdfWebTransferMode::None ||
        id == 0 || expected_size == 0) return false;
    transfer.mode = mode;
    transfer.id = id;
    transfer.started_ms = now_ms;
    transfer.expected_size = expected_size;
    if (idf_web_allocate_owned_bytes(transfer.bytes, expected_size, allocator)) return true;
    transfer = IdfWebTransfer();
    return false;
}

bool idf_web_transfer_append(IdfWebTransfer& transfer, uint32_t id, size_t offset,
                             const uint8_t* chunk, size_t chunk_size, size_t max_chunk)
{
    if (transfer.mode != IdfWebTransferMode::Restore || transfer.id != id ||
        transfer.expected_size == 0) return false;
    if (!chunk || chunk_size == 0 || chunk_size > max_chunk || offset != transfer.bytes.size ||
        transfer.bytes.size > transfer.expected_size ||
        chunk_size > transfer.expected_size - transfer.bytes.size) {
        idf_web_transfer_clear(transfer);
        return false;
    }
    memcpy(transfer.bytes.data.get() + transfer.bytes.size, chunk, chunk_size);
    transfer.bytes.size += chunk_size;
    return true;
}

bool idf_web_transfer_cancel_upload(IdfWebTransfer& transfer, uint32_t id)
{
    if (transfer.mode != IdfWebTransferMode::Restore || transfer.id != id ||
        transfer.expected_size == 0) return false;
    idf_web_transfer_clear(transfer);
    return true;
}

bool idf_web_transfer_take_complete(IdfWebTransfer& transfer, uint32_t id,
                                    IdfWebOwnedBytes& output)
{
    if (transfer.mode != IdfWebTransferMode::Restore || transfer.id != id ||
        transfer.expected_size == 0 || transfer.bytes.size != transfer.expected_size) return false;
    idf_web_secure_clear(output);
    output = std::move(transfer.bytes);
    transfer.expected_size = 0;
    return true;
}

std::string idf_web_paginate_log_json(const std::string& snapshot, bool has_cursor,
                                      uint32_t cursor, size_t limit)
{
    static const std::string empty =
        "{\"entries\":[],\"nextCursor\":null,\"hasMore\":false}";
    static const char prefix[] = "{\"seq\":";
    if (snapshot.compare(0, sizeof(prefix) - 1, prefix) != 0 || limit == 0) return empty;

    size_t pos = sizeof(prefix) - 1;
    uint32_t seq = 0;
    size_t digits = 0;
    while (pos < snapshot.size() && snapshot[pos] >= '0' && snapshot[pos] <= '9') {
        const uint8_t digit = static_cast<uint8_t>(snapshot[pos] - '0');
        if (seq > 429496729U || (seq == 429496729U && digit > 5)) return empty;
        seq = seq * 10U + digit;
        ++pos;
        ++digits;
    }
    static const char lines_prefix[] = ",\"lines\":[";
    if (digits == 0 || snapshot.compare(pos, sizeof(lines_prefix) - 1, lines_prefix) != 0) return empty;
    pos += sizeof(lines_prefix) - 1;

    std::vector<std::string> lines;
    while (pos < snapshot.size() && snapshot[pos] != ']') {
        if (snapshot[pos] != '"') return empty;
        const size_t start = pos++;
        bool escaped = false;
        bool closed = false;
        while (pos < snapshot.size()) {
            const char ch = snapshot[pos++];
            if (escaped) {
                escaped = false;
            } else if (ch == '\\') {
                escaped = true;
            } else if (ch == '"') {
                closed = true;
                break;
            }
        }
        if (!closed) return empty;
        lines.push_back(snapshot.substr(start, pos - start));
        if (pos < snapshot.size() && snapshot[pos] == ',') ++pos;
        else if (pos >= snapshot.size() || snapshot[pos] != ']') return empty;
    }
    if (pos + 2 != snapshot.size() || snapshot.compare(pos, 2, "]}") != 0 ||
        static_cast<uint64_t>(seq) + 1 < lines.size()) return empty;

    const uint32_t first_id = seq - static_cast<uint32_t>(lines.size()) + 1U;
    size_t end = lines.size();
    if (has_cursor && cursor != 0) {
        if (cursor <= first_id) end = 0;
        else if (cursor <= seq) end = static_cast<size_t>(cursor - first_id);
    }
    const size_t begin = end > limit ? end - limit : 0;
    const bool has_more = begin > 0;

    std::string out = "{\"entries\":[";
    for (size_t i = begin; i < end; ++i) {
        if (i != begin) out += ",";
        out += "{\"id\":" + std::to_string(first_id + static_cast<uint32_t>(i)) +
               ",\"message\":" + lines[i] + "}";
    }
    out += "],\"nextCursor\":";
    out += has_more ? std::to_string(first_id + static_cast<uint32_t>(begin)) : "null";
    out += ",\"hasMore\":";
    out += has_more ? "true}" : "false}";
    return out;
}

size_t idf_web_count_active_jobs(const IdfWebJobSlotMeta* slots, size_t count)
{
    if (!slots || count == 0) return 0;
    return static_cast<size_t>(std::count_if(slots, slots + count, [](const IdfWebJobSlotMeta& slot) {
        return slot.state == IdfWebJobState::Queued || slot.state == IdfWebJobState::Running;
    }));
}

int idf_web_select_job_slot(const IdfWebJobSlotMeta* slots, size_t count,
                            uint32_t now_ms, uint32_t ttl_ms)
{
    for (size_t i = 0; i < count; ++i) {
        if (slots[i].state == IdfWebJobState::Empty) return static_cast<int>(i);
    }

    int oldest_done = -1;
    uint32_t oldest_age = 0;
    for (size_t i = 0; i < count; ++i) {
        if (slots[i].state != IdfWebJobState::Done) continue;
        uint32_t age = now_ms - slots[i].completed_ms;
        if (age >= ttl_ms) return static_cast<int>(i);
        if (oldest_done < 0 || age > oldest_age) {
            oldest_done = static_cast<int>(i);
            oldest_age = age;
        }
    }
    return oldest_done;
}
