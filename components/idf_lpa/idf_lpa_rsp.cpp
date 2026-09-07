#include "idf_lpa_rsp.h"

#include "idf_esim_codec.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <initializer_list>
#include <limits>
#include <string>
#include <string_view>
#include <utility>

#ifdef ESP_PLATFORM
#include "psa/crypto.h"
#else
// OpenSSL is used only by the host fixture; it is not evidence of PSA target behavior.
#include <openssl/evp.h>
#endif

namespace {

constexpr std::size_t kMaxJsonKeys = 32U;
constexpr std::size_t kMaxJsonDepth = 8U;
constexpr std::size_t kMaxTransactionBytes = 16U;
constexpr std::size_t kMaxSignatureBytes = 1024U;
constexpr std::size_t kMaxCiKeyBytes = 128U;
constexpr std::size_t kMaxOtpkBytes = 128U;
constexpr std::size_t kMaxOidBytes = 64U;
constexpr std::size_t kHashBytes = 32U;
constexpr std::size_t kMaxBase64EncodedBytes =
    ((IDF_LPA_RSP_MAX_OBJECT_BYTES + 2U) / 3U) * 4U;

void secure_zero(void* address, std::size_t size) noexcept
{
    volatile auto* bytes = static_cast<volatile std::uint8_t*>(address);
    while (size != 0U) {
        *bytes = 0U;
        ++bytes;
        --size;
    }
}

void clear_string(std::string& value) noexcept
{
    const std::size_t capacity = value.capacity();
    if (capacity > value.size()) value.resize(capacity, '\0');
    if (capacity != 0U) secure_zero(value.data(), capacity);
    value.clear();
    std::string().swap(value);
}

void clear_bytes(std::vector<std::uint8_t>& value) noexcept
{
    const std::size_t capacity = value.capacity();
    if (capacity != 0U) secure_zero(value.data(), capacity);
    value.clear();
    std::vector<std::uint8_t>().swap(value);
}

bool fail(LpaRspError& error, LpaRspError value) noexcept
{
    error = value;
    return false;
}

bool base64_fail(std::vector<std::uint8_t>& output,
                 LpaRspError& error,
                 LpaRspError value) noexcept
{
    clear_bytes(output);
    return fail(error, value);
}

int hex_value(unsigned char value) noexcept
{
    if (value >= static_cast<unsigned char>('0') &&
        value <= static_cast<unsigned char>('9')) {
        return static_cast<int>(value - static_cast<unsigned char>('0'));
    }
    if (value >= static_cast<unsigned char>('A') &&
        value <= static_cast<unsigned char>('F')) {
        return static_cast<int>(value - static_cast<unsigned char>('A')) + 10;
    }
    if (value >= static_cast<unsigned char>('a') &&
        value <= static_cast<unsigned char>('f')) {
        return static_cast<int>(value - static_cast<unsigned char>('a')) + 10;
    }
    return -1;
}

bool is_json_space(unsigned char value) noexcept
{
    return value == static_cast<unsigned char>(' ') ||
           value == static_cast<unsigned char>('\t') ||
           value == static_cast<unsigned char>('\r') ||
           value == static_cast<unsigned char>('\n');
}

class JsonScanner {
public:
    explicit JsonScanner(std::string_view input) : input_(input) {}

    bool get_string(std::string_view wanted,
                    std::string& out,
                    LpaRspError& error)
    {
        if (wanted.empty() || wanted.size() > 128U) return fail(error, LpaRspError::json_malformed);
        skip_space();
        bool found = false;
        if (!parse_object_member(wanted, out, found, error)) return false;
        skip_space();
        if (position_ != input_.size()) return fail(error, LpaRspError::json_malformed);
        if (!found) return fail(error, LpaRspError::json_missing);
        return true;
    }

    bool get_header_function_status(std::string& out,
                                    LpaRspError& error)
    {
        skip_space();
        if (!consume('{')) return fail(error, LpaRspError::json_malformed);
        std::array<std::string_view, kMaxJsonKeys> keys = {};
        std::size_t key_count = 0U;
        bool header_found = false;
        skip_space();
        if (consume('}')) {
            skip_space();
            if (position_ != input_.size()) return fail(error, LpaRspError::json_malformed);
            return fail(error, LpaRspError::json_missing);
        }
        while (true) {
            std::string_view key;
            if (!parse_string_view(key)) return fail(error, LpaRspError::json_malformed);
            for (std::size_t i = 0U; i < key_count; ++i) {
                if (keys[i] == key) return fail(error, LpaRspError::json_duplicate);
            }
            if (key_count == keys.size()) return fail(error, LpaRspError::json_malformed);
            keys[key_count++] = key;
            skip_space();
            if (!consume(':')) return fail(error, LpaRspError::json_malformed);
            skip_space();
            if (key == "header") {
                if (!parse_nested_object_member(
                        "functionExecutionStatus", "status", out, error)) {
                    return false;
                }
                header_found = true;
            } else if (!skip_value(0U, error)) {
                return false;
            }
            skip_space();
            if (consume('}')) break;
            if (!consume(',')) return fail(error, LpaRspError::json_malformed);
            skip_space();
        }
        skip_space();
        if (position_ != input_.size()) return fail(error, LpaRspError::json_malformed);
        if (!header_found) return fail(error, LpaRspError::json_missing);
        return true;
    }

private:
    bool parse_nested_object_member(std::string_view wanted_parent,
                                    std::string_view wanted,
                                    std::string& out,
                                    LpaRspError& error)
    {
        if (!consume('{')) return fail(error, LpaRspError::json_type);
        std::array<std::string_view, kMaxJsonKeys> keys = {};
        std::size_t key_count = 0U;
        bool parent_found = false;
        skip_space();
        if (consume('}')) return fail(error, LpaRspError::json_missing);
        while (true) {
            std::string_view key;
            if (!parse_string_view(key)) return fail(error, LpaRspError::json_malformed);
            for (std::size_t i = 0U; i < key_count; ++i) {
                if (keys[i] == key) return fail(error, LpaRspError::json_duplicate);
            }
            if (key_count == keys.size()) return fail(error, LpaRspError::json_malformed);
            keys[key_count++] = key;
            skip_space();
            if (!consume(':')) return fail(error, LpaRspError::json_malformed);
            skip_space();
            if (key == wanted_parent) {
                if (position_ >= input_.size() || input_[position_] != '{') {
                    if (!skip_value(0U, error)) return false;
                    return fail(error, LpaRspError::json_type);
                }
                bool nested_found = false;
                if (!parse_object_member(wanted, out, nested_found, error)) return false;
                if (!nested_found) return fail(error, LpaRspError::json_missing);
                parent_found = true;
            } else if (!skip_value(0U, error)) {
                return false;
            }
            skip_space();
            if (consume('}')) break;
            if (!consume(',')) return fail(error, LpaRspError::json_malformed);
            skip_space();
        }
        if (!parent_found) return fail(error, LpaRspError::json_missing);
        return true;
    }

    bool parse_object_member(std::string_view wanted,
                             std::string& out,
                             bool& found,
                             LpaRspError& error)
    {
        if (!consume('{')) return fail(error, LpaRspError::json_type);
        std::array<std::string_view, kMaxJsonKeys> keys = {};
        std::size_t key_count = 0U;
        skip_space();
        if (consume('}')) return true;
        while (true) {
            std::string_view key;
            if (!parse_string_view(key)) return fail(error, LpaRspError::json_malformed);
            for (std::size_t i = 0U; i < key_count; ++i) {
                if (keys[i] == key) return fail(error, LpaRspError::json_duplicate);
            }
            if (key_count == keys.size()) return fail(error, LpaRspError::json_malformed);
            keys[key_count++] = key;
            skip_space();
            if (!consume(':')) return fail(error, LpaRspError::json_malformed);
            skip_space();
            if (key == wanted) {
                if (found) return fail(error, LpaRspError::json_duplicate);
                if (position_ >= input_.size() || input_[position_] != '"') {
                    if (!skip_value(0U, error)) return false;
                    return fail(error, LpaRspError::json_type);
                }
                std::string_view value;
                if (!parse_string_view(value)) return fail(error, LpaRspError::json_malformed);
                out.assign(value.data(), value.size());
                found = true;
            } else if (!skip_value(0U, error)) {
                return false;
            }
            skip_space();
            if (consume('}')) return true;
            if (!consume(',')) return fail(error, LpaRspError::json_malformed);
            skip_space();
        }
    }

    void skip_space() noexcept
    {
        while (position_ < input_.size() &&
               is_json_space(static_cast<unsigned char>(input_[position_]))) {
            ++position_;
        }
    }

    bool consume(char expected) noexcept
    {
        if (position_ >= input_.size() || input_[position_] != expected) return false;
        ++position_;
        return true;
    }

    bool parse_string_view(std::string_view& out)
    {
        if (!consume('"')) return false;
        const std::size_t start = position_;
        while (position_ < input_.size()) {
            const unsigned char value = static_cast<unsigned char>(input_[position_]);
            if (value == static_cast<unsigned char>('"')) {
                out = input_.substr(start, position_ - start);
                ++position_;
                return true;
            }
            // Protocol fields are ASCII strings. Reject escapes instead of decoding into an
            // unbounded temporary or accidentally accepting an escaped delimiter.
            if (value == static_cast<unsigned char>('\\') || value < 0x20U) return false;
            ++position_;
        }
        return false;
    }

    bool skip_value(std::size_t depth, LpaRspError& error)
    {
        if (depth > kMaxJsonDepth || position_ >= input_.size()) {
            return fail(error, LpaRspError::json_malformed);
        }
        switch (input_[position_]) {
        case '"': {
            std::string_view ignored;
            return parse_string_view(ignored) || fail(error, LpaRspError::json_malformed);
        }
        case '{':
            return skip_object(depth + 1U, error);
        case '[':
            return skip_array(depth + 1U, error);
        case 't':
            return consume_literal("true") || fail(error, LpaRspError::json_malformed);
        case 'f':
            return consume_literal("false") || fail(error, LpaRspError::json_malformed);
        case 'n':
            return consume_literal("null") || fail(error, LpaRspError::json_malformed);
        default:
            return skip_number(error);
        }
    }

    bool skip_object(std::size_t depth, LpaRspError& error)
    {
        if (!consume('{')) return fail(error, LpaRspError::json_malformed);
        std::array<std::string_view, kMaxJsonKeys> keys = {};
        std::size_t key_count = 0U;
        skip_space();
        if (consume('}')) return true;
        while (true) {
            std::string_view key;
            if (!parse_string_view(key)) return fail(error, LpaRspError::json_malformed);
            for (std::size_t i = 0U; i < key_count; ++i) {
                if (keys[i] == key) return fail(error, LpaRspError::json_duplicate);
            }
            if (key_count == keys.size()) return fail(error, LpaRspError::json_malformed);
            keys[key_count++] = key;
            skip_space();
            if (!consume(':')) return fail(error, LpaRspError::json_malformed);
            skip_space();
            if (!skip_value(depth, error)) return false;
            skip_space();
            if (consume('}')) return true;
            if (!consume(',')) return fail(error, LpaRspError::json_malformed);
            skip_space();
        }
    }

    bool skip_array(std::size_t depth, LpaRspError& error)
    {
        if (!consume('[')) return fail(error, LpaRspError::json_malformed);
        skip_space();
        if (consume(']')) return true;
        std::size_t count = 0U;
        while (true) {
            if (++count > kMaxJsonKeys || !skip_value(depth, error)) return false;
            skip_space();
            if (consume(']')) return true;
            if (!consume(',')) return fail(error, LpaRspError::json_malformed);
            skip_space();
        }
    }

    bool consume_literal(std::string_view literal) noexcept
    {
        if (input_.size() - position_ < literal.size() ||
            input_.compare(position_, literal.size(), literal) != 0) {
            return false;
        }
        position_ += literal.size();
        return true;
    }

    bool skip_number(LpaRspError& error) noexcept
    {
        const std::size_t start = position_;
        if (position_ < input_.size() && input_[position_] == '-') ++position_;
        if (position_ >= input_.size()) return fail(error, LpaRspError::json_malformed);
        if (input_[position_] == '0') {
            ++position_;
            if (position_ < input_.size() && input_[position_] >= '0' &&
                input_[position_] <= '9') {
                return fail(error, LpaRspError::json_malformed);
            }
        } else {
            if (input_[position_] < '1' || input_[position_] > '9') {
                return fail(error, LpaRspError::json_malformed);
            }
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
        }
        if (position_ < input_.size() && input_[position_] == '.') {
            ++position_;
            const std::size_t fraction_start = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
            if (fraction_start == position_) return fail(error, LpaRspError::json_malformed);
        }
        if (position_ < input_.size() &&
            (input_[position_] == 'e' || input_[position_] == 'E')) {
            ++position_;
            if (position_ < input_.size() &&
                (input_[position_] == '+' || input_[position_] == '-')) {
                ++position_;
            }
            const std::size_t exponent_start = position_;
            while (position_ < input_.size() && input_[position_] >= '0' &&
                   input_[position_] <= '9') {
                ++position_;
            }
            if (exponent_start == position_) return fail(error, LpaRspError::json_malformed);
        }
        if (start == position_) return fail(error, LpaRspError::json_malformed);
        return true;
    }

    std::string_view input_;
    std::size_t position_ = 0U;
};

void clear_tlv(idf_esim_internal::Tlv& value) noexcept
{
    for (idf_esim_internal::Tlv& child : value.children) clear_tlv(child);
    clear_bytes(value.tag);
    clear_bytes(value.value);
    std::vector<idf_esim_internal::Tlv>().swap(value.children);
    value.constructed = false;
}

class SensitiveTlv {
public:
    SensitiveTlv() = default;
    SensitiveTlv(const SensitiveTlv&) = delete;
    SensitiveTlv& operator=(const SensitiveTlv&) = delete;
    ~SensitiveTlv() { clear_tlv(value); }

    idf_esim_internal::Tlv value;
};

struct DerHeader {
    std::size_t value_offset = 0U;
    std::size_t value_length = 0U;
    bool constructed = false;
};

bool read_der_header(const std::uint8_t* data,
                     std::size_t end,
                     std::size_t& position,
                     DerHeader& header) noexcept
{
    if (!data || position >= end) return false;
    const std::uint8_t first_tag = data[position++];
    if (first_tag == 0U) return false;
    if ((first_tag & 0x1FU) == 0x1FU) {
        std::size_t tag_bytes = 0U;
        std::uint8_t tag_byte = 0U;
        do {
            if (position >= end || ++tag_bytes > 4U) return false;
            tag_byte = data[position++];
            if (tag_bytes == 1U && (tag_byte & 0x7FU) == 0U) return false;
        } while ((tag_byte & 0x80U) != 0U);
    }
    if (position >= end) return false;
    const std::uint8_t length_byte = data[position++];
    std::size_t value_length = 0U;
    if ((length_byte & 0x80U) == 0U) {
        value_length = length_byte;
    } else {
        const std::size_t length_bytes = length_byte & 0x7FU;
        if (length_bytes == 0U || length_bytes > 3U || position + length_bytes > end) {
            return false;
        }
        if (data[position] == 0U) return false;
        for (std::size_t i = 0U; i < length_bytes; ++i) {
            if (value_length > (std::numeric_limits<std::size_t>::max() >> 8U)) return false;
            value_length = (value_length << 8U) | data[position++];
        }
        if (value_length < 0x80U) return false;
    }
    if (value_length > end - position) return false;
    header.value_offset = position;
    header.value_length = value_length;
    header.constructed = (first_tag & 0x20U) != 0U;
    position += value_length;
    return true;
}

bool validate_der_at(const std::uint8_t* data,
                    std::size_t end,
                    std::size_t& position,
                    std::size_t depth) noexcept
{
    if (depth > kMaxJsonDepth) return false;
    const std::size_t header_start = position;
    DerHeader header;
    if (!read_der_header(data, end, position, header)) return false;
    if (header.constructed) {
        std::size_t child_position = header.value_offset;
        const std::size_t child_end = header.value_offset + header.value_length;
        while (child_position < child_end) {
            const std::size_t before = child_position;
            if (!validate_der_at(data, child_end, child_position, depth + 1U) ||
                child_position == before) {
                return false;
            }
        }
        if (child_position != child_end) return false;
    }
    return position > header_start;
}

bool parse_der_root(const std::uint8_t* data,
                    std::size_t size,
                    SensitiveTlv& holder,
                    LpaRspError& error)
{
    if (!data || size == 0U) return fail(error, LpaRspError::der_malformed);
    if (size > IDF_LPA_RSP_MAX_OBJECT_BYTES) return fail(error, LpaRspError::object_too_large);
    std::size_t position = 0U;
    const bool structural = validate_der_at(data, size, position, 0U);
    if (!structural || position != size) {
        return fail(error, LpaRspError::der_malformed);
    }
    std::vector<std::uint8_t> copy(data, data + size);
    std::string ignored_message;
    const bool parsed = idf_esim_internal::parse_tlv(copy, holder.value, ignored_message);
    clear_string(ignored_message);
    clear_bytes(copy);
    if (!parsed) return fail(error, LpaRspError::der_malformed);
    return true;
}

bool tag_matches(const idf_esim_internal::Tlv& value,
                 const std::uint8_t* tag,
                 std::size_t tag_size) noexcept
{
    return value.tag.size() == tag_size &&
           (tag_size == 0U || std::memcmp(value.tag.data(), tag, tag_size) == 0);
}

const idf_esim_internal::Tlv* unique_child(const idf_esim_internal::Tlv& parent,
                                           const std::uint8_t* tag,
                                           std::size_t tag_size,
                                           bool& duplicate) noexcept
{
    duplicate = false;
    const idf_esim_internal::Tlv* found = nullptr;
    for (const idf_esim_internal::Tlv& child : parent.children) {
        if (!tag_matches(child, tag, tag_size)) continue;
        if (found != nullptr) {
            duplicate = true;
            return nullptr;
        }
        found = &child;
    }
    return found;
}

bool equal_ascii_ci(const std::vector<std::uint8_t>& left,
                    std::string_view right) noexcept
{
    if (left.size() != right.size()) return false;
    for (std::size_t i = 0U; i < left.size(); ++i) {
        unsigned char a = left[i];
        unsigned char b = static_cast<unsigned char>(right[i]);
        if (a >= static_cast<unsigned char>('a') && a <= static_cast<unsigned char>('z')) {
            a = static_cast<unsigned char>(a - static_cast<unsigned char>('a') +
                                           static_cast<unsigned char>('A'));
        }
        if (b >= static_cast<unsigned char>('a') && b <= static_cast<unsigned char>('z')) {
            b = static_cast<unsigned char>(b - static_cast<unsigned char>('a') +
                                           static_cast<unsigned char>('A'));
        }
        if (a != b) return false;
    }
    return true;
}

bool printable_ascii(const std::vector<std::uint8_t>& value) noexcept
{
    for (std::uint8_t byte : value) {
        if (byte < 0x20U || byte > 0x7EU) return false;
    }
    return true;
}

bool ranges_overlap(const void* left,
                    std::size_t left_size,
                    const void* right,
                    std::size_t right_size) noexcept
{
    if (!left || !right || left_size == 0U || right_size == 0U) return false;
    const std::uintptr_t left_begin = reinterpret_cast<std::uintptr_t>(left);
    const std::uintptr_t right_begin = reinterpret_cast<std::uintptr_t>(right);
    const std::uintptr_t max_address = std::numeric_limits<std::uintptr_t>::max();
    if (left_size > max_address - left_begin || right_size > max_address - right_begin) {
        return true;
    }
    const std::uintptr_t left_end = left_begin + left_size;
    const std::uintptr_t right_end = right_begin + right_size;
    return left_begin < right_end && right_begin < left_end;
}

bool tagged(const idf_esim_internal::Tlv& value,
             std::initializer_list<std::uint8_t> tag) noexcept
{
    return tag_matches(value, tag.begin(), tag.size());
}

bool ordered_fields(const idf_esim_internal::Tlv& value,
                      std::initializer_list<std::initializer_list<std::uint8_t>> tags)
{
    if (value.children.size() != tags.size()) return false;
    std::size_t index = 0;
    for (const auto& tag : tags) if (!tagged(value.children[index++], tag)) return false;
    return true;
}

bool read_object(const std::vector<std::uint8_t>& encoded,
                   std::initializer_list<std::uint8_t> tag,
                   SensitiveTlv& holder, LpaRspError& error)
{
    if (!parse_der_root(encoded.data(), encoded.size(), holder, error)) return false;
    return tagged(holder.value, tag) || fail(error, LpaRspError::der_root);
}

bool output_aliases(const std::vector<std::uint8_t>& output,
                      std::initializer_list<const std::vector<std::uint8_t>*> inputs)
{
    for (const auto* input : inputs) {
        if (input == &output || ranges_overlap(input->data(), input->size(),
                                                output.data(), output.capacity())) return true;
    }
    return false;
}

void append_object(std::vector<std::uint8_t>& output,
                     std::initializer_list<std::uint8_t> tag,
                     const std::vector<std::uint8_t>& value)
{
    idf_esim_internal::append_tlv(output, tag.begin(), tag.size(), value);
}

bool valid_smdp_host(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 253U) return false;

    std::size_t label_start = 0U;
    std::size_t label_count = 0U;
    bool all_numeric_labels = true;
    while (label_start <= value.size()) {
        const std::size_t dot = value.find('.', label_start);
        const std::size_t label_end = dot == std::string_view::npos ? value.size() : dot;
        const std::size_t label_size = label_end - label_start;
        if (label_size == 0U || label_size > 63U || value[label_start] == '-' ||
            value[label_end - 1U] == '-') {
            return false;
        }
        bool numeric_label = true;
        for (std::size_t index = label_start; index < label_end; ++index) {
            const unsigned char byte = static_cast<unsigned char>(value[index]);
            const bool letter = (byte >= static_cast<unsigned char>('A') &&
                                 byte <= static_cast<unsigned char>('Z')) ||
                                (byte >= static_cast<unsigned char>('a') &&
                                 byte <= static_cast<unsigned char>('z'));
            const bool digit = byte >= static_cast<unsigned char>('0') &&
                               byte <= static_cast<unsigned char>('9');
            if (!letter && !digit && byte != static_cast<unsigned char>('-')) return false;
            if (!digit) numeric_label = false;
        }
        ++label_count;
        all_numeric_labels = all_numeric_labels && numeric_label;
        if (dot == std::string_view::npos) break;
        label_start = dot + 1U;
    }
    return label_count >= 2U && !all_numeric_labels;
}

bool canonical_nonnegative_integer(const std::vector<std::uint8_t>& value,
                                   std::size_t max_bytes,
                                   std::uint32_t& output) noexcept
{
    output = 0U;
    if (value.empty() || value.size() > max_bytes) return false;
    if ((value.front() & 0x80U) != 0U) return false;
    if (value.size() > 1U && value.front() == 0U &&
        (value[1U] & 0x80U) == 0U) {
        return false;
    }
    for (const std::uint8_t byte : value) {
        output = (output << 8U) | static_cast<std::uint32_t>(byte);
    }
    return true;
}

bool valid_oid(const std::vector<std::uint8_t>& value) noexcept
{
    if (value.empty() || value.size() > kMaxOidBytes) return false;
    std::size_t position = 0U;
    bool first_subidentifier = true;
    std::uint64_t arc = 0U;
    std::size_t arc_bytes = 0U;
    while (position < value.size()) {
        const std::uint8_t byte = value[position++];
        const std::uint8_t group = byte & 0x7FU;
        if (arc_bytes == 0U && (byte & 0x80U) != 0U && group == 0U) return false;
        if (arc > (std::numeric_limits<std::uint64_t>::max() - group) / 128U) return false;
        arc = arc * 128U + group;
        ++arc_bytes;
        if ((byte & 0x80U) != 0U) continue;
        first_subidentifier = false;
        arc = 0U;
        arc_bytes = 0U;
    }
    return !first_subidentifier && arc_bytes == 0U;
}

bool valid_iccid(const std::vector<std::uint8_t>& value) noexcept
{
    if (value.size() != 10U) return false;
    for (std::size_t index = 0U; index < value.size(); ++index) {
        const std::uint8_t low = value[index] & 0x0FU;
        const std::uint8_t high = (value[index] >> 4U) & 0x0FU;
        if (low > 9U) return false;
        if (index + 1U < value.size() && high > 9U) return false;
        if (index + 1U == value.size() && high != 0x0FU && high > 9U) return false;
    }
    return true;
}

bool display_utf8(const std::vector<std::uint8_t>& value, std::size_t max_characters) noexcept
{
    if (value.size() > max_characters * 4U) return false;
    std::size_t position = 0, characters = 0;
    while (position < value.size()) {
        const std::uint8_t first = value[position++];
        std::uint32_t code = first;
        unsigned following = 0;
        if (first >= 0xC2U && first <= 0xDFU) { code &= 0x1FU; following = 1; }
        else if (first >= 0xE0U && first <= 0xEFU) { code &= 0x0FU; following = 2; }
        else if (first >= 0xF0U && first <= 0xF4U) { code &= 0x07U; following = 3; }
        else if (first >= 0x80U) return false;
        if (following > value.size() - position) return false;
        for (unsigned index = 0; index < following; ++index) {
            const std::uint8_t next = value[position++];
            if ((next & 0xC0U) != 0x80U) return false;
            code = (code << 6U) | (next & 0x3FU);
        }
        if ((following == 1 && code < 0x80U) || (following == 2 && code < 0x800U) ||
            (following == 3 && code < 0x10000U) || code > 0x10FFFFU ||
            (code >= 0xD800U && code <= 0xDFFFU) || code < 0x20U ||
            (code >= 0x7FU && code <= 0x9FU) ||
            (code >= 0x2028U && code <= 0x202EU) ||
            (code >= 0x2066U && code <= 0x2069U) || ++characters > max_characters) return false;
    }
    return true;
}

bool named_bits(const std::vector<std::uint8_t>& value) noexcept
{
    if (value.empty() || value[0] > 7U) return false;
    if (value.size() == 1U) return value[0] == 0;
    const unsigned unused = value[0];
    return value.back() != 0 && (value.back() & ((1U << unused) - 1U)) == 0 &&
           ((value.back() >> unused) & 1U) == 1U;
}

bool metadata_owner(const idf_esim_internal::Tlv& owner) noexcept
{
    if (owner.children.empty() || owner.children.size() > 3U ||
        !tagged(owner.children[0], {0x80}) || owner.children[0].value.size() != 3U) return false;
    const auto& mcc = owner.children[0].value;
    if ((mcc[0] & 0x0FU) > 9U || (mcc[0] >> 4U) > 9U || (mcc[1] & 0x0FU) > 9U ||
        ((mcc[1] >> 4U) > 9U && (mcc[1] >> 4U) != 0x0FU) ||
        (mcc[2] & 0x0FU) > 9U || (mcc[2] >> 4U) > 9U) return false;
    unsigned previous = 0;
    for (std::size_t index = 1; index < owner.children.size(); ++index) {
        const auto& field = owner.children[index];
        if (field.tag.size() != 1U || field.tag[0] < 0x81U || field.tag[0] > 0x82U ||
            field.tag[0] <= previous) return false;
        previous = field.tag[0];
    }
    return true;
}

bool metadata_notifications(const idf_esim_internal::Tlv& list) noexcept
{
    for (const auto& item : list.children) {
        if (!tagged(item, {0x30}) || !ordered_fields(item, {{0x80}, {0x81}}) ||
            !named_bits(item.children[0].value) || item.children[0].value.size() != 2U ||
            item.children[0].value[0] < 4U) return false;
        const auto& address = item.children[1].value;
        if (!valid_smdp_host(std::string_view(reinterpret_cast<const char*>(address.data()),
                                              address.size()))) return false;
    }
    return true;
}

bool valid_download_error_code(std::uint32_t value) noexcept
{
    return (value >= 1U && value <= 5U) || value == 127U;
}

bool valid_cancel_reason(LpaRspCancelReason reason) noexcept
{
    const auto value = static_cast<std::uint8_t>(reason);
    return value <= 5U || value == 127U;
}

bool valid_bpp_command_id(std::uint32_t value) noexcept
{
    return value <= 5U;
}

bool valid_error_reason(std::uint32_t value) noexcept
{
    return (value >= 1U && value <= 15U) || value == 127U;
}

bool prepare_fail(std::vector<std::uint8_t>& output,
                  LpaRspError& error,
                  LpaRspError value) noexcept
{
    clear_bytes(output);
    return fail(error, value);
}

bool pir_fail(std::uint32_t& sequence_number,
              std::string& notification_address,
              LpaRspError& error,
              LpaRspError value) noexcept
{
    sequence_number = 0U;
    clear_string(notification_address);
    return fail(error, value);
}

const std::uint8_t* expected_root_tag(LpaRspDerObject kind, std::size_t& size) noexcept
{
    static constexpr std::uint8_t kSequence[] = {0x30U};
    static constexpr std::uint8_t kAuthenticateServerResponse[] = {0xBFU, 0x38U};
    static constexpr std::uint8_t kPrepareDownloadResponse[] = {0xBFU, 0x21U};
    static constexpr std::uint8_t kProfileMetadata[] = {0xBFU, 0x25U};
    static constexpr std::uint8_t kNotificationMetadata[] = {0xBFU, 0x2FU};
    static constexpr std::uint8_t kProfileInstallationResult[] = {0xBFU, 0x37U};
    static constexpr std::uint8_t kSignature[] = {0x5FU, 0x37U};
    static constexpr std::uint8_t kCiKey[] = {0x04U};
    switch (kind) {
    case LpaRspDerObject::server_signed1:
    case LpaRspDerObject::smdp_signed2:
        size = sizeof(kSequence);
        return kSequence;
    case LpaRspDerObject::authenticate_server_response:
        size = sizeof(kAuthenticateServerResponse);
        return kAuthenticateServerResponse;
    case LpaRspDerObject::prepare_download_response:
        size = sizeof(kPrepareDownloadResponse);
        return kPrepareDownloadResponse;
    case LpaRspDerObject::profile_metadata:
        size = sizeof(kProfileMetadata);
        return kProfileMetadata;
    case LpaRspDerObject::notification_metadata:
        size = sizeof(kNotificationMetadata);
        return kNotificationMetadata;
    case LpaRspDerObject::profile_installation_result:
        size = sizeof(kProfileInstallationResult);
        return kProfileInstallationResult;
    case LpaRspDerObject::signature:
        size = sizeof(kSignature);
        return kSignature;
    case LpaRspDerObject::ci_key:
        size = sizeof(kCiKey);
        return kCiKey;
    }
    size = 0U;
    return nullptr;
}

std::size_t expected_root_limit(LpaRspDerObject kind) noexcept
{
    switch (kind) {
    case LpaRspDerObject::signature:
        return kMaxSignatureBytes;
    case LpaRspDerObject::ci_key:
        return kMaxCiKeyBytes;
    case LpaRspDerObject::server_signed1:
    case LpaRspDerObject::smdp_signed2:
    case LpaRspDerObject::authenticate_server_response:
    case LpaRspDerObject::prepare_download_response:
    case LpaRspDerObject::profile_metadata:
    case LpaRspDerObject::notification_metadata:
    case LpaRspDerObject::profile_installation_result:
        return IDF_LPA_RSP_MAX_OBJECT_BYTES;
    }
    return 0U;
}

int base64_value(unsigned char value) noexcept
{
    if (value >= static_cast<unsigned char>('A') && value <= static_cast<unsigned char>('Z')) {
        return static_cast<int>(value - static_cast<unsigned char>('A'));
    }
    if (value >= static_cast<unsigned char>('a') && value <= static_cast<unsigned char>('z')) {
        return static_cast<int>(value - static_cast<unsigned char>('a')) + 26;
    }
    if (value >= static_cast<unsigned char>('0') && value <= static_cast<unsigned char>('9')) {
        return static_cast<int>(value - static_cast<unsigned char>('0')) + 52;
    }
    if (value == static_cast<unsigned char>('+')) return 62;
    if (value == static_cast<unsigned char>('/')) return 63;
    return -1;
}

bool hash_sha256(const std::uint8_t* input,
                 std::size_t input_size,
                 std::uint8_t output[kHashBytes]) noexcept
{
#ifdef ESP_PLATFORM
    // The target path is the PSA implementation; host results cannot substitute for it.
    psa_hash_operation_t operation = PSA_HASH_OPERATION_INIT;
    psa_status_t setup_status = psa_hash_setup(&operation, PSA_ALG_SHA_256);
    psa_status_t update_status = PSA_ERROR_BAD_STATE;
    psa_status_t finish_status = PSA_ERROR_BAD_STATE;
    psa_status_t abort_status = PSA_ERROR_BAD_STATE;
    std::size_t output_size = 0U;
    if (setup_status == PSA_SUCCESS) {
        update_status = psa_hash_update(&operation, input, input_size);
        if (update_status == PSA_SUCCESS) {
            finish_status = psa_hash_finish(&operation, output, kHashBytes, &output_size);
        }
    }
    // Abort is deliberately attempted after every setup/update/finish path.
    abort_status = psa_hash_abort(&operation);
    const bool ok = setup_status == PSA_SUCCESS && update_status == PSA_SUCCESS &&
                    finish_status == PSA_SUCCESS && abort_status == PSA_SUCCESS &&
                    output_size == kHashBytes;
    if (!ok) secure_zero(output, kHashBytes);
    return ok;
#else
    // This branch exists only for bounded host tests and uses no device state.
    EVP_MD_CTX* context = EVP_MD_CTX_new();
    if (context == nullptr) {
        secure_zero(output, kHashBytes);
        return false;
    }
    unsigned int output_size = 0U;
    const bool ok = EVP_DigestInit_ex(context, EVP_sha256(), nullptr) == 1 &&
                    EVP_DigestUpdate(context, input, input_size) == 1 &&
                    EVP_DigestFinal_ex(context, output, &output_size) == 1 &&
                    output_size == kHashBytes;
    EVP_MD_CTX_free(context);
    if (!ok) secure_zero(output, kHashBytes);
    return ok;
#endif
}

}  // namespace

const char* idf_lpa_rsp_error_name(LpaRspError error) noexcept
{
    switch (error) {
    case LpaRspError::none: return "none";
    case LpaRspError::input_too_large: return "input-too-large";
    case LpaRspError::json_malformed: return "json-malformed";
    case LpaRspError::json_duplicate: return "json-duplicate";
    case LpaRspError::json_missing: return "json-missing";
    case LpaRspError::json_type: return "json-type";
    case LpaRspError::server_error: return "server-error";
    case LpaRspError::base64_malformed: return "base64-malformed";
    case LpaRspError::base64_noncanonical: return "base64-noncanonical";
    case LpaRspError::object_too_large: return "object-too-large";
    case LpaRspError::der_malformed: return "der-malformed";
    case LpaRspError::der_root: return "der-root";
    case LpaRspError::field_missing: return "field-missing";
    case LpaRspError::der_duplicate: return "der-duplicate";
    case LpaRspError::transaction_mismatch: return "transaction-mismatch";
    case LpaRspError::challenge_mismatch: return "challenge-mismatch";
    case LpaRspError::address_mismatch: return "address-mismatch";
    case LpaRspError::confirmation_malformed: return "confirmation-malformed";
    case LpaRspError::matching_id: return "matching-id";
    case LpaRspError::crypto_input: return "crypto-input";
    case LpaRspError::transaction_malformed: return "transaction-malformed";
    case LpaRspError::crypto_failure: return "crypto-failure";
    case LpaRspError::unknown: return "unknown";
    }
    return "unknown";
}

bool idf_lpa_rsp_json_get_string(std::string_view json,
                                 std::string_view key,
                                 std::string& out,
                                 LpaRspError& error)
{
    clear_string(out);
    error = LpaRspError::none;
    if (json.size() > IDF_LPA_RSP_MAX_JSON_BYTES) return fail(error, LpaRspError::input_too_large);
    JsonScanner scanner(json);
    const bool parsed = scanner.get_string(key, out, error);
    if (!parsed) clear_string(out);
    return parsed;
}

bool idf_lpa_rsp_parse_status(std::string_view json,
                              bool& success,
                              LpaRspError& error)
{
    success = false;
    std::string status;
    if (json.size() > IDF_LPA_RSP_MAX_JSON_BYTES) {
        return fail(error, LpaRspError::input_too_large);
    }
    // SGP.22 v2.6 §§6.5.1.2–6.5.1.4 and 6.5.2.6–6.5.2.9 define the ES9+
    // execution status at header.functionExecutionStatus.status.  This
    // parser is deliberately limited to that envelope; HandleNotification
    // response handling remains an HTTP-204 transport concern.
    JsonScanner scanner(json);
    const bool parsed = scanner.get_header_function_status(status, error);
    if (!parsed) {
        clear_string(status);
        return false;
    }
    if (status != "Executed-Success") {
        clear_string(status);
        return fail(error, LpaRspError::server_error);
    }
    clear_string(status);
    error = LpaRspError::none;
    success = true;
    return true;
}

bool idf_lpa_rsp_base64_encode(const std::uint8_t* input,
                               std::size_t input_size,
                               std::string& out,
                               LpaRspError& error)
{
    clear_string(out);
    error = LpaRspError::none;
    if (input_size > IDF_LPA_RSP_MAX_OBJECT_BYTES ||
        (input_size != 0U && input == nullptr)) {
        return fail(error, LpaRspError::object_too_large);
    }
    static constexpr char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    const std::size_t encoded_size = ((input_size + 2U) / 3U) * 4U;
    out.reserve(encoded_size);
    for (std::size_t position = 0U; position < input_size; position += 3U) {
        const std::size_t remaining = input_size - position;
        const std::uint32_t first = input[position];
        const std::uint32_t second = remaining > 1U ? input[position + 1U] : 0U;
        const std::uint32_t third = remaining > 2U ? input[position + 2U] : 0U;
        const std::uint32_t value = (first << 16U) | (second << 8U) | third;
        out.push_back(alphabet[(value >> 18U) & 0x3FU]);
        out.push_back(alphabet[(value >> 12U) & 0x3FU]);
        out.push_back(remaining > 1U ? alphabet[(value >> 6U) & 0x3FU] : '=');
        out.push_back(remaining > 2U ? alphabet[value & 0x3FU] : '=');
    }
    return true;
}

bool idf_lpa_rsp_base64_decode(std::string_view input,
                               std::vector<std::uint8_t>& out,
                               LpaRspError& error)
{
    clear_bytes(out);
    error = LpaRspError::none;
    if (input.empty() || input.size() > kMaxBase64EncodedBytes) {
        return fail(error, input.size() > kMaxBase64EncodedBytes
                               ? LpaRspError::object_too_large
                               : LpaRspError::base64_malformed);
    }
    if ((input.size() % 4U) != 0U) return fail(error, LpaRspError::base64_malformed);
    std::size_t decoded_size = (input.size() / 4U) * 3U;
    if (input[input.size() - 1U] == '=') --decoded_size;
    if (input[input.size() - 2U] == '=') --decoded_size;
    if (decoded_size > IDF_LPA_RSP_MAX_OBJECT_BYTES) {
        return fail(error, LpaRspError::object_too_large);
    }
    out.reserve(decoded_size);
    for (std::size_t position = 0U; position < input.size(); position += 4U) {
        const unsigned char a = static_cast<unsigned char>(input[position]);
        const unsigned char b = static_cast<unsigned char>(input[position + 1U]);
        const unsigned char c = static_cast<unsigned char>(input[position + 2U]);
        const unsigned char d = static_cast<unsigned char>(input[position + 3U]);
        const int first = base64_value(a);
        const int second = base64_value(b);
        const bool final_group = position + 4U == input.size();
        if (first < 0 || second < 0) {
            return base64_fail(out, error, LpaRspError::base64_malformed);
        }
        if (c == '=' && d != '=') {
            return base64_fail(out, error, LpaRspError::base64_malformed);
        }
        if (!final_group && (c == '=' || d == '=')) {
            return base64_fail(out, error, LpaRspError::base64_malformed);
        }
        const int third = c == '=' ? 0 : base64_value(c);
        const int fourth = d == '=' ? 0 : base64_value(d);
        if (third < 0 || fourth < 0) {
            return base64_fail(out, error, LpaRspError::base64_malformed);
        }
        if (c == '=' && (second & 0x0FU) != 0) {
            return base64_fail(out, error, LpaRspError::base64_noncanonical);
        }
        if (d == '=' && c != '=' && (third & 0x03) != 0) {
            return base64_fail(out, error, LpaRspError::base64_noncanonical);
        }
        const std::uint32_t value = (static_cast<std::uint32_t>(first) << 18U) |
                                     (static_cast<std::uint32_t>(second) << 12U) |
                                     (static_cast<std::uint32_t>(third) << 6U) |
                                     static_cast<std::uint32_t>(fourth);
        out.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xFFU));
        if (c != '=') out.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xFFU));
        if (d != '=') out.push_back(static_cast<std::uint8_t>(value & 0xFFU));
    }
    if (out.size() != decoded_size) {
        clear_bytes(out);
        return fail(error, LpaRspError::base64_malformed);
    }
    return true;
}

bool idf_lpa_rsp_decode_transaction_id(std::string_view input,
                                       std::array<std::uint8_t, 16>& out,
                                       std::size_t& out_size,
                                       LpaRspError& error)
{
    secure_zero(out.data(), out.size());
    out_size = 0U;
    error = LpaRspError::none;
    if (input.empty() || input.size() > kMaxTransactionBytes * 2U ||
        (input.size() % 2U) != 0U) {
        return fail(error, LpaRspError::transaction_malformed);
    }
    for (std::size_t position = 0U; position < input.size(); position += 2U) {
        const int high = hex_value(static_cast<unsigned char>(input[position]));
        const int low = hex_value(static_cast<unsigned char>(input[position + 1U]));
        if (high < 0 || low < 0) {
            secure_zero(out.data(), out.size());
            return fail(error, LpaRspError::transaction_malformed);
        }
        out[position / 2U] = static_cast<std::uint8_t>((high << 4) | low);
    }
    out_size = input.size() / 2U;
    return true;
}

bool idf_lpa_rsp_transaction_id_matches(std::string_view input,
                                        const std::uint8_t* expected,
                                        std::size_t expected_size,
                                        LpaRspError& error)
{
    std::array<std::uint8_t, 16> decoded = {};
    std::size_t decoded_size = 0U;
    if (!idf_lpa_rsp_decode_transaction_id(input, decoded, decoded_size, error)) {
        secure_zero(decoded.data(), decoded.size());
        return false;
    }
    const bool matches = expected != nullptr && expected_size == decoded_size &&
                         std::memcmp(decoded.data(), expected, decoded_size) == 0;
    secure_zero(decoded.data(), decoded.size());
    if (!matches) return fail(error, LpaRspError::transaction_mismatch);
    error = LpaRspError::none;
    return true;
}

bool idf_lpa_rsp_validate_matching_id(std::string_view matching_id,
                                      LpaRspError& error)
{
    error = LpaRspError::none;
    if (matching_id.empty() || matching_id.size() > 128U) {
        return fail(error, LpaRspError::matching_id);
    }
    for (unsigned char value : matching_id) {
        if (!((value >= static_cast<unsigned char>('A') &&
               value <= static_cast<unsigned char>('Z')) ||
              (value >= static_cast<unsigned char>('0') &&
               value <= static_cast<unsigned char>('9')) ||
              value == static_cast<unsigned char>('-'))) {
            return fail(error, LpaRspError::matching_id);
        }
    }
    return true;
}

bool idf_lpa_rsp_validate_der_structure(const std::uint8_t* object,
                                        std::size_t object_size,
                                        LpaRspDerObject kind,
                                        LpaRspError& error)
{
    error = LpaRspError::none;
    if (object_size > expected_root_limit(kind)) {
        return fail(error, LpaRspError::object_too_large);
    }
    SensitiveTlv holder;
    if (!parse_der_root(object, object_size, holder, error)) return false;
    std::size_t tag_size = 0U;
    const std::uint8_t* tag = expected_root_tag(kind, tag_size);
    if (!tag || !tag_matches(holder.value, tag, tag_size)) {
        return fail(error, LpaRspError::der_root);
    }
    return true;
}

bool idf_lpa_rsp_validate_server_signed1(const std::uint8_t* object,
                                         std::size_t object_size,
                                         const std::uint8_t* transaction_id,
                                         std::size_t transaction_size,
                                         const std::array<std::uint8_t, 16>& euicc_challenge,
                                         std::string_view expected_address,
                                         LpaRspError& error)
{
    error = LpaRspError::none;
    if (!transaction_id || transaction_size == 0U || transaction_size > kMaxTransactionBytes) {
        return fail(error, LpaRspError::transaction_mismatch);
    }
    SensitiveTlv holder;
    if (!parse_der_root(object, object_size, holder, error)) return false;
    static constexpr std::uint8_t kSequence[] = {0x30U};
    if (!tag_matches(holder.value, kSequence, sizeof(kSequence))) {
        return fail(error, LpaRspError::der_root);
    }
    static constexpr std::uint8_t kTransaction[] = {0x80U};
    static constexpr std::uint8_t kEuiccChallenge[] = {0x81U};
    static constexpr std::uint8_t kAddress[] = {0x83U};
    static constexpr std::uint8_t kServerChallenge[] = {0x84U};
    bool duplicate = false;
    const idf_esim_internal::Tlv* transaction =
        unique_child(holder.value, kTransaction, sizeof(kTransaction), duplicate);
    if (duplicate) return fail(error, LpaRspError::der_duplicate);
    if (!transaction) return fail(error, LpaRspError::field_missing);
    if (transaction->value.size() != transaction_size ||
        std::memcmp(transaction->value.data(), transaction_id, transaction_size) != 0) {
        return fail(error, LpaRspError::transaction_mismatch);
    }
    const idf_esim_internal::Tlv* challenge =
        unique_child(holder.value, kEuiccChallenge, sizeof(kEuiccChallenge), duplicate);
    if (duplicate) return fail(error, LpaRspError::der_duplicate);
    if (!challenge) return fail(error, LpaRspError::field_missing);
    if (challenge->value.size() != euicc_challenge.size() ||
        std::memcmp(challenge->value.data(), euicc_challenge.data(), euicc_challenge.size()) != 0) {
        return fail(error, LpaRspError::challenge_mismatch);
    }
    const idf_esim_internal::Tlv* address =
        unique_child(holder.value, kAddress, sizeof(kAddress), duplicate);
    if (duplicate) return fail(error, LpaRspError::der_duplicate);
    if (!address || address->value.empty() || expected_address.empty() ||
        expected_address.size() > 253U || !printable_ascii(address->value) ||
        !equal_ascii_ci(address->value, expected_address)) {
        return fail(error, address ? LpaRspError::address_mismatch : LpaRspError::field_missing);
    }
    const idf_esim_internal::Tlv* server_challenge =
        unique_child(holder.value, kServerChallenge, sizeof(kServerChallenge), duplicate);
    if (duplicate) return fail(error, LpaRspError::der_duplicate);
    if (!server_challenge) return fail(error, LpaRspError::field_missing);
    if (server_challenge->value.size() != 16U) {
        return fail(error, LpaRspError::der_malformed);
    }
    for (const idf_esim_internal::Tlv& child : holder.value.children) {
        if (!tag_matches(child, kTransaction, sizeof(kTransaction)) &&
            !tag_matches(child, kEuiccChallenge, sizeof(kEuiccChallenge)) &&
            !tag_matches(child, kAddress, sizeof(kAddress)) &&
            !tag_matches(child, kServerChallenge, sizeof(kServerChallenge))) {
            return fail(error, LpaRspError::der_malformed);
        }
    }
    return true;
}

bool idf_lpa_rsp_parse_smdp_signed2(const std::uint8_t* object,
                                    std::size_t object_size,
                                    const std::uint8_t* transaction_id,
                                    std::size_t transaction_size,
                                    bool& confirmation_required,
                                    LpaRspError& error)
{
    confirmation_required = false;
    error = LpaRspError::none;
    if (!transaction_id || transaction_size == 0U || transaction_size > kMaxTransactionBytes) {
        return fail(error, LpaRspError::transaction_mismatch);
    }
    SensitiveTlv holder;
    if (!parse_der_root(object, object_size, holder, error)) return false;
    static constexpr std::uint8_t kSequence[] = {0x30U};
    if (!tag_matches(holder.value, kSequence, sizeof(kSequence))) {
        return fail(error, LpaRspError::der_root);
    }
    static constexpr std::uint8_t kTransaction[] = {0x80U};
    static constexpr std::uint8_t kConfirmation[] = {0x01U};
    bool duplicate = false;
    const idf_esim_internal::Tlv* transaction =
        unique_child(holder.value, kTransaction, sizeof(kTransaction), duplicate);
    if (duplicate) return fail(error, LpaRspError::der_duplicate);
    if (!transaction) return fail(error, LpaRspError::field_missing);
    if (transaction->value.size() != transaction_size ||
        std::memcmp(transaction->value.data(), transaction_id, transaction_size) != 0) {
        return fail(error, LpaRspError::transaction_mismatch);
    }
    const idf_esim_internal::Tlv* confirmation =
        unique_child(holder.value, kConfirmation, sizeof(kConfirmation), duplicate);
    if (duplicate) return fail(error, LpaRspError::der_duplicate);
    if (!confirmation) return fail(error, LpaRspError::field_missing);
    if (confirmation->value.size() != 1U ||
        (confirmation->value[0] != 0x00U && confirmation->value[0] != 0xFFU)) {
        return fail(error, LpaRspError::confirmation_malformed);
    }
    const auto& fields = holder.value.children;
    if (fields.size() < 2U || fields.size() > 3U ||
        !tag_matches(fields[0], kTransaction, sizeof(kTransaction)) ||
        !tag_matches(fields[1], kConfirmation, sizeof(kConfirmation)) ||
        (fields.size() == 3U && (!tagged(fields[2], {0x5F, 0x49}) ||
         fields[2].value.empty() || fields[2].value.size() > kMaxOtpkBytes))) {
        return fail(error, LpaRspError::der_malformed);
    }
    confirmation_required = confirmation->value[0] == 0xFFU;
    return true;
}

bool idf_lpa_rsp_compute_hash_cc(std::string_view confirmation_code,
                                 const std::uint8_t* transaction_id,
                                 std::size_t transaction_size,
                                 std::array<std::uint8_t, 32>& hash_cc,
                                 LpaRspError& error)
{
    secure_zero(hash_cc.data(), hash_cc.size());
    error = LpaRspError::none;
    if (confirmation_code.empty() || confirmation_code.size() > IDF_LPA_RSP_MAX_CONFIRMATION_BYTES || !transaction_id ||
        transaction_size == 0U || transaction_size > kMaxTransactionBytes) {
        return fail(error, LpaRspError::crypto_input);
    }
    for (unsigned char value : confirmation_code) {
        if (value < 0x20U || value > 0x7EU) return fail(error, LpaRspError::crypto_input);
    }
#ifdef ESP_PLATFORM
    if (psa_crypto_init() != PSA_SUCCESS) return fail(error, LpaRspError::crypto_failure);
#endif
    std::array<std::uint8_t, IDF_LPA_RSP_MAX_CONFIRMATION_BYTES> confirmation_bytes = {};
    std::memcpy(confirmation_bytes.data(), confirmation_code.data(), confirmation_code.size());
    std::array<std::uint8_t, 32> first = {};
    std::array<std::uint8_t, 48> combined = {};
    const bool first_ok = hash_sha256(confirmation_bytes.data(), confirmation_code.size(),
                                      first.data());
    if (!first_ok) {
        secure_zero(confirmation_bytes.data(), confirmation_bytes.size());
        secure_zero(first.data(), first.size());
        secure_zero(combined.data(), combined.size());
        secure_zero(hash_cc.data(), hash_cc.size());
        return fail(error, LpaRspError::crypto_failure);
    }
    std::memcpy(combined.data(), first.data(), first.size());
    std::memcpy(combined.data() + first.size(), transaction_id, transaction_size);
    const bool second_ok = hash_sha256(combined.data(), first.size() + transaction_size,
                                       hash_cc.data());
    secure_zero(confirmation_bytes.data(), confirmation_bytes.size());
    secure_zero(first.data(), first.size());
    secure_zero(combined.data(), combined.size());
    if (!second_ok) {
        secure_zero(hash_cc.data(), hash_cc.size());
        return fail(error, LpaRspError::crypto_failure);
    }
    return true;
}

bool idf_lpa_rsp_build_authenticate_server_request(
    const std::vector<std::uint8_t>& server_signed1,
    const std::vector<std::uint8_t>& server_signature1,
    const std::vector<std::uint8_t>& ci_key_id,
    const std::vector<std::uint8_t>& server_certificate,
    std::string_view matching_id, std::string_view imei,
    const std::vector<std::uint8_t>& device_capabilities,
    std::vector<std::uint8_t>& request, LpaRspError& error)
{
    error = LpaRspError::none;
    if (output_aliases(request, {&server_signed1, &server_signature1, &ci_key_id,
                                 &server_certificate, &device_capabilities}) ||
        ranges_overlap(matching_id.data(), matching_id.size(), request.data(), request.capacity()) ||
        ranges_overlap(imei.data(), imei.size(), request.data(), request.capacity())) {
        return prepare_fail(request, error, LpaRspError::der_malformed);
    }
    clear_bytes(request);
    if (!idf_lpa_rsp_validate_matching_id(matching_id, error)) return false;
    if (imei.size() != 15U || !std::all_of(imei.begin(), imei.end(),
            [](char ch) { return ch >= '0' && ch <= '9'; })) {
        return fail(error, LpaRspError::crypto_input);
    }
    SensitiveTlv signed1, signature, key, certificate, capabilities;
    if (!read_object(server_signed1, {0x30}, signed1, error) ||
        !read_object(server_signature1, {0x5F, 0x37}, signature, error) ||
        !read_object(ci_key_id, {0x04}, key, error) ||
        !read_object(server_certificate, {0x30}, certificate, error) ||
        !read_object(device_capabilities, {0x30}, capabilities, error)) return false;
    if (!ordered_fields(signed1.value, {{0x80}, {0x81}, {0x83}, {0x84}}) ||
        signed1.value.children[0].value.empty() ||
        signed1.value.children[0].value.size() > kMaxTransactionBytes ||
        signed1.value.children[1].value.size() != 16U ||
        signed1.value.children[3].value.size() != 16U ||
        signature.value.value.empty() || signature.value.value.size() > kMaxSignatureBytes ||
        key.value.value.empty() || key.value.value.size() > kMaxCiKeyBytes ||
        certificate.value.value.empty() || device_capabilities.size() > 256U) {
        return fail(error, LpaRspError::der_malformed);
    }
    const auto& address = signed1.value.children[2].value;
    if (!valid_smdp_host(std::string_view(reinterpret_cast<const char*>(address.data()),
                                          address.size()))) {
        return fail(error, LpaRspError::address_mismatch);
    }
    const std::size_t request_bound = server_signed1.size() + server_signature1.size() +
        ci_key_id.size() + server_certificate.size() + device_capabilities.size() +
        matching_id.size() + 64U;
    if (request_bound > IDF_LPA_RSP_MAX_OBJECT_BYTES) {
        return fail(error, LpaRspError::object_too_large);
    }

    std::vector<std::uint8_t> tbcd(8), device, context, body;
    device.reserve(device_capabilities.size() + 24U);
    context.reserve(device_capabilities.size() + matching_id.size() + 40U);
    body.reserve(request_bound);
    request.reserve(request_bound);
    for (std::size_t index = 0; index < 7U; ++index) {
        tbcd[index] = static_cast<std::uint8_t>((imei[index * 2U] - '0') |
                                               ((imei[index * 2U + 1U] - '0') << 4U));
    }
    // SGP.22 §4.2：末字节高半字节为校验位，低半字节为 F。
    tbcd[7] = static_cast<std::uint8_t>(((imei[14] - '0') << 4U) | 0x0FU);
    std::vector<std::uint8_t> tac(tbcd.begin(), tbcd.begin() + 4);
    std::vector<std::uint8_t> matching_bytes(matching_id.begin(), matching_id.end());
    append_object(device, {0x80}, tac);
    append_object(device, {0xA1}, capabilities.value.value);
    append_object(device, {0x82}, tbcd);
    append_object(context, {0x80}, matching_bytes);
    append_object(context, {0xA1}, device);
    for (const auto* part : {&server_signed1, &server_signature1, &ci_key_id, &server_certificate}) {
        body.insert(body.end(), part->begin(), part->end());
    }
    append_object(body, {0xA0}, context);
    append_object(request, {0xBF, 0x38}, body);
    clear_bytes(tbcd); clear_bytes(tac); clear_bytes(matching_bytes);
    clear_bytes(device); clear_bytes(context); clear_bytes(body);
    return true;
}

bool idf_lpa_rsp_parse_authenticate_server_response(
    const std::uint8_t* object, std::size_t object_size,
    const std::vector<std::uint8_t>& expected_request,
    std::vector<std::uint8_t>& authenticate_client_response, LpaRspError& error)
{
    error = LpaRspError::none;
    if (output_aliases(authenticate_client_response, {&expected_request}) ||
        ranges_overlap(object, object_size, authenticate_client_response.data(),
                       authenticate_client_response.capacity())) {
        return prepare_fail(authenticate_client_response, error, LpaRspError::der_malformed);
    }
    clear_bytes(authenticate_client_response);
    SensitiveTlv request, response;
    if (!read_object(expected_request, {0xBF, 0x38}, request, error) ||
        !parse_der_root(object, object_size, response, error)) return false;
    if (!ordered_fields(request.value, {{0x30}, {0x5F, 0x37}, {0x04}, {0x30}, {0xA0}}) ||
        !ordered_fields(request.value.children[0], {{0x80}, {0x81}, {0x83}, {0x84}}) ||
        !tagged(response.value, {0xBF, 0x38}) || response.value.children.size() != 1U) {
        return fail(error, LpaRspError::der_malformed);
    }
    const auto& original = request.value.children[0].children;
    if (original[0].value.empty() || original[0].value.size() > kMaxTransactionBytes ||
        original[1].value.size() != 16U || original[3].value.size() != 16U) {
        return fail(error, LpaRspError::der_malformed);
    }
    const auto& choice = response.value.children[0];
    if (tagged(choice, {0xA1})) {
        if (!ordered_fields(choice, {{0x80}, {0x02}})) return fail(error, LpaRspError::der_malformed);
        if (choice.children[0].value != original[0].value) return fail(error, LpaRspError::transaction_mismatch);
        std::uint32_t code = 0;
        if (!canonical_nonnegative_integer(choice.children[1].value, 1, code) ||
            !((code >= 1U && code <= 7U) || code == 127U)) return fail(error, LpaRspError::der_malformed);
        return fail(error, LpaRspError::server_error);
    }
    if (!tagged(choice, {0xA0}) ||
        !ordered_fields(choice, {{0x30}, {0x5F, 0x37}, {0x30}, {0x30}}) ||
        !ordered_fields(choice.children[0], {{0x80}, {0x83}, {0x84}, {0xBF, 0x22}, {0xA0}}) ||
        choice.children[1].value.empty() || choice.children[1].value.size() > kMaxSignatureBytes ||
        choice.children[2].value.empty() || choice.children[3].value.empty()) {
        return fail(error, LpaRspError::der_malformed);
    }
    const auto& signed1 = choice.children[0].children;
    if (signed1[0].value != original[0].value) return fail(error, LpaRspError::transaction_mismatch);
    const std::string_view address(reinterpret_cast<const char*>(original[2].value.data()),
                                    original[2].value.size());
    if (!valid_smdp_host(address) || !equal_ascii_ci(signed1[1].value, address)) {
        return fail(error, LpaRspError::address_mismatch);
    }
    if (signed1[2].value != original[3].value) return fail(error, LpaRspError::challenge_mismatch);
    if (signed1[3].value.empty() || signed1[4].value != request.value.children[4].value) {
        return fail(error, LpaRspError::der_malformed);
    }
    authenticate_client_response.assign(object, object + object_size);
    return true;
}

bool idf_lpa_rsp_build_prepare_download_request(
    const std::vector<std::uint8_t>& smdp_signed2,
    const std::vector<std::uint8_t>& smdp_signature2,
    const std::vector<std::uint8_t>& smdp_certificate,
    const std::array<std::uint8_t, 32>* hash_cc,
    std::vector<std::uint8_t>& request, LpaRspError& error)
{
    error = LpaRspError::none;
    if (output_aliases(request, {&smdp_signed2, &smdp_signature2, &smdp_certificate}) ||
        (hash_cc && ranges_overlap(hash_cc->data(), hash_cc->size(), request.data(), request.capacity()))) {
        return prepare_fail(request, error, LpaRspError::der_malformed);
    }
    clear_bytes(request);
    SensitiveTlv signed2, signature, certificate;
    if (!read_object(smdp_signed2, {0x30}, signed2, error) ||
        !read_object(smdp_signature2, {0x5F, 0x37}, signature, error) ||
        !read_object(smdp_certificate, {0x30}, certificate, error)) return false;
    if (signed2.value.children.empty() || !tagged(signed2.value.children[0], {0x80}) ||
        signature.value.value.empty() || signature.value.value.size() > kMaxSignatureBytes ||
        certificate.value.value.empty()) return fail(error, LpaRspError::der_malformed);
    const auto& transaction = signed2.value.children[0].value;
    bool confirmation_required = false;
    if (!idf_lpa_rsp_parse_smdp_signed2(smdp_signed2.data(), smdp_signed2.size(),
            transaction.data(), transaction.size(), confirmation_required, error)) return false;
    if (confirmation_required && !hash_cc) return fail(error, LpaRspError::confirmation_malformed);
    const std::size_t request_bound = smdp_signed2.size() + smdp_signature2.size() +
        smdp_certificate.size() + 40U;
    if (request_bound > IDF_LPA_RSP_MAX_OBJECT_BYTES) {
        return fail(error, LpaRspError::object_too_large);
    }
    std::vector<std::uint8_t> body;
    body.reserve(request_bound);
    request.reserve(request_bound);
    body.insert(body.end(), smdp_signed2.begin(), smdp_signed2.end());
    body.insert(body.end(), smdp_signature2.begin(), smdp_signature2.end());
    if (hash_cc) {
        std::vector<std::uint8_t> hash(hash_cc->begin(), hash_cc->end());
        append_object(body, {0x04}, hash);
        clear_bytes(hash);
    }
    body.insert(body.end(), smdp_certificate.begin(), smdp_certificate.end());
    append_object(request, {0xBF, 0x21}, body);
    clear_bytes(body);
    return true;
}

bool idf_lpa_rsp_parse_profile_metadata(const std::uint8_t* object, std::size_t object_size,
                                         LpaRspProfileMetadata& metadata, LpaRspError& error)
{
    const bool alias = ranges_overlap(object, object_size, metadata.service_provider_name.data(),
                                      metadata.service_provider_name.capacity()) ||
        ranges_overlap(object, object_size, metadata.profile_name.data(), metadata.profile_name.capacity());
    clear_string(metadata.service_provider_name);
    clear_string(metadata.profile_name);
    metadata.has_policy_rules = false;
    error = LpaRspError::none;
    if (alias) return fail(error, LpaRspError::der_malformed);
    SensitiveTlv holder;
    if (!parse_der_root(object, object_size, holder, error)) return false;
    if (!tagged(holder.value, {0xBF, 0x25})) return fail(error, LpaRspError::der_root);
    const auto& fields = holder.value.children;
    if (fields.size() < 3U || !tagged(fields[0], {0x5A}) || !valid_iccid(fields[0].value) ||
        !tagged(fields[1], {0x91}) || !display_utf8(fields[1].value, 32U) ||
        !tagged(fields[2], {0x92}) || !display_utf8(fields[2].value, 64U)) {
        return fail(error, LpaRspError::der_malformed);
    }
    bool icon_type = false, owner = false, policy = false;
    unsigned previous = 0;
    for (std::size_t index = 3; index < fields.size(); ++index) {
        const auto& field = fields[index];
        unsigned order = 0;
        std::uint32_t code = 0;
        if (tagged(field, {0x93})) {
            order = 1; icon_type = true;
            if (!canonical_nonnegative_integer(field.value, 1, code) || code > 1U)
                return fail(error, LpaRspError::der_malformed);
        } else if (tagged(field, {0x94})) {
            order = 2;
            if (!icon_type || field.value.size() > 1024U) return fail(error, LpaRspError::der_malformed);
        } else if (tagged(field, {0x95})) {
            order = 3;
            if (!canonical_nonnegative_integer(field.value, 1, code) || code > 2U)
                return fail(error, LpaRspError::der_malformed);
        } else if (tagged(field, {0xB6})) {
            order = 4;
            if (!metadata_notifications(field)) return fail(error, LpaRspError::der_malformed);
        } else if (tagged(field, {0xB7})) {
            order = 5; owner = true;
            if (!metadata_owner(field)) return fail(error, LpaRspError::der_malformed);
        } else if (tagged(field, {0x99})) {
            order = 6;
            if (!named_bits(field.value)) return fail(error, LpaRspError::der_malformed);
            policy = field.value.size() > 1U;
        } else if (tagged(field, {0xBF, 0x22}) || tagged(field, {0xBF, 0x23})) {
            order = field.tag.back() == 0x22U ? 7 : 8;
            for (const auto& extension : field.children) {
                if (!tagged(extension, {0x30}) ||
                    !ordered_fields(extension, {{0x80}, {0xA1}}) ||
                    !valid_oid(extension.children[0].value) ||
                    extension.children[1].children.size() != 1U)
                    return fail(error, LpaRspError::der_malformed);
            }
        } else return fail(error, LpaRspError::der_malformed);
        if (order <= previous) return fail(error, LpaRspError::der_duplicate);
        previous = order;
    }
    if (policy && !owner) return fail(error, LpaRspError::der_malformed);
    metadata.service_provider_name.assign(reinterpret_cast<const char*>(fields[1].value.data()),
                                           fields[1].value.size());
    metadata.profile_name.assign(reinterpret_cast<const char*>(fields[2].value.data()), fields[2].value.size());
    metadata.has_policy_rules = policy;
    return true;
}

bool idf_lpa_rsp_build_cancel_session_request(
    const std::uint8_t* transaction, std::size_t transaction_size, LpaRspCancelReason reason,
    std::vector<std::uint8_t>& request, LpaRspError& error)
{
    error = LpaRspError::none;
    const bool alias = ranges_overlap(transaction, transaction_size, request.data(), request.capacity());
    clear_bytes(request);
    if (alias) return fail(error, LpaRspError::der_malformed);
    if (!transaction || transaction_size == 0U || transaction_size > kMaxTransactionBytes)
        return fail(error, LpaRspError::transaction_mismatch);
    if (!valid_cancel_reason(reason)) return fail(error, LpaRspError::der_malformed);
    std::vector<std::uint8_t> tx(transaction, transaction + transaction_size), body;
    body.reserve(24U);
    request.reserve(28U);
    append_object(body, {0x80}, tx);
    append_object(body, {0x81}, {static_cast<std::uint8_t>(reason)});
    append_object(request, {0xBF, 0x41}, body);
    clear_bytes(tx); clear_bytes(body);
    return true;
}

bool idf_lpa_rsp_parse_cancel_session_response(
    const std::uint8_t* object, std::size_t object_size,
    const std::uint8_t* transaction, std::size_t transaction_size,
    LpaRspCancelReason reason, std::vector<std::uint8_t>& response, LpaRspError& error)
{
    error = LpaRspError::none;
    const bool alias = ranges_overlap(object, object_size, response.data(), response.capacity()) ||
        ranges_overlap(transaction, transaction_size, response.data(), response.capacity());
    clear_bytes(response);
    if (alias) return fail(error, LpaRspError::der_malformed);
    if (!transaction || transaction_size == 0U || transaction_size > kMaxTransactionBytes)
        return fail(error, LpaRspError::transaction_mismatch);
    if (!valid_cancel_reason(reason)) return fail(error, LpaRspError::der_malformed);
    SensitiveTlv holder;
    if (!parse_der_root(object, object_size, holder, error)) return false;
    if (!tagged(holder.value, {0xBF, 0x41})) return fail(error, LpaRspError::der_root);
    if (holder.value.children.size() != 1U) return fail(error, LpaRspError::der_malformed);
    const auto& choice = holder.value.children[0];
    std::uint32_t code = 0;
    if (tagged(choice, {0x81})) {
        if (!canonical_nonnegative_integer(choice.value, 1U, code) || (code != 5U && code != 127U))
            return fail(error, LpaRspError::der_malformed);
        return fail(error, LpaRspError::server_error);
    }
    if (!tagged(choice, {0xA0}) || !ordered_fields(choice, {{0x30}, {0x5F, 0x37}}) ||
        !ordered_fields(choice.children[0], {{0x80}, {0x81}, {0x82}}) ||
        choice.children[1].value.empty() || choice.children[1].value.size() > kMaxSignatureBytes)
        return fail(error, LpaRspError::der_malformed);
    const auto& signed_data = choice.children[0].children;
    if (signed_data[0].value.size() != transaction_size ||
        std::memcmp(signed_data[0].value.data(), transaction, transaction_size) != 0)
        return fail(error, LpaRspError::transaction_mismatch);
    if (!valid_oid(signed_data[1].value) ||
        !canonical_nonnegative_integer(signed_data[2].value, 1U, code) ||
        code != static_cast<std::uint8_t>(reason)) return fail(error, LpaRspError::der_malformed);
    response.assign(object, object + object_size);
    return true;
}

bool idf_lpa_rsp_parse_prepare_download_response(
    const std::uint8_t* object,
    std::size_t object_size,
    const std::uint8_t* expected_transaction,
    std::size_t expected_transaction_size,
    std::vector<std::uint8_t>& get_bpp_response,
    LpaRspError& error)
{
    error = LpaRspError::none;
    const bool output_alias =
        ranges_overlap(object, object_size, get_bpp_response.data(), get_bpp_response.capacity()) ||
        ranges_overlap(expected_transaction, expected_transaction_size, get_bpp_response.data(),
                       get_bpp_response.capacity());
    if (output_alias) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
    }
    if (!expected_transaction || expected_transaction_size == 0U ||
        expected_transaction_size > kMaxTransactionBytes) {
        return prepare_fail(get_bpp_response, error, LpaRspError::transaction_mismatch);
    }

    SensitiveTlv holder;
    if (!parse_der_root(object, object_size, holder, error)) {
        return prepare_fail(get_bpp_response, error, error);
    }
    static constexpr std::uint8_t kPrepareDownload[] = {0xBFU, 0x21U};
    static constexpr std::uint8_t kSuccess[] = {0xA0U};
    static constexpr std::uint8_t kError[] = {0xA1U};
    static constexpr std::uint8_t kSequence[] = {0x30U};
    static constexpr std::uint8_t kSignature[] = {0x5FU, 0x37U};
    static constexpr std::uint8_t kOtpk[] = {0x5FU, 0x49U};
    static constexpr std::uint8_t kHashCc[] = {0x04U};
    static constexpr std::uint8_t kTransaction[] = {0x80U};
    static constexpr std::uint8_t kInteger[] = {0x02U};

    if (!tag_matches(holder.value, kPrepareDownload, sizeof(kPrepareDownload))) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_root);
    }
    bool duplicate_success = false;
    bool duplicate_error = false;
    const idf_esim_internal::Tlv* success_choice = unique_child(
        holder.value, kSuccess, sizeof(kSuccess), duplicate_success);
    const idf_esim_internal::Tlv* error_choice = unique_child(
        holder.value, kError, sizeof(kError), duplicate_error);
    if (duplicate_success || duplicate_error) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_duplicate);
    }
    for (const idf_esim_internal::Tlv& child : holder.value.children) {
        if (!tag_matches(child, kSuccess, sizeof(kSuccess)) &&
            !tag_matches(child, kError, sizeof(kError))) {
            return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
        }
    }
    if (success_choice && error_choice) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
    }
    if (error_choice) {
        bool duplicate_transaction = false;
        bool duplicate_code = false;
        const idf_esim_internal::Tlv* transaction = unique_child(
            *error_choice, kTransaction, sizeof(kTransaction), duplicate_transaction);
        const idf_esim_internal::Tlv* code = unique_child(
            *error_choice, kInteger, sizeof(kInteger), duplicate_code);
        if (duplicate_transaction || duplicate_code) {
            return prepare_fail(get_bpp_response, error, LpaRspError::der_duplicate);
        }
        for (const idf_esim_internal::Tlv& child : error_choice->children) {
            if (!tag_matches(child, kTransaction, sizeof(kTransaction)) &&
                !tag_matches(child, kInteger, sizeof(kInteger))) {
                return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
            }
        }
        if (!transaction || !code) {
            return prepare_fail(get_bpp_response, error, LpaRspError::field_missing);
        }
        if (error_choice->children.size() != 2U ||
            !tag_matches(error_choice->children[0], kTransaction, sizeof(kTransaction)) ||
            !tag_matches(error_choice->children[1], kInteger, sizeof(kInteger))) {
            return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
        }
        if (transaction->value.size() != expected_transaction_size ||
            std::memcmp(transaction->value.data(), expected_transaction,
                        expected_transaction_size) != 0) {
            return prepare_fail(get_bpp_response, error, LpaRspError::transaction_mismatch);
        }
        std::uint32_t ignored_code = 0U;
        if (!canonical_nonnegative_integer(code->value, 4U, ignored_code) ||
            !valid_download_error_code(ignored_code)) {
            return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
        }
        // 不回傳或複製 eUICC 拒絕細節。
        return prepare_fail(get_bpp_response, error, LpaRspError::server_error);
    }
    if (!success_choice) {
        return prepare_fail(get_bpp_response, error, LpaRspError::field_missing);
    }

    bool duplicate_signed_data = false;
    bool duplicate_signature = false;
    const idf_esim_internal::Tlv* signed_data = unique_child(
        *success_choice, kSequence, sizeof(kSequence), duplicate_signed_data);
    const idf_esim_internal::Tlv* signature = unique_child(
        *success_choice, kSignature, sizeof(kSignature), duplicate_signature);
    if (duplicate_signed_data || duplicate_signature) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_duplicate);
    }
    for (const idf_esim_internal::Tlv& child : success_choice->children) {
        if (!tag_matches(child, kSequence, sizeof(kSequence)) &&
            !tag_matches(child, kSignature, sizeof(kSignature))) {
            return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
        }
    }
    if (!signed_data || !signature) {
        return prepare_fail(get_bpp_response, error, LpaRspError::field_missing);
    }
    if (success_choice->children.size() != 2U ||
        !tag_matches(success_choice->children[0], kSequence, sizeof(kSequence)) ||
        !tag_matches(success_choice->children[1], kSignature, sizeof(kSignature))) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
    }
    if (signature->value.empty() || signature->value.size() > kMaxSignatureBytes) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
    }
    bool duplicate_otpk = false;
    bool duplicate_transaction = false;
    bool duplicate_hash_cc = false;
    const idf_esim_internal::Tlv* otpk = unique_child(
        *signed_data, kOtpk, sizeof(kOtpk), duplicate_otpk);
    const idf_esim_internal::Tlv* transaction = unique_child(
        *signed_data, kTransaction, sizeof(kTransaction), duplicate_transaction);
    const idf_esim_internal::Tlv* hash_cc = unique_child(
        *signed_data, kHashCc, sizeof(kHashCc), duplicate_hash_cc);
    if (duplicate_otpk || duplicate_transaction || duplicate_hash_cc) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_duplicate);
    }
    for (const idf_esim_internal::Tlv& child : signed_data->children) {
        if (!tag_matches(child, kOtpk, sizeof(kOtpk)) &&
            !tag_matches(child, kTransaction, sizeof(kTransaction)) &&
            !tag_matches(child, kHashCc, sizeof(kHashCc))) {
            return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
        }
    }
    if (!otpk || !transaction) {
        return prepare_fail(get_bpp_response, error, LpaRspError::field_missing);
    }
    if (signed_data->children.size() < 2U || signed_data->children.size() > 3U ||
        !tag_matches(signed_data->children[0], kTransaction, sizeof(kTransaction)) ||
        !tag_matches(signed_data->children[1], kOtpk, sizeof(kOtpk)) ||
        (signed_data->children.size() == 3U &&
         !tag_matches(signed_data->children[2], kHashCc, sizeof(kHashCc)))) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
    }
    if (otpk->value.empty() || otpk->value.size() > kMaxOtpkBytes) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
    }
    if (hash_cc && hash_cc->value.size() != kHashBytes) {
        return prepare_fail(get_bpp_response, error, LpaRspError::der_malformed);
    }
    if (transaction->value.size() != expected_transaction_size ||
        std::memcmp(transaction->value.data(), expected_transaction,
                    expected_transaction_size) != 0) {
        return prepare_fail(get_bpp_response, error, LpaRspError::transaction_mismatch);
    }

    // 僅保留已驗證的有界物件；錯誤分支與 parser 內部資料不會外洩給 GetBPP。
    std::vector<std::uint8_t> copy(object, object + object_size);
    clear_bytes(get_bpp_response);
    get_bpp_response = std::move(copy);
    error = LpaRspError::none;
    return true;
}

static bool parse_installation_notification(
    const std::uint8_t* object,
    std::size_t object_size,
    const std::uint8_t* expected_transaction,
    std::size_t expected_transaction_size,
    std::string_view expected_activation_host,
    bool pending,
    bool& installed,
    std::uint32_t& sequence_number,
    std::string& notification_address,
    LpaRspError& error)
{
    installed = false;
    error = LpaRspError::none;
    const bool output_alias =
        ranges_overlap(object, object_size, notification_address.data(),
                       notification_address.capacity()) ||
        ranges_overlap(expected_transaction, expected_transaction_size,
                       notification_address.data(), notification_address.capacity()) ||
        ranges_overlap(expected_activation_host.data(), expected_activation_host.size(),
                       notification_address.data(), notification_address.capacity());
    if (output_alias) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }
    sequence_number = 0U;
    clear_string(notification_address);
    if (!pending && (!expected_transaction || expected_transaction_size == 0U ||
        expected_transaction_size > kMaxTransactionBytes)) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::transaction_mismatch);
    }
    if (!valid_smdp_host(expected_activation_host)) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::address_mismatch);
    }

    SensitiveTlv holder;
    if (!parse_der_root(object, object_size, holder, error)) {
        return pir_fail(sequence_number, notification_address, error, error);
    }
    static constexpr std::uint8_t kPir[] = {0xBFU, 0x37U};
    static constexpr std::uint8_t kData[] = {0xBFU, 0x27U};
    static constexpr std::uint8_t kMetadata[] = {0xBFU, 0x2FU};
    static constexpr std::uint8_t kSignature[] = {0x5FU, 0x37U};
    static constexpr std::uint8_t kTransaction[] = {0x80U};
    static constexpr std::uint8_t kOid[] = {0x06U};
    static constexpr std::uint8_t kFinalResult[] = {0xA2U};
    static constexpr std::uint8_t kSuccess[] = {0xA0U};
    static constexpr std::uint8_t kError[] = {0xA1U};
    static constexpr std::uint8_t kSequence[] = {0x80U};
    static constexpr std::uint8_t kOperation[] = {0x81U};
    static constexpr std::uint8_t kAddress[] = {0x0CU};
    static constexpr std::uint8_t kIccid[] = {0x5AU};
    static constexpr std::uint8_t kAid[] = {0x4FU};
    static constexpr std::uint8_t kSimaResponse[] = {0x04U};
    static constexpr std::uint8_t kInteger[] = {0x02U};

    if (!tag_matches(holder.value, kPir, sizeof(kPir))) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_root);
    }
    bool duplicate_data = false;
    bool duplicate_signature = false;
    const idf_esim_internal::Tlv* data = unique_child(
        holder.value, kData, sizeof(kData), duplicate_data);
    const idf_esim_internal::Tlv* signature = unique_child(
        holder.value, kSignature, sizeof(kSignature), duplicate_signature);
    if (duplicate_data || duplicate_signature) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_duplicate);
    }
    for (const idf_esim_internal::Tlv& child : holder.value.children) {
        if (!tag_matches(child, kData, sizeof(kData)) &&
            !tag_matches(child, kSignature, sizeof(kSignature))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
    }
    if (!data || !signature) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::field_missing);
    }
    if (holder.value.children.size() != 2U ||
        !tag_matches(holder.value.children[0], kData, sizeof(kData)) ||
        !tag_matches(holder.value.children[1], kSignature, sizeof(kSignature))) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }
    if (signature->value.empty() || signature->value.size() > kMaxSignatureBytes) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }

    bool duplicate_transaction = false;
    bool duplicate_metadata = false;
    bool duplicate_oid = false;
    bool duplicate_final_result = false;
    const idf_esim_internal::Tlv* transaction = unique_child(
        *data, kTransaction, sizeof(kTransaction), duplicate_transaction);
    const idf_esim_internal::Tlv* metadata = unique_child(
        *data, kMetadata, sizeof(kMetadata), duplicate_metadata);
    const idf_esim_internal::Tlv* oid = unique_child(
        *data, kOid, sizeof(kOid), duplicate_oid);
    const idf_esim_internal::Tlv* final_result = unique_child(
        *data, kFinalResult, sizeof(kFinalResult), duplicate_final_result);
    if (duplicate_transaction || duplicate_metadata || duplicate_oid ||
        duplicate_final_result) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_duplicate);
    }
    for (const idf_esim_internal::Tlv& child : data->children) {
        if (!tag_matches(child, kTransaction, sizeof(kTransaction)) &&
            !tag_matches(child, kMetadata, sizeof(kMetadata)) &&
            !tag_matches(child, kOid, sizeof(kOid)) &&
            !tag_matches(child, kFinalResult, sizeof(kFinalResult))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
    }
    if (!transaction || !metadata || !oid || !final_result) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::field_missing);
    }
    if (data->children.size() != 4U ||
        !tag_matches(data->children[0], kTransaction, sizeof(kTransaction)) ||
        !tag_matches(data->children[1], kMetadata, sizeof(kMetadata)) ||
        !tag_matches(data->children[2], kOid, sizeof(kOid)) ||
        !tag_matches(data->children[3], kFinalResult, sizeof(kFinalResult))) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }
    if (transaction->value.empty() || transaction->value.size() > kMaxTransactionBytes ||
        (!pending && (transaction->value.size() != expected_transaction_size ||
         std::memcmp(transaction->value.data(), expected_transaction,
                     expected_transaction_size) != 0))) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::transaction_mismatch);
    }
    if (!valid_oid(oid->value)) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }

    bool duplicate_sequence = false;
    bool duplicate_operation = false;
    bool duplicate_address = false;
    bool duplicate_iccid = false;
    const idf_esim_internal::Tlv* sequence = unique_child(
        *metadata, kSequence, sizeof(kSequence), duplicate_sequence);
    const idf_esim_internal::Tlv* operation = unique_child(
        *metadata, kOperation, sizeof(kOperation), duplicate_operation);
    const idf_esim_internal::Tlv* address = unique_child(
        *metadata, kAddress, sizeof(kAddress), duplicate_address);
    const idf_esim_internal::Tlv* iccid = unique_child(
        *metadata, kIccid, sizeof(kIccid), duplicate_iccid);
    if (duplicate_sequence || duplicate_operation || duplicate_address || duplicate_iccid) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_duplicate);
    }
    for (const idf_esim_internal::Tlv& child : metadata->children) {
        if (!tag_matches(child, kSequence, sizeof(kSequence)) &&
            !tag_matches(child, kOperation, sizeof(kOperation)) &&
            !tag_matches(child, kAddress, sizeof(kAddress)) &&
            !tag_matches(child, kIccid, sizeof(kIccid))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
    }
    if (!sequence || !operation || !address) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::field_missing);
    }
    if (metadata->children.size() < 3U || metadata->children.size() > 4U ||
        !tag_matches(metadata->children[0], kSequence, sizeof(kSequence)) ||
        !tag_matches(metadata->children[1], kOperation, sizeof(kOperation)) ||
        !tag_matches(metadata->children[2], kAddress, sizeof(kAddress)) ||
        (metadata->children.size() == 4U &&
         !tag_matches(metadata->children[3], kIccid, sizeof(kIccid))) ||
        (iccid && !valid_iccid(iccid->value))) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }
    std::uint32_t parsed_sequence = 0U;
    if (!canonical_nonnegative_integer(sequence->value, 4U, parsed_sequence)) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }
    if (operation->value.size() != 2U ||
        (static_cast<std::uint16_t>(operation->value[0]) << 8U |
         operation->value[1]) != 0x0780U) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }
    if (address->value.empty() || address->value.size() > 253U ||
        !printable_ascii(address->value)) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::address_mismatch);
    }
    const std::string_view parsed_address(
        reinterpret_cast<const char*>(address->value.data()), address->value.size());
    if (!valid_smdp_host(parsed_address) ||
        !equal_ascii_ci(address->value, expected_activation_host)) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::address_mismatch);
    }

    bool duplicate_success = false;
    bool duplicate_error = false;
    const idf_esim_internal::Tlv* success = unique_child(
        *final_result, kSuccess, sizeof(kSuccess), duplicate_success);
    const idf_esim_internal::Tlv* result_error = unique_child(
        *final_result, kError, sizeof(kError), duplicate_error);
    if (duplicate_success || duplicate_error) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_duplicate);
    }
    for (const idf_esim_internal::Tlv& child : final_result->children) {
        if (!tag_matches(child, kSuccess, sizeof(kSuccess)) &&
            !tag_matches(child, kError, sizeof(kError))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
    }
    if (success && result_error) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }
    if (result_error) {
        const std::vector<idf_esim_internal::Tlv>& fields = result_error->children;
        if (fields.size() < 2U) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::field_missing);
        }
        if (!tag_matches(fields[0], kInteger, sizeof(kInteger)) ||
            !tag_matches(fields[1], kInteger, sizeof(kInteger))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
        if (fields.size() > 2U &&
            tag_matches(fields[2], kInteger, sizeof(kInteger))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_duplicate);
        }
        if (fields.size() > 2U &&
            !tag_matches(fields[2], kSimaResponse, sizeof(kSimaResponse))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
        if (fields.size() > 3U &&
            tag_matches(fields[3], kSimaResponse, sizeof(kSimaResponse))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_duplicate);
        }
        if (fields.size() > 3U) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
        std::uint32_t command_id = 0U;
        std::uint32_t reason = 0U;
        if (!canonical_nonnegative_integer(fields[0].value, 1U, command_id) ||
            !canonical_nonnegative_integer(fields[1].value, 1U, reason) ||
            !valid_bpp_command_id(command_id) || !valid_error_reason(reason)) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
        if (fields.size() > 2U && fields[2].value.empty()) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
        // 失败通知仍须发送，但不回传 eUICC 错误细节，也不能视为安装成功。
        sequence_number = parsed_sequence;
        notification_address.assign(parsed_address.data(), parsed_address.size());
        return true;
    }
    if (!success) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::field_missing);
    }

    bool duplicate_aid = false;
    bool duplicate_sima_response = false;
    const idf_esim_internal::Tlv* aid = unique_child(
        *success, kAid, sizeof(kAid), duplicate_aid);
    const idf_esim_internal::Tlv* sima_response = unique_child(
        *success, kSimaResponse, sizeof(kSimaResponse), duplicate_sima_response);
    if (duplicate_aid || duplicate_sima_response) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_duplicate);
    }
    for (const idf_esim_internal::Tlv& child : success->children) {
        if (!tag_matches(child, kAid, sizeof(kAid)) &&
            !tag_matches(child, kSimaResponse, sizeof(kSimaResponse))) {
            return pir_fail(sequence_number, notification_address, error,
                            LpaRspError::der_malformed);
        }
    }
    if (!aid || !sima_response) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::field_missing);
    }
    if (success->children.size() != 2U ||
        !tag_matches(success->children[0], kAid, sizeof(kAid)) ||
        !tag_matches(success->children[1], kSimaResponse, sizeof(kSimaResponse))) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }
    if (aid->value.size() < 5U || aid->value.size() > 16U ||
        sima_response->value.empty()) {
        return pir_fail(sequence_number, notification_address, error,
                        LpaRspError::der_malformed);
    }

    sequence_number = parsed_sequence;
    notification_address.assign(parsed_address.data(), parsed_address.size());
    installed = true;
    error = LpaRspError::none;
    return true;
}

bool idf_lpa_rsp_parse_profile_installation_notification(
    const std::uint8_t* object, std::size_t object_size,
    const std::uint8_t* expected_transaction, std::size_t expected_transaction_size,
    std::string_view expected_activation_host, bool& installed,
    std::uint32_t& sequence_number, std::string& notification_address, LpaRspError& error)
{
    return parse_installation_notification(
        object, object_size, expected_transaction, expected_transaction_size,
        expected_activation_host, false, installed, sequence_number, notification_address, error);
}

bool idf_lpa_rsp_parse_profile_installation_result(
    const std::uint8_t* object, std::size_t object_size,
    const std::uint8_t* expected_transaction, std::size_t expected_transaction_size,
    std::string_view expected_activation_host, std::uint32_t& sequence_number,
    std::string& notification_address, LpaRspError& error)
{
    bool installed = false;
    if (!idf_lpa_rsp_parse_profile_installation_notification(
            object, object_size, expected_transaction, expected_transaction_size,
            expected_activation_host, installed, sequence_number, notification_address, error)) {
        return false;
    }
    return installed || pir_fail(sequence_number, notification_address, error, LpaRspError::server_error);
}

bool idf_lpa_rsp_parse_pending_installation_notification(
    const std::uint8_t* object, std::size_t object_size,
    std::string_view expected_activation_host, bool& installed,
    std::uint32_t& sequence_number, std::string& notification_address, LpaRspError& error)
{
    return parse_installation_notification(object, object_size, nullptr, 0,
        expected_activation_host, true, installed, sequence_number, notification_address, error);
}
