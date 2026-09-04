#include "idf_lpa_rsp.h"

#include "idf_esim_codec.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
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
    if (!value.empty()) secure_zero(value.data(), value.size());
    value.clear();
}

void clear_bytes(std::vector<std::uint8_t>& value) noexcept
{
    if (!value.empty()) secure_zero(value.data(), value.size());
    value.clear();
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

const std::uint8_t* expected_root_tag(LpaRspDerObject kind, std::size_t& size) noexcept
{
    static constexpr std::uint8_t kSequence[] = {0x30U};
    static constexpr std::uint8_t kAuthenticateServerResponse[] = {0xBFU, 0x38U};
    static constexpr std::uint8_t kPrepareDownloadResponse[] = {0xBFU, 0x21U};
    static constexpr std::uint8_t kProfileMetadata[] = {0xBFU, 0x2FU};
    static constexpr std::uint8_t kProfileInstallationResult[] = {0xBFU, 0x37U};
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
    case LpaRspDerObject::notification_metadata:
        size = sizeof(kProfileMetadata);
        return kProfileMetadata;
    case LpaRspDerObject::profile_installation_result:
        size = sizeof(kProfileInstallationResult);
        return kProfileInstallationResult;
    }
    size = 0U;
    return nullptr;
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
    for (const idf_esim_internal::Tlv& child : holder.value.children) {
        if (!tag_matches(child, kTransaction, sizeof(kTransaction)) &&
            !tag_matches(child, kConfirmation, sizeof(kConfirmation))) {
            return fail(error, LpaRspError::der_malformed);
        }
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
    if (confirmation_code.empty() || confirmation_code.size() > 128U || !transaction_id ||
        transaction_size == 0U || transaction_size > kMaxTransactionBytes) {
        return fail(error, LpaRspError::crypto_input);
    }
    for (unsigned char value : confirmation_code) {
        if (value < 0x20U || value > 0x7EU) return fail(error, LpaRspError::crypto_input);
    }
#ifdef ESP_PLATFORM
    if (psa_crypto_init() != PSA_SUCCESS) return fail(error, LpaRspError::crypto_failure);
#endif
    std::array<std::uint8_t, 128> confirmation_bytes = {};
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
