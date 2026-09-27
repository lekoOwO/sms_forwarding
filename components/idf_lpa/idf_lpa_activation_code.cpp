#include "idf_lpa_activation_code.h"

#include <algorithm>
#include <cctype>
#include <iterator>

namespace {

constexpr std::size_t kMaxCoreBytes = 512U;
constexpr std::size_t kMaxInputBytes = 516U;
constexpr std::size_t kMaxFields = 7U;
constexpr std::size_t kMaxOptionalFieldBytes = 64U;

void secure_zero(void* data, std::size_t size) noexcept
{
    volatile unsigned char* bytes = static_cast<volatile unsigned char*>(data);
    while (size != 0U) {
        *bytes++ = 0U;
        --size;
    }
}

bool is_printable_ascii(std::string_view value) noexcept
{
    for (unsigned char byte : value) {
        if (byte < 0x20U || byte > 0x7EU) return false;
    }
    return true;
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
        const std::size_t label_length = label_end - label_start;
        if (label_length == 0U || label_length > 63U) return false;
        if (value[label_start] == '-' || value[label_end - 1U] == '-') return false;

        bool numeric_label = true;
        for (std::size_t index = label_start; index < label_end; ++index) {
            const unsigned char byte = static_cast<unsigned char>(value[index]);
            const bool letter = (byte >= 'A' && byte <= 'Z') ||
                                (byte >= 'a' && byte <= 'z');
            const bool digit = byte >= '0' && byte <= '9';
            if (!letter && !digit && byte != '-') return false;
            if (!digit) numeric_label = false;
        }

        ++label_count;
        all_numeric_labels = all_numeric_labels && numeric_label;
        if (dot == std::string_view::npos) break;
        label_start = dot + 1U;
    }

    return label_count >= 2U && !all_numeric_labels;
}

bool valid_matching_id(std::string_view value) noexcept
{
    if (value.empty() || value.size() > 128U) return false;
    for (unsigned char byte : value) {
        if (byte < 0x21U || byte > 0x7EU) return false;
    }
    return true;
}

bool valid_optional_field(std::string_view value) noexcept
{
    return !value.empty() && value.size() <= kMaxOptionalFieldBytes &&
           is_printable_ascii(value);
}

bool starts_with(std::string_view value, std::string_view prefix) noexcept
{
    return value.size() >= prefix.size() && value.substr(0U, prefix.size()) == prefix;
}

bool fail(LpaActivationCode& output,
          LpaActivationCodeParseError* error,
          LpaActivationCodeParseError reason) noexcept
{
    output.clear_sensitive();
    if (error) *error = reason;
    return false;
}

}  // namespace

LpaActivationCode::LpaActivationCode(LpaActivationCode&& other) noexcept
{
    std::copy(std::begin(other.smdp_host_), std::end(other.smdp_host_), std::begin(smdp_host_));
    std::copy(std::begin(other.matching_id_), std::end(other.matching_id_),
              std::begin(matching_id_));
    smdp_host_length_ = other.smdp_host_length_;
    matching_id_length_ = other.matching_id_length_;
    other.clear_sensitive();
}

LpaActivationCode& LpaActivationCode::operator=(LpaActivationCode&& other) noexcept
{
    if (this == &other) return *this;
    clear_sensitive();
    std::copy(std::begin(other.smdp_host_), std::end(other.smdp_host_), std::begin(smdp_host_));
    std::copy(std::begin(other.matching_id_), std::end(other.matching_id_),
              std::begin(matching_id_));
    smdp_host_length_ = other.smdp_host_length_;
    matching_id_length_ = other.matching_id_length_;
    other.clear_sensitive();
    return *this;
}

void LpaActivationCode::clear_sensitive() noexcept
{
    secure_zero(this, sizeof(*this));
}

LpaActivationCode::~LpaActivationCode() noexcept
{
    clear_sensitive();
}

bool idf_lpa_parse_activation_code(std::string_view input,
                                   LpaActivationCode& output,
                                   LpaActivationCodeParseError* error) noexcept
{
    output.clear_sensitive();
    if (error) *error = LpaActivationCodeParseError::unknown;

    if (input.size() > kMaxInputBytes) {
        return fail(output, error, LpaActivationCodeParseError::input_too_long);
    }
    if (!is_printable_ascii(input)) {
        return fail(output, error, LpaActivationCodeParseError::non_printable);
    }

    std::size_t begin = 0U;
    std::size_t end = input.size();
    // The printable-ASCII check above runs first, so isspace() can only
    // normalize printable spaces without allowing control whitespace.
    while (begin < end && std::isspace(static_cast<unsigned char>(input[begin]))) {
        ++begin;
    }
    while (end > begin && std::isspace(static_cast<unsigned char>(input[end - 1U]))) {
        --end;
    }
    if (begin == end) return fail(output, error, LpaActivationCodeParseError::empty);

    const std::string_view normalized = input.substr(begin, end - begin);
    std::size_t core_offset = 0U;
    if (starts_with(normalized, "LPA:")) {
        if (normalized.size() <= 4U || normalized[4U] != '1') {
            return fail(output, error, LpaActivationCodeParseError::version);
        }
        core_offset = 4U;
    }

    const std::string_view core = normalized.substr(core_offset);
    if (core.empty()) return fail(output, error, LpaActivationCodeParseError::fields);
    if (core.size() > kMaxCoreBytes) {
        return fail(output, error, LpaActivationCodeParseError::core_too_long);
    }

    std::size_t field_begin[kMaxFields] = {};
    std::size_t field_end[kMaxFields] = {};
    std::size_t field_count = 0U;
    std::size_t cursor = 0U;
    while (true) {
        if (field_count == kMaxFields) {
            return fail(output, error, LpaActivationCodeParseError::too_many_fields);
        }
        const std::size_t delimiter = core.find('$', cursor);
        field_begin[field_count] = cursor;
        field_end[field_count] = delimiter == std::string_view::npos ? core.size() : delimiter;
        ++field_count;
        if (delimiter == std::string_view::npos) break;
        cursor = delimiter + 1U;
    }

    if (core.substr(field_begin[0], field_end[0] - field_begin[0]) != "1") {
        return fail(output, error, LpaActivationCodeParseError::version);
    }
    if (field_count < 3U) return fail(output, error, LpaActivationCodeParseError::fields);

    const std::string_view host =
        core.substr(field_begin[1], field_end[1] - field_begin[1]);
    const std::string_view matching_id =
        core.substr(field_begin[2], field_end[2] - field_begin[2]);
    if (!valid_smdp_host(host)) return fail(output, error, LpaActivationCodeParseError::host);
    if (!valid_matching_id(matching_id)) {
        return fail(output, error, LpaActivationCodeParseError::matching_id);
    }
    for (std::size_t index = 3U; index < field_count; ++index) {
        const std::string_view optional =
            core.substr(field_begin[index], field_end[index] - field_begin[index]);
        if (!valid_optional_field(optional)) {
            return fail(output, error, LpaActivationCodeParseError::optional_field);
        }
    }

    std::copy(host.begin(), host.end(), std::begin(output.smdp_host_));
    output.smdp_host_[host.size()] = '\0';
    output.smdp_host_length_ = host.size();
    std::copy(matching_id.begin(), matching_id.end(), std::begin(output.matching_id_));
    output.matching_id_[matching_id.size()] = '\0';
    output.matching_id_length_ = matching_id.size();
    if (error) *error = LpaActivationCodeParseError::none;
    return true;
}

const char* idf_lpa_activation_code_error_name(LpaActivationCodeParseError error) noexcept
{
    switch (error) {
        case LpaActivationCodeParseError::none: return "none";
        case LpaActivationCodeParseError::empty: return "empty";
        case LpaActivationCodeParseError::input_too_long: return "input_too_long";
        case LpaActivationCodeParseError::core_too_long: return "core_too_long";
        case LpaActivationCodeParseError::non_printable: return "non_printable";
        case LpaActivationCodeParseError::version: return "version";
        case LpaActivationCodeParseError::fields: return "fields";
        case LpaActivationCodeParseError::too_many_fields: return "too_many_fields";
        case LpaActivationCodeParseError::host: return "host";
        case LpaActivationCodeParseError::matching_id: return "matching_id";
        case LpaActivationCodeParseError::optional_field: return "optional_field";
        case LpaActivationCodeParseError::unknown: return "unknown";
    }
    return "unknown";
}

#ifdef IDF_LPA_ACTIVATION_CODE_TESTING
bool LpaActivationCode::test_storage_is_zero(const void* storage) noexcept
{
    if (!storage) return false;
    const volatile unsigned char* bytes =
        static_cast<const volatile unsigned char*>(storage);
    for (std::size_t index = 0U; index < sizeof(LpaActivationCode); ++index) {
        if (*bytes++ != 0U) return false;
    }
    return true;
}
#endif
