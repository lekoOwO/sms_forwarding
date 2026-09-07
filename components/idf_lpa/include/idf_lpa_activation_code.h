#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

// Bounded, non-echoing outcomes for activation-code validation.
enum class LpaActivationCodeParseError : uint8_t {
    none = 0,
    empty,
    input_too_long,
    core_too_long,
    non_printable,
    version,
    fields,
    too_many_fields,
    host,
    matching_id,
    optional_field,
    unknown,
};

// The parser owns only the two fields needed by the next LPA stage.  Optional
// fields are validated and discarded so they cannot persist accidentally.
class LpaActivationCode final {
public:
    LpaActivationCode() noexcept = default;
    LpaActivationCode(const LpaActivationCode&) = delete;
    LpaActivationCode& operator=(const LpaActivationCode&) = delete;
    LpaActivationCode(LpaActivationCode&& other) noexcept;
    LpaActivationCode& operator=(LpaActivationCode&& other) noexcept;
    ~LpaActivationCode() noexcept;

    std::string_view smdp_host() const noexcept
    {
        return std::string_view(smdp_host_, smdp_host_length_);
    }

    std::string_view matching_id() const noexcept
    {
        return std::string_view(matching_id_, matching_id_length_);
    }

    // Clears all owned bytes and lengths. Parsing also invokes this before
    // every failure so a reused output cannot retain a previous value.
    void clear_sensitive() noexcept;

#ifdef IDF_LPA_ACTIVATION_CODE_TESTING
    // Test-only boolean inspection; production builds expose no storage hook.
    static bool test_storage_is_zero(const void* storage) noexcept;
#endif

private:
    static constexpr std::size_t kMaxSmdpHostBytes = 253U;
    static constexpr std::size_t kMaxMatchingIdBytes = 128U;

    char smdp_host_[kMaxSmdpHostBytes + 1U] = {};
    char matching_id_[kMaxMatchingIdBytes + 1U] = {};
    std::size_t smdp_host_length_ = 0;
    std::size_t matching_id_length_ = 0;

    friend bool idf_lpa_parse_activation_code(std::string_view input,
                                              LpaActivationCode& output,
                                              LpaActivationCodeParseError* error) noexcept;
};

// Accepts only SGP.22 activation-code version 1.  The input and core limits
// are 516 and 512 bytes respectively; no input is copied into an error.
bool idf_lpa_parse_activation_code(
    std::string_view input,
    LpaActivationCode& output,
    LpaActivationCodeParseError* error = nullptr) noexcept;

const char* idf_lpa_activation_code_error_name(
    LpaActivationCodeParseError error) noexcept;
