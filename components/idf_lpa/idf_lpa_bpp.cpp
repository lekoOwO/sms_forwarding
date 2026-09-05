#include "idf_lpa_bpp.h"

#include "idf_esim_lpa.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <vector>

namespace {

constexpr char kMalformedMessage[] = "BPP response rejected";
constexpr char kLimitMessage[] = "BPP response exceeds its limit";
constexpr char kCardMessage[] = "BPP card operation failed";
constexpr std::size_t kJsonMaxDepth = 8U;
constexpr std::size_t kJsonMaxMembers = 32U;
constexpr std::size_t kJsonMaxKeyBytes = 64U;
constexpr std::size_t kJsonMaxPrimitiveBytes = 64U;
constexpr std::size_t kJsonMaxPrefixBytes = 16U * 1024U;

void secure_zero(void* address, std::size_t size) noexcept
{
    volatile auto* bytes = static_cast<volatile std::uint8_t*>(address);
    while (size != 0U) {
        *bytes = 0U;
        ++bytes;
        --size;
    }
}

void secure_clear(std::string& value) noexcept
{
    if (!value.empty()) secure_zero(value.data(), value.size());
    value.clear();
    std::string().swap(value);
}

void secure_clear(std::vector<std::uint8_t>& value) noexcept
{
    if (value.capacity() != 0U && value.data() != nullptr) {
        secure_zero(value.data(), value.capacity());
    }
    value.clear();
    std::vector<std::uint8_t>().swap(value);
}

void secure_clear(std::array<std::uint8_t, 4>& value) noexcept
{
    secure_zero(value.data(), value.size());
}

void set_safe_message(std::string& message, const char* text) noexcept
{
    secure_clear(message);
    message.assign(text ? text : kMalformedMessage);
}

bool is_json_space(unsigned char value) noexcept
{
    return value == static_cast<unsigned char>(' ') ||
           value == static_cast<unsigned char>('\t') ||
           value == static_cast<unsigned char>('\r') ||
           value == static_cast<unsigned char>('\n');
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

bool safe_add(std::size_t left, std::size_t right, std::size_t limit) noexcept
{
    return left <= limit && right <= limit - left;
}

class BppSegmentWriter final {
public:
    ~BppSegmentWriter() { close(); }

    esp_err_t begin(std::string& message)
    {
        close();
        std::string card_message;
        const esp_err_t error = session_.begin_segment(card_message);
        secure_clear(card_message);
        if (error != ESP_OK) {
            (void)message;
            return error;
        }
        session_open_ = true;
        active_ = true;
        return ESP_OK;
    }

    esp_err_t write(const std::uint8_t* data,
                    std::size_t length,
                    std::string& message)
    {
        if (!active_) {
            (void)message;
            return ESP_ERR_INVALID_STATE;
        }
        if (data == nullptr && length != 0U) {
            (void)message;
            return ESP_ERR_INVALID_ARG;
        }
        if (length > IDF_LPA_BPP_MAX_SEGMENT_BYTES ||
            segment_bytes_ > IDF_LPA_BPP_MAX_SEGMENT_BYTES - length ||
            length > IDF_LPA_BPP_MAX_CARD_SEGMENT_BYTES ||
            segment_bytes_ > IDF_LPA_BPP_MAX_CARD_SEGMENT_BYTES - length) {
            (void)message;
            return ESP_ERR_INVALID_SIZE;
        }
        segment_bytes_ += length;
        while (length != 0U) {
            if (pending_size_ == pending_.size()) {
                const esp_err_t error = flush(false, message);
                if (error != ESP_OK) {
                    return error;
                }
            }
            const std::size_t copied = std::min(length, pending_.size() - pending_size_);
            std::memcpy(pending_.data() + pending_size_, data, copied);
            pending_size_ += copied;
            data += copied;
            length -= copied;
        }
        return ESP_OK;
    }

    esp_err_t finish(std::vector<std::uint8_t>& response, std::string& message)
    {
        secure_clear(response);
        if (!active_ || segment_bytes_ == 0U || pending_size_ == 0U) {
            (void)message;
            return ESP_ERR_INVALID_STATE;
        }
        const esp_err_t error = flush(true, message);
        if (error != ESP_OK) {
            return error;
        }
        response = std::move(last_response_);
        close();
        return ESP_OK;
    }

    void close() noexcept
    {
        if (session_open_) {
            session_.close();
            session_open_ = false;
        }
        active_ = false;
        secure_zero(pending_.data(), pending_.size());
        pending_size_ = 0U;
        segment_bytes_ = 0U;
        block_number_ = 0U;
        secure_clear(last_response_);
    }

    bool sensitive_storage_is_zero() const noexcept
    {
        for (const std::uint8_t byte : pending_) {
            if (byte != 0U) return false;
        }
        return pending_size_ == 0U && segment_bytes_ == 0U && block_number_ == 0U &&
               !session_open_ && !active_ && last_response_.empty();
    }

    std::size_t segment_bytes() const noexcept { return segment_bytes_; }

private:
    esp_err_t flush(bool last, std::string& message)
    {
        if (pending_size_ == 0U || block_number_ > 0xFFU) {
            (void)message;
            return ESP_ERR_INVALID_SIZE;
        }
        std::vector<std::uint8_t> response;
        std::string card_message;
        const esp_err_t error = session_.write_block(
            pending_.data(), pending_size_, last, block_number_, response, card_message);
        secure_clear(card_message);
        if (error != ESP_OK) {
            secure_clear(response);
            (void)message;
            return error;
        }
        if (!last && !response.empty()) {
            secure_clear(response);
            (void)message;
            return ESP_ERR_INVALID_RESPONSE;
        }
        if (last) {
            secure_clear(last_response_);
            last_response_ = std::move(response);
        } else {
            secure_clear(response);
        }
        secure_zero(pending_.data(), pending_.size());
        pending_size_ = 0U;
        ++block_number_;
        return ESP_OK;
    }

    IdfEsimLpaBppSession session_;
    std::array<std::uint8_t, IDF_LPA_BPP_BLOCK_BYTES> pending_ = {};
    std::size_t pending_size_ = 0U;
    std::size_t segment_bytes_ = 0U;
    std::uint16_t block_number_ = 0U;
    bool session_open_ = false;
    bool active_ = false;
    std::vector<std::uint8_t> last_response_;
};

class DerHeaderReader final {
public:
    void reset() noexcept
    {
        secure_zero(raw_.data(), raw_.size());
        raw_size_ = 0U;
        tag_bytes_ = 0U;
        length_bytes_ = 0U;
        length_ = 0U;
        complete_ = false;
    }

    bool consume(std::uint8_t byte) noexcept
    {
        if (complete_ || raw_size_ >= raw_.size()) return false;
        if (raw_size_ == 0U) {
            raw_[raw_size_++] = byte;
            if (byte == 0xBFU) {
                tag_bytes_ = 2U;
            } else if ((byte & 0x1FU) == 0x1FU) {
                return false;
            } else {
                tag_bytes_ = 1U;
            }
            return true;
        }
        if (raw_size_ < tag_bytes_) {
            if (tag_bytes_ == 2U && (byte & 0x80U) != 0U) return false;
            raw_[raw_size_++] = byte;
            return true;
        }
        if (raw_size_ == tag_bytes_) {
            raw_[raw_size_++] = byte;
            if (byte < 0x80U) {
                length_ = byte;
                complete_ = true;
                return true;
            }
            if (byte < 0x81U || byte > 0x84U) return false;
            length_bytes_ = static_cast<std::size_t>(byte & 0x7FU);
            return true;
        }
        raw_[raw_size_++] = byte;
        if (raw_size_ - tag_bytes_ - 1U != length_bytes_) return true;
        if (length_bytes_ > 1U && raw_[tag_bytes_ + 1U] == 0U) return false;
        std::uint64_t parsed = 0U;
        for (std::size_t i = 0U; i < length_bytes_; ++i) {
            parsed = (parsed << 8U) |
                     static_cast<std::uint64_t>(raw_[tag_bytes_ + 1U + i]);
        }
        if (parsed > static_cast<std::uint64_t>(std::numeric_limits<std::size_t>::max()) ||
            parsed < 0x80U) {
            return false;
        }
        length_ = static_cast<std::size_t>(parsed);
        complete_ = true;
        return true;
    }

    bool complete() const noexcept { return complete_; }
    std::size_t length() const noexcept { return length_; }
    const std::uint8_t* raw_data() const noexcept { return raw_.data(); }
    std::size_t raw_size() const noexcept { return raw_size_; }

    bool tag_is(std::uint8_t first, std::uint8_t second) const noexcept
    {
        return raw_size_ >= 2U && tag_bytes_ == 2U && raw_[0] == first && raw_[1] == second;
    }

    bool one_byte_tag(std::uint8_t tag) const noexcept
    {
        return raw_size_ >= 1U && tag_bytes_ == 1U && raw_[0] == tag;
    }

    bool sensitive_storage_is_zero() const noexcept
    {
        for (const std::uint8_t byte : raw_) {
            if (byte != 0U) return false;
        }
        return raw_size_ == 0U && !complete_;
    }

private:
    std::array<std::uint8_t, 7> raw_ = {};
    std::size_t raw_size_ = 0U;
    std::size_t tag_bytes_ = 0U;
    std::size_t length_bytes_ = 0U;
    std::size_t length_ = 0U;
    bool complete_ = false;
};

class BppDerStreamParser final {
public:
    BppDerStreamParser() = default;

    esp_err_t feed(const std::uint8_t* data, std::size_t length, std::string& message)
    {
        if (data == nullptr && length != 0U) return reject(ESP_ERR_INVALID_ARG, message);
        if (state_ == State::failed || state_ == State::done) {
            return reject(ESP_ERR_INVALID_STATE, message);
        }
        for (std::size_t i = 0U; i < length; ++i) {
            if (state_ == State::metadata_child && sequence_remaining_ == 0U) {
                if (child_count_ == 0U) return reject(ESP_ERR_INVALID_RESPONSE, message);
                sequence_active_ = false;
                state_ = State::second_sequence_or_profile;
            }
            if (state_ == State::profile_child && sequence_remaining_ == 0U) {
                if (child_count_ == 0U || outer_remaining_ != 0U) {
                    return reject(ESP_ERR_INVALID_RESPONSE, message);
                }
                sequence_active_ = false;
                state_ = State::done;
            }
            if (state_ == State::done) return reject(ESP_ERR_INVALID_RESPONSE, message);
            if (state_ == State::value) {
                const esp_err_t error = consume_value_byte(data[i], message);
                if (error != ESP_OK) return error;
                continue;
            }
            if (!header_.consume(data[i])) return reject(ESP_ERR_INVALID_RESPONSE, message);
            if (!header_.complete()) continue;
            const esp_err_t error = handle_header(message);
            header_.reset();
            if (error != ESP_OK) return error;
        }
        return ESP_OK;
    }

    esp_err_t finish(std::vector<std::uint8_t>& result, std::string& message)
    {
        if (state_ == State::metadata_child && sequence_remaining_ == 0U) {
            if (child_count_ == 0U) return reject(ESP_ERR_INVALID_RESPONSE, message);
            sequence_active_ = false;
            state_ = State::second_sequence_or_profile;
        }
        if (state_ == State::profile_child && sequence_remaining_ == 0U) {
            if (child_count_ == 0U || outer_remaining_ != 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            sequence_active_ = false;
            state_ = State::done;
        }
        if (state_ != State::done || !header_.sensitive_storage_is_zero() ||
            outer_remaining_ != 0U || installation_result_.empty()) {
            return reject(ESP_ERR_INVALID_RESPONSE, message);
        }
        result = std::move(installation_result_);
        return ESP_OK;
    }

    void abort() noexcept
    {
        writer_.close();
        secure_clear(installation_result_);
        clear_pending_parent_header();
        header_.reset();
        value_remaining_ = 0U;
        outer_remaining_ = 0U;
        sequence_remaining_ = 0U;
        child_count_ = 0U;
        decoded_bytes_ = 0U;
        segment_count_ = 0U;
        element_count_ = 0U;
        sequence_active_ = false;
        state_ = State::failed;
    }

    bool sensitive_storage_is_zero() const noexcept
    {
        return header_.sensitive_storage_is_zero() && writer_.sensitive_storage_is_zero() &&
               installation_result_.empty() && value_remaining_ == 0U &&
               outer_remaining_ == 0U && sequence_remaining_ == 0U && child_count_ == 0U &&
               decoded_bytes_ == 0U && segment_count_ == 0U && element_count_ == 0U &&
               !sequence_active_;
    }

private:
    enum class State {
        outer_header,
        outer_child,
        first_sequence_header,
        first_sequence_child,
        metadata_sequence_header,
        metadata_child,
        second_sequence_or_profile,
        second_sequence_child,
        profile_sequence_header,
        profile_child,
        value,
        done,
        failed,
    };

    enum class ValueKind {
        outer_child,
        first_sequence_child,
        metadata_child,
        second_sequence_child,
        profile_child,
    };

    esp_err_t reject(esp_err_t error, std::string& message) noexcept
    {
        state_ = State::failed;
        (void)message;
        return error;
    }

    esp_err_t emit(const std::uint8_t* data, std::size_t length, std::string& message)
    {
        if (length == 0U) return ESP_OK;
        if (outer_remaining_ < length ||
            (sequence_active_ && sequence_remaining_ < length)) {
            return reject(ESP_ERR_INVALID_RESPONSE, message);
        }
        if (!safe_add(decoded_bytes_, length, IDF_LPA_BPP_MAX_DECODED_BYTES)) {
            return reject(ESP_ERR_INVALID_SIZE, message);
        }
        const esp_err_t error = writer_.write(data, length, message);
        if (error != ESP_OK) {
            return reject(error, message);
        }
        outer_remaining_ -= length;
        if (sequence_active_) sequence_remaining_ -= length;
        decoded_bytes_ += length;
        return ESP_OK;
    }

    esp_err_t finish_segment(std::string& message, bool final_segment)
    {
        std::vector<std::uint8_t> response;
        const esp_err_t error = writer_.finish(response, message);
        if (error != ESP_OK) return reject(error, message);
        if (!response.empty()) {
            if (!final_segment || !installation_result_.empty()) {
                secure_clear(response);
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            installation_result_ = std::move(response);
        }
        ++segment_count_;
        if (segment_count_ > IDF_LPA_BPP_MAX_ELEMENTS) {
            return reject(ESP_ERR_INVALID_SIZE, message);
        }
        return ESP_OK;
    }

    bool card_tlv_fits(std::size_t raw_size, std::size_t value_size) const noexcept
    {
        return safe_add(raw_size, value_size, IDF_LPA_BPP_MAX_CARD_SEGMENT_BYTES) &&
               safe_add(writer_.segment_bytes(), raw_size + value_size,
                        IDF_LPA_BPP_MAX_CARD_SEGMENT_BYTES);
    }

    bool sequence_tlv_fits(std::size_t raw_size, std::size_t value_size) const noexcept
    {
        return (!sequence_active_ && sequence_remaining_ == 0U) ||
               (sequence_remaining_ >= raw_size &&
                sequence_remaining_ - raw_size >= value_size);
    }

    bool outer_tlv_fits(std::size_t raw_size, std::size_t value_size) const noexcept
    {
        return safe_add(raw_size, value_size, IDF_LPA_BPP_MAX_DECODED_BYTES) &&
               outer_remaining_ >= raw_size + value_size;
    }

    esp_err_t preflight_pending_child(std::size_t raw_size,
                                      std::size_t value_size,
                                      bool exact_parent_length,
                                      std::string& message)
    {
        if (pending_parent_header_size_ == 0U ||
            !safe_add(raw_size, value_size, IDF_LPA_BPP_MAX_CARD_SEGMENT_BYTES)) {
            return reject(ESP_ERR_INVALID_SIZE, message);
        }
        const std::size_t child_size = raw_size + value_size;
        if (exact_parent_length && pending_parent_length_ != child_size) {
            return reject(ESP_ERR_INVALID_RESPONSE, message);
        }
        if (!safe_add(pending_parent_header_size_, child_size,
                      IDF_LPA_BPP_MAX_CARD_SEGMENT_BYTES)) {
            return reject(ESP_ERR_INVALID_SIZE, message);
        }
        const std::size_t enclosing_size = pending_parent_header_size_ + child_size;
        const std::size_t body_size = exact_parent_length ? enclosing_size : child_size;
        if (outer_remaining_ < body_size ||
            !safe_add(decoded_bytes_, enclosing_size, IDF_LPA_BPP_MAX_DECODED_BYTES)) {
            return reject(outer_remaining_ < body_size ? ESP_ERR_INVALID_RESPONSE :
                                                         ESP_ERR_INVALID_SIZE,
                          message);
        }
        return ESP_OK;
    }

    void clear_pending_parent_header() noexcept
    {
        secure_zero(pending_parent_header_.data(), pending_parent_header_.size());
        pending_parent_header_size_ = 0U;
        pending_parent_length_ = 0U;
    }

    bool standalone_header_fits(std::size_t raw_size) const noexcept
    {
        return raw_size <= IDF_LPA_BPP_MAX_CARD_SEGMENT_BYTES;
    }

    esp_err_t handle_header(std::string& message)
    {
        const std::size_t length = header_.length();
        const std::size_t raw_size = header_.raw_size();
        if (raw_size == 0U || !safe_add(raw_size, length, IDF_LPA_BPP_MAX_DECODED_BYTES)) {
            return reject(ESP_ERR_INVALID_SIZE, message);
        }
        const std::size_t declared_size = raw_size + length;
        if (!safe_add(decoded_bytes_, declared_size, IDF_LPA_BPP_MAX_DECODED_BYTES)) {
            return reject(ESP_ERR_INVALID_SIZE, message);
        }
        ++element_count_;
        if (element_count_ > IDF_LPA_BPP_MAX_ELEMENTS) {
            return reject(ESP_ERR_INVALID_SIZE, message);
        }
        if (segment_count_ >= IDF_LPA_BPP_MAX_ELEMENTS) {
            return reject(ESP_ERR_INVALID_SIZE, message);
        }
        const std::uint8_t* raw = header_.raw_data();
        switch (state_) {
        case State::outer_header: {
            if (!header_.tag_is(0xBFU, 0x36U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            if (!standalone_header_fits(raw_size)) {
                return reject(ESP_ERR_INVALID_SIZE, message);
            }
            std::memcpy(pending_parent_header_.data(), raw, raw_size);
            pending_parent_header_size_ = raw_size;
            pending_parent_length_ = length;
            outer_remaining_ = length;
            state_ = State::outer_child;
            return ESP_OK;
        }
        case State::outer_child: {
            if (!header_.tag_is(0xBFU, 0x23U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            const esp_err_t preflight = preflight_pending_child(raw_size, length, false, message);
            if (preflight != ESP_OK) return preflight;
            esp_err_t error = writer_.begin(message);
            if (error != ESP_OK) return reject(error, message);
            error = writer_.write(pending_parent_header_.data(), pending_parent_header_size_,
                                  message);
            if (error != ESP_OK) return reject(error, message);
            decoded_bytes_ = pending_parent_header_size_;
            error = emit(raw, raw_size, message);
            if (error != ESP_OK) return error;
            clear_pending_parent_header();
            value_remaining_ = length;
            value_kind_ = ValueKind::outer_child;
            state_ = State::value;
            return ESP_OK;
        }
        case State::first_sequence_header: {
            if (!header_.one_byte_tag(0xA0U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            std::memcpy(pending_parent_header_.data(), raw, raw_size);
            pending_parent_header_size_ = raw_size;
            pending_parent_length_ = length;
            child_count_ = 0U;
            state_ = State::first_sequence_child;
            return ESP_OK;
        }
        case State::first_sequence_child: {
            if (!header_.one_byte_tag(0x87U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            const esp_err_t preflight = preflight_pending_child(raw_size, length, true, message);
            if (preflight != ESP_OK) return preflight;
            esp_err_t error = writer_.begin(message);
            if (error != ESP_OK) return reject(error, message);
            error = emit(pending_parent_header_.data(), pending_parent_header_size_, message);
            if (error != ESP_OK) return error;
            sequence_remaining_ = pending_parent_length_;
            sequence_active_ = true;
            error = emit(raw, raw_size, message);
            if (error != ESP_OK) return error;
            clear_pending_parent_header();
            value_remaining_ = length;
            value_kind_ = ValueKind::first_sequence_child;
            state_ = State::value;
            return ESP_OK;
        }
        case State::metadata_sequence_header: {
            if (!header_.one_byte_tag(0xA1U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            if (!standalone_header_fits(raw_size)) {
                return reject(ESP_ERR_INVALID_SIZE, message);
            }
            if (!outer_tlv_fits(raw_size, length)) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            esp_err_t error = writer_.begin(message);
            if (error != ESP_OK) return reject(error, message);
            error = emit(raw, raw_size, message);
            if (error != ESP_OK) return error;
            sequence_remaining_ = length;
            sequence_active_ = true;
            child_count_ = 0U;
            error = finish_segment(message, false);
            if (error != ESP_OK) return error;
            state_ = State::metadata_child;
            return ESP_OK;
        }
        case State::metadata_child: {
            if (!header_.one_byte_tag(0x88U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            if (!card_tlv_fits(raw_size, length)) {
                return reject(ESP_ERR_INVALID_SIZE, message);
            }
            if (!outer_tlv_fits(raw_size, length) || !sequence_tlv_fits(raw_size, length)) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            esp_err_t error = writer_.begin(message);
            if (error != ESP_OK) return reject(error, message);
            error = emit(raw, raw_size, message);
            if (error != ESP_OK) return error;
            value_remaining_ = length;
            value_kind_ = ValueKind::metadata_child;
            state_ = State::value;
            return ESP_OK;
        }
        case State::second_sequence_or_profile: {
            if (header_.one_byte_tag(0xA2U)) {
                if (length == 0U) return reject(ESP_ERR_INVALID_RESPONSE, message);
                std::memcpy(pending_parent_header_.data(), raw, raw_size);
                pending_parent_header_size_ = raw_size;
                pending_parent_length_ = length;
                child_count_ = 0U;
                state_ = State::second_sequence_child;
                return ESP_OK;
            }
            if (!header_.one_byte_tag(0xA3U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            if (!standalone_header_fits(raw_size)) {
                return reject(ESP_ERR_INVALID_SIZE, message);
            }
            if (!outer_tlv_fits(raw_size, length)) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            esp_err_t error = writer_.begin(message);
            if (error != ESP_OK) return reject(error, message);
            error = emit(raw, raw_size, message);
            if (error != ESP_OK) return error;
            sequence_remaining_ = length;
            sequence_active_ = true;
            child_count_ = 0U;
            error = finish_segment(message, false);
            if (error != ESP_OK) return error;
            state_ = State::profile_child;
            return ESP_OK;
        }
        case State::second_sequence_child: {
            if (!header_.one_byte_tag(0x87U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            const esp_err_t preflight = preflight_pending_child(raw_size, length, true, message);
            if (preflight != ESP_OK) return preflight;
            esp_err_t error = writer_.begin(message);
            if (error != ESP_OK) return reject(error, message);
            error = emit(pending_parent_header_.data(), pending_parent_header_size_, message);
            if (error != ESP_OK) return error;
            sequence_remaining_ = pending_parent_length_;
            sequence_active_ = true;
            error = emit(raw, raw_size, message);
            if (error != ESP_OK) return error;
            clear_pending_parent_header();
            value_remaining_ = length;
            value_kind_ = ValueKind::second_sequence_child;
            state_ = State::value;
            return ESP_OK;
        }
        case State::profile_sequence_header: {
            if (!header_.one_byte_tag(0xA3U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            if (!standalone_header_fits(raw_size)) {
                return reject(ESP_ERR_INVALID_SIZE, message);
            }
            if (!outer_tlv_fits(raw_size, length)) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            esp_err_t error = writer_.begin(message);
            if (error != ESP_OK) return reject(error, message);
            error = emit(raw, raw_size, message);
            if (error != ESP_OK) return error;
            sequence_remaining_ = length;
            sequence_active_ = true;
            child_count_ = 0U;
            error = finish_segment(message, false);
            if (error != ESP_OK) return error;
            state_ = State::profile_child;
            return ESP_OK;
        }
        case State::profile_child: {
            if (!header_.one_byte_tag(0x86U) || length == 0U) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            if (!card_tlv_fits(raw_size, length)) {
                return reject(ESP_ERR_INVALID_SIZE, message);
            }
            if (!outer_tlv_fits(raw_size, length) || !sequence_tlv_fits(raw_size, length)) {
                return reject(ESP_ERR_INVALID_RESPONSE, message);
            }
            esp_err_t error = writer_.begin(message);
            if (error != ESP_OK) return reject(error, message);
            error = emit(raw, raw_size, message);
            if (error != ESP_OK) return error;
            value_remaining_ = length;
            value_kind_ = ValueKind::profile_child;
            state_ = State::value;
            return ESP_OK;
        }
        case State::value:
        case State::done:
        case State::failed:
            return reject(ESP_ERR_INVALID_RESPONSE, message);
        }
        return reject(ESP_ERR_INVALID_RESPONSE, message);
    }

    esp_err_t consume_value_byte(std::uint8_t byte, std::string& message)
    {
        const esp_err_t error = emit(&byte, 1U, message);
        if (error != ESP_OK) return error;
        if (value_remaining_ == 0U) return reject(ESP_ERR_INVALID_RESPONSE, message);
        --value_remaining_;
        if (value_remaining_ != 0U) return ESP_OK;

        switch (value_kind_) {
        case ValueKind::outer_child:
            {
                const esp_err_t finish_error = finish_segment(message, false);
                if (finish_error != ESP_OK) return finish_error;
            }
            state_ = State::first_sequence_header;
            break;
        case ValueKind::first_sequence_child:
            if (sequence_remaining_ != 0U) return reject(ESP_ERR_INVALID_RESPONSE, message);
            sequence_active_ = false;
            {
                const esp_err_t finish_error = finish_segment(message, false);
                if (finish_error != ESP_OK) return finish_error;
            }
            state_ = State::metadata_sequence_header;
            break;
        case ValueKind::metadata_child:
            {
                const esp_err_t finish_error = finish_segment(message, false);
                if (finish_error != ESP_OK) return finish_error;
            }
            ++child_count_;
            state_ = State::metadata_child;
            break;
        case ValueKind::second_sequence_child:
            if (sequence_remaining_ != 0U) return reject(ESP_ERR_INVALID_RESPONSE, message);
            sequence_active_ = false;
            {
                const esp_err_t finish_error = finish_segment(message, false);
                if (finish_error != ESP_OK) return finish_error;
            }
            state_ = State::profile_sequence_header;
            break;
        case ValueKind::profile_child:
            {
                const esp_err_t finish_error = finish_segment(
                    message, sequence_remaining_ == 0U && outer_remaining_ == 0U);
                if (finish_error != ESP_OK) return finish_error;
            }
            ++child_count_;
            state_ = State::profile_child;
            break;
        }
        return ESP_OK;
    }

    State state_ = State::outer_header;
    ValueKind value_kind_ = ValueKind::outer_child;
    DerHeaderReader header_;
    BppSegmentWriter writer_;
    std::size_t value_remaining_ = 0U;
    std::size_t outer_remaining_ = 0U;
    std::size_t sequence_remaining_ = 0U;
    std::size_t child_count_ = 0U;
    std::size_t decoded_bytes_ = 0U;
    std::size_t segment_count_ = 0U;
    std::size_t element_count_ = 0U;
    std::vector<std::uint8_t> installation_result_;
    std::array<std::uint8_t, 7> pending_parent_header_ = {};
    std::size_t pending_parent_header_size_ = 0U;
    std::size_t pending_parent_length_ = 0U;
    bool sequence_active_ = false;
};

class BppBase64Decoder final {
public:
    explicit BppBase64Decoder(BppDerStreamParser& parser) : parser_(parser) {}

    esp_err_t feed(char character, std::string& message)
    {
        if (encoded_chars_ >= IDF_LPA_BPP_MAX_ENCODED_BYTES) {
            (void)message;
            return ESP_ERR_INVALID_SIZE;
        }
        if (character == '\r' || character == '\n' || character == ' ' || character == '\t') {
            return reject(message);
        }
        if (finished_) return reject(message);
        const int value = base64_value(character);
        if (value == -2) {
            if (quartet_size_ < 2U || padding_count_ == 2U) return reject(message);
            quartet_[quartet_size_++] = 0U;
            ++padding_count_;
        } else if (value >= 0) {
            if (padding_count_ != 0U || quartet_size_ >= quartet_.size()) return reject(message);
            quartet_[quartet_size_++] = static_cast<std::uint8_t>(value);
        } else {
            return reject(message);
        }
        ++encoded_chars_;
        if (quartet_size_ != quartet_.size()) return ESP_OK;
        if ((padding_count_ == 2U && (quartet_[1] & 0x0FU) != 0U) ||
            (padding_count_ == 1U && (quartet_[2] & 0x03U) != 0U)) {
            return reject(message);
        }
        const std::array<std::uint8_t, 3> decoded = {
            static_cast<std::uint8_t>((quartet_[0] << 2U) | (quartet_[1] >> 4U)),
            static_cast<std::uint8_t>((quartet_[1] << 4U) | (quartet_[2] >> 2U)),
            static_cast<std::uint8_t>((quartet_[2] << 6U) | quartet_[3]),
        };
        const std::size_t output = padding_count_ == 2U ? 1U :
                                    (padding_count_ == 1U ? 2U : 3U);
        const esp_err_t error = parser_.feed(decoded.data(), output, message);
        if (error != ESP_OK) return error;
        finished_ = padding_count_ != 0U;
        secure_clear(quartet_);
        quartet_size_ = 0U;
        padding_count_ = 0U;
        return ESP_OK;
    }

    esp_err_t finish(std::string& message)
    {
        if (encoded_chars_ == 0U || quartet_size_ != 0U) return reject(message);
        return ESP_OK;
    }

    void abort() noexcept
    {
        secure_clear(quartet_);
        quartet_size_ = 0U;
        padding_count_ = 0U;
        encoded_chars_ = 0U;
        finished_ = false;
    }

private:
    static int base64_value(char character) noexcept
    {
        if (character >= 'A' && character <= 'Z') return character - 'A';
        if (character >= 'a' && character <= 'z') return character - 'a' + 26;
        if (character >= '0' && character <= '9') return character - '0' + 52;
        if (character == '+') return 62;
        if (character == '/') return 63;
        if (character == '=') return -2;
        return -1;
    }

    esp_err_t reject(std::string& message) noexcept
    {
        (void)message;
        return ESP_ERR_INVALID_RESPONSE;
    }

    BppDerStreamParser& parser_;
    std::array<std::uint8_t, 4> quartet_ = {};
    std::size_t quartet_size_ = 0U;
    std::size_t padding_count_ = 0U;
    std::size_t encoded_chars_ = 0U;
    bool finished_ = false;
};

}  // 匿名命名空間

class IdfLpaBppStream::Impl final {
public:
    explicit Impl(std::string_view expected_transaction_id) noexcept
        : decoder_(der_)
    {
        expected_valid_ = decode_transaction(expected_transaction_id,
                                              expected_transaction_, expected_size_);
    }

    ~Impl() { abort(); }

    esp_err_t feed(const char* data, std::size_t length, std::string& message)
    {
        if (data == nullptr && length != 0U) return fail_once(ESP_ERR_INVALID_ARG, message);
        if (failed_ || complete_) return fail_once(ESP_ERR_INVALID_STATE, message);
        constexpr std::size_t response_limit =
            IDF_LPA_BPP_MAX_ENCODED_BYTES + kJsonMaxPrefixBytes + 256U;
        if (!safe_add(response_bytes_, length, response_limit)) {
            return fail_once(ESP_ERR_INVALID_SIZE, message);
        }
        response_bytes_ += length;
        for (std::size_t i = 0U; i < length; ++i) {
            if (!bpp_started_ && !bpp_seen_ && ++prefix_bytes_ > kJsonMaxPrefixBytes) {
                return fail_once(ESP_ERR_INVALID_SIZE, message);
            }
            const esp_err_t error = consume_json(data[i], message);
            if (error != ESP_OK) return fail_once(error, message);
        }
        return ESP_OK;
    }

    esp_err_t finish(std::vector<std::uint8_t>& result, std::string& message)
    {
        secure_clear(result);
        if (failed_ || complete_) return fail_once(ESP_ERR_INVALID_STATE, message);
        if (!root_done_ || depth_ != 0U || string_mode_ != StringMode::none ||
            primitive_active_ || !expected_valid_ || !status_seen_ ||
            !transaction_seen_ || !bpp_seen_) {
            return fail_once(ESP_ERR_INVALID_RESPONSE, message);
        }
        const esp_err_t error = der_.finish(result, message);
        if (error != ESP_OK) return fail_once(error, message);
        if (result.empty()) return fail_once(ESP_ERR_INVALID_RESPONSE, message);
        cleanup();
        complete_ = true;
        return ESP_OK;
    }

    void abort() noexcept
    {
        if (cleanup_done_) return;
        cleanup();
        failed_ = true;
        complete_ = false;
    }

#ifdef IDF_LPA_BPP_TESTING
    bool sensitive_storage_is_zero() const noexcept
    {
        bool string_zero = true;
        for (const char value : string_value_) {
            if (value != '\0') string_zero = false;
        }
        bool primitive_zero = true;
        for (const char value : primitive_value_) {
            if (value != '\0') primitive_zero = false;
        }
        bool frames_zero = true;
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(frames_.data());
        for (std::size_t i = 0U; i < sizeof(frames_); ++i) {
            if (bytes[i] != 0U) frames_zero = false;
        }
        return string_zero && primitive_zero && frames_zero && expected_size_ == 0U &&
               !expected_valid_ && response_bytes_ == 0U && prefix_bytes_ == 0U &&
               depth_ == 0U && der_.sensitive_storage_is_zero();
    }

    std::size_t cleanup_count() const noexcept { return cleanup_count_; }
#endif

private:
    enum class JsonFrameKind : std::uint8_t {
        object,
        array,
    };

    enum class JsonFrameState : std::uint8_t {
        object_key_or_end,
        object_need_key,
        object_colon,
        object_value,
        object_after_value,
        array_value_or_end,
        array_value,
        array_after_value,
    };

    struct JsonKeyRecord {
        std::uint64_t hash = 0U;
        std::size_t length = 0U;
    };

    struct JsonFrame {
        JsonFrameKind kind = JsonFrameKind::object;
        JsonFrameState state = JsonFrameState::object_key_or_end;
        std::size_t member_count = 0U;
        std::size_t key_length = 0U;
        std::array<char, kJsonMaxKeyBytes> key = {};
        std::array<JsonKeyRecord, kJsonMaxMembers> keys = {};
    };

    enum class StringMode : std::uint8_t {
        none,
        key,
        status,
        transaction,
        unknown,
        bpp,
    };

    // Nested JSON callbacks only propagate errors.  The public entry points
    // call fail_once(), which owns the single parser/card cleanup.
    esp_err_t fail(esp_err_t error, std::string& message) noexcept
    {
        (void)message;
        return error;
    }

    void cleanup() noexcept
    {
        if (cleanup_done_) return;
        ++cleanup_count_;
        der_.abort();
        decoder_.abort();
        clear_sensitive_state();
        cleanup_done_ = true;
    }

    esp_err_t fail_once(esp_err_t error, std::string& message) noexcept
    {
        cleanup();
        failed_ = true;
        complete_ = false;
        set_safe_message(message, error == ESP_ERR_INVALID_SIZE ? kLimitMessage :
                                      (error == ESP_FAIL ? kCardMessage : kMalformedMessage));
        return error;
    }

    static bool decode_transaction(std::string_view value,
                                   std::array<std::uint8_t, 16>& output,
                                   std::size_t& output_size) noexcept
    {
        secure_zero(output.data(), output.size());
        output_size = 0U;
        if (value.empty() || value.size() > output.size() * 2U || (value.size() & 1U) != 0U) {
            return false;
        }
        for (std::size_t i = 0U; i < value.size(); i += 2U) {
            const int first = hex_value(static_cast<unsigned char>(value[i]));
            const int second = hex_value(static_cast<unsigned char>(value[i + 1U]));
            if (first < 0 || second < 0) {
                secure_zero(output.data(), output.size());
                output_size = 0U;
                return false;
            }
            output[i / 2U] = static_cast<std::uint8_t>((first << 4) | second);
        }
        output_size = value.size() / 2U;
        return output_size != 0U;
    }

    static std::uint64_t key_hash(const char* value, std::size_t length) noexcept
    {
        std::uint64_t hash = 1469598103934665603ULL;
        for (std::size_t i = 0U; i < length; ++i) {
            hash ^= static_cast<std::uint8_t>(value[i]);
            hash *= 1099511628211ULL;
        }
        return hash;
    }

    static bool is_value_delimiter(char character) noexcept
    {
        return is_json_space(static_cast<unsigned char>(character)) || character == ',' ||
               character == ']' || character == '}';
    }

    static bool valid_json_number(const char* value, std::size_t length) noexcept
    {
        std::size_t index = 0U;
        if (index < length && value[index] == '-') ++index;
        if (index == length) return false;
        if (value[index] == '0') {
            ++index;
            if (index < length && value[index] >= '0' && value[index] <= '9') return false;
        } else {
            if (value[index] < '1' || value[index] > '9') return false;
            do {
                ++index;
            } while (index < length && value[index] >= '0' && value[index] <= '9');
        }
        if (index < length && value[index] == '.') {
            ++index;
            const std::size_t fraction_start = index;
            while (index < length && value[index] >= '0' && value[index] <= '9') ++index;
            if (fraction_start == index) return false;
        }
        if (index < length && (value[index] == 'e' || value[index] == 'E')) {
            ++index;
            if (index < length && (value[index] == '+' || value[index] == '-')) ++index;
            const std::size_t exponent_start = index;
            while (index < length && value[index] >= '0' && value[index] <= '9') ++index;
            if (exponent_start == index) return false;
        }
        return index == length;
    }

    bool frame_key_is(const JsonFrame& frame, std::string_view wanted) const noexcept
    {
        return frame.key_length == wanted.size() &&
               std::memcmp(frame.key.data(), wanted.data(), wanted.size()) == 0;
    }

    bool root_member_is(std::string_view wanted) const noexcept
    {
        return depth_ == 1U && frame_key_is(frames_[0], wanted);
    }

    bool header_member_is(std::string_view wanted) const noexcept
    {
        return depth_ == 2U && frame_key_is(frames_[0], "header") &&
               frame_key_is(frames_[1], wanted);
    }

    bool status_member_is(std::string_view wanted) const noexcept
    {
        return depth_ == 3U && frame_key_is(frames_[0], "header") &&
               frame_key_is(frames_[1], "functionExecutionStatus") &&
               frame_key_is(frames_[2], wanted);
    }

    esp_err_t push_frame(JsonFrameKind kind, std::string& message)
    {
        if (depth_ >= kJsonMaxDepth) return fail(ESP_ERR_INVALID_SIZE, message);
        JsonFrame& frame = frames_[depth_];
        frame = JsonFrame();
        frame.kind = kind;
        frame.state = kind == JsonFrameKind::object ? JsonFrameState::object_key_or_end :
                                                       JsonFrameState::array_value_or_end;
        ++depth_;
        return ESP_OK;
    }

    void clear_string_buffer() noexcept
    {
        secure_zero(string_value_.data(), string_value_.size());
        string_length_ = 0U;
    }

    void clear_sensitive_state() noexcept
    {
        secure_zero(expected_transaction_.data(), expected_transaction_.size());
        expected_size_ = 0U;
        expected_valid_ = false;
        clear_string_buffer();
        secure_zero(primitive_value_.data(), primitive_value_.size());
        primitive_length_ = 0U;
        secure_zero(frames_.data(), sizeof(frames_));
        depth_ = 0U;
        response_bytes_ = 0U;
        prefix_bytes_ = 0U;
        string_mode_ = StringMode::none;
        primitive_active_ = false;
        escaped_ = false;
        unicode_left_ = 0U;
        unicode_value_ = 0U;
        root_done_ = false;
        status_seen_ = false;
        transaction_seen_ = false;
        bpp_seen_ = false;
        bpp_started_ = false;
        header_depth_ = 0U;
        status_depth_ = 0U;
        function_status_seen_ = false;
        status_value_seen_ = false;
    }

    esp_err_t begin_key(std::string& message)
    {
        if (depth_ == 0U || frames_[depth_ - 1U].kind != JsonFrameKind::object) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        clear_string_buffer();
        string_mode_ = StringMode::key;
        escaped_ = false;
        unicode_left_ = 0U;
        unicode_value_ = 0U;
        return ESP_OK;
    }

    esp_err_t finish_key(std::string& message)
    {
        JsonFrame& frame = frames_[depth_ - 1U];
        if (frame.member_count >= kJsonMaxMembers || string_length_ > kJsonMaxKeyBytes) {
            return fail(ESP_ERR_INVALID_SIZE, message);
        }
        const std::uint64_t hash = key_hash(string_value_.data(), string_length_);
        for (std::size_t i = 0U; i < frame.member_count; ++i) {
            if (frame.keys[i].hash == hash && frame.keys[i].length == string_length_) {
                return fail(ESP_ERR_INVALID_RESPONSE, message);
            }
        }
        frame.keys[frame.member_count++] = {hash, string_length_};
        std::memcpy(frame.key.data(), string_value_.data(), string_length_);
        frame.key_length = string_length_;
        frame.state = JsonFrameState::object_colon;
        string_mode_ = StringMode::none;
        clear_string_buffer();
        escaped_ = false;
        unicode_left_ = 0U;
        unicode_value_ = 0U;
        return ESP_OK;
    }

    esp_err_t start_string(StringMode mode, std::string& message)
    {
        if (mode == StringMode::key || mode == StringMode::status ||
            mode == StringMode::transaction) {
            clear_string_buffer();
        }
        string_mode_ = mode;
        escaped_ = false;
        unicode_left_ = 0U;
        unicode_value_ = 0U;
        (void)message;
        return ESP_OK;
    }

    esp_err_t append_string_char(char character, std::string& message)
    {
        if (string_mode_ == StringMode::unknown || string_mode_ == StringMode::bpp) {
            return ESP_OK;
        }
        if (string_length_ >= string_value_.size()) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        string_value_[string_length_++] = character;
        return ESP_OK;
    }

    esp_err_t finish_string(std::string& message)
    {
        const StringMode mode = string_mode_;
        if (mode == StringMode::key) return finish_key(message);
        if (mode == StringMode::status) {
            static constexpr char expected[] = "Executed-Success";
            if (string_length_ != sizeof(expected) - 1U ||
                std::memcmp(string_value_.data(), expected, sizeof(expected) - 1U) != 0) {
                return fail(ESP_ERR_INVALID_RESPONSE, message);
            }
            status_value_seen_ = true;
        } else if (mode == StringMode::transaction) {
            std::array<std::uint8_t, 16> actual = {};
            std::size_t actual_size = 0U;
            if (!decode_transaction(std::string_view(string_value_.data(), string_length_),
                                     actual, actual_size) ||
                !expected_valid_ || actual_size != expected_size_ ||
                std::memcmp(actual.data(), expected_transaction_.data(), actual_size) != 0) {
                secure_zero(actual.data(), actual.size());
                return fail(ESP_ERR_INVALID_RESPONSE, message);
            }
            secure_zero(actual.data(), actual.size());
            transaction_seen_ = true;
        } else if (mode == StringMode::bpp) {
            const esp_err_t error = decoder_.finish(message);
            if (error != ESP_OK) return fail(error, message);
            bpp_started_ = false;
            bpp_seen_ = true;
        }
        string_mode_ = StringMode::none;
        escaped_ = false;
        unicode_left_ = 0U;
        unicode_value_ = 0U;
        clear_string_buffer();
        return complete_value(message);
    }

    esp_err_t consume_string(char character, std::string& message)
    {
        if (string_mode_ == StringMode::bpp) {
            if (character == '"') return finish_string(message);
            if (character == '\\' || static_cast<unsigned char>(character) < 0x20U ||
                static_cast<unsigned char>(character) >= 0x80U) {
                return fail(ESP_ERR_INVALID_RESPONSE, message);
            }
            const esp_err_t error = decoder_.feed(character, message);
            if (error != ESP_OK) return fail(error, message);
            return ESP_OK;
        }
        if (unicode_left_ != 0U) {
            const int value = hex_value(static_cast<unsigned char>(character));
            if (value < 0) return fail(ESP_ERR_INVALID_RESPONSE, message);
            unicode_value_ = (unicode_value_ << 4U) | static_cast<unsigned int>(value);
            --unicode_left_;
            if (unicode_left_ == 0U) {
                if ((string_mode_ == StringMode::key || string_mode_ == StringMode::status ||
                     string_mode_ == StringMode::transaction) && unicode_value_ > 0x7FU) {
                    return fail(ESP_ERR_INVALID_RESPONSE, message);
                }
                const esp_err_t error = append_string_char(
                    static_cast<char>(unicode_value_), message);
                unicode_value_ = 0U;
                if (error != ESP_OK) return error;
            }
            return ESP_OK;
        }
        if (escaped_) {
            escaped_ = false;
            switch (character) {
            case '"':
            case '\\':
            case '/':
                return append_string_char(character, message);
            case 'b': return append_string_char('\b', message);
            case 'f': return append_string_char('\f', message);
            case 'n': return append_string_char('\n', message);
            case 'r': return append_string_char('\r', message);
            case 't': return append_string_char('\t', message);
            case 'u':
                unicode_left_ = 4U;
                unicode_value_ = 0U;
                return ESP_OK;
            default:
                return fail(ESP_ERR_INVALID_RESPONSE, message);
            }
        }
        if (character == '\\') {
            escaped_ = true;
            return ESP_OK;
        }
        if (character == '"') return finish_string(message);
        if (static_cast<unsigned char>(character) < 0x20U) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        if ((string_mode_ == StringMode::key || string_mode_ == StringMode::status ||
             string_mode_ == StringMode::transaction) &&
            static_cast<unsigned char>(character) >= 0x80U) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        return append_string_char(character, message);
    }

    esp_err_t start_primitive(char character, std::string& message)
    {
        if (character == ',' || character == ']' || character == '}' || character == ':') {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        primitive_active_ = true;
        primitive_length_ = 0U;
        return append_primitive(character, message);
    }

    esp_err_t append_primitive(char character, std::string& message)
    {
        if (primitive_length_ >= primitive_value_.size() - 1U) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        primitive_value_[primitive_length_++] = character;
        primitive_value_[primitive_length_] = '\0';
        return ESP_OK;
    }

    esp_err_t finish_primitive(std::string& message)
    {
        const bool literal = primitive_length_ == 4U &&
                             std::memcmp(primitive_value_.data(), "true", 4U) == 0;
        const bool false_literal = primitive_length_ == 5U &&
                                   std::memcmp(primitive_value_.data(), "false", 5U) == 0;
        const bool null_literal = primitive_length_ == 4U &&
                                  std::memcmp(primitive_value_.data(), "null", 4U) == 0;
        if (!literal && !false_literal && !null_literal &&
            !valid_json_number(primitive_value_.data(), primitive_length_)) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        primitive_active_ = false;
        secure_zero(primitive_value_.data(), primitive_value_.size());
        primitive_length_ = 0U;
        return complete_value(message);
    }

    esp_err_t start_value(char character, std::string& message)
    {
        if (depth_ == 0U) return fail(ESP_ERR_INVALID_RESPONSE, message);
        JsonFrame& parent = frames_[depth_ - 1U];
        if ((parent.kind == JsonFrameKind::object && parent.state != JsonFrameState::object_value) ||
            (parent.kind == JsonFrameKind::array && parent.state != JsonFrameState::array_value &&
             parent.state != JsonFrameState::array_value_or_end)) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        parent.state = parent.kind == JsonFrameKind::object ? JsonFrameState::object_after_value :
                                                               JsonFrameState::array_after_value;
        const bool root_header = root_member_is("header");
        const bool root_transaction = root_member_is("transactionId");
        const bool root_bpp = root_member_is("boundProfilePackage");
        const bool status_object = header_member_is("functionExecutionStatus");
        const bool status_value = status_member_is("status");
        if ((root_header || status_object) && character != '{') {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        if ((root_transaction || status_value || root_bpp) && character != '"') {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        if (root_bpp && (!status_seen_ || !transaction_seen_)) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        if (character == '{' || character == '[') {
            const esp_err_t error = push_frame(
                character == '{' ? JsonFrameKind::object : JsonFrameKind::array, message);
            if (error != ESP_OK) return error;
            if (root_header) {
                header_depth_ = depth_;
                function_status_seen_ = false;
                status_value_seen_ = false;
            } else if (status_object) {
                status_depth_ = depth_;
                status_value_seen_ = false;
            }
            return ESP_OK;
        }
        if (character == '"') {
            StringMode mode = StringMode::unknown;
            if (root_transaction) mode = StringMode::transaction;
            else if (status_value) mode = StringMode::status;
            else if (root_bpp) {
                mode = StringMode::bpp;
                bpp_started_ = true;
            }
            return start_string(mode, message);
        }
        if (root_header || root_transaction || root_bpp || status_object || status_value) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        return start_primitive(character, message);
    }

    esp_err_t complete_value(std::string& message)
    {
        if (depth_ == 0U) return fail(ESP_ERR_INVALID_RESPONSE, message);
        JsonFrame& parent = frames_[depth_ - 1U];
        if ((parent.kind == JsonFrameKind::object &&
             parent.state != JsonFrameState::object_after_value) ||
            (parent.kind == JsonFrameKind::array &&
             parent.state != JsonFrameState::array_after_value)) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        return ESP_OK;
    }

    esp_err_t close_container(char character, std::string& message)
    {
        if (depth_ == 0U) return fail(ESP_ERR_INVALID_RESPONSE, message);
        JsonFrame& frame = frames_[depth_ - 1U];
        if (frame.kind == JsonFrameKind::object) {
            if (character != '}' || (frame.state != JsonFrameState::object_key_or_end &&
                                     frame.state != JsonFrameState::object_after_value)) {
                return fail(ESP_ERR_INVALID_RESPONSE, message);
            }
        } else if (character != ']' || (frame.state != JsonFrameState::array_value_or_end &&
                                        frame.state != JsonFrameState::array_after_value)) {
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        if (status_depth_ == depth_) {
            if (!status_value_seen_) return fail(ESP_ERR_INVALID_RESPONSE, message);
            status_depth_ = 0U;
            function_status_seen_ = true;
        }
        if (header_depth_ == depth_) {
            if (!function_status_seen_ || !status_value_seen_) {
                return fail(ESP_ERR_INVALID_RESPONSE, message);
            }
            header_depth_ = 0U;
            status_seen_ = true;
        }
        secure_zero(&frame, sizeof(frame));
        --depth_;
        if (depth_ == 0U) {
            root_done_ = true;
            return ESP_OK;
        }
        return complete_value(message);
    }

    esp_err_t consume_structural(char character, std::string& message)
    {
        if (depth_ == 0U) {
            if (root_done_) {
                if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
                return fail(ESP_ERR_INVALID_RESPONSE, message);
            }
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            if (character != '{') return fail(ESP_ERR_INVALID_RESPONSE, message);
            return push_frame(JsonFrameKind::object, message);
        }
        JsonFrame& frame = frames_[depth_ - 1U];
        switch (frame.state) {
        case JsonFrameState::object_key_or_end:
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            if (character == '}') return close_container(character, message);
            if (character == '"') return begin_key(message);
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        case JsonFrameState::object_need_key:
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            if (character != '"') return fail(ESP_ERR_INVALID_RESPONSE, message);
            return begin_key(message);
        case JsonFrameState::object_colon:
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            if (character != ':') return fail(ESP_ERR_INVALID_RESPONSE, message);
            frame.state = JsonFrameState::object_value;
            return ESP_OK;
        case JsonFrameState::object_value:
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            return start_value(character, message);
        case JsonFrameState::object_after_value:
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            if (character == ',') {
                if (depth_ == 1U && bpp_seen_) {
                    return fail(ESP_ERR_INVALID_RESPONSE, message);
                }
                frame.state = JsonFrameState::object_need_key;
                return ESP_OK;
            }
            if (character == '}') return close_container(character, message);
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        case JsonFrameState::array_value_or_end:
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            if (character == ']') return close_container(character, message);
            return start_value(character, message);
        case JsonFrameState::array_value:
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            return start_value(character, message);
        case JsonFrameState::array_after_value:
            if (is_json_space(static_cast<unsigned char>(character))) return ESP_OK;
            if (character == ',') {
                frame.state = JsonFrameState::array_value;
                return ESP_OK;
            }
            if (character == ']') return close_container(character, message);
            return fail(ESP_ERR_INVALID_RESPONSE, message);
        }
        return fail(ESP_ERR_INVALID_RESPONSE, message);
    }

    esp_err_t consume_json(char character, std::string& message)
    {
        if (string_mode_ != StringMode::none) return consume_string(character, message);
        if (primitive_active_) {
            if (is_value_delimiter(character)) {
                const esp_err_t error = finish_primitive(message);
                if (error != ESP_OK) return error;
                return consume_structural(character, message);
            }
            return append_primitive(character, message);
        }
        return consume_structural(character, message);
    }

    std::array<std::uint8_t, 16> expected_transaction_ = {};
    std::size_t expected_size_ = 0U;
    std::array<char, kJsonMaxKeyBytes> string_value_ = {};
    std::array<char, kJsonMaxPrimitiveBytes> primitive_value_ = {};
    std::array<JsonFrame, kJsonMaxDepth> frames_ = {};
    std::size_t depth_ = 0U;
    std::size_t string_length_ = 0U;
    std::size_t primitive_length_ = 0U;
    std::size_t unicode_left_ = 0U;
    unsigned int unicode_value_ = 0U;
    std::size_t header_depth_ = 0U;
    std::size_t status_depth_ = 0U;
    std::size_t response_bytes_ = 0U;
    std::size_t prefix_bytes_ = 0U;
    StringMode string_mode_ = StringMode::none;
    BppDerStreamParser der_;
    BppBase64Decoder decoder_;
    bool expected_valid_ = false;
    bool status_seen_ = false;
    bool transaction_seen_ = false;
    bool bpp_seen_ = false;
    bool bpp_started_ = false;
    bool root_done_ = false;
    bool function_status_seen_ = false;
    bool status_value_seen_ = false;
    bool primitive_active_ = false;
    bool escaped_ = false;
    bool failed_ = false;
    bool complete_ = false;
    std::size_t cleanup_count_ = 0U;
    bool cleanup_done_ = false;
};

IdfLpaBppStream::IdfLpaBppStream(std::string_view expected_transaction_id) noexcept
    : impl_(new (std::nothrow) Impl(expected_transaction_id))
{
}

IdfLpaBppStream::~IdfLpaBppStream()
{
    delete impl_;
}

esp_err_t IdfLpaBppStream::feed(const char* data,
                                std::size_t length,
                                std::string& safe_message)
{
    secure_clear(safe_message);
    if (impl_ == nullptr) {
        set_safe_message(safe_message, kMalformedMessage);
        return ESP_ERR_NO_MEM;
    }
    return impl_->feed(data, length, safe_message);
}

esp_err_t IdfLpaBppStream::finish(std::vector<std::uint8_t>& installation_result,
                                  std::string& safe_message)
{
    secure_clear(safe_message);
    if (impl_ == nullptr) {
        secure_clear(installation_result);
        set_safe_message(safe_message, kMalformedMessage);
        return ESP_ERR_NO_MEM;
    }
    return impl_->finish(installation_result, safe_message);
}

void IdfLpaBppStream::abort() noexcept
{
    if (impl_ != nullptr) impl_->abort();
}

#ifdef IDF_LPA_BPP_TESTING
bool IdfLpaBppStream::test_sensitive_storage_is_zero() const noexcept
{
    return impl_ != nullptr && impl_->sensitive_storage_is_zero();
}

std::size_t IdfLpaBppStream::test_cleanup_count() const noexcept
{
    return impl_ == nullptr ? 0U : impl_->cleanup_count();
}
#endif
