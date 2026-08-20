#pragma once

#include <stddef.h>
#include <stdint.h>

#include <memory>
#include <string>
#include <utility>
#include <vector>

bool idf_web_constant_time_equal(const char* actual, size_t actual_len,
                                 const std::string& expected);
bool idf_web_ap_auth_bypass(bool ap_mode, bool ap_local, const char* uri);
bool idf_web_ap_csrf_bypass(bool ap_mode, bool ap_local, const char* uri, const char* token);
bool idf_web_at_command_allowed(const std::string& input);
bool idf_web_valid_utf8_text(const std::string& value);

struct IdfWebFormDecodeResult {
    bool valid = false;
    bool too_many_fields = false;
    std::vector<std::pair<std::string, std::string>> fields;
};

IdfWebFormDecodeResult idf_web_decode_form(const std::string& body, size_t max_fields);

struct IdfWebOwnedJobInput {
    std::string type;
    std::string payload;
};

enum class IdfWebTransferMode : uint8_t { None, Export, Restore };
using IdfWebByteAllocator = uint8_t* (*)(size_t);

struct IdfWebOwnedBytes {
    std::unique_ptr<uint8_t[]> data;
    size_t size = 0;
    size_t capacity = 0;

    IdfWebOwnedBytes() = default;
    IdfWebOwnedBytes(const IdfWebOwnedBytes&) = delete;
    IdfWebOwnedBytes& operator=(const IdfWebOwnedBytes&) = delete;
    IdfWebOwnedBytes(IdfWebOwnedBytes&& other) noexcept
        : data(std::move(other.data)),
          size(std::exchange(other.size, 0)),
          capacity(std::exchange(other.capacity, 0)) {}
    ~IdfWebOwnedBytes()
    {
        volatile uint8_t* bytes = data.get();
        for (size_t i = 0; i < capacity; ++i) bytes[i] = 0;
    }
    IdfWebOwnedBytes& operator=(IdfWebOwnedBytes&& other) noexcept
    {
        if (this == &other) return *this;
        volatile uint8_t* old = data.get();
        for (size_t i = 0; i < capacity; ++i) old[i] = 0;
        data = std::move(other.data);
        size = std::exchange(other.size, 0);
        capacity = std::exchange(other.capacity, 0);
        return *this;
    }
};

struct IdfWebTransfer {
    IdfWebTransferMode mode = IdfWebTransferMode::None;
    uint32_t id = 0;
    uint32_t started_ms = 0;
    size_t expected_size = 0;
    IdfWebOwnedBytes bytes;
};

void idf_web_secure_clear(std::string& value);
void idf_web_secure_clear(std::vector<uint8_t>& value);
void idf_web_secure_clear(IdfWebOwnedBytes& value);
bool idf_web_allocate_owned_bytes(IdfWebOwnedBytes& value, size_t size,
                                  IdfWebByteAllocator allocator = nullptr);
bool idf_web_finalize_owned_bytes(IdfWebOwnedBytes& value, size_t written,
                                  size_t maximum);
void idf_web_transfer_clear(IdfWebTransfer& transfer);
bool idf_web_transfer_expire(IdfWebTransfer& transfer, uint32_t now_ms, uint32_t ttl_ms);
bool idf_web_transfer_start(IdfWebTransfer& transfer, IdfWebTransferMode mode,
                            uint32_t id, size_t expected_size, uint32_t now_ms,
                            IdfWebByteAllocator allocator = nullptr);
bool idf_web_transfer_append(IdfWebTransfer& transfer, uint32_t id, size_t offset,
                             const uint8_t* chunk, size_t chunk_size, size_t max_chunk);
bool idf_web_transfer_cancel_upload(IdfWebTransfer& transfer, uint32_t id);
bool idf_web_transfer_take_complete(IdfWebTransfer& transfer, uint32_t id,
                                    IdfWebOwnedBytes& output);

IdfWebOwnedJobInput idf_web_own_job_input(const char* type, const char* payload,
                                          size_t payload_size);
std::string idf_web_paginate_log_json(const std::string& snapshot, bool has_cursor,
                                      uint32_t cursor, size_t limit);

enum class IdfWebJobState : uint8_t { Empty, Queued, Running, Done };

struct IdfWebJobSlotMeta {
    uint32_t id = 0;
    IdfWebJobState state = IdfWebJobState::Empty;
    uint32_t completed_ms = 0;
};

size_t idf_web_count_active_jobs(const IdfWebJobSlotMeta* slots, size_t count);
int idf_web_select_job_slot(const IdfWebJobSlotMeta* slots, size_t count,
                            uint32_t now_ms, uint32_t ttl_ms);
