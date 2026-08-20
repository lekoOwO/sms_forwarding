#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

static constexpr size_t IDF_WEB_OTA_CHUNK_BYTES = 8192;
static constexpr size_t IDF_WEB_OTA_MAX_IMAGE_BYTES = 0x1e0000;
static constexpr size_t IDF_WEB_OTA_MAX_MANIFEST_BYTES = 512;

enum class IdfWebOtaCode : uint8_t {
    Ok,
    ManifestInvalid,
    SignatureInvalid,
    Replay,
    Busy,
    SessionInvalid,
    ChunkInvalid,
    BeginFailed,
    WriteFailed,
    HashInvalid,
    FinalizeFailed,
    MetadataFailed,
    BootFailed,
};

struct IdfWebOtaManifest {
    uint32_t release_counter = 0;
    size_t size = 0;
    std::string sha256;
    std::string version;
};

IdfWebOtaCode idf_web_ota_parse_manifest(const std::string& text,
                                         IdfWebOtaManifest& output);

struct IdfWebOtaPlatform {
    void* context = nullptr;
    bool (*load_counters)(void*, uint32_t*, uint32_t*) = nullptr;
    bool (*verify_signature)(void*, const uint8_t*, size_t,
                             const uint8_t*, size_t) = nullptr;
    bool (*hash_begin)(void*) = nullptr;
    bool (*hash_update)(void*, const uint8_t*, size_t) = nullptr;
    bool (*hash_matches)(void*, const char*) = nullptr;
    bool (*begin)(void*, size_t, uint32_t*) = nullptr;
    bool (*write)(void*, const uint8_t*, size_t) = nullptr;
    bool (*finish)(void*) = nullptr;
    void (*abort)(void*) = nullptr;
    bool (*store_pending)(void*, uint32_t, uint32_t) = nullptr;
    void (*clear_pending)(void*) = nullptr;
    bool (*set_boot)(void*, uint32_t) = nullptr;
};

class IdfWebOtaSession {
public:
    explicit IdfWebOtaSession(IdfWebOtaPlatform platform);
    IdfWebOtaCode start(const std::string& manifest, const uint8_t* signature,
                        size_t signature_size, uint32_t upload_id, uint32_t now_ms);
    IdfWebOtaCode append(uint32_t upload_id, size_t offset, const uint8_t* data,
                         size_t size, uint32_t now_ms, size_t* next_offset = nullptr);
    IdfWebOtaCode prepare_finish(uint32_t upload_id);
    bool cancel_finish(uint32_t upload_id);
    bool cancel_upload(uint32_t upload_id);
    IdfWebOtaCode finish(uint32_t upload_id);
    bool expire(uint32_t now_ms, uint32_t ttl_ms);
    bool active() const { return active_; }
    bool finishing() const { return finishing_; }
    bool restart_pending() const { return restart_pending_; }
    uint32_t upload_id() const { return upload_id_; }
    size_t written() const { return written_; }

private:
    void reset(bool abort_update);
    IdfWebOtaPlatform platform_;
    IdfWebOtaManifest manifest_;
    bool active_ = false;
    bool finishing_ = false;
    bool begun_ = false;
    bool restart_pending_ = false;
    uint32_t upload_id_ = 0;
    uint32_t last_activity_ms_ = 0;
    uint32_t target_address_ = 0;
    size_t written_ = 0;
};

enum class IdfWebOtaImageState : uint8_t { Other, PendingVerify, Valid };
enum class IdfWebOtaHealthDecision : uint8_t {
    None,
    Wait,
    Confirm,
    CommitAccepted,
    Rollback,
    ClearStale,
};

IdfWebOtaHealthDecision idf_web_ota_health_decide(
    IdfWebOtaImageState state, bool http_live, bool management_reachable,
    bool deadline_expired, uint32_t accepted, uint32_t pending,
    uint32_t running_address, uint32_t pending_address);

struct IdfWebOtaHealthPlatform {
    void* context = nullptr;
    bool (*bind_pending_address)(void*, uint32_t) = nullptr;
    bool (*mark_valid)(void*) = nullptr;
    bool (*persist_accepted)(void*, uint32_t) = nullptr;
    bool (*clear_pending)(void*) = nullptr;
    void (*rollback)(void*) = nullptr;
};

enum class IdfWebOtaHealthResult : uint8_t { Done, Waiting, Retry, RolledBack };

IdfWebOtaHealthResult idf_web_ota_apply_health(
    IdfWebOtaImageState state, bool http_live, bool management_reachable,
    bool deadline_expired, uint32_t accepted, uint32_t pending,
    uint32_t running_address, uint32_t pending_address,
    const IdfWebOtaHealthPlatform& platform);
