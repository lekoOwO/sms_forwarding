#include "idf_web_ota_core.h"

#include <algorithm>
#include <cstring>
#include <limits>

namespace {

class JsonCursor {
public:
    explicit JsonCursor(const std::string& text) : text_(text) {}

    bool literal(const char* value)
    {
        const size_t length = std::strlen(value);
        if (text_.compare(position_, length, value) != 0) return false;
        position_ += length;
        return true;
    }

    bool unsigned_value(uint32_t& output, bool nonzero)
    {
        if (position_ >= text_.size() || text_[position_] < '0' || text_[position_] > '9') {
            return false;
        }
        if (text_[position_] == '0' && position_ + 1 < text_.size() &&
            text_[position_ + 1] >= '0' && text_[position_ + 1] <= '9') return false;
        uint64_t value = 0;
        do {
            value = value * 10 + static_cast<unsigned>(text_[position_] - '0');
            if (value > std::numeric_limits<uint32_t>::max()) return false;
            ++position_;
        } while (position_ < text_.size() && text_[position_] >= '0' && text_[position_] <= '9');
        if (nonzero && value == 0) return false;
        output = static_cast<uint32_t>(value);
        return true;
    }

    bool quoted(std::string& output)
    {
        if (position_ >= text_.size() || text_[position_++] != '"') return false;
        const size_t start = position_;
        while (position_ < text_.size() && text_[position_] != '"') {
            const unsigned char value = static_cast<unsigned char>(text_[position_]);
            if (value < 0x20 || value > 0x7e || value == '\\') return false;
            ++position_;
        }
        if (position_ >= text_.size()) return false;
        output.assign(text_.data() + start, position_ - start);
        ++position_;
        return true;
    }

    bool done() const { return position_ == text_.size(); }

private:
    const std::string& text_;
    size_t position_ = 0;
};

bool valid_sha256(const std::string& value)
{
    if (value.size() != 64) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= '0' && ch <= '9') || (ch >= 'a' && ch <= 'f');
    });
}

bool valid_version(const std::string& value)
{
    if (value.empty() || value.size() > 32) return false;
    return std::all_of(value.begin(), value.end(), [](char ch) {
        return (ch >= 'a' && ch <= 'z') || (ch >= 'A' && ch <= 'Z') ||
               (ch >= '0' && ch <= '9') || ch == '.' || ch == '_' || ch == '+' || ch == '-';
    });
}

}  // namespace

IdfWebOtaCode idf_web_ota_parse_manifest(const std::string& text,
                                         IdfWebOtaManifest& output)
{
    output = IdfWebOtaManifest();
    if (text.empty() || text.size() > IDF_WEB_OTA_MAX_MANIFEST_BYTES) {
        return IdfWebOtaCode::ManifestInvalid;
    }
    JsonCursor cursor(text);
    uint32_t format = 0;
    uint32_t size = 0;
    std::string target;
    if (!cursor.literal("{\"format\":") || !cursor.unsigned_value(format, false) || format != 1 ||
        !cursor.literal(",\"releaseCounter\":") || !cursor.unsigned_value(output.release_counter, true) ||
        !cursor.literal(",\"sha256\":") || !cursor.quoted(output.sha256) ||
        !cursor.literal(",\"size\":") || !cursor.unsigned_value(size, true) ||
        !cursor.literal(",\"target\":") || !cursor.quoted(target) ||
        !cursor.literal(",\"version\":") || !cursor.quoted(output.version) ||
        !cursor.literal("}") || !cursor.done() || target != "esp32c3" ||
        size > IDF_WEB_OTA_MAX_IMAGE_BYTES || !valid_sha256(output.sha256) ||
        !valid_version(output.version)) {
        output = IdfWebOtaManifest();
        return IdfWebOtaCode::ManifestInvalid;
    }
    output.size = size;
    return IdfWebOtaCode::Ok;
}

IdfWebOtaSession::IdfWebOtaSession(IdfWebOtaPlatform platform) : platform_(platform) {}

void IdfWebOtaSession::reset(bool abort_update)
{
    if (abort_update && begun_ && platform_.abort) platform_.abort(platform_.context);
    manifest_ = IdfWebOtaManifest();
    active_ = false;
    finishing_ = false;
    begun_ = false;
    upload_id_ = 0;
    last_activity_ms_ = 0;
    target_address_ = 0;
    written_ = 0;
}

IdfWebOtaCode IdfWebOtaSession::start(const std::string& manifest,
                                      const uint8_t* signature, size_t signature_size,
                                      uint32_t upload_id, uint32_t now_ms)
{
    if (active_ || restart_pending_) return IdfWebOtaCode::Busy;
    IdfWebOtaManifest parsed;
    IdfWebOtaCode parsed_code = idf_web_ota_parse_manifest(manifest, parsed);
    if (parsed_code != IdfWebOtaCode::Ok) return parsed_code;
    if (!signature || signature_size < 8 || signature_size > 72 ||
        !platform_.verify_signature ||
        !platform_.verify_signature(platform_.context,
            reinterpret_cast<const uint8_t*>(manifest.data()), manifest.size(),
            signature, signature_size)) return IdfWebOtaCode::SignatureInvalid;
    uint32_t accepted = 0;
    uint32_t pending = 0;
    if (!platform_.load_counters ||
        !platform_.load_counters(platform_.context, &accepted, &pending)) {
        return IdfWebOtaCode::MetadataFailed;
    }
    const uint32_t effective = accepted > pending ? accepted : pending;
    if (parsed.release_counter <= effective) return IdfWebOtaCode::Replay;
    uint32_t target = 0;
    if (upload_id == 0 || !platform_.begin || !platform_.hash_begin ||
        !platform_.begin(platform_.context, parsed.size, &target) || target == 0) {
        return IdfWebOtaCode::BeginFailed;
    }
    begun_ = true;
    if (!platform_.hash_begin(platform_.context)) {
        reset(true);
        return IdfWebOtaCode::BeginFailed;
    }
    manifest_ = std::move(parsed);
    active_ = true;
    finishing_ = false;
    upload_id_ = upload_id;
    last_activity_ms_ = now_ms;
    target_address_ = target;
    written_ = 0;
    return IdfWebOtaCode::Ok;
}

IdfWebOtaCode IdfWebOtaSession::append(uint32_t upload_id, size_t offset,
                                       const uint8_t* data, size_t size,
                                       uint32_t now_ms, size_t* next_offset)
{
    if (!active_ || finishing_ || upload_id != upload_id_) return IdfWebOtaCode::SessionInvalid;
    if (!data || size == 0 || size > IDF_WEB_OTA_CHUNK_BYTES || offset != written_ ||
        written_ > manifest_.size || size > manifest_.size - written_) {
        reset(true);
        return IdfWebOtaCode::ChunkInvalid;
    }
    if (!platform_.write || !platform_.write(platform_.context, data, size)) {
        reset(true);
        return IdfWebOtaCode::WriteFailed;
    }
    if (!platform_.hash_update || !platform_.hash_update(platform_.context, data, size)) {
        reset(true);
        return IdfWebOtaCode::WriteFailed;
    }
    written_ += size;
    last_activity_ms_ = now_ms;
    if (next_offset) *next_offset = written_;
    return IdfWebOtaCode::Ok;
}

IdfWebOtaCode IdfWebOtaSession::prepare_finish(uint32_t upload_id)
{
    if (!active_ || finishing_ || upload_id != upload_id_) return IdfWebOtaCode::SessionInvalid;
    if (written_ != manifest_.size) {
        reset(true);
        return IdfWebOtaCode::SessionInvalid;
    }
    finishing_ = true;
    return IdfWebOtaCode::Ok;
}

bool IdfWebOtaSession::cancel_finish(uint32_t upload_id)
{
    if (!active_ || !finishing_ || upload_id != upload_id_) return false;
    finishing_ = false;
    return true;
}

bool IdfWebOtaSession::cancel_upload(uint32_t upload_id)
{
    if (!active_ || upload_id != upload_id_) return false;
    reset(true);
    return true;
}

IdfWebOtaCode IdfWebOtaSession::finish(uint32_t upload_id)
{
    if (!active_ || !finishing_ || upload_id != upload_id_) return IdfWebOtaCode::SessionInvalid;
    if (!platform_.hash_matches ||
        !platform_.hash_matches(platform_.context, manifest_.sha256.c_str())) {
        reset(true);
        return IdfWebOtaCode::HashInvalid;
    }
    if (!platform_.finish || !platform_.finish(platform_.context)) {
        reset(true);
        return IdfWebOtaCode::FinalizeFailed;
    }
    begun_ = false;
    if (!platform_.store_pending ||
        !platform_.store_pending(platform_.context, manifest_.release_counter, target_address_)) {
        if (platform_.clear_pending) platform_.clear_pending(platform_.context);
        reset(true);
        return IdfWebOtaCode::MetadataFailed;
    }
    if (!platform_.set_boot || !platform_.set_boot(platform_.context, target_address_)) {
        if (platform_.clear_pending) platform_.clear_pending(platform_.context);
        reset(true);
        return IdfWebOtaCode::BootFailed;
    }
    restart_pending_ = true;
    reset(false);
    return IdfWebOtaCode::Ok;
}

bool IdfWebOtaSession::expire(uint32_t now_ms, uint32_t ttl_ms)
{
    if (!active_ || finishing_ || now_ms - last_activity_ms_ < ttl_ms) return false;
    reset(true);
    return true;
}

IdfWebOtaHealthDecision idf_web_ota_health_decide(
    IdfWebOtaImageState state, bool http_live, bool management_reachable,
    bool deadline_expired, uint32_t accepted, uint32_t pending,
    uint32_t running_address, uint32_t pending_address)
{
    if (state == IdfWebOtaImageState::PendingVerify) {
        if (pending == 0 || pending <= accepted || pending_address == 0 ||
            running_address != pending_address) return IdfWebOtaHealthDecision::Rollback;
        if (deadline_expired) return IdfWebOtaHealthDecision::Rollback;
        if (!http_live || !management_reachable) return IdfWebOtaHealthDecision::Wait;
        return IdfWebOtaHealthDecision::Confirm;
    }
    if (pending == 0) return IdfWebOtaHealthDecision::None;
    if (state == IdfWebOtaImageState::Valid && running_address == pending_address &&
        pending > accepted) return IdfWebOtaHealthDecision::CommitAccepted;
    return IdfWebOtaHealthDecision::ClearStale;
}

IdfWebOtaHealthResult idf_web_ota_apply_health(
    IdfWebOtaImageState state, bool http_live, bool management_reachable,
    bool deadline_expired, uint32_t accepted, uint32_t pending,
    uint32_t running_address, uint32_t pending_address,
    const IdfWebOtaHealthPlatform& platform)
{
    if (state == IdfWebOtaImageState::PendingVerify && pending > accepted &&
        pending_address == 0) {
        if (!platform.bind_pending_address ||
            !platform.bind_pending_address(platform.context, running_address)) {
            if (platform.rollback) platform.rollback(platform.context);
            return IdfWebOtaHealthResult::RolledBack;
        }
        pending_address = running_address;
    }
    const IdfWebOtaHealthDecision decision = idf_web_ota_health_decide(
        state, http_live, management_reachable, deadline_expired,
        accepted, pending, running_address, pending_address);
    if (decision == IdfWebOtaHealthDecision::Wait) return IdfWebOtaHealthResult::Waiting;
    if (decision == IdfWebOtaHealthDecision::Rollback) {
        if (platform.rollback) platform.rollback(platform.context);
        return IdfWebOtaHealthResult::RolledBack;
    }
    if (decision == IdfWebOtaHealthDecision::Confirm) {
        if (!platform.mark_valid || !platform.mark_valid(platform.context)) {
            if (platform.rollback) platform.rollback(platform.context);
            return IdfWebOtaHealthResult::RolledBack;
        }
    }
    if (decision == IdfWebOtaHealthDecision::Confirm ||
        decision == IdfWebOtaHealthDecision::CommitAccepted) {
        const uint32_t target = accepted > pending ? accepted : pending;
        if (!platform.persist_accepted || !platform.persist_accepted(platform.context, target)) {
            return IdfWebOtaHealthResult::Retry;
        }
        if (!platform.clear_pending || !platform.clear_pending(platform.context)) {
            return IdfWebOtaHealthResult::Retry;
        }
    } else if (decision == IdfWebOtaHealthDecision::ClearStale) {
        if (!platform.clear_pending || !platform.clear_pending(platform.context)) {
            return IdfWebOtaHealthResult::Retry;
        }
    }
    return IdfWebOtaHealthResult::Done;
}
