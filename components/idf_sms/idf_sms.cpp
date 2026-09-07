#include "idf_sms.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <functional>
#include <string>
#include <vector>

#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"
#include "idf_config.h"
#include "idf_inbox.h"
#include "idf_log.h"
#include "idf_modem.h"
#include "idf_modem_query_filter.h"
#include "idf_push.h"
#include "idf_util.h"
#include "pdulib.h"

static constexpr size_t MAX_PDU_HEX_CHARS = 600;
static constexpr size_t INDEX_QUEUE_MAX = 8;
static constexpr size_t OUT_SMS_QUEUE_MAX = 3;
static constexpr size_t PENDING_FORWARD_MAX = 3;
static constexpr size_t SEEN_RING_MAX = 32;
static constexpr size_t CONCAT_SLOTS = 5;
static constexpr size_t CONCAT_PARTS = 10;
// Carrier retries and polling can take minutes after SIM storage rejects a segment.
// Wait 15 minutes before forwarding a direct message with missing-segment markers.
static constexpr int64_t CONCAT_TIMEOUT_US = 15LL * 60LL * 1000LL * 1000LL;
// Poll every 10 seconds while a multipart message is incomplete.
static constexpr uint32_t CONCAT_HUNT_POLL_MS = 10000;
static constexpr uint32_t SMS_POLL_INTERVAL_MS = 60000;
static constexpr uint32_t SMS_STARTUP_POLL_INTERVAL_MS = 8000;
static constexpr uint32_t SMS_STARTUP_FAST_WINDOW_MS = 120000;
static constexpr uint8_t SMS_CNMI_REASSERT_EVERY = 5;
// Allow 60 seconds for +CMGS during roaming or cell reselection.
static constexpr uint32_t SMS_SUBMIT_TIMEOUT_MS = 60000;

struct ConcatPart {
    bool valid = false;
    std::string text;
    std::string timestamp;
};

struct ConcatSlot {
    bool active = false;
    int ref = 0;
    int total = 0;
    int received = 0;
    std::string sender;
    std::string timestamp;
    int64_t lastUs = 0;
    std::array<ConcatPart, CONCAT_PARTS> parts;
};

struct OutgoingSmsJob {
    std::string phone;
    std::string text;
};

struct PendingForwardJob {
    std::string sender;
    std::string text;
    std::string timestamp;
    uint32_t inbox_id = 0;
};

struct DecodedSms {
    std::string sender;
    std::string text;
    std::string timestamp;
    int concat[3] = {};
};

static SemaphoreHandle_t s_status_mutex = nullptr;
static SemaphoreHandle_t s_pdu_mutex = nullptr;
static SemaphoreHandle_t s_out_mutex = nullptr;
static IdfSmsStatus s_status;
static bool s_started = false;
static PDU s_pdu(4096);
static std::array<int, INDEX_QUEUE_MAX> s_index_queue = {};
static size_t s_index_count = 0;
static std::array<OutgoingSmsJob, OUT_SMS_QUEUE_MAX> s_out_queue = {};
static size_t s_out_head = 0;
static size_t s_out_count = 0;
static std::array<PendingForwardJob, PENDING_FORWARD_MAX> s_pending_forwards = {};
static size_t s_pending_forward_head = 0;
static size_t s_pending_forward_count = 0;
static std::array<uint32_t, SEEN_RING_MAX> s_seen = {};
static size_t s_seen_next = 0;
static size_t s_seen_filled = 0;
static std::array<ConcatSlot, CONCAT_SLOTS> s_concat = {};
static std::string s_urc_carry;
static bool s_wait_pdu = false;
static int64_t s_wait_pdu_until_us = 0;   // Three-second PDU window after +CMT
static bool s_backfill_pending = false;   // Request CMGL after queue overflow or CMGR failure
static bool s_cnma_error_logged = false;  // Log a repeated CNMA firmware error once

static void cleanup_start_resources()
{
    if (s_status_mutex) {
        vSemaphoreDelete(s_status_mutex);
        s_status_mutex = nullptr;
    }
    if (s_pdu_mutex) {
        vSemaphoreDelete(s_pdu_mutex);
        s_pdu_mutex = nullptr;
    }
    if (s_out_mutex) {
        vSemaphoreDelete(s_out_mutex);
        s_out_mutex = nullptr;
    }
    s_pending_forwards = {};
    s_pending_forward_head = 0;
    s_pending_forward_count = 0;
}

// SIM storage index 0 is valid. Reject malformed text instead of converting it to 0.
static bool parse_sms_index_token(const char* start, size_t len, int& index)
{
    if (!start || len == 0 || len > 5) return false;
    int parsed = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char ch = static_cast<unsigned char>(start[i]);
        if (!isdigit(ch)) return false;
        parsed = parsed * 10 + static_cast<int>(ch - '0');
    }
    index = parsed;
    return true;
}

static bool starts_with(const std::string& text, const char* prefix)
{
    return text.rfind(prefix, 0) == 0;
}

static bool is_hex_string(const std::string& line)
{
    if (line.empty() || line.size() > MAX_PDU_HEX_CHARS || (line.size() & 1U)) return false;
    return std::all_of(line.begin(), line.end(), [](char ch) {
        return isxdigit(static_cast<unsigned char>(ch));
    });
}

// The deduplication ring is not stable across restarts, so use the standard hash.
static uint32_t hash32(const std::string& text)
{
    return static_cast<uint32_t>(std::hash<std::string>{}(text));
}

static bool was_seen(uint32_t hash)
{
    return std::find(s_seen.begin(), s_seen.begin() + s_seen_filled, hash) !=
           s_seen.begin() + s_seen_filled;
}

static void remember_seen(uint32_t hash)
{
    // Record only accepted or intentionally discarded messages. A full queue must allow a SIM retry.
    s_seen[s_seen_next] = hash;
    s_seen_next = (s_seen_next + 1) % SEEN_RING_MAX;
    if (s_seen_filled < SEEN_RING_MAX) ++s_seen_filled;
}

static bool enqueue_pending_forward(const std::string& sender, const std::string& text,
                                    const std::string& timestamp, uint32_t inbox_id)
{
    if (s_pending_forward_count >= PENDING_FORWARD_MAX) return false;
    size_t tail = (s_pending_forward_head + s_pending_forward_count) % PENDING_FORWARD_MAX;
    PendingForwardJob& job = s_pending_forwards[tail];
    job.sender = sender;
    job.text = text;
    job.timestamp = timestamp;
    job.inbox_id = inbox_id;
    ++s_pending_forward_count;
    return true;
}

static bool retry_pending_forward()
{
    if (s_pending_forward_count == 0) return false;
    PendingForwardJob& job = s_pending_forwards[s_pending_forward_head];
    if (!idf_push_enqueue_forward(job.sender.c_str(), job.text.c_str(),
                                  job.timestamp.c_str(), job.inbox_id)) {
        return false;
    }
    idf_logf("SMS RAM retry entered the forward queue id=%u", static_cast<unsigned>(job.inbox_id));
    job = PendingForwardJob();
    s_pending_forward_head = (s_pending_forward_head + 1) % PENDING_FORWARD_MAX;
    --s_pending_forward_count;
    return true;
}

static std::string canonical_phone(const std::string& num)
{
    size_t start = 0;
    while (start < num.size() && isspace(static_cast<unsigned char>(num[start]))) ++start;
    bool explicit_cn_prefix = start < num.size() && num[start] == '+';

    std::string out;
    out.reserve(num.size());
    for (size_t i = 0; i < num.size(); ++i) {
        unsigned char ch = static_cast<unsigned char>(num[i]);
        if (isdigit(ch)) out += static_cast<char>(ch);
    }
    if (out.rfind("86", 0) == 0 && out.size() > 2 && (explicit_cn_prefix || out.size() == 13)) {
        return out.substr(2);
    }
    return out;
}

static std::string masked_phone(const std::string& number)
{
    std::string digits = canonical_phone(number);
    if (digits.empty()) return "Unknown number";
    if (digits.size() <= 4) return "***";
    return "***" + digits.substr(digits.size() - 4);
}

static bool number_blacklisted(const std::string& list, const std::string& sender)
{
    if (list.empty()) return false;
    std::string target = canonical_phone(sender);
    if (target.empty()) return false;
    size_t pos = 0;
    while (pos <= list.size()) {
        size_t end = list.find('\n', pos);
        if (end == std::string::npos) end = list.size();
        std::string line = idf_util_trim_copy(list.substr(pos, end - pos));
        if (!line.empty() && canonical_phone(line) == target) {
            return true;
        }
        if (end == list.size()) break;
        pos = end + 1;
    }
    return false;
}

static bool is_valid_phone_number(const std::string& phone)
{
    if (phone.size() < 3 || phone.size() > 20) return false;
    for (size_t i = 0; i < phone.size(); ++i) {
        char ch = phone[i];
        if (i == 0 && ch == '+') continue;
        if (!isdigit(static_cast<unsigned char>(ch))) return false;
    }
    return true;
}

static void update_status(bool receive_ready, bool got_sms)
{
    if (!s_status_mutex) return;
    if (xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return;
    s_status.receiveReady = receive_ready || s_status.receiveReady;
    if (got_sms) {
        ++s_status.total;
        s_status.lastSmsEpoch = static_cast<uint32_t>(time(nullptr));
    }
    xSemaphoreGive(s_status_mutex);
}

static void enqueue_index(int idx)
{
    if (idx < 0) {
        s_backfill_pending = true;  // Use CMGL after an invalid index.
        return;
    }
    for (size_t i = 0; i < s_index_count; ++i) {
        if (s_index_queue[i] == idx) return;
    }
    if (s_index_count < INDEX_QUEUE_MAX) {
        s_index_queue[s_index_count++] = idx;
    } else {
        s_backfill_pending = true;  // Drop the index but request CMGL after queue overflow.
    }
}

static bool pop_index(int& idx)
{
    if (s_index_count == 0) return false;
    idx = s_index_queue[0];
    for (size_t i = 1; i < s_index_count; ++i) s_index_queue[i - 1] = s_index_queue[i];
    --s_index_count;
    return true;
}

static int outgoing_depth_locked()
{
    return static_cast<int>(s_out_count);
}

static bool pop_outgoing_sms(OutgoingSmsJob& job)
{
    if (!s_out_mutex || xSemaphoreTake(s_out_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return false;
    if (s_out_count == 0) {
        xSemaphoreGive(s_out_mutex);
        return false;
    }
    job = std::move(s_out_queue[s_out_head]);
    s_out_queue[s_out_head] = OutgoingSmsJob();
    s_out_head = (s_out_head + 1) % OUT_SMS_QUEUE_MAX;
    --s_out_count;
    xSemaphoreGive(s_out_mutex);
    return true;
}

static int parse_cmti_index(const std::string& line)
{
    size_t comma = line.rfind(',');
    if (comma == std::string::npos || comma + 1 >= line.size()) return -1;
    std::string num = idf_util_trim_copy(line.substr(comma + 1));
    int index = -1;
    if (!parse_sms_index_token(num.c_str(), num.size(), index)) return -1;
    return index;
}

static int parse_cmgl_index(const std::string& line)
{
    const char* p = strchr(line.c_str(), ':');
    if (!p) return -1;
    while (*++p && isspace(static_cast<unsigned char>(*p))) {}
    const char* start = p;
    while (*p && isdigit(static_cast<unsigned char>(*p))) ++p;
    int index = -1;
    if (!parse_sms_index_token(start, static_cast<size_t>(p - start), index)) return -1;
    while (*p && isspace(static_cast<unsigned char>(*p))) ++p;
    if (*p != ',' && *p != '\0') return -1;
    return index;
}

static void clear_concat_slot(ConcatSlot& slot)
{
    slot.active = false;
    slot.ref = 0;
    slot.total = 0;
    slot.received = 0;
    slot.sender.clear();
    slot.timestamp.clear();
    slot.lastUs = 0;
    for (auto& part : slot.parts) {
        part.valid = false;
        part.text.clear();
        part.timestamp.clear();
    }
}

static std::string assemble_concat(const ConcatSlot& slot)
{
    std::string text;
    for (int i = 0; i < slot.total && i < static_cast<int>(CONCAT_PARTS); ++i) {
        if (slot.parts[i].valid) {
            text += slot.parts[i].text;
        } else {
            // Mark each gap when an incomplete message times out.
            text += "[Missing segment ";
            text += std::to_string(i + 1);
            text += "]";
        }
    }
    return text;
}

struct SmsProcessResult {
    bool retained = false;
    bool admitted = false;
};

static SmsProcessResult process_sms_content(const char* sender_raw, const char* text_raw,
                                            const char* timestamp_raw, bool allow_ram_retry);

// Track completed multipart messages because an SMSC can retry the full message
// after SIM storage rejects some segments. Match the reference, sender, total,
// and content hash so carrier reference reuse does not discard a new message.
struct ConcatDone {
    bool used = false;
    int ref = 0;
    int total = 0;
    std::string sender;
    std::array<uint32_t, CONCAT_PARTS> partHash = {};
    std::array<std::string, CONCAT_PARTS> partTimestamp;
    int64_t doneUs = 0;
};
static constexpr int64_t CONCAT_DONE_TTL_US = 10LL * 60 * 1000 * 1000;
static std::array<ConcatDone, 4> s_concat_done = {};
static size_t s_concat_done_next = 0;

static bool concat_recently_done(int ref, const std::string& sender, int total,
                                 int part, const std::string& text, const std::string& timestamp)
{
    int64_t now = esp_timer_get_time();
    return std::any_of(s_concat_done.begin(), s_concat_done.end(), [&](const auto& done) {
        return done.used && now - done.doneUs <= CONCAT_DONE_TTL_US &&
               done.ref == ref && done.total == total && done.sender == sender &&
               done.partHash[part - 1] == hash32(text) && done.partTimestamp[part - 1] == timestamp;
    });
}

static void record_concat_done(const ConcatSlot& slot)
{
    ConcatDone& d = s_concat_done[s_concat_done_next];
    s_concat_done_next = (s_concat_done_next + 1) % s_concat_done.size();
    d.used = true;
    d.ref = slot.ref;
    d.total = slot.total;
    d.sender = slot.sender;
    d.partHash.fill(0);
    for (auto& timestamp : d.partTimestamp) timestamp.clear();
    for (int i = 0; i < slot.total && i < static_cast<int>(CONCAT_PARTS); ++i) {
        if (slot.parts[i].valid) {
            d.partHash[i] = hash32(slot.parts[i].text);
            d.partTimestamp[i] = slot.parts[i].timestamp;
        }
    }
    d.doneUs = esp_timer_get_time();
}

// SMSC can stop retrying acknowledged direct segments. Before clearing or reusing
// a concat slot, admit its content to push or the SMS RAM fallback. Retain it on failure.
static SmsProcessResult retain_concat_before_clear(ConcatSlot& slot, bool allow_ram_retry)
{
    std::string partial = assemble_concat(slot);
    SmsProcessResult result = process_sms_content(
        slot.sender.c_str(), partial.c_str(), slot.timestamp.c_str(), allow_ram_retry);
    if (result.retained) record_concat_done(slot);
    return result;
}

static ConcatSlot* find_concat_slot(int ref, const std::string& sender, int total,
                                    bool allow_ram_retry, bool allow_admission,
                                    bool& admission_blocked, bool& deferred,
                                    bool& eviction_admitted)
{
    int64_t now = esp_timer_get_time();
    auto slot = std::find_if(s_concat.begin(), s_concat.end(), [&](const auto& candidate) {
        return candidate.active && candidate.ref == ref && candidate.sender == sender &&
               candidate.total == total;
    });
    if (slot != s_concat.end()) return &*slot;
    slot = std::find_if(s_concat.begin(), s_concat.end(), [&](const auto& candidate) {
        return !candidate.active || now - candidate.lastUs > CONCAT_TIMEOUT_US;
    });
    if (slot != s_concat.end()) {
        clear_concat_slot(*slot);
        slot->active = true;
        slot->ref = ref;
        slot->total = total;
        slot->sender = sender;
        slot->lastUs = now;
        return &*slot;
    }
    if (!allow_admission) {
        deferred = true;
        return nullptr;
    }
    auto oldest = std::min_element(s_concat.begin(), s_concat.end(),
        [](const ConcatSlot& a, const ConcatSlot& b) { return a.lastUs < b.lastUs; });
    // Do not discard received segments when every slot is busy. They can already
    // be deleted from the SIM. Forward the partial message before reusing a slot.
    {
        idf_logf("multipart SMS slots full; forwarding %d/%d segments before reuse",
                 oldest->received, oldest->total);
        SmsProcessResult result = retain_concat_before_clear(*oldest, allow_ram_retry);
        if (!result.retained) {
            admission_blocked = true;
            return nullptr;
        }
        eviction_admitted = result.admitted;
    }
    clear_concat_slot(*oldest);
    oldest->active = true;
    oldest->ref = ref;
    oldest->total = total;
    oldest->sender = sender;
    oldest->lastUs = now;
    return &*oldest;
}

static SmsProcessResult process_sms_content(const char* sender_raw, const char* text_raw,
                                            const char* timestamp_raw, bool allow_ram_retry)
{
    std::string sender = sender_raw ? sender_raw : "";
    std::string text = text_raw ? text_raw : "";
    std::string timestamp = timestamp_raw ? timestamp_raw : "";
    const IdfSmsProcessView cfg = idf_config_get_sms_process_view();

    if (number_blacklisted(cfg.numberBlackList, sender)) {
        idf_logf("SMS sender %s is blocked; message ignored", masked_phone(sender).c_str());
        return {true, false};
    }

    // Use the original PDU timestamp for URC and CMGL deduplication.
    // Use local display time, or the original digits before time synchronization.
    uint32_t hash = hash32(sender + "|" + timestamp + "|" + text);
    if (was_seen(hash)) {
        idf_logf("duplicate SMS from %s ignored", masked_phone(sender).c_str());
        return {true, false};
    }

    std::string display_ts = idf_util_format_epoch_local(static_cast<uint32_t>(time(nullptr)), cfg.tzOffsetMin);
    if (display_ts.empty()) display_ts = timestamp;

    uint32_t id = idf_inbox_add(sender.c_str(), text.c_str(), display_ts.c_str());
    idf_logf("SMS received id=%u from %s; entering forward queue",
             static_cast<unsigned>(id), masked_phone(sender).c_str());
    if (!idf_push_enqueue_forward(sender.c_str(), text.c_str(), display_ts.c_str(), id)) {
        if (allow_ram_retry &&
            enqueue_pending_forward(sender, text, display_ts, id)) {
            update_status(true, true);
            remember_seen(hash);
            idf_logf("forward queue full; SMS id=%u entered the RAM retry queue",
                     static_cast<unsigned>(id));
            return {true, true};
        }
        idf_inbox_delete(id);
        idf_logf("forward queue full; SMS id=%u waits for a storage retry",
                 static_cast<unsigned>(id));
        return {false, false};
    }
    update_status(true, true);
    remember_seen(hash);
    return {true, true};
}

struct PduDecodeOutcome {
    bool decoded = false;
    bool safe_to_delete = false;
    bool admission_blocked = false;
    bool admitted = false;
    bool deferred = false;
};

static PduDecodeOutcome handle_decoded_pdu(const DecodedSms& sms, bool allow_ram_retry,
                                           bool allow_admission)
{
    const char* sender = sms.sender.c_str();
    const char* text = sms.text.c_str();
    const char* ts = sms.timestamp.c_str();
    int ref = sms.concat[0];
    int part = sms.concat[1];
    int total = sms.concat[2];

    if (total > 1 && part > 0) {
        if (total > static_cast<int>(CONCAT_PARTS) || part > total) {
            idf_logf("multipart fields out of range part=%d total=%d; treating as one SMS", part, total);
            if (!allow_admission) return {true, false, false, false, true};
            SmsProcessResult result = process_sms_content(sender, text, ts, allow_ram_retry);
            return {true, result.retained, !result.retained, result.admitted, false};
        }
        if (concat_recently_done(ref, sender ? sender : "", total, part,
                                 text ? text : "", ts ? ts : "")) {
            idf_logf("multipart segment ref=%d %d/%d duplicates a recent message; ignored", ref, part, total);
            return {true, true, false, false, false};
        }
        bool lookup_blocked = false;
        bool lookup_deferred = false;
        bool eviction_admitted = false;
        ConcatSlot* slot_ptr = find_concat_slot(ref, sender ? sender : "", total,
                                                allow_ram_retry, allow_admission,
                                                lookup_blocked, lookup_deferred,
                                                eviction_admitted);
        if (!slot_ptr) {
            return {true, false, lookup_blocked, eviction_admitted, lookup_deferred};
        }
        ConcatSlot& slot = *slot_ptr;
        int idx = part - 1;
        const std::string incoming_text = text ? text : "";
        const std::string incoming_timestamp = ts ? ts : "";
        bool same_part = slot.parts[idx].valid &&
                         slot.parts[idx].text == incoming_text &&
                         slot.parts[idx].timestamp == incoming_timestamp;
        if (slot.parts[idx].valid && !same_part) {
            // Identical content can be a new SMS, so the timestamp identifies a segment.
            // Safely admit an old acknowledged slot before accepting a reused reference.
            if (!allow_admission || eviction_admitted) {
                return {true, false, false, eviction_admitted, true};
            }
            idf_logf("multipart ref=%d reused; retaining old incomplete %d/%d message before regrouping",
                     ref, slot.received, slot.total);
            SmsProcessResult result = retain_concat_before_clear(slot, allow_ram_retry);
            if (!result.retained) {
                return {true, false, true, eviction_admitted, false};
            }
            eviction_admitted = result.admitted;
            clear_concat_slot(slot);
            slot.active = true;
            slot.ref = ref;
            slot.total = total;
            slot.sender = sender ? sender : "";
            slot.lastUs = esp_timer_get_time();
        }
        if (!slot.parts[idx].valid) {
            slot.parts[idx].valid = true;
            slot.parts[idx].text = text ? text : "";
            slot.parts[idx].timestamp = ts ? ts : "";
            slot.received++;
            slot.lastUs = esp_timer_get_time();
            if (slot.timestamp.empty()) slot.timestamp = ts ? ts : "";
            idf_logf("multipart SMS segment received ref=%d %d/%d", ref, part, total);
        }
        if (slot.received >= slot.total) {
            if (!allow_admission || eviction_admitted) {
                return {true, false, false, eviction_admitted, true};
            }
            SmsProcessResult result = retain_concat_before_clear(slot, allow_ram_retry);
            if (result.retained) {
                clear_concat_slot(slot);
            }
            return {true, result.retained, !result.retained, result.admitted, false};
        }
        return {true, false, false, eviction_admitted, false};
    }

    if (!allow_admission) return {true, false, false, false, true};
    SmsProcessResult result = process_sms_content(sender, text, ts, allow_ram_retry);
    return {true, result.retained, !result.retained, result.admitted, false};
}

static PduDecodeOutcome decode_pdu_line(const std::string& line, bool allow_ram_retry,
                                        bool allow_admission = true)
{
    if (!is_hex_string(line)) return {};
    if (!s_pdu_mutex) return {};
    // Retry while the shared PDU codec encodes a Web SMS. Returning false would
    // mark a direct message as corrupt and can delete a valid stored message.
    bool locked = false;
    for (int attempt = 0; attempt < 3 && !locked; ++attempt) {
        locked = xSemaphoreTake(s_pdu_mutex, pdMS_TO_TICKS(2000)) == pdTRUE;
        if (!locked) idf_log_line("PDU codec busy; waiting to retry...");
    }
    if (!locked) return {};
    DecodedSms decoded;
    if (!s_pdu.decodePDU(line.c_str())) {
        xSemaphoreGive(s_pdu_mutex);
        idf_logf("PDU parse failed (hex=%u)", static_cast<unsigned>(line.size()));
        return {};
    }
    decoded.sender = s_pdu.getSender();
    decoded.text = s_pdu.getText();
    decoded.timestamp = s_pdu.getTimeStamp();
    int* concat = s_pdu.getConcatInfo();
    if (concat) {
        decoded.concat[0] = concat[0];
        decoded.concat[1] = concat[1];
        decoded.concat[2] = concat[2];
    }
    xSemaphoreGive(s_pdu_mutex);
    // Release the shared PDU codec before inbox and forwarding work.
    return handle_decoded_pdu(decoded, allow_ram_retry, allow_admission);
}

// Only sms_task accesses incomplete multipart slots, so no lock is required.
static bool concat_waiting()
{
    return std::any_of(s_concat.begin(), s_concat.end(), [](const auto& slot) {
        return slot.active && slot.received < slot.total;
    });
}

static void expire_concat_slots()
{
    int64_t now = esp_timer_get_time();
    for (auto& slot : s_concat) {
        if (!slot.active || now - slot.lastUs <= CONCAT_TIMEOUT_US) continue;
        std::string full = assemble_concat(slot);
        if (!full.empty()) {
            idf_logf("multipart SMS timed out; assembled %d/%d segments", slot.received, slot.total);
            SmsProcessResult result = retain_concat_before_clear(slot, true);
            if (result.retained) {
                clear_concat_slot(slot);
            } else {
                // Retain acknowledged direct segments if push and RAM fallback are full.
                slot.lastUs = now;
            }
        }
    }
}

// ===== Call notifications =====
static int64_t s_call_last_urc_us = 0;
static int64_t s_call_first_ring_us = 0;
static bool s_call_active = false;
static bool s_call_notified = false;
static bool s_call_saw_ring = false;
static bool s_call_recovery_attempted = false;
static std::string s_call_number;
static constexpr int64_t CALL_GAP_US = 30LL * 1000 * 1000;
static constexpr int64_t CALL_CLCC_DELAY_US = 3LL * 1000 * 1000;

static void process_urc_text(const std::string& text);

static void skip_call_spaces(const std::string& line, size_t& pos)
{
    while (pos < line.size() && (line[pos] == ' ' || line[pos] == '\t')) ++pos;
}

static bool read_call_uint(const std::string& line, size_t& pos, int& value)
{
    skip_call_spaces(line, pos);
    const size_t start = pos;
    while (pos < line.size() && line[pos] >= '0' && line[pos] <= '9') ++pos;
    if (!parse_sms_index_token(line.data() + start, pos - start, value)) return false;
    skip_call_spaces(line, pos);
    return true;
}

static bool read_call_number(const std::string& line, size_t& pos, std::string& number)
{
    skip_call_spaces(line, pos);
    if (pos == line.size() || line[pos++] != '"') return false;
    const size_t end = line.find('"', pos);
    if (end == std::string::npos) return false;
    number = line.substr(pos, end - pos);
    if (!number.empty() && !is_valid_phone_number(number)) return false;
    pos = end + 1;
    skip_call_spaces(line, pos);
    if (pos == line.size() || line[pos++] != ',') return false;
    int type = 0;
    return read_call_uint(line, pos, type) && type <= 255;
}

static std::string parse_clip_number(const std::string& line)
{
    if (!starts_with(line, "+CLIP:")) return {};
    size_t pos = 6;
    std::string number;
    if (!read_call_number(line, pos, number) ||
        (pos != line.size() && line[pos] != ',')) return {};
    return number;
}

static bool parse_clcc_line(const std::string& line, bool& incoming, std::string& number)
{
    size_t pos = 6;
    int fields[5] = {};
    for (size_t i = 0; i < 5; ++i) {
        if (!read_call_uint(line, pos, fields[i])) return false;
        if (i != 4 && (pos == line.size() || line[pos++] != ',')) return false;
    }
    if (fields[0] == 0 || fields[1] > 1 || fields[2] > 5 ||
        fields[3] > 2 || fields[4] > 1) return false;
    incoming = fields[1] == 1 && (fields[2] == 4 || fields[2] == 5);
    if (pos == line.size()) return true;
    if (line[pos++] != ',' || !read_call_number(line, pos, number)) return false;
    if (pos == line.size()) return true;
    if (line[pos++] != ',') return false;
    skip_call_spaces(line, pos);
    if (pos == line.size() || line[pos++] != '"') return false;
    const size_t end = line.find('"', pos);
    if (end == std::string::npos) return false;
    for (; pos < end; ++pos) {
        const unsigned char ch = static_cast<unsigned char>(line[pos]);
        if (ch < 0x20 || ch == 0x7F) return false;
    }
    pos = end + 1;
    skip_call_spaces(line, pos);
    return pos == line.size();
}

static std::string query_clcc_number()
{
    std::string response;
    if (idf_modem_send_at("AT+CLCC", 1500, response) != ESP_OK) return {};
    bool terminal = false, echo_seen = false, row_seen = false, waiting_for_pdu = false;
    unsigned incoming_count = 0;
    std::string number;
    size_t pos = 0;
    while (pos < response.size()) {
        size_t end = response.find_first_of("\r\n", pos);
        if (end == std::string::npos) end = response.size();
        const std::string line = idf_util_trim_copy(response.substr(pos, end - pos));
        pos = end + 1;
        if (line.empty()) continue;
        if (idf_modem_is_standalone_urc_line(line)) continue;
        if (starts_with(line, "+CMT:")) {
            waiting_for_pdu = true;
            continue;
        }
        if (waiting_for_pdu && line.size() >= 32 && is_hex_string(line)) {
            waiting_for_pdu = false;
            continue;
        }
        if (terminal || waiting_for_pdu) return {};
        if (line == "AT+CLCC") {
            if (echo_seen || row_seen) return {};
            echo_seen = true;
        } else if (line == "OK") {
            terminal = true;
        } else if (starts_with(line, "+CLCC:")) {
            row_seen = true;
            bool incoming = false;
            std::string candidate;
            if (!parse_clcc_line(line, incoming, candidate)) return {};
            if (incoming) {
                if (++incoming_count != 1) return {};
                number = candidate;
            }
        } else {
            return {};
        }
    }
    return terminal ? number : std::string();
}

static void notify_incoming_call(const std::string& number)
{
    if (!idf_config_call_notify_enabled()) return;
    // Apply the SMS blocklist to known caller numbers. Notify for unknown numbers.
    if (!number.empty()) {
        const IdfSmsProcessView cfg = idf_config_get_sms_process_view();
        if (number_blacklisted(cfg.numberBlackList, number)) {
            idf_logf("caller %s is blocked; call ignored", masked_phone(number).c_str());
            return;
        }
    }
    std::string num = number.empty() ? std::string("Unknown number") : number;
    std::string body = "Incoming call: " + num;
    std::string display_ts = idf_util_format_epoch_local(static_cast<uint32_t>(time(nullptr)),
                                                         idf_config_get_tz_offset());
    idf_logf("call notification for %s entering forward queue", masked_phone(num).c_str());
    // Send caller ID and the call message through the SMS push and email channels.
    if (!idf_push_enqueue_forward(num.c_str(), body.c_str(), display_ts.c_str(), 0)) {
        idf_log_line("forward queue full; call notification not queued");
    }
}

static void handle_call_urc_line(const std::string& line)
{
    int64_t now = esp_timer_get_time();
    if (!s_call_active || now - s_call_last_urc_us > CALL_GAP_US) {
        s_call_active = true;
        s_call_notified = false;
        s_call_saw_ring = false;
        s_call_recovery_attempted = false;
        s_call_number.clear();
    }
    s_call_last_urc_us = now;
    if (starts_with(line, "+CLIP:")) {
        std::string num = parse_clip_number(line);
        if (!num.empty()) s_call_number = num;
        if (!s_call_notified && !s_call_number.empty()) {
            s_call_notified = true;
            notify_incoming_call(s_call_number);
        }
    } else if (!s_call_saw_ring) {
        s_call_first_ring_us = now;
        s_call_saw_ring = true;
    }
}

static void flush_pending_call_notify(void)
{
    const int64_t now = esp_timer_get_time();
    if (!s_call_saw_ring || s_call_notified ||
        now - s_call_first_ring_us < CALL_CLCC_DELAY_US) return;
    if (!idf_config_call_notify_enabled() || now - s_call_last_urc_us > CALL_GAP_US) {
        s_call_notified = true;
        notify_incoming_call(std::string());
        return;
    }
    if (s_wait_pdu || idf_modem_esim_operation_active() || s_call_recovery_attempted) return;

    s_call_recovery_attempted = true;
    const int64_t first_ring = s_call_first_ring_us;
    const std::string recovered = query_clcc_number();
    std::string urc;
    if (idf_modem_take_urc(urc)) process_urc_text(urc);
    if (s_call_notified || !s_call_saw_ring || s_call_first_ring_us != first_ring) return;
    s_call_number = recovered;
    s_call_notified = true;
    notify_incoming_call(s_call_number);
}

static void process_urc_line(const std::string& raw)
{
    std::string line = idf_util_trim_copy(raw);
    if (line.empty()) return;

    // Handle call URCs before and separately from the SMS PDU window.
    if (line == "RING" || starts_with(line, "+CLIP:")) {
        handle_call_urc_line(line);
        return;
    }

    if (s_wait_pdu) {
        if (starts_with(line, "+CMT:")) {
            // A second +CMT means the prior direct PDU is lost. Rearm for the new one.
            idf_log_line("received +CMT while waiting for a direct PDU; prior SMS can be lost");
            size_t comma = line.rfind(',');
            idf_logf("direct SMS header received; TPDU length=%d",
                     comma == std::string::npos ? -1 : atoi(line.c_str() + comma + 1));
            s_wait_pdu_until_us = esp_timer_get_time() + 3LL * 1000LL * 1000LL;
            return;
        }
        if (starts_with(line, "+CMTI:")) {
            enqueue_index(parse_cmti_index(line));
            return;
        }
        PduDecodeOutcome outcome = decode_pdu_line(line, true);
        if (outcome.decoded) {
            s_wait_pdu = false;
            if (!outcome.safe_to_delete) s_backfill_pending = true;
            if (outcome.admission_blocked) {
                idf_log_line("no RAM slot for direct SMS; waiting for modem retry without acknowledgment");
                return;
            }
            // ML307R requires +CNMA for direct SMS before it reports later segments.
            // Stored messages read through CMGR or CMGL do not use this branch.
            std::string ack_resp;
            if (idf_modem_send_at("AT+CNMA=0", 1500, ack_resp) == ESP_OK) {
                s_cnma_error_logged = false;
            } else if (!s_cnma_error_logged) {
                s_cnma_error_logged = true;
                idf_log_line("direct SMS acknowledgment failed; SIM polling can recover later segments");
            }
            return;
        }
        if (line != "OK" && line != "ERROR") {
            idf_log_line("non-PDU line received in direct PDU window; window closed");
            s_wait_pdu = false;
            s_backfill_pending = true;  // Poll storage in case this was a truncated PDU.
        }
        return;
    }

    if (starts_with(line, "+CMT:")) {
        size_t comma = line.rfind(',');
        idf_logf("direct SMS header received; TPDU length=%d",
                 comma == std::string::npos ? -1 : atoi(line.c_str() + comma + 1));
        s_wait_pdu = true;
        s_wait_pdu_until_us = esp_timer_get_time() + 3LL * 1000LL * 1000LL;  // Three-second window
    } else if (starts_with(line, "+CMTI:")) {
        enqueue_index(parse_cmti_index(line));
    }
}

// Close the +CMT window if no PDU arrives, so later hexadecimal URCs are not decoded as SMS.
static void expire_wait_pdu_window()
{
    if (s_wait_pdu && esp_timer_get_time() > s_wait_pdu_until_us) {
        s_wait_pdu = false;
        s_backfill_pending = true;  // Poll storage to recover a lost direct SMS.
    }
}

static void process_urc_text(const std::string& text)
{
    s_urc_carry += text;
    size_t pos = 0;
    while (true) {
        size_t nl = s_urc_carry.find('\n', pos);
        if (nl == std::string::npos) break;
        std::string line = s_urc_carry.substr(pos, nl - pos);
        process_urc_line(line);
        pos = nl + 1;
    }
    if (pos > 0) s_urc_carry.erase(0, pos);
    if (s_urc_carry.size() > MAX_PDU_HEX_CHARS + 128) {
        s_urc_carry.clear();
        s_wait_pdu = false;
    }
}

static bool extract_first_stored_pdu(const std::string& resp, const char* header, std::string& pdu_line)
{
    pdu_line.clear();
    size_t h = resp.find(header);
    if (h == std::string::npos) return false;
    size_t pos = resp.find('\n', h);
    if (pos == std::string::npos) return false;
    ++pos;
    while (pos < resp.size()) {
        size_t nl = resp.find('\n', pos);
        if (nl == std::string::npos) nl = resp.size();
        std::string line = idf_util_trim_copy(resp.substr(pos, nl - pos));
        pos = nl + 1;
        if (line.empty() || line == "OK" || line == "ERROR" ||
            starts_with(line, "+") || starts_with(line, "AT")) {
            continue;
        }
        pdu_line = line;
        return true;
    }
    return false;
}

static bool delete_stored_sms(int idx)
{
    char cmd[24];
    snprintf(cmd, sizeof(cmd), "AT+CMGD=%d", idx);
    std::string ignored;
    esp_err_t delete_err = idf_modem_send_at(cmd, 2000, ignored);
    if (delete_err == ESP_OK) return true;
    idf_logf("failed to delete SIM SMS index=%d; later backfill will retry", idx);
    s_backfill_pending = true;
    return false;
}

static void fetch_stored_sms_by_index(int idx)
{
    if (idx < 0) return;
    char cmd[24];
    snprintf(cmd, sizeof(cmd), "AT+CMGR=%d", idx);
    std::string resp;
    esp_err_t err = idf_modem_send_at(cmd, 3000, resp);
    bool has_header = resp.find("+CMGR:") != std::string::npos;
    std::string pdu_line;
    bool has_pdu_line = extract_first_stored_pdu(resp, "+CMGR:", pdu_line);
    PduDecodeOutcome outcome = has_pdu_line ? decode_pdu_line(pdu_line, false) : PduDecodeOutcome();
    bool decoded = outcome.decoded;
    if (has_header) {
        if (decoded && outcome.safe_to_delete) {
            delete_stored_sms(idx);
        } else if (decoded) {
            idf_logf(outcome.admission_blocked
                         ? "SMS index=%d not admitted to forward queue; retaining SIM record"
                         : "multipart SMS index=%d incomplete; retaining SIM segment",
                     idx);
            if (outcome.admission_blocked) s_backfill_pending = true;
        } else if (has_pdu_line) {
            idf_logf("PDU parse failed (index=%d); retaining SIM record for retry", idx);
            s_backfill_pending = true;
        } else {
            idf_logf("SMS index=%d has no PDU line; waiting for CMGL backfill", idx);
            s_backfill_pending = true;
        }
    } else if (err != ESP_OK) {
        // Do not requeue an empty slot or +CMS ERROR forever. Request one CMGL backfill.
        s_backfill_pending = true;
    }
}

static void backfill_stored_sms(bool announce)
{
    std::string resp;
    esp_err_t err = idf_modem_send_at("AT+CMGL=4", 4000, resp);
    if (err != ESP_OK && resp.find("+CMGL:") == std::string::npos) {
        if (announce) idf_logf("failed to read stored SIM SMS: %s", esp_err_to_name(err));
        return;
    }

    // Process at most five records per pass so the main loop can drain URCs and send SMS.
    constexpr int BATCH_MAX = 5;
    // Count passes with missing PDU lines and no progress. Remove a corrupt record
    // before repeated AT+CMGL calls starve the AT channel.
    static uint8_t s_nopdu_stall_rounds = 0;
    static uint8_t s_decode_stall_rounds = 0;
    int nopdu_idx[BATCH_MAX];
    int decode_fail_idx[BATCH_MAX];
    int nopdu_count = 0;
    int decode_fail_count = 0;
    int processed = 0;
    int handled = 0;
    int admissions = 0;
    bool more_left = false;
    bool admission_blocked = false;
    size_t pos = 0;
    while (pos < resp.size()) {
        size_t nl = resp.find('\n', pos);
        if (nl == std::string::npos) nl = resp.size();
        std::string line = idf_util_trim_copy(resp.substr(pos, nl - pos));
        pos = nl + 1;
        if (!starts_with(line, "+CMGL:")) continue;
        int idx = parse_cmgl_index(line);
        std::string pdu_line;
        bool has_pdu_line = false;
        while (pos < resp.size()) {
            nl = resp.find('\n', pos);
            if (nl == std::string::npos) nl = resp.size();
            std::string candidate = idf_util_trim_copy(resp.substr(pos, nl - pos));
            if (starts_with(candidate, "+CMGL:")) break;  // Do not consume the next header as a missing PDU.
            pos = nl + 1;
            if (candidate.empty() || candidate == "OK" || candidate == "ERROR" ||
                starts_with(candidate, "+") || starts_with(candidate, "AT")) {
                continue;
            }
            if (!candidate.empty()) {
                pdu_line = candidate;
                has_pdu_line = true;
                break;
            }
        }

        PduDecodeOutcome outcome = has_pdu_line
                                       ? decode_pdu_line(pdu_line, false, admissions < BATCH_MAX)
                                       : PduDecodeOutcome();
        if (outcome.admitted) ++admissions;
        bool decoded = outcome.decoded;
        if (idx >= 0 && decoded && outcome.safe_to_delete && handled < BATCH_MAX) {
            if (delete_stored_sms(idx)) {
                ++handled;
                ++processed;
            } else {
                more_left = true;
            }
        } else if (idx >= 0 && decoded && outcome.safe_to_delete) {
            more_left = true;
        } else if (idx >= 0 && decoded) {
            if (outcome.admission_blocked) {
                s_backfill_pending = true;
                idf_logf("SMS index=%d not admitted to forward queue; retaining SIM record", idx);
                admission_blocked = true;
                break;
            }
            if (outcome.deferred) more_left = true;
        } else if (idx >= 0 && has_pdu_line) {
            idf_logf("PDU parse failed (index=%d); retaining SIM record for retry", idx);
            if (decode_fail_count < BATCH_MAX) decode_fail_idx[decode_fail_count++] = idx;
        } else if (idx >= 0) {
            idf_logf("CMGL index=%d has no PDU line; record retained", idx);
            if (nopdu_count < BATCH_MAX) nopdu_idx[nopdu_count++] = idx;
        }
    }

    if (nopdu_count > 0) {
        if (handled > 0 || processed > 0) {
            // Progress means an 8 KB response was probably truncated. The next pass can recover.
            s_nopdu_stall_rounds = 0;
            s_backfill_pending = true;
        } else {
            if (s_nopdu_stall_rounds < 3) ++s_nopdu_stall_rounds;
        }
        if (handled == 0 && processed == 0 && s_nopdu_stall_rounds >= 3) {
            // Three passes without progress indicate a corrupt record. Delete it to stop the loop.
            bool all_deleted = true;
            for (int i = 0; i < nopdu_count; ++i) {
                idf_logf("index=%d repeatedly missing PDU line; deleting corrupt record", nopdu_idx[i]);
                if (delete_stored_sms(nopdu_idx[i])) {
                    ++handled;
                } else {
                    all_deleted = false;
                }
            }
            if (all_deleted) s_nopdu_stall_rounds = 0;
            else s_backfill_pending = true;
        }
    } else {
        s_nopdu_stall_rounds = 0;
    }

    if (decode_fail_count > 0) {
        if (handled > 0 || processed > 0) {
            s_decode_stall_rounds = 0;
            s_backfill_pending = true;
        } else {
            if (s_decode_stall_rounds < 3) ++s_decode_stall_rounds;
        }
        if (handled == 0 && processed == 0 && s_decode_stall_rounds >= 3) {
            bool all_deleted = true;
            for (int i = 0; i < decode_fail_count; ++i) {
                idf_logf("index=%d repeatedly failed PDU parsing; deleting corrupt record", decode_fail_idx[i]);
                if (delete_stored_sms(decode_fail_idx[i])) {
                    ++handled;
                } else {
                    all_deleted = false;
                }
            }
            if (all_deleted) s_decode_stall_rounds = 0;
            else s_backfill_pending = true;
        }
    } else {
        s_decode_stall_rounds = 0;
    }

    if (more_left || admission_blocked) s_backfill_pending = true;
    if (processed > 0) idf_logf("processed and deleted %d stored SIM messages", processed);
}

static void sms_task(void*)
{
    uint64_t last_poll_ms = 0;  // 64 bits avoid the 49.7-day startup-window wrap.
    uint64_t start_ms = static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
    uint32_t poll_count = 0;
    uint8_t reassert_step = 0;  // 1=CSMS, 2=CMGF, 3=CPMS, 4=CNMI. Send one AT command per step.
    bool backfill_after_reassert = false;
    bool configured = false;
    bool first_backfill = true;

    while (true) {
        std::string urc;
        if (idf_modem_take_urc(urc)) process_urc_text(urc);
        expire_wait_pdu_window();
        flush_pending_call_notify();
        expire_concat_slots();

        // Drain RAM fallback without registration to free slots for direct SMS.
        if (retry_pending_forward()) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        // During an eSIM channel session, receive URCs but do not insert SMS AT commands.
        if (idf_modem_esim_operation_active()) {
            idf_modem_wait_event(500);
            continue;
        }

        IdfModemStatus modem = idf_modem_get_status();
        if (modem.atReady && !configured) {
            std::string ignored;
            idf_modem_send_at("AT+CSMS=1", 1200, ignored);
            idf_modem_send_at("AT+CMGF=0", 1200, ignored);
            idf_modem_send_at("AT+CNMI=2,2,0,0,0", 1200, ignored);
            configured = true;
            update_status(true, false);
            idf_log_line("SMS reception configured (PDU and storage notifications)");
        }

        if (configured && modem.modemReady) {
            if (reassert_step != 0) {
                std::string ignored;
                if (reassert_step == 1) {
                    idf_modem_send_at("AT+CSMS=1", 1200, ignored);
                    reassert_step = 2;
                } else if (reassert_step == 2) {
                    idf_modem_send_at("AT+CMGF=0", 1200, ignored);
                    reassert_step = 3;
                } else if (reassert_step == 3) {
                    // Reassert CPMS because an unobserved modem reset restores default storage.
                    idf_modem_reassert_sms_storage();
                    reassert_step = 4;
                } else {
                    idf_modem_send_at("AT+CNMI=2,2,0,0,0", 1200, ignored);
                    reassert_step = 0;
                    backfill_after_reassert = true;
                }
                vTaskDelay(pdMS_TO_TICKS(120));
                continue;
            }

            if (backfill_after_reassert) {
                backfill_after_reassert = false;
                backfill_stored_sms(false);
                last_poll_ms = static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
                vTaskDelay(pdMS_TO_TICKS(200));
                continue;
            }

            int idx = -1;
            if (pop_index(idx)) {
                fetch_stored_sms_by_index(idx);
                vTaskDelay(pdMS_TO_TICKS(200));
                continue;
            }

            OutgoingSmsJob out;
            if (pop_outgoing_sms(out)) {
                std::string send_message;
                idf_logf("sending queued Web SMS: %s len=%u",
                         masked_phone(out.phone).c_str(), static_cast<unsigned>(out.text.size()));
                idf_sms_send_text(out.phone, out.text, send_message);
                vTaskDelay(pdMS_TO_TICKS(200));
                continue;
            }

            if (s_backfill_pending) {
                s_backfill_pending = false;
                backfill_stored_sms(false);
                last_poll_ms = static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
                vTaskDelay(pdMS_TO_TICKS(200));
                continue;
            }

            uint64_t now_ms = static_cast<uint64_t>(esp_timer_get_time()) / 1000ULL;
            uint32_t interval = (now_ms - start_ms < SMS_STARTUP_FAST_WINDOW_MS)
                ? SMS_STARTUP_POLL_INTERVAL_MS
                : SMS_POLL_INTERVAL_MS;
            // Poll faster while multipart segments are missing from a truncated +CMTI response.
            if (concat_waiting() && interval > CONCAT_HUNT_POLL_MS) interval = CONCAT_HUNT_POLL_MS;
            if (first_backfill || now_ms - last_poll_ms >= interval) {
                if (!first_backfill && (poll_count % SMS_CNMI_REASSERT_EVERY) == 0) {
                    reassert_step = 1;
                    ++poll_count;
                    last_poll_ms = now_ms;
                    continue;
                }
                backfill_stored_sms(first_backfill);
                first_backfill = false;
                last_poll_ms = now_ms;
                ++poll_count;
            }
        }

        // Wake for a URC or queued Web SMS. Use a 500 ms timeout as fallback.
        idf_modem_wait_event(500);
    }
}

esp_err_t idf_sms_start(void)
{
    if (s_started) return ESP_OK;
    cleanup_start_resources();
    s_status_mutex = xSemaphoreCreateMutex();
    s_pdu_mutex = xSemaphoreCreateMutex();
    s_out_mutex = xSemaphoreCreateMutex();
    if (!s_status_mutex || !s_pdu_mutex || !s_out_mutex) {
        cleanup_start_resources();
        return ESP_ERR_NO_MEM;
    }
    BaseType_t ok = xTaskCreate(sms_task, "idf_sms", 8192, nullptr, 3, nullptr);
    if (ok != pdPASS) {
        cleanup_start_resources();
        return ESP_ERR_NO_MEM;
    }
    s_started = true;
    return ESP_OK;
}

// ===== Multipart SMS send helpers =====
// Treat only printable ASCII and CR/LF as basic GSM7. Use UCS2 for all other text.
// Conservative UCS2 selection avoids an oversized segment at encoding time.
static bool sms_text_basic_gsm7(const std::string& text)
{
    // Backtick is outside GSM 03.38. The PDU codec uses UCS2 for that segment.
    return std::all_of(text.begin(), text.end(), [](unsigned char ch) {
        return ch == '\r' || ch == '\n' || (ch >= 0x20 && ch < 0x7F && ch != '`');
    });
}

// Split by segment capacity without breaking UTF-8. Count GSM7 extension characters
// as two septets and non-BMP UCS2 characters as two UTF-16 code units.
static std::vector<std::string> sms_split_parts(const std::string& text, bool gsm7, size_t per_part)
{
    std::vector<std::string> parts;
    size_t pos = 0;
    while (pos < text.size()) {
        size_t units = 0;
        size_t end = pos;
        while (end < text.size()) {
            unsigned char lead = static_cast<unsigned char>(text[end]);
            size_t clen = (lead >= 0xF0) ? 4 : (lead >= 0xE0) ? 3 : (lead >= 0xC0) ? 2 : 1;
            if (end + clen > text.size()) clen = text.size() - end;
            size_t u;
            if (gsm7) u = (clen == 1 && strchr("[]{}\\^~|", text[end])) ? 2 : 1;
            else u = (clen == 4) ? 2 : 1;
            if (units + u > per_part) break;
            units += u;
            end += clen;
        }
        if (end == pos) break;  // Defensive: one character cannot exceed a segment.
        parts.push_back(text.substr(pos, end - pos));
        pos = end;
    }
    return parts;
}

// Encode one PDU. csms=0 means a single-part message.
static esp_err_t sms_encode_one(const std::string& phone, const std::string& body,
                                uint16_t csms, uint8_t total, uint8_t part,
                                std::string& sms_pdu, int& pdu_len, std::string& message)
{
    if (!s_pdu_mutex || xSemaphoreTake(s_pdu_mutex, pdMS_TO_TICKS(3000)) != pdTRUE) {
        message = "PDU codec busy";
        return ESP_ERR_TIMEOUT;
    }
    s_pdu.setSCAnumber();
    pdu_len = s_pdu.encodePDU(phone.c_str(), body.c_str(), csms, total, part);
    if (pdu_len >= 0) sms_pdu.assign(s_pdu.getSMS(), strlen(s_pdu.getSMS()));
    xSemaphoreGive(s_pdu_mutex);
    if (pdu_len < 0) {
        char buf[64];
        snprintf(buf, sizeof(buf), "PDU encoding failed (%d)", pdu_len);
        message = buf;
        return ESP_FAIL;
    }
    return ESP_OK;
}

static std::string sms_response_error_line(const std::string& response)
{
    static const char* kTokens[] = {"+CMS ERROR", "+CME ERROR", "ERROR"};
    size_t pos = 0;
    while (pos < response.size()) {
        size_t end = response.find('\n', pos);
        if (end == std::string::npos) end = response.size();
        std::string line = idf_util_trim_copy(response.substr(pos, end - pos));
        for (const char* token : kTokens) {
            if (line.find(token) != std::string::npos) return line;
        }
        pos = end + 1;
    }
    return {};
}

static std::string sms_submit_failure_detail(esp_err_t err, const std::string& response)
{
    std::string error_line = sms_response_error_line(response);
    if (!error_line.empty()) return error_line;
    if (err == ESP_ERR_TIMEOUT) {
        if (response.find('>') != std::string::npos) {
            return "SMS submission timed out after PDU upload. Delivery status is unknown";
        }
        return "SMS prompt timed out before PDU upload";
    }
    if (err == ESP_OK) return "Invalid modem response format";
    return esp_err_to_name(err);
}

esp_err_t idf_sms_send_text(const std::string& phone_raw, const std::string& text_raw, std::string& message)
{
    message.clear();
    std::string phone = idf_util_trim_copy(phone_raw);
    std::string text = idf_util_trim_copy(text_raw);
    if (!is_valid_phone_number(phone) || text.empty() || text.size() > 300) {
        message = "Invalid phone number or message";
        return ESP_ERR_INVALID_ARG;
    }
    IdfModemStatus modem = idf_modem_get_status();
    if (!modem.modemReady) {
        message = "Modem is not registered on the network";
        return ESP_ERR_INVALID_STATE;
    }

    // Single-part limits are 160 GSM7 septets or 70 UCS2 units.
    // Multipart limits are 152 septets or 66 units after the seven-byte UDH.
    bool gsm7 = sms_text_basic_gsm7(text);
    std::vector<std::string> parts = sms_split_parts(text, gsm7, gsm7 ? 160 : 70);
    if (parts.empty()) {
        message = "Invalid phone number or message";
        return ESP_ERR_INVALID_ARG;
    }
    if (parts.size() > 1) parts = sms_split_parts(text, gsm7, gsm7 ? 152 : 66);

    uint16_t csms = 0;
    if (parts.size() > 1) {
        // Seed and increment the 16-bit reference. Reserve zero for single-part SMS.
        static std::atomic<uint16_t> s_csms_ref{static_cast<uint16_t>(esp_timer_get_time() & 0x7FFF)};
        csms = s_csms_ref.fetch_add(1, std::memory_order_relaxed);
        if (csms == 0) csms = s_csms_ref.fetch_add(1, std::memory_order_relaxed);
    }

    esp_err_t err = ESP_OK;
    // A hot swap or internal reset can restore CMGF text mode. Text mode accepts
    // `>` but treats hexadecimal PDU data as text. Reassert PDU mode before each send.
    std::string mode_resp;
    err = idf_modem_send_at("AT+CMGF=0", 3000, mode_resp);
    if (err != ESP_OK) {
        message = "Failed to restore SMS PDU mode: " + sms_submit_failure_detail(err, mode_resp);
        idf_sent_add(phone.c_str(), text.c_str(), false);
        idf_logf("SMS mode setup failed before send; requesting hard modem reset: %s", message.c_str());
        idf_modem_request_reset(true);
        return err;
    }

    for (size_t i = 0; i < parts.size(); ++i) {
        std::string sms_pdu;
        int pdu_len = -1;
        // encodePDU requires all part fields to be zero or all to be nonzero.
        err = sms_encode_one(phone, parts[i], csms,
                             csms ? static_cast<uint8_t>(parts.size()) : 0,
                             csms ? static_cast<uint8_t>(i + 1) : 0,
                             sms_pdu, pdu_len, message);
        if (err != ESP_OK) {
            idf_sent_add(phone.c_str(), text.c_str(), false);
            return err;
        }
        char cmd[32];
        snprintf(cmd, sizeof(cmd), "AT+CMGS=%d", pdu_len);
        std::string resp;
        err = idf_modem_send_pdu(cmd, sms_pdu.c_str(), SMS_SUBMIT_TIMEOUT_MS, resp);
        if (err != ESP_OK) {
            std::string detail = sms_submit_failure_detail(err, resp);
            if (parts.size() > 1) {
                char prefix[64];
                snprintf(prefix, sizeof(prefix), "Multipart SMS part %u/%u failed: ",
                         static_cast<unsigned>(i + 1), static_cast<unsigned>(parts.size()));
                message = std::string(prefix) + detail;
            } else {
                message = detail;
            }
            if (err == ESP_ERR_TIMEOUT) {
                // Do not resend after a post-Ctrl+Z timeout because delivery is unknown.
                // Reset the modem to clear the remaining CMGS session.
                idf_log_line("SMS submission timed out; resetting modem without resending this message");
                idf_modem_request_reset(true);
            }
            idf_sent_add(phone.c_str(), text.c_str(), false);
            idf_logf("Web SMS send failed: %s", message.c_str());
            return err;
        }
        // Pause between segments so the modem can process URCs.
        if (i + 1 < parts.size()) vTaskDelay(pdMS_TO_TICKS(300));
    }

    idf_sent_add(phone.c_str(), text.c_str(), true);
    if (parts.size() > 1) {
        char buf[64];
        snprintf(buf, sizeof(buf), "Multipart SMS sent (%u parts)", static_cast<unsigned>(parts.size()));
        message = buf;
    } else {
        message = "SMS sent";
    }
    idf_logf("Web SMS sent: %s len=%u parts=%u", masked_phone(phone).c_str(),
             static_cast<unsigned>(text.size()), static_cast<unsigned>(parts.size()));
    return ESP_OK;
}

esp_err_t idf_sms_enqueue_outgoing(const std::string& phone_raw, const std::string& text_raw, std::string& message)
{
    std::string phone = idf_util_trim_copy(phone_raw);
    std::string text = idf_util_trim_copy(text_raw);
    message.clear();
    if (phone.empty()) {
        message = "Enter a destination number";
        return ESP_ERR_INVALID_ARG;
    }
    if (!is_valid_phone_number(phone)) {
        message = "Enter 3-20 digits with an optional + prefix";
        return ESP_ERR_INVALID_ARG;
    }
    if (text.empty()) {
        message = "Enter an SMS message";
        return ESP_ERR_INVALID_ARG;
    }
    if (text.size() > 300) {
        message = "SMS message exceeds 300 bytes";
        return ESP_ERR_INVALID_SIZE;
    }
    if (!s_out_mutex || xSemaphoreTake(s_out_mutex, pdMS_TO_TICKS(100)) != pdTRUE) {
        message = "Send queue is busy. Try again later";
        return ESP_ERR_TIMEOUT;
    }
    if (s_out_count >= OUT_SMS_QUEUE_MAX) {
        xSemaphoreGive(s_out_mutex);
        message = "Send queue is full. Try again later";
        return ESP_ERR_NO_MEM;
    }

    size_t tail = (s_out_head + s_out_count) % OUT_SMS_QUEUE_MAX;
    s_out_queue[tail].phone = phone;
    s_out_queue[tail].text = text;
    ++s_out_count;
    int depth = outgoing_depth_locked();
    xSemaphoreGive(s_out_mutex);

    idf_modem_signal_event();  // Wake the SMS task without waiting for its poll interval.
    idf_logf("Web SMS queued; pending=%d", depth);
    message = "SMS queued. Check the sent list for the result";
    return ESP_OK;
}

int idf_sms_outgoing_queue_depth(void)
{
    if (!s_out_mutex || xSemaphoreTake(s_out_mutex, pdMS_TO_TICKS(100)) != pdTRUE) return 0;
    int n = outgoing_depth_locked();
    xSemaphoreGive(s_out_mutex);
    return n;
}

IdfSmsStatus idf_sms_get_status(void)
{
    IdfSmsStatus copy;
    if (!s_status_mutex) return copy;
    if (xSemaphoreTake(s_status_mutex, pdMS_TO_TICKS(100)) == pdTRUE) {
        copy = s_status;
        xSemaphoreGive(s_status_mutex);
    }
    return copy;
}
