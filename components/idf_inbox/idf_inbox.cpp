#include "idf_inbox.h"

#include <stdio.h>
#include <time.h>

#include <algorithm>
#include <array>

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "idf_util.h"

// 收发件箱只供本次运行中的网页速览；正文不会写入 flash，重启即清空。
static constexpr size_t INBOX_MAX = 50;
static constexpr size_t SENT_MAX = 10;
static constexpr size_t BODY_MAX = 320;

struct InboxSlot : IdfInboxEntry {
    bool deleted = false;
};

static SemaphoreHandle_t s_mutex = nullptr;
static std::array<InboxSlot, INBOX_MAX> s_inbox;
static std::array<IdfSentEntry, SENT_MAX> s_sent;
static size_t s_inbox_head = 0;
static size_t s_inbox_filled = 0;
static uint32_t s_inbox_seq = 0;
static size_t s_sent_head = 0;
static size_t s_sent_filled = 0;
static uint32_t s_sent_seq = 0;

static void ensure_init()
{
    if (!s_mutex) s_mutex = xSemaphoreCreateMutex();
}

static std::string truncate_body(const char* text)
{
    std::string out = text ? text : "";
    if (out.size() > BODY_MAX) {
        size_t end = BODY_MAX;
        while (end > 0 && (static_cast<unsigned char>(out[end]) & 0xC0) == 0x80) --end;
        out.resize(end);
        out += "...";
    }
    return out;
}

static void json_prop(std::string& out, const char* key, const std::string& value)
{
    out += "\"";
    out += key;
    out += "\":\"";
    idf_util_json_escape_append(out, value);
    out += "\"";
}

void idf_inbox_init(void)
{
    ensure_init();
}

uint32_t idf_inbox_add(const char* sender, const char* text, const char* ts)
{
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return 0;

    InboxSlot& entry = s_inbox[s_inbox_head];
    entry.id = ++s_inbox_seq;
    entry.recvEpoch = static_cast<uint32_t>(time(nullptr));
    entry.sender = sender ? sender : "";
    entry.ts = ts ? ts : "";
    entry.text = truncate_body(text);
    entry.forwarded = false;
    entry.deleted = false;

    s_inbox_head = (s_inbox_head + 1) % INBOX_MAX;
    if (s_inbox_filled < INBOX_MAX) ++s_inbox_filled;
    uint32_t id = entry.id;
    xSemaphoreGive(s_mutex);
    return id;
}

void idf_inbox_set_forwarded(uint32_t id, bool forwarded)
{
    if (id == 0) return;
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return;
    for (size_t i = 0; i < s_inbox_filled; ++i) {
        if (s_inbox[i].id == id && !s_inbox[i].deleted) {
            s_inbox[i].forwarded = forwarded;
            break;
        }
    }
    xSemaphoreGive(s_mutex);
}

void idf_inbox_mark_forwarded(uint32_t id)
{
    idf_inbox_set_forwarded(id, true);
}

size_t idf_inbox_count(void)
{
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return 0;
    size_t count = 0;
    for (size_t i = 0; i < s_inbox_filled; ++i) {
        if (!s_inbox[i].deleted) ++count;
    }
    xSemaphoreGive(s_mutex);
    return count;
}

bool idf_inbox_get_by_id(uint32_t id, IdfInboxEntry& out)
{
    if (id == 0) return false;
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return false;
    bool found = false;
    for (size_t i = 0; i < s_inbox_filled; ++i) {
        if (s_inbox[i].id == id && !s_inbox[i].deleted) {
            out = static_cast<const IdfInboxEntry&>(s_inbox[i]);
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_mutex);
    return found;
}

bool idf_inbox_delete(uint32_t id)
{
    if (id == 0) return false;
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return false;
    bool found = false;
    for (size_t i = 0; i < s_inbox_filled; ++i) {
        if (s_inbox[i].id == id && !s_inbox[i].deleted) {
            s_inbox[i].deleted = true;
            s_inbox[i].sender.clear();
            s_inbox[i].ts.clear();
            s_inbox[i].text.clear();
            found = true;
            break;
        }
    }
    xSemaphoreGive(s_mutex);
    return found;
}

void idf_sent_add(const char* target, const char* text, bool ok)
{
    ensure_init();
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return;

    IdfSentEntry& entry = s_sent[s_sent_head];
    entry.id = ++s_sent_seq;
    entry.sentEpoch = static_cast<uint32_t>(time(nullptr));
    entry.target = target ? target : "";
    entry.text = truncate_body(text);
    entry.ok = ok;

    s_sent_head = (s_sent_head + 1) % SENT_MAX;
    if (s_sent_filled < SENT_MAX) ++s_sent_filled;
    xSemaphoreGive(s_mutex);
}

std::string idf_inbox_json(bool sent_box, int limit)
{
    ensure_init();
    if (limit < 0) limit = 0;

    std::string out = "[";
    if (!s_mutex || xSemaphoreTake(s_mutex, portMAX_DELAY) != pdTRUE) return out + "]";

    size_t emitted = 0;
    char buf[80];
    if (sent_box) {
        out.reserve(64 + std::min<size_t>(s_sent_filled, limit ? limit : s_sent_filled) * 160);
        for (size_t offset = 0; offset < s_sent_filled; ++offset) {
            if (limit > 0 && emitted >= static_cast<size_t>(limit)) break;
            size_t index = (s_sent_head + SENT_MAX - 1 - offset) % SENT_MAX;
            const IdfSentEntry& entry = s_sent[index];
            if (emitted) out += ",";
            snprintf(buf, sizeof(buf), "{\"id\":%u,\"sent\":%u,",
                     static_cast<unsigned>(entry.id), static_cast<unsigned>(entry.sentEpoch));
            out += buf;
            json_prop(out, "target", entry.target); out += ",";
            json_prop(out, "text", entry.text); out += ",";
            out += "\"ok\":";
            out += entry.ok ? "true" : "false";
            out += "}";
            ++emitted;
        }
    } else {
        out.reserve(64 + std::min<size_t>(s_inbox_filled, limit ? limit : s_inbox_filled) * 200);
        for (size_t offset = 0; offset < s_inbox_filled; ++offset) {
            if (limit > 0 && emitted >= static_cast<size_t>(limit)) break;
            size_t index = (s_inbox_head + INBOX_MAX - 1 - offset) % INBOX_MAX;
            const InboxSlot& entry = s_inbox[index];
            if (entry.deleted) continue;
            if (emitted) out += ",";
            snprintf(buf, sizeof(buf), "{\"id\":%u,\"recv\":%u,",
                     static_cast<unsigned>(entry.id), static_cast<unsigned>(entry.recvEpoch));
            out += buf;
            json_prop(out, "sender", entry.sender); out += ",";
            json_prop(out, "ts", entry.ts); out += ",";
            json_prop(out, "text", entry.text); out += ",";
            out += "\"fwd\":";
            out += entry.forwarded ? "true" : "false";
            out += "}";
            ++emitted;
        }
    }
    xSemaphoreGive(s_mutex);
    out += "]";
    return out;
}
