#pragma once

#include <stddef.h>
#include <stdint.h>

#include <string>

struct IdfInboxEntry {
    uint32_t id = 0;
    uint32_t recvEpoch = 0;
    std::string sender;
    std::string ts;
    std::string text;
    bool forwarded = false;
};

struct IdfSentEntry {
    uint32_t id = 0;
    uint32_t sentEpoch = 0;
    std::string target;
    std::string text;
    bool ok = false;
};

// The inbox and outbox are bounded RAM rings. A restart clears them. Phone numbers and message bodies are not persistent.
void idf_inbox_init(void);
uint32_t idf_inbox_add(const char* sender, const char* text, const char* ts);
void idf_inbox_mark_forwarded(uint32_t id);
// If delivery fails permanently, mark the item as not forwarded so the user can see and resend it.
void idf_inbox_set_forwarded(uint32_t id, bool forwarded);
size_t idf_inbox_count(void);
bool idf_inbox_get_by_id(uint32_t id, IdfInboxEntry& out);
bool idf_inbox_delete(uint32_t id);

void idf_sent_add(const char* target, const char* text, bool ok);

std::string idf_inbox_json(bool sent_box, int limit);
