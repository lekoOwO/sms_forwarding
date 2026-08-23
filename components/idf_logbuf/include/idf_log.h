#pragma once

#include <stdint.h>

#include <string>

void idf_log_init(void);
void idf_log_line(const char* line);
void idf_logf(const char* fmt, ...);
bool idf_logf_try(const char* fmt, ...);
std::string idf_log_json_since(uint32_t since);
std::string idf_log_text_dump(void);

// Previous-run log: capture only the noinit RAM image during startup. Save it to smsdata NVS after an abnormal reset.
// Read the fallback log in flash only when the user requests the previous log dump.
bool idf_log_has_prev(void);
std::string idf_log_prev_dump(void);
