#pragma once

#include <stdint.h>

#include <string>

// Shared small utilities. Most components already depend on idf_logbuf, so keep the common implementation here.

// Append value to out with JSON string escaping for slashes, quotes, whitespace, and other control characters.
void idf_util_json_escape_append(std::string& out, const std::string& value);

// Return a copy without leading or trailing isspace characters. Do not change the source string.
std::string idf_util_trim_copy(const std::string& value);

// Convert epoch seconds to local time in "YYYY-MM-DD HH:MM:SS" format. Return an empty string if time is not synchronized.
std::string idf_util_format_epoch_local(uint32_t epoch, int tz_offset_min);
