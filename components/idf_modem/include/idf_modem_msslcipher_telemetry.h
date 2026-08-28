#pragma once

#include <stdint.h>

// Bit 7 remains reserved so future telemetry additions can be rejected by old hosts.
static constexpr uint8_t IDF_MODEM_MSSLCIPHER_TELEMETRY_OTHER_LINE_PRESENT = 0x01;
static constexpr uint8_t IDF_MODEM_MSSLCIPHER_TELEMETRY_LINE_OVERFLOW = 0x02;
static constexpr uint8_t IDF_MODEM_MSSLCIPHER_TELEMETRY_CONTAINS_MSSLCIPHER_TOKEN = 0x04;
static constexpr uint8_t IDF_MODEM_MSSLCIPHER_TELEMETRY_CONTAINS_EXACT_OFFICIAL_PREFIX_ANYWHERE = 0x08;
static constexpr uint8_t IDF_MODEM_MSSLCIPHER_TELEMETRY_LEADING_WHITESPACE_BEFORE_PREFIX = 0x10;
static constexpr uint8_t IDF_MODEM_MSSLCIPHER_TELEMETRY_PARENTHESES_PRESENT = 0x20;
static constexpr uint8_t IDF_MODEM_MSSLCIPHER_TELEMETRY_COMMA_PRESENT = 0x40;
static constexpr uint8_t IDF_MODEM_MSSLCIPHER_TELEMETRY_MASK = 0x7F;
