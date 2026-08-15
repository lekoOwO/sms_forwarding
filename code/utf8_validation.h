#ifndef UTF8_VALIDATION_H
#define UTF8_VALIDATION_H

#include <stdint.h>

inline int validUtf8CharLength(const char* text) {
  const uint8_t* bytes = reinterpret_cast<const uint8_t*>(text);
  const uint8_t first = bytes[0];
  if (first < 0x80) return first == 0 ? 0 : 1;

  if (first >= 0xC2 && first <= 0xDF) {
    return bytes[1] >= 0x80 && bytes[1] <= 0xBF ? 2 : 0;
  }
  if (first >= 0xE0 && first <= 0xEF) {
    if (bytes[1] == 0 || bytes[2] == 0) return 0;
    if (bytes[2] < 0x80 || bytes[2] > 0xBF) return 0;
    if (first == 0xE0) return bytes[1] >= 0xA0 && bytes[1] <= 0xBF ? 3 : 0;
    if (first == 0xED) return bytes[1] >= 0x80 && bytes[1] <= 0x9F ? 3 : 0;
    return bytes[1] >= 0x80 && bytes[1] <= 0xBF ? 3 : 0;
  }
  if (first >= 0xF0 && first <= 0xF4) {
    if (bytes[1] == 0 || bytes[2] == 0 || bytes[3] == 0) return 0;
    if (bytes[2] < 0x80 || bytes[2] > 0xBF || bytes[3] < 0x80 || bytes[3] > 0xBF) return 0;
    if (first == 0xF0) return bytes[1] >= 0x90 && bytes[1] <= 0xBF ? 4 : 0;
    if (first == 0xF4) return bytes[1] >= 0x80 && bytes[1] <= 0x8F ? 4 : 0;
    return bytes[1] >= 0x80 && bytes[1] <= 0xBF ? 4 : 0;
  }
  return 0;
}

inline bool isValidUtf8(const char* text) {
  if (!text) return false;
  while (*text) {
    int length = validUtf8CharLength(text);
    if (length == 0) return false;
    text += length;
  }
  return true;
}

inline bool isValidUtf8Text(const char* text) {
  if (!text) return false;
  while (*text) {
    uint8_t first = static_cast<uint8_t>(*text);
    if (first < 0x20 && first != '\t' && first != '\n' && first != '\r') return false;
    int length = validUtf8CharLength(text);
    if (length == 0) return false;
    text += length;
  }
  return true;
}

inline bool hasValidJsonEncoding(const char* text) {
  if (!isValidUtf8(text)) return false;
  while (*text) {
    if (static_cast<uint8_t>(*text) < 0x20) return false;
    text++;
  }
  return true;
}

#endif
