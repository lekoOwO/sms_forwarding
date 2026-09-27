#pragma once

#include <stdint.h>

#include <string>

#include "idf_web_core.h"

enum class IdfWebCryptoResult : uint8_t {
    Ok,
    InvalidPassphrase,
    TooLarge,
    InvalidEnvelope,
    AuthenticationFailed,
    Failed,
};

using IdfWebKeyDeriver = bool (*)(const std::string&, const uint8_t*, uint8_t[32]);

bool idf_web_valid_backup_passphrase(const std::string& passphrase);
IdfWebCryptoResult idf_web_encrypt_backup(const uint8_t* plaintext, size_t plaintext_size,
                                          const std::string& passphrase,
                                          const uint8_t salt[16], const uint8_t iv[12],
                                          IdfWebOwnedBytes& output,
                                          IdfWebByteAllocator allocator = nullptr,
                                          IdfWebKeyDeriver key_deriver = nullptr);
IdfWebCryptoResult idf_web_decrypt_backup(const uint8_t* encrypted, size_t encrypted_size,
                                          const std::string& passphrase,
                                          IdfWebOwnedBytes& output,
                                          IdfWebByteAllocator allocator = nullptr,
                                          IdfWebKeyDeriver key_deriver = nullptr);
std::string idf_web_hex(const uint8_t* value, size_t value_size);
