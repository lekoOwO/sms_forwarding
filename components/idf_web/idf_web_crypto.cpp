#include "idf_web_crypto.h"

#include <cstring>

#include "idf_web_core.h"
#include "config_schema_generated.h"

#ifdef ESP_PLATFORM
#include "mbedtls/gcm.h"
#include "mbedtls/md.h"
#include "mbedtls/pkcs5.h"
#include "mbedtls/platform_util.h"
#else
#include <openssl/crypto.h>
#include <openssl/evp.h>
#endif

namespace {
void put_u32_le(uint8_t* out, uint32_t value)
{
    for (int i = 0; i < 4; ++i) out[i] = static_cast<uint8_t>(value >> (i * 8));
}

bool valid_header(const uint8_t* input, size_t input_size)
{
    return input && input_size >= BACKUP_HEADER_BYTES + BACKUP_TAG_BYTES &&
           input_size <= MAX_ENCRYPTED_CONFIG_BYTES &&
           memcmp(input, BACKUP_ENVELOPE_MAGIC, 8) == 0 &&
           input[8] == static_cast<uint8_t>(BACKUP_ENVELOPE_VERSION) &&
           input[9] == static_cast<uint8_t>(BACKUP_ENVELOPE_VERSION >> 8) &&
           input[10] == BACKUP_KDF_ID && input[11] == BACKUP_CIPHER_ID &&
           input[12] == static_cast<uint8_t>(BACKUP_KDF_ITERATIONS) &&
           input[13] == static_cast<uint8_t>(BACKUP_KDF_ITERATIONS >> 8) &&
           input[14] == static_cast<uint8_t>(BACKUP_KDF_ITERATIONS >> 16) &&
           input[15] == static_cast<uint8_t>(BACKUP_KDF_ITERATIONS >> 24);
}

bool derive_key(const std::string& passphrase, const uint8_t* salt, uint8_t key[32])
{
#ifdef ESP_PLATFORM
    return mbedtls_pkcs5_pbkdf2_hmac_ext(MBEDTLS_MD_SHA256,
        reinterpret_cast<const unsigned char*>(passphrase.data()), passphrase.size(),
        salt, BACKUP_SALT_BYTES, BACKUP_KDF_ITERATIONS, 32, key) == 0;
#else
    return PKCS5_PBKDF2_HMAC(passphrase.data(), static_cast<int>(passphrase.size()), salt,
                            BACKUP_SALT_BYTES, BACKUP_KDF_ITERATIONS, EVP_sha256(), 32, key) == 1;
#endif
}

void clear_key(uint8_t key[32])
{
#ifdef ESP_PLATFORM
    mbedtls_platform_zeroize(key, 32);
#else
    OPENSSL_cleanse(key, 32);
#endif
}
}

bool idf_web_valid_backup_passphrase(const std::string& passphrase)
{
    if (passphrase.size() < 12 || passphrase.size() > 128) return false;
    return idf_web_valid_utf8_text(passphrase);
}

IdfWebCryptoResult idf_web_encrypt_backup(const uint8_t* plaintext, size_t plaintext_size,
                                          const std::string& passphrase,
                                          const uint8_t salt[16], const uint8_t iv[12],
                                          IdfWebOwnedBytes& output,
                                          IdfWebByteAllocator allocator,
                                          IdfWebKeyDeriver key_deriver)
{
    idf_web_secure_clear(output);
    if (!idf_web_valid_backup_passphrase(passphrase)) return IdfWebCryptoResult::InvalidPassphrase;
    if (!plaintext || plaintext_size == 0 || plaintext_size > MAX_CONFIG_BLOB_SIZE) {
        return IdfWebCryptoResult::TooLarge;
    }
    if (!idf_web_allocate_owned_bytes(output,
            BACKUP_HEADER_BYTES + plaintext_size + BACKUP_TAG_BYTES, allocator)) {
        return IdfWebCryptoResult::Failed;
    }
    output.size = output.capacity;
    uint8_t* out = output.data.get();
    memcpy(out, BACKUP_ENVELOPE_MAGIC, 8);
    out[8] = static_cast<uint8_t>(BACKUP_ENVELOPE_VERSION);
    out[9] = static_cast<uint8_t>(BACKUP_ENVELOPE_VERSION >> 8);
    out[10] = BACKUP_KDF_ID; out[11] = BACKUP_CIPHER_ID;
    put_u32_le(out + 12, BACKUP_KDF_ITERATIONS);
    memcpy(out + 16, salt, BACKUP_SALT_BYTES);
    memcpy(out + 32, iv, BACKUP_IV_BYTES);
    uint8_t key[32] = {};
    if (!(key_deriver ? key_deriver(passphrase, salt, key) : derive_key(passphrase, salt, key))) {
        clear_key(key);
        idf_web_secure_clear(output);
        return IdfWebCryptoResult::Failed;
    }
    int rc = -1;
#ifdef ESP_PLATFORM
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);
    if (mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 256) == 0) {
        rc = mbedtls_gcm_crypt_and_tag(&context, MBEDTLS_GCM_ENCRYPT, plaintext_size, iv, BACKUP_IV_BYTES,
            out, BACKUP_AAD_BYTES, plaintext, out + BACKUP_HEADER_BYTES,
            BACKUP_TAG_BYTES, out + BACKUP_HEADER_BYTES + plaintext_size);
    }
    mbedtls_gcm_free(&context);
#else
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    int length = 0;
    if (context && EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, BACKUP_IV_BYTES, nullptr) == 1 &&
        EVP_EncryptInit_ex(context, nullptr, nullptr, key, iv) == 1 &&
        EVP_EncryptUpdate(context, nullptr, &length, out, BACKUP_AAD_BYTES) == 1 &&
        EVP_EncryptUpdate(context, out + BACKUP_HEADER_BYTES, &length,
                          plaintext, static_cast<int>(plaintext_size)) == 1) {
        rc = EVP_EncryptFinal_ex(context, out + BACKUP_HEADER_BYTES + plaintext_size, &length) == 1 &&
             EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, BACKUP_TAG_BYTES,
                out + BACKUP_HEADER_BYTES + plaintext_size) == 1 ? 0 : -1;
    }
    EVP_CIPHER_CTX_free(context);
#endif
    clear_key(key);
    if (rc != 0) { idf_web_secure_clear(output); return IdfWebCryptoResult::Failed; }
    return IdfWebCryptoResult::Ok;
}

IdfWebCryptoResult idf_web_decrypt_backup(const uint8_t* encrypted, size_t encrypted_size,
                                          const std::string& passphrase,
                                          IdfWebOwnedBytes& output,
                                          IdfWebByteAllocator allocator,
                                          IdfWebKeyDeriver key_deriver)
{
    idf_web_secure_clear(output);
    if (!idf_web_valid_backup_passphrase(passphrase)) return IdfWebCryptoResult::InvalidPassphrase;
    if (!valid_header(encrypted, encrypted_size)) return IdfWebCryptoResult::InvalidEnvelope;
    const size_t length = encrypted_size - BACKUP_HEADER_BYTES - BACKUP_TAG_BYTES;
    if (length == 0 || !idf_web_allocate_owned_bytes(output, length, allocator)) {
        return IdfWebCryptoResult::Failed;
    }
    output.size = length;
    uint8_t key[32] = {};
    if (!(key_deriver ? key_deriver(passphrase, encrypted + 16, key) :
                        derive_key(passphrase, encrypted + 16, key))) {
        clear_key(key);
        idf_web_secure_clear(output);
        return IdfWebCryptoResult::Failed;
    }
    int rc = -1;
#ifdef ESP_PLATFORM
    mbedtls_gcm_context context;
    mbedtls_gcm_init(&context);
    if (mbedtls_gcm_setkey(&context, MBEDTLS_CIPHER_ID_AES, key, 256) == 0) {
        rc = mbedtls_gcm_auth_decrypt(&context, length, encrypted + 32, BACKUP_IV_BYTES,
            encrypted, BACKUP_AAD_BYTES, encrypted + BACKUP_HEADER_BYTES + length,
            BACKUP_TAG_BYTES, encrypted + BACKUP_HEADER_BYTES, output.data.get());
    }
    mbedtls_gcm_free(&context);
#else
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    int out_length = 0;
    if (context && EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, BACKUP_IV_BYTES, nullptr) == 1 &&
        EVP_DecryptInit_ex(context, nullptr, nullptr, key, encrypted + 32) == 1 &&
        EVP_DecryptUpdate(context, nullptr, &out_length, encrypted, BACKUP_AAD_BYTES) == 1 &&
        EVP_DecryptUpdate(context, output.data.get(), &out_length,
                          encrypted + BACKUP_HEADER_BYTES, static_cast<int>(length)) == 1 &&
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, BACKUP_TAG_BYTES,
            const_cast<uint8_t*>(encrypted + BACKUP_HEADER_BYTES + length)) == 1) {
        rc = EVP_DecryptFinal_ex(context, output.data.get() + out_length, &out_length) == 1 ? 0 : -1;
    }
    EVP_CIPHER_CTX_free(context);
#endif
    clear_key(key);
    if (rc != 0) { idf_web_secure_clear(output); return IdfWebCryptoResult::AuthenticationFailed; }
    return IdfWebCryptoResult::Ok;
}

std::string idf_web_hex(const uint8_t* value, size_t value_size)
{
    static const char hex[] = "0123456789abcdef";
    std::string out(value_size * 2, '0');
    for (size_t i = 0; i < value_size; ++i) {
        out[i * 2] = hex[value[i] >> 4];
        out[i * 2 + 1] = hex[value[i] & 15];
    }
    return out;
}
