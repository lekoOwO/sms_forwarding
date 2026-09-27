#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/random.h>
#include <string.h>
#include <time.h>

#include "mbedtls/ecp.h"
#include <stdbool.h>
#include "mbedtls/x509_crt.h"
#include "mbedtls/private/ecdsa.h"
#include "esp_crt_bundle.h"
#include "esp_log.h"
#include "mbedtls/ssl.h"
#include "psa/crypto.h"

#if defined(MBEDTLS_PSA_CRYPTO_EXTERNAL_RNG)
/* Pinned IDF uses this ABI for its hardware RNG. The native fixture supplies
 * OS entropy only to satisfy unrelated PSA key-import plumbing; no key or
 * certificate is generated, and the trust decision remains IDF code below. */
psa_status_t mbedtls_psa_external_get_random(
    mbedtls_psa_external_random_context_t *context,
    uint8_t *output,
    size_t output_size,
    size_t *output_length)
{
    if (context == NULL || output == NULL || output_length == NULL) {
        return PSA_ERROR_INVALID_ARGUMENT;
    }
    *output_length = 0;
    while (*output_length < output_size) {
        ssize_t got = getrandom(output + *output_length,
                                 output_size - *output_length, 0);
        if (got <= 0) return PSA_ERROR_INSUFFICIENT_ENTROPY;
        *output_length += (size_t) got;
    }
    return PSA_SUCCESS;
}
#endif

/*
 * Include the exact pinned IDF implementation after the repository's
 * immutable-source backport preparation. This is not a copy of the
 * verification algorithm: the production target compiles the same source.
 */
#ifndef ESP_CRT_BUNDLE_SOURCE
#define ESP_CRT_BUNDLE_SOURCE "esp_crt_bundle.c"
#endif
#include ESP_CRT_BUNDLE_SOURCE

static time_t fixture_time;

time_t __wrap_time(time_t *out)
{
    if (out != NULL) *out = fixture_time;
    return fixture_time;
}

int main(int argc, char **argv)
{
    if (argc != 5) return 2;
    fixture_time = (time_t) strtoll(argv[4], NULL, 10);
    if (psa_crypto_init() != PSA_SUCCESS) return 3;

    mbedtls_ssl_config ssl_config;
    mbedtls_ssl_config_init(&ssl_config);
    if (esp_crt_bundle_attach(&ssl_config) != ESP_OK) return 4;

    mbedtls_x509_crt server;
    mbedtls_x509_crt anchor;
    mbedtls_x509_crt_init(&server);
    mbedtls_x509_crt_init(&anchor);
    int parsed = mbedtls_x509_crt_parse_file(&anchor, argv[1]);
    if (parsed == 0) parsed = mbedtls_x509_crt_parse_file(&server, argv[2]);
    if (parsed != 0) {
        fprintf(stderr, "fixture parse failed: %d\n", parsed);
        mbedtls_x509_crt_free(&anchor);
        mbedtls_x509_crt_free(&server);
        mbedtls_ssl_config_free(&ssl_config);
        return 5;
    }

#if defined(CROSS_SIGNED_FIXTURE)
    /* The official ESP-IDF fixture contains a leaf plus the cross-signed root
     * served by the peer.  The real IDF callback path is run first.  Then
     * model the CA callback's synthetic parent: it keeps the bundle root's
     * subject and key but has no DER or validity window.  This second verify
     * is still the pinned Mbed TLS chain verifier, not a Python/OpenSSL mock;
     * it isolates the validity decision changed by the official backport. */
    uint32_t real_flags = 0;
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY)
    int real_result = mbedtls_x509_crt_verify_with_ca_cb(
        &server,
        esp_crt_ca_cb_callback,
        NULL,
        &mbedtls_x509_crt_profile_default,
        argv[3],
        &real_flags,
        esp_crt_verify_callback,
        NULL
    );
#else
    int real_result = mbedtls_x509_crt_verify(
        &server,
        ssl_config.MBEDTLS_PRIVATE(ca_chain),
        NULL,
        argv[3],
        &real_flags,
        esp_crt_verify_callback,
        NULL
    );
#endif

    mbedtls_x509_crt synthetic;
    mbedtls_x509_crt_init(&synthetic);
    int synthetic_parsed = mbedtls_x509_crt_parse_file(&synthetic, argv[1]);
    if (synthetic_parsed < 0) {
        fprintf(stderr, "synthetic root fixture parse failed: %d\n",
                synthetic_parsed);
        mbedtls_x509_crt_free(&synthetic);
        mbedtls_x509_crt_free(&anchor);
        mbedtls_x509_crt_free(&server);
        esp_crt_bundle_detach(&ssl_config);
        mbedtls_ssl_config_free(&ssl_config);
        return 6;
    }
    unsigned char *synthetic_raw = synthetic.raw.p;
    size_t synthetic_raw_len = synthetic.raw.len;
    synthetic.raw.p = NULL;
    synthetic.raw.len = 0;
    memset(&synthetic.valid_from, 0, sizeof(synthetic.valid_from));
    memset(&synthetic.valid_to, 0, sizeof(synthetic.valid_to));
    uint32_t synthetic_flags = 0;
    int synthetic_result = mbedtls_x509_crt_verify(
        &server,
        &synthetic,
        NULL,
        argv[3],
        &synthetic_flags,
        esp_crt_verify_callback,
        NULL
    );
    synthetic.raw.p = synthetic_raw;
    synthetic.raw.len = synthetic_raw_len;
    int chain_count = 0;
    for (const mbedtls_x509_crt *crt = &server; crt != NULL; crt = crt->next) {
        ++chain_count;
    }
    printf("%d %u %d %u %d %u\n", real_result, (unsigned) real_flags,
           synthetic_result, (unsigned) synthetic_flags, chain_count,
           (unsigned) esp_crt_get_certcount(s_crt_bundle));
    mbedtls_x509_crt_free(&synthetic);
    mbedtls_x509_crt_free(&anchor);
    mbedtls_x509_crt_free(&server);
    esp_crt_bundle_detach(&ssl_config);
    mbedtls_ssl_config_free(&ssl_config);
    return 0;
#endif

    uint32_t direct_flags = 0;
    int direct_result = mbedtls_x509_crt_verify(
        &server,
        &anchor,
        NULL,
        argv[3],
        &direct_flags,
        NULL,
        NULL
    );
    uint32_t flags = 0;
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY)
    int result = mbedtls_x509_crt_verify_with_ca_cb(
        &server,
        esp_crt_ca_cb_callback,
        NULL,
        &mbedtls_x509_crt_profile_default,
        argv[3],
        &flags,
        esp_crt_verify_callback,
        NULL
    );
#else
    int result = mbedtls_x509_crt_verify(
        &server,
        ssl_config.MBEDTLS_PRIVATE(ca_chain),
        NULL,
        argv[3],
        &flags,
        esp_crt_verify_callback,
        NULL
    );
#endif

    /* The production callback is installed on an ssl_config.  Detach must
     * clear both the verifier and the CA callback/chain before that config is
     * reused; otherwise a later connection can retain a stale bundle hook. */
    esp_crt_bundle_detach(&ssl_config);
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY)
    if (ssl_config.MBEDTLS_PRIVATE(f_ca_cb) != NULL ||
        ssl_config.MBEDTLS_PRIVATE(p_ca_cb) != NULL) {
        fprintf(stderr, "detach left a CA callback installed\n");
        mbedtls_x509_crt_free(&anchor);
        mbedtls_x509_crt_free(&server);
        mbedtls_ssl_config_free(&ssl_config);
        return 6;
    }
#else
    if (ssl_config.MBEDTLS_PRIVATE(ca_chain) != NULL) {
        fprintf(stderr, "detach left a CA chain installed\n");
        mbedtls_x509_crt_free(&anchor);
        mbedtls_x509_crt_free(&server);
        mbedtls_ssl_config_free(&ssl_config);
        return 6;
    }
#endif
    if (esp_crt_bundle_attach(&ssl_config) != ESP_OK) {
        fprintf(stderr, "bundle reattach failed\n");
        mbedtls_x509_crt_free(&anchor);
        mbedtls_x509_crt_free(&server);
        mbedtls_ssl_config_free(&ssl_config);
        return 7;
    }
    uint32_t reused_flags = 0;
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY)
    int reused_result = mbedtls_x509_crt_verify_with_ca_cb(
        &server,
        esp_crt_ca_cb_callback,
        NULL,
        &mbedtls_x509_crt_profile_default,
        argv[3],
        &reused_flags,
        esp_crt_verify_callback,
        NULL
    );
#else
    int reused_result = mbedtls_x509_crt_verify(
        &server,
        ssl_config.MBEDTLS_PRIVATE(ca_chain),
        NULL,
        argv[3],
        &reused_flags,
        esp_crt_verify_callback,
        NULL
    );
#endif
    if (reused_result != result || reused_flags != flags) {
        fprintf(stderr, "bundle result changed after detach/attach: %d/%u -> %d/%u\n",
                result, (unsigned) flags, reused_result, (unsigned) reused_flags);
        mbedtls_x509_crt_free(&anchor);
        mbedtls_x509_crt_free(&server);
        esp_crt_bundle_detach(&ssl_config);
        mbedtls_ssl_config_free(&ssl_config);
        return 8;
    }
    printf("%d %u %d %u %u\n", result, (unsigned) flags,
           direct_result, (unsigned) direct_flags,
           (unsigned) esp_crt_get_certcount(s_crt_bundle));

    mbedtls_x509_crt_free(&anchor);
    mbedtls_x509_crt_free(&server);
    esp_crt_bundle_detach(&ssl_config);
    mbedtls_ssl_config_free(&ssl_config);
    return 0;
}
