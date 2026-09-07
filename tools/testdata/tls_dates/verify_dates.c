#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#include "mbedtls/x509_crt.h"
#include "psa/crypto.h"

static time_t fixture_time;

/* 只替換不確定的系統時間；憑證解析、簽章、日期與主機名驗證使用原始函式。 */
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
    mbedtls_x509_crt root, server;
    mbedtls_x509_crt_init(&root);
    mbedtls_x509_crt_init(&server);
    int parsed = mbedtls_x509_crt_parse_file(&root, argv[1]);
    if (parsed == 0) parsed = mbedtls_x509_crt_parse_file(&server, argv[2]);
    if (parsed != 0) {
        fprintf(stderr, "fixture parse failed: %d\n", parsed);
        mbedtls_x509_crt_free(&server);
        mbedtls_x509_crt_free(&root);
        return 4;
    }
    uint32_t flags = 0;
    int result = mbedtls_x509_crt_verify(&server, &root, NULL, argv[3], &flags, NULL, NULL);
    printf("%d %u\n", result, (unsigned) flags);
    mbedtls_x509_crt_free(&server);
    mbedtls_x509_crt_free(&root);
    return 0;
}
