#!/usr/bin/env python3
"""Prepare the pinned ESP-IDF certificate-bundle source with one backport.

The project must not modify the shared ESP-IDF installation.  This script
copies the immutable 6.0.2 source to the build tree and applies only the
official cross-signed synthetic-root validity and detach cleanup from
0e03327f698a9e69217fde1a647f5b8d4f34fd94.
"""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path


PINNED_SOURCE_SHA256 = (
    "e44d1e0a42a9d33cfc072ea005e93c8a0337c5ebcbfb9a1cf1554930f4f2816f"
)
OFFICIAL_COMMIT = "0e03327f698a9e69217fde1a647f5b8d4f34fd94"

_ANCHOR = """int esp_crt_verify_callback(void *buf, mbedtls_x509_crt* const crt, const int depth, uint32_t* const flags)
{
    const mbedtls_x509_crt* const child = crt;

    /* It's OK for a trusted cert to have a weak signature hash alg.
       as we already trust this certificate */
"""

_BACKPORT = """int esp_crt_verify_callback(void *buf, mbedtls_x509_crt* const crt, const int depth, uint32_t* const flags)
{
    const mbedtls_x509_crt* const child = crt;

#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY)
    /* When cross-signed verification is enabled, the CA callback provides a
     * synthetic bundle root containing only the subject name and public key.
     * It has no meaningful validity window, so mbedtls may set EXPIRED/FUTURE
     * on this generated cert. Clear those flags only for this synthetic bundle
     * root so that cross-signed verification can continue.
     *
     * Real certificates must keep their time-based verification result and
     * should not proceed to additional bundle signature checks once they are
     * marked expired or not-yet-valid. */
    const uint32_t time_flags = *flags &
        (MBEDTLS_X509_BADCERT_EXPIRED | MBEDTLS_X509_BADCERT_FUTURE);
    if (time_flags && s_crt_bundle != NULL && child->raw.p == NULL &&
        child->valid_from.year == 0 && child->valid_to.year == 0) {
        cert_t cert = esp_crt_find_cert(child->subject_raw.p,
                                        child->subject_raw.len);
        if (cert != NULL) {
            *flags &= ~(MBEDTLS_X509_BADCERT_EXPIRED |
                         MBEDTLS_X509_BADCERT_FUTURE);
        }
    }
#endif /* CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY */

    /* It's OK for a trusted bundle cert to have a weak signature hash alg,
     * as we already trust this certificate. Do not ignore EXPIRED/FUTURE here:
     * real certificates must fail on validity checks, and only the synthetic
     * cross-signed bundle root has those flags cleared above. */
"""

_DETACH_ANCHOR = """void esp_crt_bundle_detach(mbedtls_ssl_config *conf)
{
    s_crt_bundle = NULL;
    if (conf) {
        mbedtls_ssl_conf_verify(conf, NULL, NULL);
    }
}
"""

_DETACH_BACKPORT = """void esp_crt_bundle_detach(mbedtls_ssl_config *conf)
{
    s_crt_bundle = NULL;
    if (conf) {
        mbedtls_ssl_conf_verify(conf, NULL, NULL);
#if defined(CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY)
        mbedtls_ssl_conf_ca_cb(conf, NULL, NULL);
#else
        mbedtls_ssl_conf_ca_chain(conf, NULL, NULL);
#endif /* CONFIG_MBEDTLS_CERTIFICATE_BUNDLE_CROSS_SIGNED_VERIFY */
    }
}
"""


def prepare(input_path: Path, output_path: Path) -> None:
    source = input_path.read_bytes()
    source_hash = hashlib.sha256(source).hexdigest()
    if source_hash != PINNED_SOURCE_SHA256:
        raise SystemExit(
            f"unexpected ESP-IDF certificate-bundle source hash: {source_hash}; "
            f"expected pinned 6.0.2 {PINNED_SOURCE_SHA256}"
        )

    text = source.decode("utf-8")
    if text.count(_ANCHOR) != 1:
        raise SystemExit("pinned certificate-bundle source callback anchor is not unique")
    if text.count(_DETACH_ANCHOR) != 1:
        raise SystemExit("pinned certificate-bundle source detach anchor is not unique")

    patched_text = text.replace(_ANCHOR, _BACKPORT, 1)
    patched_text = patched_text.replace(_DETACH_ANCHOR, _DETACH_BACKPORT, 1)
    patched = patched_text.encode("utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(patched)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    prepare(args.input, args.output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
