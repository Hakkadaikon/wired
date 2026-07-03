#ifndef WIRED_ECKEY_H
#define WIRED_ECKEY_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/**
 * @file
 * P-256 private-key extraction from the two DER shapes tools emit:
 * SEC1 ECPrivateKey (RFC 5915 3) and PKCS#8 PrivateKeyInfo (RFC 5958 2)
 * wrapping a SEC1 key. Only the leading version INTEGER and the private
 * key OCTET STRING are examined; parameters and the public key are ignored.
 */

/**
 * Extract the 32-byte P-256 private scalar from key_der.
 *
 * The outer SEQUENCE's version INTEGER selects the shape: 1 means SEC1
 * (RFC 5915 3), 0 means PKCS#8 (RFC 5958 2) whose privateKey OCTET STRING
 * holds a SEC1 key.
 *
 * @param key_der DER-encoded private key (SEC1 or unencrypted PKCS#8).
 * @param out     receives the 32-byte private scalar.
 * @return 1 on success; 0 on malformed DER, a scalar not exactly 32
 *         bytes, or an unsupported structure/version.
 */
int wired_eckey_p256_priv(quic_span key_der, u8 out[32]);

#endif
