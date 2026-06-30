#ifndef QUIC_P256SIGN_SIGN_H
#define QUIC_P256SIGN_SIGN_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 Section 6.3 ECDSA signature generation on P-256 with the
 * RFC 6979 deterministic nonce. priv and hash are big-endian 32-byte; hash is
 * the SHA-256 digest of the message. Writes big-endian r and s, with s
 * low-S normalized (s <= n/2) for BoringSSL/RFC 6979 compatibility.
 * Returns 1 on success, 0 if r == 0 or s == 0 (caller may re-key). */
int quic_p256sign_sign(
    const u8 priv[32], const u8 hash[32], u8 r[32], u8 s[32]);

#endif
