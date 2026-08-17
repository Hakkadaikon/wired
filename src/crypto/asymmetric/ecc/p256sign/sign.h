#ifndef QUIC_P256SIGN_SIGN_H
#define QUIC_P256SIGN_SIGN_H

#include "common/platform/sys/syscall.h"

/* FIPS 186-4 Section 6.3 ECDSA signature generation on P-256 with the
 * RFC 6979 deterministic nonce. priv and hash are big-endian 32-byte; hash is
 * the SHA-256 digest of the message. Writes big-endian r and s, with s
 * low-S normalized (s <= n/2) for BoringSSL/RFC 6979 compatibility.
 * Per RFC 6979 Section 3.4 / FIPS 186-4 6.3, a candidate k that yields
 * r == 0 or s == 0 is unsuitable and the nonce generation loop draws a new
 * one, so this always succeeds; always returns 1. */
int p256sign_sign(const u8 priv[32], const u8 hash[32], u8 r[32], u8 s[32]);

#endif
