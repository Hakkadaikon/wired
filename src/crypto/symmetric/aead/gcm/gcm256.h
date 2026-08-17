#ifndef QUIC_GCM_GCM256_H
#define QUIC_GCM_GCM256_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/aead/aes/aes.h"
#include "crypto/symmetric/aead/gcm/gcm.h"

/* AES-256-GCM AEAD (NIST SP 800-38D), block cipher = AES-256 (FIPS 197).
 * 96-bit nonce, 128-bit tag, identical mode of operation to gcm_ctx
 * (gcm.h) but keyed with the 256-bit block cipher used by
 * TLS_AES_256_GCM_SHA384 (RFC 8446 Appendix B.4, 0x1302). */

/** One AEAD invocation's fixed inputs: key schedule, nonce, and AAD. */
typedef struct {
  const aes256* aes;
  const u8*     nonce; /* QUIC_GCM_NONCE bytes */
  wired_span    aad;
} gcm256_ctx;

/* Seal: encrypt pt and append the 16-byte tag; out receives pt.n + 16 bytes
 * (ciphertext || tag). Returns the sealed length (pt.n + QUIC_GCM_TAG). */
usz gcm256_seal(const gcm256_ctx* g, wired_span pt, u8* out);

/* Open: ct spans ciphertext || 16-byte tag. On tag mismatch, returns 0 and
 * does NOT write plaintext. On success, writes ct.n - 16 bytes to pt and
 * returns 1. */
int gcm256_open(const gcm256_ctx* g, wired_span ct, u8* pt);

#endif
