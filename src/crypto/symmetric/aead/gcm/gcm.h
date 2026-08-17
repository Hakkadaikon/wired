#ifndef GCM_GCM_H
#define GCM_GCM_H

#include "common/bytes/span/span.h"
#include "crypto/symmetric/aead/aes/aes.h"

/* AES-128-GCM AEAD (NIST SP 800-38D). 96-bit nonce, 128-bit tag. This is
 * the AEAD QUIC uses for AES-based packet protection (RFC 9001 5.3). */

#define GCM_NONCE 12
#define GCM_TAG 16

/** One AEAD invocation's fixed inputs: key schedule, nonce, and AAD. */
typedef struct {
  const aes128* aes;
  const u8*     nonce; /* GCM_NONCE bytes */
  wired_span    aad;
} gcm_ctx;

/* Seal: encrypt pt and append the 16-byte tag; out receives pt.n + 16 bytes
 * (ciphertext || tag). Returns the sealed length (pt.n + GCM_TAG). */
usz gcm_seal(const gcm_ctx* g, wired_span pt, u8* out);

/* Open: ct spans ciphertext || 16-byte tag. On tag mismatch, returns 0 and
 * does NOT write plaintext. On success, writes ct.n - 16 bytes to pt and
 * returns 1. */
int gcm_open(const gcm_ctx* g, wired_span ct, u8* pt);

#endif
