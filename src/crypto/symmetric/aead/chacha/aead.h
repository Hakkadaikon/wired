#ifndef QUIC_CHACHA_AEAD_H
#define QUIC_CHACHA_AEAD_H

#include "crypto/symmetric/aead/chacha/chacha20.h"
#include "crypto/symmetric/aead/chacha/poly1305.h"

/* RFC 8439 2.8 ChaCha20-Poly1305 AEAD. 256-bit key, 96-bit nonce, 16-byte
 * tag. This is QUIC's other packet-protection AEAD (RFC 9001 5.3). */

#define QUIC_CHAPOLY_TAG 16

/* One AEAD invocation's fixed inputs: key, nonce, and AAD. */
typedef struct {
  const u8 *key;   /* QUIC_CHACHA_KEY bytes */
  const u8 *nonce; /* QUIC_CHACHA_NONCE bytes */
  quic_span aad;
} quic_chapoly_ctx;

/* Seal: encrypt pt and append the 16-byte tag; out receives pt.n + 16 bytes
 * (ciphertext || tag). Returns the sealed length (pt.n + QUIC_CHAPOLY_TAG). */
usz quic_chapoly_seal(const quic_chapoly_ctx *c, quic_span pt, u8 *out);

/* Open: ct spans ciphertext || 16-byte tag. Returns 1 on success, 0 on tag
 * mismatch (leaving pt untouched). */
int quic_chapoly_open(const quic_chapoly_ctx *c, quic_span ct, u8 *pt);

#endif
