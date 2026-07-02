#ifndef QUIC_CHACHA_CHACHA20_H
#define QUIC_CHACHA_CHACHA20_H

#include "common/bytes/span/span.h"

/* RFC 8439 ChaCha20. 256-bit key, 96-bit nonce, 32-bit block counter. */

#define QUIC_CHACHA_KEY 32
#define QUIC_CHACHA_NONCE 12
#define QUIC_CHACHA_BLOCK 64

/* Stream position: key, nonce, and the starting block counter. */
typedef struct {
  const u8 *key;   /* QUIC_CHACHA_KEY bytes */
  const u8 *nonce; /* QUIC_CHACHA_NONCE bytes */
  u32       counter;
} quic_chacha_ctx;

/* Produce the 64-byte keystream block for (key, counter, nonce). */
void quic_chacha20_block(
    const u8 key[QUIC_CHACHA_KEY],
    u32      counter,
    const u8 nonce[QUIC_CHACHA_NONCE],
    u8       out[QUIC_CHACHA_BLOCK]);

/* Encrypt/decrypt in (XOR keystream) starting at c->counter. */
void quic_chacha20_xor(const quic_chacha_ctx *c, quic_span in, u8 *out);

#endif
