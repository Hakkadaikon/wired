#ifndef CHACHA_CHACHA20_H
#define CHACHA_CHACHA20_H

#include "common/bytes/span/span.h"

/* RFC 8439 ChaCha20. 256-bit key, 96-bit nonce, 32-bit block counter. */

#define CHACHA_KEY 32
#define CHACHA_NONCE 12
#define CHACHA_BLOCK 64

/** Stream position: key, nonce, and the starting block counter. */
typedef struct {
  const u8* key;   /* CHACHA_KEY bytes */
  const u8* nonce; /* CHACHA_NONCE bytes */
  u32       counter;
} chacha_ctx;

/* Produce the 64-byte keystream block for (key, counter, nonce). */
void chacha20_block(
    const u8 key[CHACHA_KEY],
    u32      counter,
    const u8 nonce[CHACHA_NONCE],
    u8       out[CHACHA_BLOCK]);

/* Encrypt/decrypt in (XOR keystream) starting at c->counter. */
void chacha20_xor(const chacha_ctx* c, wired_span in, u8* out);

#endif
