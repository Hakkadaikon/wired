#ifndef QUIC_CHACHA_CHACHA20_H
#define QUIC_CHACHA_CHACHA20_H

#include "common/platform/sys/syscall.h"

/* RFC 8439 ChaCha20. 256-bit key, 96-bit nonce, 32-bit block counter. */

#define QUIC_CHACHA_KEY 32
#define QUIC_CHACHA_NONCE 12
#define QUIC_CHACHA_BLOCK 64

/* Produce the 64-byte keystream block for (key, counter, nonce). */
void quic_chacha20_block(
    const u8 key[QUIC_CHACHA_KEY],
    u32      counter,
    const u8 nonce[QUIC_CHACHA_NONCE],
    u8       out[QUIC_CHACHA_BLOCK]);

/* Encrypt/decrypt len bytes (XOR keystream) starting at the given counter. */
void quic_chacha20_xor(
    const u8  key[QUIC_CHACHA_KEY],
    u32       counter,
    const u8  nonce[QUIC_CHACHA_NONCE],
    const u8 *in,
    usz       len,
    u8       *out);

#endif
