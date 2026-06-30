#ifndef QUIC_HP_HP_CHACHA_H
#define QUIC_HP_HP_CHACHA_H

#include "common/platform/sys/syscall.h"

/* RFC 9001 5.4.2 ChaCha20-based header protection. The 16-byte sample
 * splits into a little-endian 32-bit counter (sample[0..3]) and a 96-bit
 * nonce (sample[4..15]); the mask is the first 5 bytes of the ChaCha20
 * keystream block for (hp_key, counter, nonce). */
void quic_hp_chacha_mask(const u8 hp_key[32], const u8 sample[16], u8 mask[5]);

#endif
