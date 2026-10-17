#ifndef CRYPTO_SYMMETRIC_AEAD_AES_AES_IMPL_H
#define CRYPTO_SYMMETRIC_AEAD_AES_AES_IMPL_H

/* Internal to the aes*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/symmetric/aead/aes/aes.h"

/* GF(2^8) xtime: multiply by 2 modulo the AES polynomial. */
#define XTIME(x) ((u8)(((x) << 1) ^ (((x) >> 7) * 0x1b)))

u32 aes128_schedule_word256(u32 prev, usz i);

extern const u8 SBOX[256];

/* Forward declarations: the inline definitions below are unordered. */
static inline void aes128_copy16(u8* dst, const u8* src);

static inline void aes128_copy16(u8* dst, const u8* src) {
  for (usz i = 0; i < 16; i++) dst[i] = src[i];
}

#endif
