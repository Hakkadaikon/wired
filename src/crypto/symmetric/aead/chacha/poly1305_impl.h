#ifndef CRYPTO_SYMMETRIC_AEAD_CHACHA_POLY1305_IMPL_H
#define CRYPTO_SYMMETRIC_AEAD_CHACHA_POLY1305_IMPL_H

/* Internal to the poly1305*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/symmetric/aead/chacha/poly1305.h"

/* 26-bit x5 limb representation (poly1305-donna style). h is the accumulator,
 * r the clamped key half, pad the second key half added to the final tag. */
typedef struct {
  u32 r[5];
  u32 h[5];
  u32 pad[4];
} poly;

u32  poly1305_rd32le(const u8* p);
void poly_init(poly* st, const u8 key[32]);
void poly_blocks(poly* st, const u8* msg, usz len);

#endif
