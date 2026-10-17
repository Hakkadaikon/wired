#ifndef CRYPTO_ASYMMETRIC_ECC_P256_P256_FIELD_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_P256_P256_FIELD_IMPL_H

#include "crypto/asymmetric/ecc/p256/p256_field_impl_head.h"

/* r = w mod m via binary long division from the top bit down. Starts at
 * shift 256: with a,b < 2^256 (not necessarily < m) the product can reach
 * m<<256, and m > 2^255 keeps that quotient digit at most 1. */
static inline void p256_fe_reduce_wide(p256_fe r, u64 w[8], const p256_fe m) {
  for (usz sh = 257; sh-- > 0;) {
    fe_reduce_step(w, m, sh);
  }
  for (usz i = 0; i < 4; i++) {
    r[i] = w[i];
  }
}
/* The c-th 32-bit word of the 512-bit accumulator (c in 0..15). */
static inline u64 p256_w32(const u64 w[8], usz c) {
  return (w[c / 2] >> (32 * (c & 1))) & 0xffffffffULL;
}

#endif
