#ifndef CRYPTO_ASYMMETRIC_ECC_P256_P256_FIELD_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_P256_P256_FIELD_IMPL_H

#include "crypto/asymmetric/ecc/p256/p256_field_impl_head.h"

/* All-ones when bit is 1, 0 when 0. The barrier keeps the compiler from
 * turning a select on it back into a branch or a selected load. */
static inline u64 p256_mask(u64 bit) {
  return wired_arch_value_barrier((u64)0 - bit);
}

/* r = t where mask is all-ones, d where it is 0 (r may alias d or t). */
static inline void p256_fe_select(
    p256_fe r, const p256_fe d, const p256_fe t, u64 mask) {
  for (usz i = 0; i < 4; i++) {
    r[i] = d[i] ^ (mask & (d[i] ^ t[i]));
  }
}

/* Final conditional subtraction, constant-time: for a value hi * 2^256 + t
 * below 2m (hi in {0, 1}), r = that value mod m. Always subtracts and keeps
 * t only when there is no carry and the subtraction borrowed (t < m). */
static inline void p256_fe_csub(
    p256_fe r, const p256_fe t, u64 hi, const p256_fe m) {
  p256_fe d;
  u64     br = p256_fe_sub_raw(d, t, m);
  p256_fe_select(r, d, t, p256_mask(br & (hi ^ 1)));
}

/* r = w mod m via binary long division from the top bit down. Starts at
 * shift 256: with a,b < 2^256 (not necessarily < m) the product can reach
 * m<<256, and m > 2^255 keeps that quotient digit at most 1. Variable time:
 * public inputs only (test oracle). */
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
