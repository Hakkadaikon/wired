#ifndef CRYPTO_ASYMMETRIC_ECC_P256_P256_FIELD_IMPL_HEAD_H
#define CRYPTO_ASYMMETRIC_ECC_P256_P256_FIELD_IMPL_HEAD_H

/* Internal to the p256_field*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/asymmetric/ecc/p256/p256_field.h"

/* Forward declarations: the inline definitions below are unordered. */
static inline u64  wide_bit(const u64 w[8], usz bit);
static inline u64  mshift_bit(const p256_fe m, usz sh, usz bit);
static inline void wide_sub_shifted(u64 w[8], const p256_fe m, usz sh);
static inline int  wide_ge_shifted(const u64 w[8], const p256_fe m, usz sh);
static inline void fe_reduce_step(u64 w[8], const p256_fe m, usz sh);
static inline void fe_mul_row(u64 w[8], u64 ai, const p256_fe b, usz i);
static inline int  p256_fe_ge(const p256_fe a, const p256_fe b);
static inline void p256_fe_sub_raw(p256_fe r, const p256_fe a, const p256_fe b);
static inline void p256_fe_mul_wide(u64 w[8], const p256_fe a, const p256_fe b);
static inline void p256_fe_reduce_wide(p256_fe r, u64 w[8], const p256_fe m);
static inline u64  p256_w32(const u64 w[8], usz c);

static inline u64 wide_bit(const u64 w[8], usz bit) {
  return (w[bit / 64] >> (bit & 63)) & 1;
}

/* Read bit `bit` of m shifted left by `sh` within the 512-bit space. */
static inline u64 mshift_bit(const p256_fe m, usz sh, usz bit) {
  if (bit < sh) {
    return 0;
  }
  usz s = bit - sh;
  if (s >= 256) {
    return 0;
  }
  return (m[s / 64] >> (s & 63)) & 1;
}

static inline void wide_sub_shifted(u64 w[8], const p256_fe m, usz sh) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 8; i++) {
    u64               mlimb = 0;
    unsigned __int128 t;
    for (usz b = 0; b < 64; b++) {
      mlimb |= mshift_bit(m, sh, i * 64 + b) << b;
    }
    t    = (unsigned __int128)w[i] - mlimb - br;
    w[i] = (u64)t;
    br   = (t >> 64) & 1;
  }
}

static inline int wide_ge_shifted(const u64 w[8], const p256_fe m, usz sh) {
  for (usz bit = 512; bit-- > 0;) {
    u64 wb = wide_bit(w, bit), mb = mshift_bit(m, sh, bit);
    if (wb != mb) {
      return wb > mb;
    }
  }
  return 1;
}

/* One long-division step at bit position sh. */
static inline void fe_reduce_step(u64 w[8], const p256_fe m, usz sh) {
  if (wide_ge_shifted(w, m, sh)) {
    wide_sub_shifted(w, m, sh);
  }
}

/* w[i..i+4] += ai * b: one row of the schoolbook product. */
static inline void fe_mul_row(u64 w[8], u64 ai, const p256_fe b, usz i) {
  unsigned __int128 c = 0;
  for (usz j = 0; j < 4; j++) {
    c += (unsigned __int128)ai * b[j] + w[i + j];
    w[i + j] = (u64)c;
    c >>= 64;
  }
  w[i + 4] = (u64)c;
}

/* Compare: returns 1 if a >= b (treating limb 3 as most significant). */
static inline int p256_fe_ge(const p256_fe a, const p256_fe b) {
  for (usz i = 4; i-- > 0;) {
    if (a[i] != b[i]) {
      return a[i] > b[i];
    }
  }
  return 1;
}
/* r = a - b assuming a >= b; ignores final borrow. */
static inline void p256_fe_sub_raw(
    p256_fe r, const p256_fe a, const p256_fe b) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 4; i++) {
    unsigned __int128 t = (unsigned __int128)a[i] - b[i] - br;
    r[i]                = (u64)t;
    br                  = (t >> 64) & 1;
  }
}
/* 512-bit product as eight little-endian limbs. */
static inline void p256_fe_mul_wide(
    u64 w[8], const p256_fe a, const p256_fe b) {
  for (usz i = 0; i < 8; i++) {
    w[i] = 0;
  }
  for (usz i = 0; i < 4; i++) {
    fe_mul_row(w, a[i], b, i);
  }
}

#endif
