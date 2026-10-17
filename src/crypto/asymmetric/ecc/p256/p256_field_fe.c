#include "crypto/asymmetric/ecc/p256/p256_field_impl.h"

static void fe_mul_row(u64 w[8], u64 ai, const p256_fe b, usz i);
static void fe_reduce_step(u64 w[8], const p256_fe m, usz sh);
static u64  mshift_bit(const p256_fe m, usz sh, usz bit);
static u64  wide_bit(const u64 w[8], usz bit);
static int  wide_ge_shifted(const u64 w[8], const p256_fe m, usz sh);
static void wide_sub_shifted(u64 w[8], const p256_fe m, usz sh);

/* w[i..i+4] += ai * b: one row of the schoolbook product. */
static void fe_mul_row(u64 w[8], u64 ai, const p256_fe b, usz i) {
  unsigned __int128 c = 0;
  for (usz j = 0; j < 4; j++) {
    c += (unsigned __int128)ai * b[j] + w[i + j];
    w[i + j] = (u64)c;
    c >>= 64;
  }
  w[i + 4] = (u64)c;
}

/* 512-bit product as eight little-endian limbs. */
void p256_fe_mul_wide(u64 w[8], const p256_fe a, const p256_fe b) {
  for (usz i = 0; i < 8; i++) w[i] = 0;
  for (usz i = 0; i < 4; i++) fe_mul_row(w, a[i], b, i);
}

/* One long-division step at bit position sh. */
static void fe_reduce_step(u64 w[8], const p256_fe m, usz sh) {
  if (wide_ge_shifted(w, m, sh)) wide_sub_shifted(w, m, sh);
}

/* r = w mod m via binary long division from the top bit down. Starts at
 * shift 256: with a,b < 2^256 (not necessarily < m) the product can reach
 * m<<256, and m > 2^255 keeps that quotient digit at most 1. */
void p256_fe_reduce_wide(p256_fe r, u64 w[8], const p256_fe m) {
  for (usz sh = 257; sh-- > 0;) fe_reduce_step(w, m, sh);
  for (usz i = 0; i < 4; i++) r[i] = w[i];
}

/* Read bit `bit` of m shifted left by `sh` within the 512-bit space. */
static u64 mshift_bit(const p256_fe m, usz sh, usz bit) {
  if (bit < sh) return 0;
  usz s = bit - sh;
  if (s >= 256) return 0;
  return (m[s / 64] >> (s & 63)) & 1;
}

static u64 wide_bit(const u64 w[8], usz bit) {
  return (w[bit / 64] >> (bit & 63)) & 1;
}

static int wide_ge_shifted(const u64 w[8], const p256_fe m, usz sh) {
  for (usz bit = 512; bit-- > 0;) {
    u64 wb = wide_bit(w, bit), mb = mshift_bit(m, sh, bit);
    if (wb != mb) return wb > mb;
  }
  return 1;
}

static void wide_sub_shifted(u64 w[8], const p256_fe m, usz sh) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 8; i++) {
    u64               mlimb = 0;
    unsigned __int128 t;
    for (usz b = 0; b < 64; b++) mlimb |= mshift_bit(m, sh, i * 64 + b) << b;
    t    = (unsigned __int128)w[i] - mlimb - br;
    w[i] = (u64)t;
    br   = (t >> 64) & 1;
  }
}

void p256_fp_mul(p256_fe r, fpab ab, const p256_fe m) {
  u64 w[8];
  p256_fe_mul_wide(w, ab.a, ab.b);
  p256_fe_reduce_wide(r, w, m);
}

void p256_fp_sqr(p256_fe r, const p256_fe a, const p256_fe m) {
  p256_fp_mul(r, (fpab){a, a}, m);
}

/* FIPS 186-4 D.2.5 fast reduction modulo the P-256 prime p = 2^256 - 2^224 +
 * 2^192 + 2^96 - 1. The 512-bit product is viewed as sixteen 32-bit words
 * c0..c15 (c0 least significant); p's special form lets the reduction be a few
 * 256-bit add/subtracts of words rearranged from the high half, replacing the
 * generic bit-at-a-time long division (which cost ~885ms per scalar mul). The
 * generic p256_fp_mul stays for the group order n; this path is p only.
 * Correctness is pinned by a differential test against the generic reducer. */

/* The c-th 32-bit word of the 512-bit accumulator (c in 0..15). */
u64 p256_w32(const u64 w[8], usz c) {
  return (w[c / 2] >> (32 * (c & 1))) & 0xffffffffULL;
}
