#include "crypto/asymmetric/ecc/p384/p384_field_impl.h"

static void fe6_mul_row(u64 w[12], u64 ai, const p384_fe b, usz i);
static u64  mshift6_bit(const p384_fe m, usz sh, usz bit);
static u64  wide6_bit(const u64 w[12], usz bit);
static int  wide6_ge_shifted(const u64 w[12], const p384_fe m, usz sh);
static void wide6_sub_shifted(u64 w[12], const p384_fe m, usz sh);

/* w[i..i+6] += ai * b: one row of the schoolbook product. */
static void fe6_mul_row(u64 w[12], u64 ai, const p384_fe b, usz i) {
  unsigned __int128 c = 0;
  for (usz j = 0; j < 6; j++) {
    c += (unsigned __int128)ai * b[j] + w[i + j];
    w[i + j] = (u64)c;
    c >>= 64;
  }
  w[i + 6] = (u64)c;
}

/* 768-bit product as twelve little-endian limbs. */
void fp384_fe6_mul_wide(u64 w[12], const p384_fe a, const p384_fe b) {
  for (usz i = 0; i < 12; i++) w[i] = 0;
  for (usz i = 0; i < 6; i++) fe6_mul_row(w, a[i], b, i);
}

/* --- generic long-division reducer (oracle path; also serves order n) --- */

static u64 mshift6_bit(const p384_fe m, usz sh, usz bit) {
  if (bit < sh) return 0;
  usz s = bit - sh;
  if (s >= 384) return 0;
  return (m[s / 64] >> (s & 63)) & 1;
}

static u64 wide6_bit(const u64 w[12], usz bit) {
  return (w[bit / 64] >> (bit & 63)) & 1;
}

static int wide6_ge_shifted(const u64 w[12], const p384_fe m, usz sh) {
  for (usz bit = 768; bit-- > 0;) {
    u64 wb = wide6_bit(w, bit), mb = mshift6_bit(m, sh, bit);
    if (wb != mb) return wb > mb;
  }
  return 1;
}

static void wide6_sub_shifted(u64 w[12], const p384_fe m, usz sh) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 12; i++) {
    u64               mlimb = 0;
    unsigned __int128 t;
    for (usz b = 0; b < 64; b++) mlimb |= mshift6_bit(m, sh, i * 64 + b) << b;
    t    = (unsigned __int128)w[i] - mlimb - br;
    w[i] = (u64)t;
    br   = (t >> 64) & 1;
  }
}

void fp384_fe6_reduce_step(u64 w[12], const p384_fe m, usz sh) {
  if (wide6_ge_shifted(w, m, sh)) wide6_sub_shifted(w, m, sh);
}
