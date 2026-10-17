#include "crypto/asymmetric/ecc/p256/p256_field_impl.h"

static void from_words(p256_fe t, const u64 e[8]);
static void reduce_once_p(p256_fe r);
static void build_term(p256_fe out, const u64 w[8], usz t);
static void fp_add_p(p256_fe r, const p256_fe t);
static void fp_sub_p(p256_fe r, const p256_fe t);
static void reduce_add_half(p256_fe r, const u64 w[8]);
static void reduce_sub_half(p256_fe r, const u64 w[8]);
static void fp_reduce_p256(p256_fe r, const u64 w[8]);

/* Assemble a 256-bit value from eight 32-bit words, e[0] least significant. */
static void from_words(p256_fe t, const u64 e[8]) {
  for (usz i = 0; i < 4; i++) {
    t[i] = e[2 * i] | (e[2 * i + 1] << 32);
  }
}

/* The nine Solinas terms s1..s9 as word-index tables into c0..c15; 0xff marks a
 * zero word. Rows 0..3 are added, rows 4..8 (s5..s9) are handled by the
 * caller's sign vector. Order of the eight entries is least-significant word
 * first. */
static const u8 P256_TERMS[9][8] = {
    {0, 1, 2, 3, 4, 5, 6, 7},                 /* s1 */
    {0xff, 0xff, 0xff, 11, 12, 13, 14, 15},   /* s2 (doubled) */
    {0xff, 0xff, 0xff, 12, 13, 14, 15, 0xff}, /* s3 (doubled) */
    {8, 9, 10, 0xff, 0xff, 0xff, 14, 15},     /* s4 */
    {9, 10, 11, 13, 14, 15, 13, 8},           /* s5 */
    {11, 12, 13, 0xff, 0xff, 0xff, 8, 10},    /* s6 (subtract) */
    {12, 13, 14, 15, 0xff, 0xff, 9, 11},      /* s7 (subtract) */
    {13, 14, 15, 8, 9, 10, 0xff, 12},         /* s8 (subtract) */
    {14, 15, 0xff, 9, 10, 11, 0xff, 13}};     /* s9 (subtract) */

/* A 256-bit term is < 2^256 < 2p, so at most one subtraction of p brings it
 * below p (the precondition of p256_fp_add / p256_fp_sub). */
static void reduce_once_p(p256_fe r) {
  if (p256_fe_ge(r, p256_p)) {
    p256_fe_sub_raw(r, r, p256_p);
  }
}

/* Build term row `t` (0..8) from the 512-bit accumulator into fe out, reduced
 * below p so it satisfies the < p precondition of p256_fp_add / p256_fp_sub. */
static void build_term(p256_fe out, const u64 w[8], usz t) {
  u64 e[8];
  for (usz i = 0; i < 8; i++) {
    e[i] = (P256_TERMS[t][i] == 0xff) ? 0 : p256_w32(w, P256_TERMS[t][i]);
  }
  from_words(out, e);
  reduce_once_p(out);
}

/* r += t (mod p), one reduced add. */
static void fp_add_p(p256_fe r, const p256_fe t) {
  p256_fp_add(r, (fpab){r, t}, p256_p);
}

/* r -= t (mod p), one reduced sub. */
static void fp_sub_p(p256_fe r, const p256_fe t) {
  p256_fp_sub(r, (fpab){r, t}, p256_p);
}

/* r = s1 + 2*s2 + 2*s3 + s4 + s5 (the additive half). */
static void reduce_add_half(p256_fe r, const u64 w[8]) {
  p256_fe t;
  build_term(r, w, 0); /* s1 */
  build_term(t, w, 1);
  fp_add_p(r, t);
  fp_add_p(r, t); /* 2*s2 */
  build_term(t, w, 2);
  fp_add_p(r, t);
  fp_add_p(r, t); /* 2*s3 */
  build_term(t, w, 3);
  fp_add_p(r, t); /* s4 */
  build_term(t, w, 4);
  fp_add_p(r, t); /* s5 */
}

/* r -= s6 + s7 + s8 + s9 (the subtractive half). */
static void reduce_sub_half(p256_fe r, const u64 w[8]) {
  p256_fe t;
  for (usz k = 5; k < 9; k++) {
    build_term(t, w, k);
    fp_sub_p(r, t);
  }
}

/* r = w mod p via the Solinas reduction. The reduced add/sub keep r < p at each
 * step, so no final correction is needed. */
static void fp_reduce_p256(p256_fe r, const u64 w[8]) {
  reduce_add_half(r, w);
  reduce_sub_half(r, w);
}

void p256_fp_mul_p(p256_fe r, const p256_fe a, const p256_fe b) {
  u64 w[8];
  p256_fe_mul_wide(w, a, b);
  fp_reduce_p256(r, w);
}

void p256_fp_sqr_p(p256_fe r, const p256_fe a) { p256_fp_mul_p(r, a, a); }

void p256_fp_reduce(p256_fe r, const p256_fe a, const p256_fe m) {
  u64 w[8];
  for (usz i = 0; i < 4; i++) {
    w[i]     = a[i];
    w[i + 4] = 0;
  }
  p256_fe_reduce_wide(r, w, m);
}

/* r = a^(m-2) mod m via square-and-multiply (Fermat); m must be prime. */
void p256_fp_inv(p256_fe r, const p256_fe a, const p256_fe m) {
  p256_fe base, e, two = {2, 0, 0, 0};
  /* e = m - 2 in plain integers (m >= 3, no wrap). */
  p256_fe_sub_raw(e, m, two);
  p256_fp_set(base, a);
  r[0] = 1;
  r[1] = r[2] = r[3] = 0;
  for (usz bit = 0; bit < 256; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1) {
      p256_fp_mul(r, (fpab){r, base}, m);
    }
    p256_fp_sqr(base, base, m);
  }
}
