#include "crypto/asymmetric/ecc/p384/p384_field_impl.h"

static void fe6_reduce_wide(p384_fe r, u64 w[12], const p384_fe m);
static u64  w32_384(const u64 w[12], usz c);
static void from_words6(p384_fe t, const u64 e[12]);
static void reduce_once_p384(p384_fe r);

/* Starts at shift 384: with a,b < 2^384 (not necessarily < m) the product
 * can reach m<<384, and m > 2^383 keeps that quotient digit at most 1. */
static void fe6_reduce_wide(p384_fe r, u64 w[12], const p384_fe m) {
  for (usz sh = 385; sh-- > 0;) {
    fp384_fe6_reduce_step(w, m, sh);
  }
  for (usz i = 0; i < 6; i++) {
    r[i] = w[i];
  }
}

void fp384_mul(p384_fe r, fp384ab ab, const p384_fe m) {
  u64 w[12];
  fp384_fe6_mul_wide(w, ab.a, ab.b);
  fe6_reduce_wide(r, w, m);
}

void fp384_sqr(p384_fe r, const p384_fe a, const p384_fe m) {
  fp384_mul(r, (fp384ab){a, a}, m);
}

void fp384_reduce(p384_fe r, const p384_fe a, const p384_fe m) {
  u64 w[12];
  for (usz i = 0; i < 6; i++) {
    w[i]     = a[i];
    w[i + 6] = 0;
  }
  fe6_reduce_wide(r, w, m);
}

/* --- FIPS 186-4 D.2.4 Solinas reduction modulo p (fast path) -------------
 * The 768-bit product is viewed as 24 32-bit words c0..c23. p's special form
 * yields r = s1 + 2*s2 + s3 + s4 + s5 + s6 + s7 - s8 - s9 - s10, each s a
 * permutation of the high words. The word tables and signs were derived and
 * checked against the generic reducer in Python (20006 cases) before use, and
 * the C path is pinned by the differential test in p384_field_test.c. */

/* The c-th 32-bit word of the accumulator (c in 0..23). */
static u64 w32_384(const u64 w[12], usz c) {
  return (w[c / 2] >> (32 * (c & 1))) & 0xffffffffULL;
}

/* Assemble a 384-bit value from twelve 32-bit words, e[0] least significant. */
static void from_words6(p384_fe t, const u64 e[12]) {
  for (usz i = 0; i < 6; i++) {
    t[i] = e[2 * i] | (e[2 * i + 1] << 32);
  }
}

/* The ten Solinas terms as word-index tables into c0..c23; 0xff marks a zero
 * word. Order is least-significant word first. s1..s7 add (s2 doubled by the
 * caller), s8..s10 subtract. */
static const u8 P384_TERMS[10][12] = {
    {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},                             /* s1 */
    {0xff, 0xff, 0xff, 0xff, 21, 22, 23, 0xff, 0xff, 0xff, 0xff, 0xff}, /* s2 */
    {12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23},                   /* s3 */
    {21, 22, 23, 12, 13, 14, 15, 16, 17, 18, 19, 20},                   /* s4 */
    {0xff, 23, 0xff, 20, 12, 13, 14, 15, 16, 17, 18, 19},               /* s5 */
    {0xff, 0xff, 0xff, 0xff, 20, 21, 22, 23, 0xff, 0xff, 0xff, 0xff},   /* s6 */
    {20, 0xff, 0xff, 21, 22, 23, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},   /* s7 */
    {23, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22},                   /* s8 */
    {0xff, 20, 21, 22, 23, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff},   /* s9 */
    {0xff, 0xff, 0xff, 23, 23, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
     0xff}}; /* s10 */

/* Each term is < 2^384 < 2p, so one subtraction of p brings it below p. */
static void reduce_once_p384(p384_fe r) {
  if (fp384_fe6_ge(r, p384_p)) {
    fp384_fe6_sub_raw(r, r, p384_p);
  }
}

/* Build term row t (0..9) from the accumulator, reduced below p. */
void fp384_build_term384(p384_fe out, const u64 w[12], usz t) {
  u64 e[12];
  for (usz i = 0; i < 12; i++) {
    e[i] = (P384_TERMS[t][i] == 0xff) ? 0 : w32_384(w, P384_TERMS[t][i]);
  }
  from_words6(out, e);
  reduce_once_p384(out);
}

void fp384_add_p(p384_fe r, const p384_fe t) {
  fp384_add(r, (fp384ab){r, t}, p384_p);
}

void fp384_sub_p(p384_fe r, const p384_fe t) {
  fp384_sub(r, (fp384ab){r, t}, p384_p);
}
