#include "crypto/asymmetric/ecc/p256/p256_field.h"

/* FIPS 186-4 D.1.2.3 / D.2.3. */
const p256_fe quic_p256_p = {
    0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL,
    0xffffffff00000001ULL};
const p256_fe quic_p256_n = {
    0xf3b9cac2fc632551ULL, 0xbce6faada7179e84ULL, 0xffffffffffffffffULL,
    0xffffffff00000000ULL};

void quic_fp_set(p256_fe r, const p256_fe a) {
  for (usz i = 0; i < 4; i++) r[i] = a[i];
}

int quic_fp_is_zero(const p256_fe a) {
  u64 d = 0;
  for (usz i = 0; i < 4; i++) d |= a[i];
  return d == 0;
}

int quic_fp_eq(const p256_fe a, const p256_fe b) {
  u64 d = 0;
  for (usz i = 0; i < 4; i++) d |= a[i] ^ b[i];
  return d == 0;
}

/* Compare: returns 1 if a >= b (treating limb 3 as most significant). */
static int fe_ge(const p256_fe a, const p256_fe b) {
  for (usz i = 4; i-- > 0;)
    if (a[i] != b[i]) return a[i] > b[i];
  return 1;
}

int quic_fp_lt(const p256_fe a, const p256_fe b) { return !fe_ge(a, b); }

/* r = a - b assuming a >= b; ignores final borrow. */
static void fe_sub_raw(p256_fe r, const p256_fe a, const p256_fe b) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 4; i++) {
    unsigned __int128 t = (unsigned __int128)a[i] - b[i] - br;
    r[i]                = (u64)t;
    br                  = (t >> 64) & 1;
  }
}

/* t = a + b (256-bit); returns the carry out of bit 255. */
static u64 fe_add_raw(p256_fe t, const p256_fe a, const p256_fe b) {
  unsigned __int128 c = 0;
  for (usz i = 0; i < 4; i++) {
    c += (unsigned __int128)a[i] + b[i];
    t[i] = (u64)c;
    c >>= 64;
  }
  return (u64)c;
}

void quic_fp_add(p256_fe r, const p256_fe a, const p256_fe b, const p256_fe m) {
  p256_fe t;
  u64     carry = fe_add_raw(t, a, b);
  /* Single subtract of m suffices since a,b < m (sum < 2m). */
  int over = carry || fe_ge(t, m);
  if (over)
    fe_sub_raw(r, t, m);
  else
    quic_fp_set(r, t);
}

void quic_fp_sub(p256_fe r, const p256_fe a, const p256_fe b, const p256_fe m) {
  if (fe_ge(a, b))
    fe_sub_raw(r, a, b);
  else {
    p256_fe t;
    fe_sub_raw(t, b, a);
    fe_sub_raw(r, m, t);
  }
}

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
static void fe_mul_wide(u64 w[8], const p256_fe a, const p256_fe b) {
  for (usz i = 0; i < 8; i++) w[i] = 0;
  for (usz i = 0; i < 4; i++) fe_mul_row(w, a[i], b, i);
}

/* Subtract m << shift from the 512-bit accumulator w if it fits (w >=
 * m<<shift). shift is a whole bit count 0..256. */
static int  wide_ge_shifted(const u64 w[8], const p256_fe m, usz sh);
static void wide_sub_shifted(u64 w[8], const p256_fe m, usz sh);

/* One long-division step at bit position sh. */
static void fe_reduce_step(u64 w[8], const p256_fe m, usz sh) {
  if (wide_ge_shifted(w, m, sh)) wide_sub_shifted(w, m, sh);
}

/* r = w mod m via binary long division from the top bit down. */
static void fe_reduce_wide(p256_fe r, u64 w[8], const p256_fe m) {
  for (usz sh = 256; sh-- > 0;) fe_reduce_step(w, m, sh);
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

void quic_fp_mul(p256_fe r, const p256_fe a, const p256_fe b, const p256_fe m) {
  u64 w[8];
  fe_mul_wide(w, a, b);
  fe_reduce_wide(r, w, m);
}

void quic_fp_sqr(p256_fe r, const p256_fe a, const p256_fe m) {
  quic_fp_mul(r, a, a, m);
}

/* FIPS 186-4 D.2.5 fast reduction modulo the P-256 prime p = 2^256 - 2^224 +
 * 2^192 + 2^96 - 1. The 512-bit product is viewed as sixteen 32-bit words
 * c0..c15 (c0 least significant); p's special form lets the reduction be a few
 * 256-bit add/subtracts of words rearranged from the high half, replacing the
 * generic bit-at-a-time long division (which cost ~885ms per scalar mul). The
 * generic quic_fp_mul stays for the group order n; this path is p only.
 * Correctness is pinned by a differential test against the generic reducer. */

/* The c-th 32-bit word of the 512-bit accumulator (c in 0..15). */
static u64 w32(const u64 w[8], usz c) { return (w[c / 2] >> (32 * (c & 1))) & 0xffffffffULL; }

/* Assemble a 256-bit value from eight 32-bit words, e[0] least significant. */
static void from_words(p256_fe t, const u64 e[8]) {
  for (usz i = 0; i < 4; i++) t[i] = e[2 * i] | (e[2 * i + 1] << 32);
}

/* The nine Solinas terms s1..s9 as word-index tables into c0..c15; 0xff marks a
 * zero word. Rows 0..3 are added, rows 4..8 (s5..s9) are handled by the caller's
 * sign vector. Order of the eight entries is least-significant word first. */
static const u8 P256_TERMS[9][8] = {
    {0, 1, 2, 3, 4, 5, 6, 7},                         /* s1 */
    {0xff, 0xff, 0xff, 11, 12, 13, 14, 15},           /* s2 (doubled) */
    {0xff, 0xff, 0xff, 12, 13, 14, 15, 0xff},         /* s3 (doubled) */
    {8, 9, 10, 0xff, 0xff, 0xff, 14, 15},             /* s4 */
    {9, 10, 11, 13, 14, 15, 13, 8},                   /* s5 */
    {11, 12, 13, 0xff, 0xff, 0xff, 8, 10},            /* s6 (subtract) */
    {12, 13, 14, 15, 0xff, 0xff, 9, 11},              /* s7 (subtract) */
    {13, 14, 15, 8, 9, 10, 0xff, 12},                 /* s8 (subtract) */
    {14, 15, 0xff, 9, 10, 11, 0xff, 13}};             /* s9 (subtract) */

/* A 256-bit term is < 2^256 < 2p, so at most one subtraction of p brings it
 * below p (the precondition of quic_fp_add / quic_fp_sub). */
static void reduce_once_p(p256_fe r) {
  if (fe_ge(r, quic_p256_p)) fe_sub_raw(r, r, quic_p256_p);
}

/* Build term row `t` (0..8) from the 512-bit accumulator into fe out, reduced
 * below p so it satisfies the < p precondition of quic_fp_add / quic_fp_sub. */
static void build_term(p256_fe out, const u64 w[8], usz t) {
  u64 e[8];
  for (usz i = 0; i < 8; i++)
    e[i] = (P256_TERMS[t][i] == 0xff) ? 0 : w32(w, P256_TERMS[t][i]);
  from_words(out, e);
  reduce_once_p(out);
}

/* r += t (mod p), one reduced add. */
static void fp_add_p(p256_fe r, const p256_fe t) {
  quic_fp_add(r, r, t, quic_p256_p);
}

/* r -= t (mod p), one reduced sub. */
static void fp_sub_p(p256_fe r, const p256_fe t) {
  quic_fp_sub(r, r, t, quic_p256_p);
}

/* r = s1 + 2*s2 + 2*s3 + s4 + s5 (the additive half). */
static void reduce_add_half(p256_fe r, const u64 w[8]) {
  p256_fe t;
  build_term(r, w, 0); /* s1 */
  build_term(t, w, 1); fp_add_p(r, t); fp_add_p(r, t); /* 2*s2 */
  build_term(t, w, 2); fp_add_p(r, t); fp_add_p(r, t); /* 2*s3 */
  build_term(t, w, 3); fp_add_p(r, t);                 /* s4 */
  build_term(t, w, 4); fp_add_p(r, t);                 /* s5 */
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

void quic_fp_mul_p(p256_fe r, const p256_fe a, const p256_fe b) {
  u64 w[8];
  fe_mul_wide(w, a, b);
  fp_reduce_p256(r, w);
}

void quic_fp_sqr_p(p256_fe r, const p256_fe a) { quic_fp_mul_p(r, a, a); }

void quic_fp_reduce(p256_fe r, const p256_fe a, const p256_fe m) {
  u64 w[8];
  for (usz i = 0; i < 4; i++) {
    w[i]     = a[i];
    w[i + 4] = 0;
  }
  fe_reduce_wide(r, w, m);
}

/* r = a^e mod m, e given big-endian as the bytes of (m-2) supplied by caller.
 */
static void fp_pow(
    p256_fe r, const p256_fe a, const p256_fe e, const p256_fe m) {
  p256_fe base;
  quic_fp_set(base, a);
  r[0] = 1;
  r[1] = r[2] = r[3] = 0;
  for (usz bit = 0; bit < 256; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1) quic_fp_mul(r, r, base, m);
    quic_fp_sqr(base, base, m);
  }
}

void quic_fp_inv(p256_fe r, const p256_fe a, const p256_fe m) {
  p256_fe e, two = {2, 0, 0, 0};
  /* e = m - 2 in plain integers (m >= 3, no wrap). */
  fe_sub_raw(e, m, two);
  fp_pow(r, a, e, m);
}

/* a^(p-2) mod p via the fast Solinas mul/sqr: Fermat inverse specialised to p.
 * Called once per scalar multiply (jac_to_affine), where the generic Fermat
 * inverse over the slow reducer otherwise dominates the cost (~24ms). */
void quic_fp_inv_p(p256_fe r, const p256_fe a) {
  p256_fe base, e, two = {2, 0, 0, 0};
  fe_sub_raw(e, quic_p256_p, two); /* p - 2 */
  quic_fp_set(base, a);
  r[0] = 1;
  r[1] = r[2] = r[3] = 0;
  for (usz bit = 0; bit < 256; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1) quic_fp_mul_p(r, r, base);
    quic_fp_sqr_p(base, base);
  }
}

void quic_fp_from_be(p256_fe r, const u8 b[32]) {
  for (usz i = 0; i < 4; i++) {
    u64 v = 0;
    for (usz j = 0; j < 8; j++) v = (v << 8) | b[i * 8 + j];
    r[3 - i] = v;
  }
}

void quic_fp_to_be(u8 b[32], const p256_fe a) {
  for (usz i = 0; i < 4; i++)
    for (usz j = 0; j < 8; j++) b[i * 8 + j] = (u8)(a[3 - i] >> (56 - 8 * j));
}
