#include "crypto/asymmetric/ecc/p256/p256_field.h"

/* FIPS 186-4 D.1.2.3 / D.2.3. */
const p256_fe quic_p256_p = {
    0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL,
    0xffffffff00000001ULL};
const p256_fe quic_p256_n = {
    0xf3b9cac2fc632551ULL, 0xbce6faada7179e84ULL, 0xffffffffffffffffULL,
    0xffffffff00000000ULL};

/* Montgomery contexts (R = 2^256). Constants precomputed and cross-checked:
 * n0inv = -m[0]^-1 mod 2^64, rr = R^2 mod m, one = R mod m. */
const quic_mont quic_p256_mont_p = {
    {0xffffffffffffffffULL, 0x00000000ffffffffULL, 0x0000000000000000ULL,
     0xffffffff00000001ULL},
    {0x0000000000000003ULL, 0xfffffffbffffffffULL, 0xfffffffffffffffeULL,
     0x00000004fffffffdULL},
    {0x0000000000000001ULL, 0xffffffff00000000ULL, 0xffffffffffffffffULL,
     0x00000000fffffffeULL},
    0x0000000000000001ULL};
const quic_mont quic_p256_mont_n = {
    {0xf3b9cac2fc632551ULL, 0xbce6faada7179e84ULL, 0xffffffffffffffffULL,
     0xffffffff00000000ULL},
    {0x83244c95be79eea2ULL, 0x4699799c49bd6fa6ULL, 0x2845b2392b6bec59ULL,
     0x66e12d94f3d95620ULL},
    {0x0c46353d039cdaafULL, 0x4319055258e8617bULL, 0x0000000000000000ULL,
     0x00000000ffffffffULL},
    0xccd1c8aaee00bc4fULL};

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

void quic_fp_add(p256_fe r, quic_fpab ab, const p256_fe m) {
  p256_fe t;
  u64     carry = fe_add_raw(t, ab.a, ab.b);
  /* Single subtract of m suffices since a,b < m (sum < 2m). */
  int over = carry || fe_ge(t, m);
  if (over)
    fe_sub_raw(r, t, m);
  else
    quic_fp_set(r, t);
}

void quic_fp_sub(p256_fe r, quic_fpab ab, const p256_fe m) {
  if (fe_ge(ab.a, ab.b))
    fe_sub_raw(r, ab.a, ab.b);
  else {
    p256_fe t;
    fe_sub_raw(t, ab.b, ab.a);
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

void quic_fp_mul(p256_fe r, quic_fpab ab, const p256_fe m) {
  u64 w[8];
  fe_mul_wide(w, ab.a, ab.b);
  fe_reduce_wide(r, w, m);
}

void quic_fp_sqr(p256_fe r, const p256_fe a, const p256_fe m) {
  quic_fp_mul(r, (quic_fpab){a, a}, m);
}

/* FIPS 186-4 D.2.5 fast reduction modulo the P-256 prime p = 2^256 - 2^224 +
 * 2^192 + 2^96 - 1. The 512-bit product is viewed as sixteen 32-bit words
 * c0..c15 (c0 least significant); p's special form lets the reduction be a few
 * 256-bit add/subtracts of words rearranged from the high half, replacing the
 * generic bit-at-a-time long division (which cost ~885ms per scalar mul). The
 * generic quic_fp_mul stays for the group order n; this path is p only.
 * Correctness is pinned by a differential test against the generic reducer. */

/* The c-th 32-bit word of the 512-bit accumulator (c in 0..15). */
static u64 w32(const u64 w[8], usz c) {
  return (w[c / 2] >> (32 * (c & 1))) & 0xffffffffULL;
}

/* Assemble a 256-bit value from eight 32-bit words, e[0] least significant. */
static void from_words(p256_fe t, const u64 e[8]) {
  for (usz i = 0; i < 4; i++) t[i] = e[2 * i] | (e[2 * i + 1] << 32);
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
  quic_fp_add(r, (quic_fpab){r, t}, quic_p256_p);
}

/* r -= t (mod p), one reduced sub. */
static void fp_sub_p(p256_fe r, const p256_fe t) {
  quic_fp_sub(r, (quic_fpab){r, t}, quic_p256_p);
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

/* r = a^(m-2) mod m via square-and-multiply (Fermat); m must be prime. */
void quic_fp_inv(p256_fe r, const p256_fe a, const p256_fe m) {
  p256_fe base, e, two = {2, 0, 0, 0};
  /* e = m - 2 in plain integers (m >= 3, no wrap). */
  fe_sub_raw(e, m, two);
  quic_fp_set(base, a);
  r[0] = 1;
  r[1] = r[2] = r[3] = 0;
  for (usz bit = 0; bit < 256; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1)
      quic_fp_mul(r, (quic_fpab){r, base}, m);
    quic_fp_sqr(base, base, m);
  }
}

/* --- Montgomery arithmetic over an arbitrary odd modulus -----------------
 * The generic reducer above is a bit-at-a-time long division; for the group
 * order n (no Solinas special form) a Fermat inverse over it costs ~91ms and
 * dominates ECDSA signing. CIOS Montgomery multiplication replaces the division
 * with shifts/adds: one mont_mul is ~the cost of a schoolbook multiply, so an
 * inverse over n drops to a few ms. Constants (mont->n0inv = -m[0]^-1 mod 2^64,
 * mont->rr = R^2 mod m, R = 2^256) are precomputed per modulus. */

/* One CIOS round: t += a[i]*b, then fold in m to clear the low limb. t has 5
 * active limbs (t[0..4]); the function shifts the result down by one limb. */
static void cios_mul_row(u64 t[6], u64 ai, const p256_fe b) {
  unsigned __int128 c = 0;
  for (usz j = 0; j < 4; j++) {
    c += (unsigned __int128)ai * b[j] + t[j];
    t[j] = (u64)c;
    c >>= 64;
  }
  c += t[4];
  t[4] = (u64)c;
  t[5] = (u64)(c >> 64);
}

static void cios_reduce_row(u64 t[6], const quic_mont *mont) {
  u64               u = t[0] * mont->n0inv;
  unsigned __int128 c = (unsigned __int128)u * mont->m[0] + t[0];
  c >>= 64;
  for (usz j = 1; j < 4; j++) {
    c += (unsigned __int128)u * mont->m[j] + t[j];
    t[j - 1] = (u64)c;
    c >>= 64;
  }
  c += t[4];
  t[3] = (u64)c;
  t[4] = t[5] + (u64)(c >> 64);
  t[5] = 0;
}

/* 1 if the CIOS result t (low 4 limbs + overflow t[4]) is >= m. */
static int mont_needs_sub(const u64 t[6], const p256_fe m) {
  return t[4] != 0 || fe_ge(t, m);
}

/* Move the 4 low limbs of t into r, conditionally subtracting m once so r < m.
 */
static void mont_finalize(p256_fe r, const u64 t[6], const p256_fe m) {
  int sub = mont_needs_sub(t, m);
  for (usz i = 0; i < 4; i++) r[i] = t[i];
  if (sub) fe_sub_raw(r, r, m);
}

/* r = a * b * R^-1 mod m (Montgomery product). a,b < m. */
void quic_mont_mul(p256_fe r, quic_fpab ab, const quic_mont *mont) {
  u64 t[6] = {0, 0, 0, 0, 0, 0};
  for (usz i = 0; i < 4; i++) {
    cios_mul_row(t, ab.a[i], ab.b);
    cios_reduce_row(t, mont);
  }
  mont_finalize(r, t, mont->m);
}

/* from Montgomery form: r = a * R^-1 mod m = mont_mul(a, 1). */
static void mont_from(p256_fe r, const p256_fe a, const quic_mont *mont) {
  p256_fe one = {1, 0, 0, 0};
  quic_mont_mul(r, (quic_fpab){a, one}, mont);
}

/* a^(m-2) mod m via Montgomery mul (Fermat inverse). */
void quic_mont_inv(p256_fe r, const p256_fe a, const quic_mont *mont) {
  p256_fe e, base, acc, two = {2, 0, 0, 0};
  fe_sub_raw(e, mont->m, two); /* exponent m-2 */
  /* base = a*R mod m (to Montgomery form). */
  quic_mont_mul(base, (quic_fpab){a, mont->rr}, mont);
  quic_fp_set(acc, mont->one); /* acc = R mod m (Montgomery one) */
  for (usz bit = 0; bit < 256; bit++) {
    if ((e[bit / 64] >> (bit & 63)) & 1)
      quic_mont_mul(acc, (quic_fpab){acc, base}, mont);
    quic_mont_mul(base, (quic_fpab){base, base}, mont);
  }
  mont_from(r, acc, mont); /* back from Montgomery form */
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
