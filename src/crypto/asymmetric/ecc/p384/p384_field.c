#include "crypto/asymmetric/ecc/p384/p384_field.h"

/* FIPS 186-4 D.1.2.4. */
const p384_fe quic_p384_p = {0x00000000ffffffffULL, 0xffffffff00000000ULL,
                             0xfffffffffffffffeULL, 0xffffffffffffffffULL,
                             0xffffffffffffffffULL, 0xffffffffffffffffULL};
const p384_fe quic_p384_n = {0xecec196accc52973ULL, 0x581a0db248b0a77aULL,
                             0xc7634d81f4372ddfULL, 0xffffffffffffffffULL,
                             0xffffffffffffffffULL, 0xffffffffffffffffULL};

/* Montgomery contexts (R = 2^384). Constants precomputed in Python and
 * limb-checked. */
const quic_mont384 quic_p384_mont_p = {
    {0x00000000ffffffffULL, 0xffffffff00000000ULL, 0xfffffffffffffffeULL,
     0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
    {0xfffffffe00000001ULL, 0x0000000200000000ULL, 0xfffffffe00000000ULL,
     0x0000000200000000ULL, 0x0000000000000001ULL, 0x0000000000000000ULL},
    {0xffffffff00000001ULL, 0x00000000ffffffffULL, 0x0000000000000001ULL,
     0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
    0x0000000100000001ULL};
const quic_mont384 quic_p384_mont_n = {
    {0xecec196accc52973ULL, 0x581a0db248b0a77aULL, 0xc7634d81f4372ddfULL,
     0xffffffffffffffffULL, 0xffffffffffffffffULL, 0xffffffffffffffffULL},
    {0x2d319b2419b409a9ULL, 0xff3d81e5df1aa419ULL, 0xbc3e483afcb82947ULL,
     0xd40d49174aab1cc5ULL, 0x3fb05b7a28266895ULL, 0x0c84ee012b39bf21ULL},
    {0x1313e695333ad68dULL, 0xa7e5f24db74f5885ULL, 0x389cb27e0bc8d220ULL,
     0x0000000000000000ULL, 0x0000000000000000ULL, 0x0000000000000000ULL},
    0x6ed46089e88fdc45ULL};

void quic_fp384_set(p384_fe r, const p384_fe a) {
  for (usz i = 0; i < 6; i++) r[i] = a[i];
}

int quic_fp384_is_zero(const p384_fe a) {
  u64 d = 0;
  for (usz i = 0; i < 6; i++) d |= a[i];
  return d == 0;
}

int quic_fp384_eq(const p384_fe a, const p384_fe b) {
  u64 d = 0;
  for (usz i = 0; i < 6; i++) d |= a[i] ^ b[i];
  return d == 0;
}

/* 1 if a >= b (limb 5 most significant). */
static int fe6_ge(const p384_fe a, const p384_fe b) {
  for (usz i = 6; i-- > 0;)
    if (a[i] != b[i]) return a[i] > b[i];
  return 1;
}

int quic_fp384_lt(const p384_fe a, const p384_fe b) { return !fe6_ge(a, b); }

/* r = a - b assuming a >= b; ignores final borrow. */
static void fe6_sub_raw(p384_fe r, const p384_fe a, const p384_fe b) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 6; i++) {
    unsigned __int128 t = (unsigned __int128)a[i] - b[i] - br;
    r[i]                = (u64)t;
    br                  = (t >> 64) & 1;
  }
}

/* t = a + b (384-bit); returns carry out of bit 383. */
static u64 fe6_add_raw(p384_fe t, const p384_fe a, const p384_fe b) {
  unsigned __int128 c = 0;
  for (usz i = 0; i < 6; i++) {
    c += (unsigned __int128)a[i] + b[i];
    t[i] = (u64)c;
    c >>= 64;
  }
  return (u64)c;
}

void quic_fp384_add(p384_fe r, quic_fp384ab ab, const p384_fe m) {
  p384_fe t;
  u64     carry = fe6_add_raw(t, ab.a, ab.b);
  int     over  = carry || fe6_ge(t, m);
  if (over)
    fe6_sub_raw(r, t, m);
  else
    quic_fp384_set(r, t);
}

void quic_fp384_sub(p384_fe r, quic_fp384ab ab, const p384_fe m) {
  if (fe6_ge(ab.a, ab.b))
    fe6_sub_raw(r, ab.a, ab.b);
  else {
    p384_fe t;
    fe6_sub_raw(t, ab.b, ab.a);
    fe6_sub_raw(r, m, t);
  }
}

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
static void fe6_mul_wide(u64 w[12], const p384_fe a, const p384_fe b) {
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

static void fe6_reduce_step(u64 w[12], const p384_fe m, usz sh) {
  if (wide6_ge_shifted(w, m, sh)) wide6_sub_shifted(w, m, sh);
}

static void fe6_reduce_wide(p384_fe r, u64 w[12], const p384_fe m) {
  for (usz sh = 384; sh-- > 0;) fe6_reduce_step(w, m, sh);
  for (usz i = 0; i < 6; i++) r[i] = w[i];
}

void quic_fp384_mul(p384_fe r, quic_fp384ab ab, const p384_fe m) {
  u64 w[12];
  fe6_mul_wide(w, ab.a, ab.b);
  fe6_reduce_wide(r, w, m);
}

void quic_fp384_sqr(p384_fe r, const p384_fe a, const p384_fe m) {
  quic_fp384_mul(r, (quic_fp384ab){a, a}, m);
}

void quic_fp384_reduce(p384_fe r, const p384_fe a, const p384_fe m) {
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
  for (usz i = 0; i < 6; i++) t[i] = e[2 * i] | (e[2 * i + 1] << 32);
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
  if (fe6_ge(r, quic_p384_p)) fe6_sub_raw(r, r, quic_p384_p);
}

/* Build term row t (0..9) from the accumulator, reduced below p. */
static void build_term384(p384_fe out, const u64 w[12], usz t) {
  u64 e[12];
  for (usz i = 0; i < 12; i++)
    e[i] = (P384_TERMS[t][i] == 0xff) ? 0 : w32_384(w, P384_TERMS[t][i]);
  from_words6(out, e);
  reduce_once_p384(out);
}

static void fp384_add_p(p384_fe r, const p384_fe t) {
  quic_fp384_add(r, (quic_fp384ab){r, t}, quic_p384_p);
}

static void fp384_sub_p(p384_fe r, const p384_fe t) {
  quic_fp384_sub(r, (quic_fp384ab){r, t}, quic_p384_p);
}

/* r = s1 + 2*s2 + s3 + s4 + s5 + s6 + s7 (the additive terms). */
static void reduce384_add_half(p384_fe r, const u64 w[12]) {
  p384_fe t;
  build_term384(r, w, 0); /* s1 */
  build_term384(t, w, 1);
  fp384_add_p(r, t);
  fp384_add_p(r, t); /* 2*s2 */
  for (usz k = 2; k < 7; k++) {
    build_term384(t, w, k);
    fp384_add_p(r, t); /* s3..s7 */
  }
}

/* r -= s8 + s9 + s10 (the subtractive terms). */
static void reduce384_sub_half(p384_fe r, const u64 w[12]) {
  p384_fe t;
  for (usz k = 7; k < 10; k++) {
    build_term384(t, w, k);
    fp384_sub_p(r, t);
  }
}

static void fp384_reduce_p(p384_fe r, const u64 w[12]) {
  reduce384_add_half(r, w);
  reduce384_sub_half(r, w);
}

void quic_fp384_mul_p(p384_fe r, const p384_fe a, const p384_fe b) {
  u64 w[12];
  fe6_mul_wide(w, a, b);
  fp384_reduce_p(r, w);
}

void quic_fp384_sqr_p(p384_fe r, const p384_fe a) { quic_fp384_mul_p(r, a, a); }

/* Set r to the field element 1. */
static void fp384_set_one(p384_fe r) {
  static const p384_fe one = {1, 0, 0, 0, 0, 0};
  quic_fp384_set(r, one);
}

/* Bit i (0 = LSB) of a 384-bit little-endian value. */
static int fp384_ebit(const p384_fe e, usz i) {
  return (int)((e[i / 64] >> (i & 63)) & 1);
}

/* r = a^(m-2) mod m via square-and-multiply (Fermat), generic reducer. */
void quic_fp384_inv(p384_fe r, const p384_fe a, const p384_fe m) {
  p384_fe base, e, two = {2, 0, 0, 0, 0, 0};
  fe6_sub_raw(e, m, two);
  quic_fp384_set(base, a);
  fp384_set_one(r);
  for (usz bit = 0; bit < 384; bit++) {
    if (fp384_ebit(e, bit)) quic_fp384_mul(r, (quic_fp384ab){r, base}, m);
    quic_fp384_sqr(base, base, m);
  }
}

/* a^(p-2) mod p via the fast Solinas mul/sqr. */
void quic_fp384_inv_p(p384_fe r, const p384_fe a) {
  p384_fe base, e, two = {2, 0, 0, 0, 0, 0};
  fe6_sub_raw(e, quic_p384_p, two);
  quic_fp384_set(base, a);
  fp384_set_one(r);
  for (usz bit = 0; bit < 384; bit++) {
    if (fp384_ebit(e, bit)) quic_fp384_mul_p(r, r, base);
    quic_fp384_sqr_p(base, base);
  }
}

/* --- Montgomery arithmetic over an arbitrary odd modulus (order n) ------- */

static void cios6_mul_row(u64 t[8], u64 ai, const p384_fe b) {
  unsigned __int128 c = 0;
  for (usz j = 0; j < 6; j++) {
    c += (unsigned __int128)ai * b[j] + t[j];
    t[j] = (u64)c;
    c >>= 64;
  }
  c += t[6];
  t[6] = (u64)c;
  t[7] = (u64)(c >> 64);
}

static void cios6_reduce_row(u64 t[8], const quic_mont384* mont) {
  u64               u = t[0] * mont->n0inv;
  unsigned __int128 c = (unsigned __int128)u * mont->m[0] + t[0];
  c >>= 64;
  for (usz j = 1; j < 6; j++) {
    c += (unsigned __int128)u * mont->m[j] + t[j];
    t[j - 1] = (u64)c;
    c >>= 64;
  }
  c += t[6];
  t[5] = (u64)c;
  t[6] = t[7] + (u64)(c >> 64);
  t[7] = 0;
}

static int mont6_needs_sub(const u64 t[8], const p384_fe m) {
  return t[6] != 0 || fe6_ge(t, m);
}

static void mont6_finalize(p384_fe r, const u64 t[8], const p384_fe m) {
  int sub = mont6_needs_sub(t, m);
  for (usz i = 0; i < 6; i++) r[i] = t[i];
  if (sub) fe6_sub_raw(r, r, m);
}

void quic_mont384_mul(p384_fe r, quic_fp384ab ab, const quic_mont384* mont) {
  u64 t[8] = {0, 0, 0, 0, 0, 0, 0, 0};
  for (usz i = 0; i < 6; i++) {
    cios6_mul_row(t, ab.a[i], ab.b);
    cios6_reduce_row(t, mont);
  }
  mont6_finalize(r, t, mont->m);
}

static void mont6_from(p384_fe r, const p384_fe a, const quic_mont384* mont) {
  p384_fe one = {1, 0, 0, 0, 0, 0};
  quic_mont384_mul(r, (quic_fp384ab){a, one}, mont);
}

void quic_mont384_inv(p384_fe r, const p384_fe a, const quic_mont384* mont) {
  p384_fe e, base, acc, two = {2, 0, 0, 0, 0, 0};
  fe6_sub_raw(e, mont->m, two);
  quic_mont384_mul(base, (quic_fp384ab){a, mont->rr}, mont);
  quic_fp384_set(acc, mont->one);
  for (usz bit = 0; bit < 384; bit++) {
    if (fp384_ebit(e, bit))
      quic_mont384_mul(acc, (quic_fp384ab){acc, base}, mont);
    quic_mont384_mul(base, (quic_fp384ab){base, base}, mont);
  }
  mont6_from(r, acc, mont);
}

void quic_fp384_from_be(p384_fe r, const u8 b[48]) {
  for (usz i = 0; i < 6; i++) {
    u64 v = 0;
    for (usz j = 0; j < 8; j++) v = (v << 8) | b[i * 8 + j];
    r[5 - i] = v;
  }
}

void quic_fp384_to_be(u8 b[48], const p384_fe a) {
  for (usz i = 0; i < 6; i++)
    for (usz j = 0; j < 8; j++) b[i * 8 + j] = (u8)(a[5 - i] >> (56 - 8 * j));
}
