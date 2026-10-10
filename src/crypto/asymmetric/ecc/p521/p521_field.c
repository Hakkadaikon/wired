#include "crypto/asymmetric/ecc/p521/p521_field.h"

/* FIPS 186-4 D.1.2.5 (cross-checked against `openssl ecparam -name
 * secp521r1 -param_enc explicit`). */
const p521_fe p521_p = {~0ULL, ~0ULL, ~0ULL, ~0ULL,   ~0ULL,
                        ~0ULL, ~0ULL, ~0ULL, 0x1ffULL};
const p521_fe p521_n = {
    0xbb6fb71e91386409ULL, 0x3bb5c9b8899c47aeULL, 0x7fcc0148f709a5d0ULL,
    0x51868783bf2f966bULL, 0xfffffffffffffffaULL, 0xffffffffffffffffULL,
    0xffffffffffffffffULL, 0xffffffffffffffffULL, 0x00000000000001ffULL};

static const p521_fe fp521_one = {1};

void fp521_set(p521_fe r, const p521_fe a) {
  for (usz i = 0; i < 9; i++) r[i] = a[i];
}

int fp521_is_zero(const p521_fe a) {
  u64 d = 0;
  for (usz i = 0; i < 9; i++) d |= a[i];
  return d == 0;
}

int fp521_eq(const p521_fe a, const p521_fe b) {
  u64 d = 0;
  for (usz i = 0; i < 9; i++) d |= a[i] ^ b[i];
  return d == 0;
}

/* 1 if a >= b (limb 8 most significant). */
static int fe9_ge(const p521_fe a, const p521_fe b) {
  for (usz i = 9; i-- > 0;)
    if (a[i] != b[i]) return a[i] > b[i];
  return 1;
}

int fp521_lt(const p521_fe a, const p521_fe b) { return !fe9_ge(a, b); }

/* r = a - b, final borrow dropped (callers ensure a >= b). */
static void fe9_sub_raw(p521_fe r, const p521_fe a, const p521_fe b) {
  unsigned __int128 br = 0;
  for (usz i = 0; i < 9; i++) {
    unsigned __int128 t = (unsigned __int128)a[i] - b[i] - br;
    r[i]                = (u64)t;
    br                  = (t >> 64) & 1;
  }
}

/* r = a + b; operands stay below 2^523, so 576 bits never carry out. */
static void fe9_add_raw(p521_fe r, const p521_fe a, const p521_fe b) {
  unsigned __int128 c = 0;
  for (usz i = 0; i < 9; i++) {
    c += (unsigned __int128)a[i] + b[i];
    r[i] = (u64)c;
    c >>= 64;
  }
}

static void fe9_cond_sub(p521_fe r, const p521_fe m) {
  if (fe9_ge(r, m)) fe9_sub_raw(r, r, m);
}

void fp521_add(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m) {
  fe9_add_raw(r, a, b);
  fe9_cond_sub(r, m);
}

/* a + m - b lies in [1, 2m), so one conditional subtraction reduces it. */
void fp521_sub(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m) {
  p521_fe t;
  fe9_add_raw(t, a, m);
  fe9_sub_raw(t, t, b);
  fe9_cond_sub(t, m);
  fp521_set(r, t);
}

/* w[i..i+9] += ai * b: one row of the schoolbook product. */
static void fe9_mul_row(u64 w[18], u64 ai, const p521_fe b, usz i) {
  unsigned __int128 c = 0;
  for (usz j = 0; j < 9; j++) {
    c += (unsigned __int128)ai * b[j] + w[i + j];
    w[i + j] = (u64)c;
    c >>= 64;
  }
  w[i + 9] = (u64)c;
}

/* r < 2^522 -> r < p: 2^521 == 1 (mod p), so bit 521 folds onto bit 0. */
static void fe9_fold_top(p521_fe r) {
  p521_fe c = {r[8] >> 9};
  r[8] &= 0x1ff;
  fe9_add_raw(r, r, c);
  fe9_cond_sub(r, p521_p);
}

/* p = 2^521 - 1: w = hi*2^521 + lo == hi + lo (mod p). */
void fp521_mul_p(p521_fe r, const p521_fe a, const p521_fe b) {
  u64     w[18] = {0};
  p521_fe hi;
  for (usz i = 0; i < 9; i++) fe9_mul_row(w, a[i], b, i);
  for (usz i = 0; i < 9; i++) {
    r[i]  = w[i];
    hi[i] = (w[8 + i] >> 9) | (w[9 + i] << 55);
  }
  r[8] &= 0x1ff;
  fe9_add_raw(r, r, hi);
  fe9_fold_top(r);
}

static int fe9_bit(const p521_fe a, usz i) {
  return (int)((a[i / 64] >> (i & 63)) & 1);
}

void fp521_mul(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m) {
  p521_fe acc = {0};
  for (usz i = 521; i-- > 0;) {
    fp521_add(acc, acc, acc, m);
    if (fe9_bit(a, i)) fp521_add(acc, acc, b, m);
  }
  fp521_set(r, acc);
}

static void fe9_shr1(p521_fe a) {
  for (usz i = 0; i < 8; i++) a[i] = (a[i] >> 1) | (a[i + 1] << 63);
  a[8] >>= 1;
}

/* x = x / 2 mod m (m odd). */
static void fe9_half(p521_fe x, const p521_fe m) {
  if (x[0] & 1) fe9_add_raw(x, x, m);
  fe9_shr1(x);
}

/* Binary inversion state: x1*a == u and x2*a == v (mod m). */
typedef struct {
  p521_fe u, v, x1, x2;
} fp521_invst;

/* Strip twos from u, halving x alongside to keep the invariant. */
static void fp521_inv_even(p521_fe u, p521_fe x, const p521_fe m) {
  while (!(u[0] & 1)) {
    fe9_shr1(u);
    fe9_half(x, m);
  }
}

static void fp521_inv_step(fp521_invst* s, const p521_fe m) {
  fp521_inv_even(s->u, s->x1, m);
  fp521_inv_even(s->v, s->x2, m);
  if (fe9_ge(s->u, s->v)) {
    fe9_sub_raw(s->u, s->u, s->v);
    fp521_sub(s->x1, s->x1, s->x2, m);
  } else {
    fe9_sub_raw(s->v, s->v, s->u);
    fp521_sub(s->x2, s->x2, s->x1, m);
  }
}

static int fp521_inv_done(const fp521_invst* s) {
  return fp521_eq(s->u, fp521_one) || fp521_eq(s->v, fp521_one);
}

/* Guide to ECC, Algorithm 2.22. */
void fp521_inv(p521_fe r, const p521_fe a, const p521_fe m) {
  fp521_invst s = {{0}, {0}, {1}, {0}};
  fp521_set(s.u, a);
  fp521_set(s.v, m);
  while (!fp521_inv_done(&s)) fp521_inv_step(&s, m);
  fp521_set(r, fp521_eq(s.u, fp521_one) ? s.x1 : s.x2);
}

void fp521_from_be(p521_fe r, const u8 b[66]) {
  for (usz i = 0; i < 9; i++) r[i] = 0;
  for (usz k = 0; k < 66; k++) r[k / 8] |= (u64)b[65 - k] << (8 * (k & 7));
}

void fp521_to_be(u8 b[66], const p521_fe a) {
  for (usz k = 0; k < 66; k++) b[65 - k] = (u8)(a[k / 8] >> (8 * (k & 7)));
}
