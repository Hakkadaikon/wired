#include "tls/handshake/core/tls/x25519.h"

/* GF(2^255-19) as five 51-bit limbs. Implementation follows the standard
 * radix-2^51 representation (ref10-style), kept in small helpers for CCN<=3. */

typedef u64 fe[5];
#define MASK51 0x7ffffffffffffULL

static void x25519_fe_0(fe h) {
  for (usz i = 0; i < 5; i++) h[i] = 0;
}
static void x25519_fe_1(fe h) {
  x25519_fe_0(h);
  h[0] = 1;
}
static void x25519_fe_copy(fe h, const fe f) {
  for (usz i = 0; i < 5; i++) h[i] = f[i];
}

static void x25519_fe_add(fe h, const fe f, const fe g) {
  for (usz i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

/* h = f - g (mod p), adding 2p first to stay non-negative. */
static void x25519_fe_sub(fe h, const fe f, const fe g) {
  static const u64 twop[5] = {
      0xfffffffffffdaULL, 0xffffffffffffeULL, 0xffffffffffffeULL,
      0xffffffffffffeULL, 0xffffffffffffeULL};
  for (usz i = 0; i < 5; i++) h[i] = f[i] + twop[i] - g[i];
}

/* One column of the schoolbook product: sum f[j]*g'[i-j] with the 19-fold
 * wrap applied to the terms that cross 2^255. */
static unsigned __int128 x25519_mul_col(const fe f, const fe g, usz i) {
  unsigned __int128 t = 0;
  for (usz j = 0; j < 5; j++) {
    u64 gj = (i >= j) ? g[i - j] : g[5 + i - j] * 19;
    t += (unsigned __int128)f[j] * gj;
  }
  return t;
}

/* Reduce five 128-bit column sums to 51-bit limbs via a carry chain. */
static void x25519_fe_reduce(fe h, unsigned __int128 t[5]) {
  u64 c = 0;
  for (usz i = 0; i < 5; i++) {
    t[i] += c;
    h[i] = (u64)t[i] & MASK51;
    c    = (u64)(t[i] >> 51);
  }
  h[0] += c * 19;
  h[1] += h[0] >> 51;
  h[0] &= MASK51;
}

/* h = f * g (mod p). */
static void x25519_fe_mul(fe h, const fe f, const fe g) {
  unsigned __int128 t[5];
  for (usz i = 0; i < 5; i++) t[i] = x25519_mul_col(f, g, i);
  x25519_fe_reduce(h, t);
}

static void x25519_fe_sq(fe h, const fe f) { x25519_fe_mul(h, f, f); }

/* h = f * 121666 (the Montgomery curve constant a24). */
static void fe_mul121666(fe h, const fe f) {
  unsigned __int128 t[5];
  for (usz i = 0; i < 5; i++) t[i] = (unsigned __int128)f[i] * 121666;
  x25519_fe_reduce(h, t);
}

/* Constant-time conditional swap of f and g when swap == 1. */
static void fe_cswap(fe f, fe g, u64 swap) {
  u64 mask = (u64)(0 - swap);
  for (usz i = 0; i < 5; i++) {
    u64 x = mask & (f[i] ^ g[i]);
    f[i] ^= x;
    g[i] ^= x;
  }
}

/* Repeated squaring: out = in^(2^n). */
static void x25519_fe_sqn(fe out, const fe in, usz n) {
  x25519_fe_copy(out, in);
  for (usz i = 0; i < n; i++) x25519_fe_sq(out, out);
}

/* z = f^(2^252-3)... full inverse via the standard 254-square addition
 * chain for p-2 = 2^255 - 21 (RFC 7748 / ref10). */
static void x25519_fe_invert(fe out, const fe z) {
  fe t0, t1, t2, t3;
  x25519_fe_sq(t0, z);
  x25519_fe_sqn(t1, t0, 2);
  x25519_fe_mul(t1, z, t1);
  x25519_fe_mul(t0, t0, t1);
  x25519_fe_sq(t2, t0);
  x25519_fe_mul(t1, t1, t2);
  x25519_fe_sqn(t2, t1, 5);
  x25519_fe_mul(t1, t2, t1);
  x25519_fe_sqn(t2, t1, 10);
  x25519_fe_mul(t2, t2, t1);
  x25519_fe_sqn(t3, t2, 20);
  x25519_fe_mul(t2, t3, t2);
  x25519_fe_sqn(t2, t2, 10);
  x25519_fe_mul(t1, t2, t1);
  x25519_fe_sqn(t2, t1, 50);
  x25519_fe_mul(t2, t2, t1);
  x25519_fe_sqn(t3, t2, 100);
  x25519_fe_mul(t2, t3, t2);
  x25519_fe_sqn(t2, t2, 50);
  x25519_fe_mul(t1, t2, t1);
  x25519_fe_sqn(t1, t1, 5);
  x25519_fe_mul(out, t1, t0);
}

/* Load 32 little-endian bytes into limbs (top bit of byte 31 is cleared). */
static void x25519_fe_frombytes(fe h, const u8 *s) {
  u64 t[4];
  for (usz i = 0; i < 4; i++) {
    t[i] = 0;
    for (usz j = 0; j < 8; j++) t[i] |= (u64)s[i * 8 + j] << (8 * j);
  }
  h[0] = t[0] & MASK51;
  h[1] = ((t[0] >> 51) | (t[1] << 13)) & MASK51;
  h[2] = ((t[1] >> 38) | (t[2] << 26)) & MASK51;
  h[3] = ((t[2] >> 25) | (t[3] << 39)) & MASK51;
  h[4] = (t[3] >> 12) & MASK51;
}

/* Pack five reduced 51-bit limbs into 32 little-endian bytes. */
static void x25519_store_reduced(u8 *s, const fe r) {
  u64 w[4];
  w[0] = r[0] | (r[1] << 51);
  w[1] = (r[1] >> 13) | (r[2] << 38);
  w[2] = (r[2] >> 26) | (r[3] << 25);
  w[3] = (r[3] >> 39) | (r[4] << 12);
  for (usz i = 0; i < 4; i++)
    for (usz j = 0; j < 8; j++) s[i * 8 + j] = (u8)(w[i] >> (8 * j));
}

/* One weak-carry pass: every limb < 2^51, top carry folded by 19. */
static void x25519_carry_pass(fe r) {
  u64 c = 0;
  for (usz i = 0; i < 5; i++) {
    r[i] += c;
    c = r[i] >> 51;
    r[i] &= MASK51;
  }
  r[0] += c * 19;
}

/* Final carry after the conditional +19: propagate carries and DISCARD the
 * 2^255 overflow bit (that bit is exactly the p we conditionally subtracted).
 * Folding it back by 19 (as the weak pass does) would re-add p and leave the
 * result 19 short — the bug that made r==p reduce to 19 instead of 0. */
static void x25519_carry_final(fe r) {
  u64 c = 0;
  for (usz i = 0; i < 5; i++) {
    r[i] += c;
    c = r[i] >> 51;
    r[i] &= MASK51;
  }
}

/* Fully reduce h mod p and store 32 little-endian bytes. h's limbs come in
 * below 2^52 (weak-reduced), so two weak passes bring r into [0, 2p). */
static void x25519_fe_tobytes(u8 *s, const fe h) {
  fe  r;
  u64 q;
  x25519_fe_copy(r, h);
  x25519_carry_pass(r);
  x25519_carry_pass(r);
  q = (r[0] + 19) >> 51; /* q==1 iff r >= p (adding 19 overflows 2^255) */
  for (usz i = 1; i < 5; i++) q = (r[i] + q) >> 51;
  r[0] += 19 * q;        /* if r >= p, +19 pushes past 2^255 = subtract p */
  x25519_carry_final(r); /* drop the 2^255 carry instead of folding it */
  x25519_store_reduced(s, r);
}

/* The Montgomery ladder's running (x2,z2,x3,z3) state, mutated in place each
 * step. */
typedef struct {
  u64 x2[5], z2[5], x3[5], z3[5];
} ladder_state;

/* One Montgomery ladder step on st with difference x1. */
static void ladder_step(ladder_state *st, const fe x1) {
  fe a, b, c, d, e, da, cb;
  x25519_fe_add(a, st->x2, st->z2);
  x25519_fe_sub(b, st->x2, st->z2);
  x25519_fe_add(c, st->x3, st->z3);
  x25519_fe_sub(d, st->x3, st->z3);
  x25519_fe_mul(da, d, a);
  x25519_fe_mul(cb, c, b);
  x25519_fe_add(st->x3, da, cb);
  x25519_fe_sq(st->x3, st->x3);
  x25519_fe_sub(st->z3, da, cb);
  x25519_fe_sq(st->z3, st->z3);
  x25519_fe_mul(st->z3, st->z3, x1);
  x25519_fe_sq(a, a);
  x25519_fe_sq(b, b);
  x25519_fe_mul(st->x2, a, b);
  x25519_fe_sub(e, a, b);
  fe_mul121666(da, e);
  x25519_fe_add(da, da, b);
  x25519_fe_mul(st->z2, e, da);
}

/* Clamp the scalar per RFC 7748 (clear low 3 bits, set bit 254, clear 255). */
static void clamp(u8 e[32], const u8 scalar[32]) {
  for (usz i = 0; i < 32; i++) e[i] = scalar[i];
  e[0] &= 248;
  e[31] = (e[31] & 127) | 64;
}

/* Run the ladder for all 255 scalar bits, leaving the result in x2,z2. */
static void ladder(fe x2, fe z2, const u8 e[32], const fe x1) {
  ladder_state st;
  u64          swap = 0;
  x25519_fe_1(st.x2);
  x25519_fe_0(st.z2);
  x25519_fe_copy(st.x3, x1);
  x25519_fe_1(st.z3);
  for (usz pos = 255; pos-- > 0;) {
    u64 bit = (e[pos / 8] >> (pos & 7)) & 1;
    swap ^= bit;
    fe_cswap(st.x2, st.x3, swap);
    fe_cswap(st.z2, st.z3, swap);
    swap = bit;
    ladder_step(&st, x1);
  }
  fe_cswap(st.x2, st.x3, swap);
  fe_cswap(st.z2, st.z3, swap);
  x25519_fe_copy(x2, st.x2);
  x25519_fe_copy(z2, st.z2);
}

/* RFC 7748 6.1: a low-order point yields an all-zero shared secret. Detect it
 * in constant time (OR-accumulate all bytes, branch only on the fold). */
static int x25519_nonzero(const u8 out[32]) {
  u8 d = 0;
  for (usz i = 0; i < 32; i++) d |= out[i];
  return d != 0;
}

int quic_x25519(
    u8       out[QUIC_X25519_LEN],
    const u8 scalar[QUIC_X25519_LEN],
    const u8 point[QUIC_X25519_LEN]) {
  fe x1, x2, z2, zinv;
  u8 e[32];
  clamp(e, scalar);
  x25519_fe_frombytes(x1, point);
  ladder(x2, z2, e, x1);
  x25519_fe_invert(zinv, z2);
  x25519_fe_mul(x2, x2, zinv);
  x25519_fe_tobytes(out, x2);
  return x25519_nonzero(out);
}

int quic_x25519_base(
    u8 out[QUIC_X25519_LEN], const u8 scalar[QUIC_X25519_LEN]) {
  u8 base[32] = {9};
  return quic_x25519(out, scalar, base);
}
