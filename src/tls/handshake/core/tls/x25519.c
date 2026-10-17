#include "tls/handshake/core/tls/x25519_impl.h"

static unsigned __int128 x25519_mul_col(const fe f, const fe g, usz i);
static void              x25519_fe_reduce(fe h, unsigned __int128 t[5]);
static void              x25519_fe_sqn(fe out, const fe in, usz n);

void x25519_fe_0(fe h) {
  for (usz i = 0; i < 5; i++) h[i] = 0;
}

void x25519_fe_1(fe h) {
  x25519_fe_0(h);
  h[0] = 1;
}

void x25519_fe_copy(fe h, const fe f) {
  for (usz i = 0; i < 5; i++) h[i] = f[i];
}

void x25519_fe_add(fe h, const fe f, const fe g) {
  for (usz i = 0; i < 5; i++) h[i] = f[i] + g[i];
}

/* h = f - g (mod p), adding 2p first to stay non-negative. */
void x25519_fe_sub(fe h, const fe f, const fe g) {
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
void x25519_fe_mul(fe h, const fe f, const fe g) {
  unsigned __int128 t[5];
  for (usz i = 0; i < 5; i++) t[i] = x25519_mul_col(f, g, i);
  x25519_fe_reduce(h, t);
}

void x25519_fe_sq(fe h, const fe f) { x25519_fe_mul(h, f, f); }

/* h = f * 121666 (the Montgomery curve constant a24). */
void x25519_fe_mul121666(fe h, const fe f) {
  unsigned __int128 t[5];
  for (usz i = 0; i < 5; i++) t[i] = (unsigned __int128)f[i] * 121666;
  x25519_fe_reduce(h, t);
}

/* Constant-time conditional swap of f and g when swap == 1. */
void x25519_fe_cswap(fe f, fe g, u64 swap) {
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
void x25519_fe_invert(fe out, const fe z) {
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
