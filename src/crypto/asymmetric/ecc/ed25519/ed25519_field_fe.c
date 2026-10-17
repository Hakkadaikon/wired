#include "crypto/asymmetric/ecc/ed25519/ed25519_field_impl.h"

static unsigned __int128 mul_col(const fe f, const fe g, usz i);
static void              fe_reduce(fe h, unsigned __int128 t[5]);
static void              fe_sqn(fe out, const fe in, usz n);

void ed_fe_1(fe h) {
  ed_fe_0(h);
  h[0] = 1;
}

void ed_fe_copy(fe h, const fe f) {
  for (usz i = 0; i < 5; i++) {
    h[i] = f[i];
  }
}

void ed_fe_add(fe h, const fe f, const fe g) {
  for (usz i = 0; i < 5; i++) {
    h[i] = f[i] + g[i];
  }
}

/* h = f - g (mod p), adding 2p first to stay non-negative. */
void ed_fe_sub(fe h, const fe f, const fe g) {
  static const u64 twop[5] = {
      0xfffffffffffdaULL, 0xffffffffffffeULL, 0xffffffffffffeULL,
      0xffffffffffffeULL, 0xffffffffffffeULL};
  for (usz i = 0; i < 5; i++) {
    h[i] = f[i] + twop[i] - g[i];
  }
}

/* One column of the schoolbook product with the 19-fold wrap past 2^255. */
static unsigned __int128 mul_col(const fe f, const fe g, usz i) {
  unsigned __int128 t = 0;
  for (usz j = 0; j < 5; j++) {
    u64 gj = (i >= j) ? g[i - j] : g[5 + i - j] * 19;
    t += (unsigned __int128)f[j] * gj;
  }
  return t;
}

/* Reduce five 128-bit column sums to 51-bit limbs via a carry chain. */
static void fe_reduce(fe h, unsigned __int128 t[5]) {
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

void ed_fe_mul(fe h, const fe f, const fe g) {
  unsigned __int128 t[5];
  for (usz i = 0; i < 5; i++) {
    t[i] = mul_col(f, g, i);
  }
  fe_reduce(h, t);
}

void ed_fe_sq(fe h, const fe f) { ed_fe_mul(h, f, f); }

/* Repeated squaring: out = in^(2^n). */
static void fe_sqn(fe out, const fe in, usz n) {
  ed_fe_copy(out, in);
  for (usz i = 0; i < n; i++) {
    ed_fe_sq(out, out);
  }
}

/* z = f^(p-2): modular inverse via the standard ref10 addition chain. */
void ed_fe_invert(fe out, const fe z) {
  fe t0, t1, t2, t3;
  ed_fe_sq(t0, z);
  fe_sqn(t1, t0, 2);
  ed_fe_mul(t1, z, t1);
  ed_fe_mul(t0, t0, t1);
  ed_fe_sq(t2, t0);
  ed_fe_mul(t1, t1, t2);
  fe_sqn(t2, t1, 5);
  ed_fe_mul(t1, t2, t1);
  fe_sqn(t2, t1, 10);
  ed_fe_mul(t2, t2, t1);
  fe_sqn(t3, t2, 20);
  ed_fe_mul(t2, t3, t2);
  fe_sqn(t2, t2, 10);
  ed_fe_mul(t1, t2, t1);
  fe_sqn(t2, t1, 50);
  ed_fe_mul(t2, t2, t1);
  fe_sqn(t3, t2, 100);
  ed_fe_mul(t2, t3, t2);
  fe_sqn(t2, t2, 50);
  ed_fe_mul(t1, t2, t1);
  fe_sqn(t1, t1, 5);
  ed_fe_mul(out, t1, t0);
}

/* out = z^((p-5)/8), the exponent used for the candidate square root. */
void ed_fe_pow_p58(fe out, const fe z) {
  fe t0, t1, t2;
  ed_fe_sq(t0, z);
  fe_sqn(t1, t0, 2);
  ed_fe_mul(t1, z, t1);
  ed_fe_mul(t0, t0, t1);
  ed_fe_sq(t0, t0);
  ed_fe_mul(t0, t1, t0);
  fe_sqn(t1, t0, 5);
  ed_fe_mul(t0, t1, t0);
  fe_sqn(t1, t0, 10);
  ed_fe_mul(t1, t1, t0);
  fe_sqn(t2, t1, 20);
  ed_fe_mul(t1, t2, t1);
  fe_sqn(t1, t1, 10);
  ed_fe_mul(t0, t1, t0);
  fe_sqn(t1, t0, 50);
  ed_fe_mul(t1, t1, t0);
  fe_sqn(t2, t1, 100);
  ed_fe_mul(t1, t2, t1);
  fe_sqn(t1, t1, 50);
  ed_fe_mul(t0, t1, t0);
  ed_fe_sq(t0, t0);
  ed_fe_sq(t0, t0);
  ed_fe_mul(out, t0, z);
}
