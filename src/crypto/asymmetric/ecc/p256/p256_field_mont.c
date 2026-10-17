#include "crypto/asymmetric/ecc/p256/p256_field_impl.h"

static void cios_mul_row(u64 t[6], u64 ai, const p256_fe b);
static void cios_reduce_row(u64 t[6], const mont* mont);
static int  mont_needs_sub(const u64 t[6], const p256_fe m);
static void mont_finalize(p256_fe r, const u64 t[6], const p256_fe m);

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

static void cios_reduce_row(u64 t[6], const mont* mont) {
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
  return t[4] != 0 || p256_fe_ge(t, m);
}

/* Move the 4 low limbs of t into r, conditionally subtracting m once so r < m.
 */
static void mont_finalize(p256_fe r, const u64 t[6], const p256_fe m) {
  int sub = mont_needs_sub(t, m);
  for (usz i = 0; i < 4; i++) {
    r[i] = t[i];
  }
  if (sub) {
    p256_fe_sub_raw(r, r, m);
  }
}

/* r = a * b * R^-1 mod m (Montgomery product). a,b < m. */
void mont_mul(p256_fe r, fpab ab, const mont* mont) {
  u64 t[6] = {0, 0, 0, 0, 0, 0};
  for (usz i = 0; i < 4; i++) {
    cios_mul_row(t, ab.a[i], ab.b);
    cios_reduce_row(t, mont);
  }
  mont_finalize(r, t, mont->m);
}

/* Two CIOS products: a*R (to Montgomery form via rr), then (aR)*b*R^-1 =
 * a*b mod n. Side-channel posture matches mont_mul's own
 * (mont_finalize's public-modulus conditional subtract) -- neither
 * strengthened nor weakened by this fast path. */
void p256_fp_mul_n(p256_fe r, fpab ab) {
  p256_fe am;
  mont_mul(am, (fpab){ab.a, p256_mont_n.rr}, &p256_mont_n);
  mont_mul(r, (fpab){am, ab.b}, &p256_mont_n);
}

void p256_fp_reduce_n(p256_fe r, const p256_fe a) {
  p256_fp_set(r, a);
  if (p256_fe_ge(r, p256_n)) {
    p256_fe_sub_raw(r, r, p256_n);
  }
}
