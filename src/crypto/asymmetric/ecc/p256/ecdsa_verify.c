#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"

#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/asymmetric/ecc/p256fixed/p256fixed.h"

/* FIPS 186-4 Section 6.4.2. Every input here is public (Q, r, s, hash), so
 * u1*G takes the windowed fixed-base table (p256fixed) instead of the
 * generic ladder; u2*Q still runs the constant-time ec_mul ladder shared
 * with ECDH / key generation, which this file does not touch. */

/* 1 if 1 <= v <= n-1. */
static int scalar_in_range(const p256_fe v) {
  return !p256_fp_is_zero(v) && p256_fp_lt(v, p256_n);
}

/* Load Q; valid only if on the curve and not infinity. */
static int load_pubkey(ec_point* q, const u8 px[32], const u8 py[32]) {
  p256_fp_from_be(q->x, px);
  p256_fp_from_be(q->y, py);
  q->inf = 0;
  return ec_on_curve(q);
}

/* a = u1*G via the fixed-base table (infinity when u1 == 0). */
static void mul_g(ec_point* a, const p256_fe u1) {
  u8 u1b[32];
  p256_fp_to_be(u1b, u1);
  a->inf = !p256fixed_mul_g(a->x, a->y, u1b);
}

/* R = u1*G + u2*Q, u = (u1, u2). */
static void compute_r(ec_point* r, fpab u, const ec_point* q) {
  ec_point a, b;
  u8       u2b[32];
  mul_g(&a, u.a);
  p256_fp_to_be(u2b, u.b);
  ec_mul(&b, u2b, q);
  ec_add(r, &a, &b);
}

/* valid iff R is finite and (R.x mod n) == r. */
static int check_r(const ec_point* rpt, const p256_fe r) {
  p256_fe rx;
  if (rpt->inf) return 0;
  p256_fp_reduce_n(rx, rpt->x);
  return p256_fp_eq(rx, r);
}

/* Inputs accepted: r,s in range and Q a valid curve point. */
static int inputs_ok(
    ec_point*     q,
    const p256_fe r,
    const p256_fe s,
    const u8      px[32],
    const u8      py[32]) {
  if (!scalar_in_range(r) || !scalar_in_range(s)) return 0;
  return load_pubkey(q, px, py);
}

int ecdsa_p256_verify(
    const u8 pub_x[32],
    const u8 pub_y[32],
    const u8 sig_r[32],
    const u8 sig_s[32],
    const u8 msg_hash[32]) {
  ec_point q, rpt;
  p256_fe  r, s, e, eh, w, u1, u2;
  p256_fp_from_be(r, sig_r);
  p256_fp_from_be(s, sig_s);
  if (!inputs_ok(&q, r, s, pub_x, pub_y)) return 0;
  /* e = hash mod n (SHA-256 digest is 256 bits = field size). */
  p256_fp_from_be(eh, msg_hash);
  p256_fp_reduce_n(e, eh);
  /* u1 = e*w, u2 = r*w mod n with w = s^-1 mod n (Montgomery throughout). */
  mont_inv(w, s, &p256_mont_n);
  p256_fp_mul_n(u1, (fpab){e, w});
  p256_fp_mul_n(u2, (fpab){r, w});
  compute_r(&rpt, (fpab){u1, u2}, &q);
  return check_r(&rpt, r);
}
