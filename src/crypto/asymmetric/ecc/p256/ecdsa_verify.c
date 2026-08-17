#include "crypto/asymmetric/ecc/p256/ecdsa_verify.h"

#include "crypto/asymmetric/ecc/p256/p256_point.h"

/* FIPS 186-4 Section 6.4.2. */

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

/* R = u1*G + u2*Q, u = (u1, u2). */
static void compute_r(ec_point* r, fpab u, const ec_point* q) {
  ec_point a, b;
  u8       u1b[32], u2b[32];
  p256_fp_to_be(u1b, u.a);
  p256_fp_to_be(u2b, u.b);
  ec_mul(&a, u1b, &p256_g);
  ec_mul(&b, u2b, q);
  ec_add(r, &a, &b);
}

/* valid iff R is finite and (R.x mod n) == r. */
static int check_r(const ec_point* rpt, const p256_fe r) {
  p256_fe rx;
  if (rpt->inf) return 0;
  p256_fp_reduce(rx, rpt->x, p256_n);
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
  p256_fp_reduce(e, eh, p256_n);
  /* u1 = e*w, u2 = r*w mod n with w = s^-1 mod n (fast Montgomery). */
  mont_inv(w, s, &p256_mont_n);
  p256_fp_mul(u1, (fpab){e, w}, p256_n);
  p256_fp_mul(u2, (fpab){r, w}, p256_n);
  compute_r(&rpt, (fpab){u1, u2}, &q);
  return check_r(&rpt, r);
}
