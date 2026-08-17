#include "crypto/asymmetric/ecc/p384/ecdsa_verify.h"

#include "crypto/asymmetric/ecc/p384/p384_point.h"

/* FIPS 186-4 Section 6.4.2. */

/* 1 if 1 <= v <= n-1. */
static int p384ev_scalar_in_range(const p384_fe v) {
  return !fp384_is_zero(v) && fp384_lt(v, p384_n);
}

/* Load Q; valid only if on the curve and not infinity. */
static int p384ev_load_pubkey(
    ec_point384* q, const u8 px[48], const u8 py[48]) {
  fp384_from_be(q->x, px);
  fp384_from_be(q->y, py);
  q->inf = 0;
  return p384_point_on_curve(q);
}

/* R = u1*G + u2*Q, u = (u1, u2). */
static void p384ev_compute_r(ec_point384* r, fp384ab u, const ec_point384* q) {
  ec_point384 a, b;
  u8          u1b[48], u2b[48];
  fp384_to_be(u1b, u.a);
  fp384_to_be(u2b, u.b);
  p384_point_mul(&a, u1b, &p384_g);
  p384_point_mul(&b, u2b, q);
  p384_point_add(r, &a, &b);
}

/* valid iff R is finite and (R.x mod n) == r. */
static int p384ev_check_r(const ec_point384* rpt, const p384_fe r) {
  p384_fe rx;
  if (rpt->inf) return 0;
  fp384_reduce(rx, rpt->x, p384_n);
  return fp384_eq(rx, r);
}

/* Inputs accepted: r,s in range and Q a valid curve point. */
static int p384ev_inputs_ok(
    ec_point384*  q,
    const p384_fe r,
    const p384_fe s,
    const u8      px[48],
    const u8      py[48]) {
  if (!p384ev_scalar_in_range(r) || !p384ev_scalar_in_range(s)) return 0;
  return p384ev_load_pubkey(q, px, py);
}

int ecdsa_p384_verify(
    const u8 pub_x[48],
    const u8 pub_y[48],
    const u8 sig_r[48],
    const u8 sig_s[48],
    const u8 msg_hash[48]) {
  ec_point384 q, rpt;
  p384_fe     r, s, e, eh, w, u1, u2;
  fp384_from_be(r, sig_r);
  fp384_from_be(s, sig_s);
  if (!p384ev_inputs_ok(&q, r, s, pub_x, pub_y)) return 0;
  /* e = hash mod n (a 48-byte digest is 384 bits = field size). */
  fp384_from_be(eh, msg_hash);
  fp384_reduce(e, eh, p384_n);
  /* u1 = e*w, u2 = r*w mod n with w = s^-1 mod n. */
  mont384_inv(w, s, &p384_mont_n);
  fp384_mul(u1, (fp384ab){e, w}, p384_n);
  fp384_mul(u2, (fp384ab){r, w}, p384_n);
  p384ev_compute_r(&rpt, (fp384ab){u1, u2}, &q);
  return p384ev_check_r(&rpt, r);
}
