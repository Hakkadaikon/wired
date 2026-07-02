#include "crypto/asymmetric/ecc/p384/ecdsa_verify.h"

#include "crypto/asymmetric/ecc/p384/p384_point.h"

/* FIPS 186-4 Section 6.4.2. */

/* 1 if 1 <= v <= n-1. */
static int p384ev_scalar_in_range(const p384_fe v) {
  return !quic_fp384_is_zero(v) && quic_fp384_lt(v, quic_p384_n);
}

/* Load Q; valid only if on the curve and not infinity. */
static int p384ev_load_pubkey(
    ec_point384 *q, const u8 px[48], const u8 py[48]) {
  quic_fp384_from_be(q->x, px);
  quic_fp384_from_be(q->y, py);
  q->inf = 0;
  return quic_p384_point_on_curve(q);
}

/* R = u1*G + u2*Q. */
static void p384ev_compute_r(
    ec_point384 *r, const p384_fe u1, const p384_fe u2, const ec_point384 *q) {
  ec_point384 a, b;
  u8          u1b[48], u2b[48];
  quic_fp384_to_be(u1b, u1);
  quic_fp384_to_be(u2b, u2);
  quic_p384_point_mul(&a, u1b, &quic_p384_g);
  quic_p384_point_mul(&b, u2b, q);
  quic_p384_point_add(r, &a, &b);
}

/* u1 = e*w mod n, u2 = r*w mod n with w = s^-1 mod n. */
static void p384ev_compute_u(
    p384_fe u1, p384_fe u2, const p384_fe e, const p384_fe r, const p384_fe s) {
  p384_fe w;
  quic_mont384_inv(w, s, &quic_p384_mont_n);
  quic_fp384_mul(u1, e, w, quic_p384_n);
  quic_fp384_mul(u2, r, w, quic_p384_n);
}

/* valid iff R is finite and (R.x mod n) == r. */
static int p384ev_check_r(const ec_point384 *rpt, const p384_fe r) {
  p384_fe rx;
  if (rpt->inf) return 0;
  quic_fp384_reduce(rx, rpt->x, quic_p384_n);
  return quic_fp384_eq(rx, r);
}

/* Inputs accepted: r,s in range and Q a valid curve point. */
static int p384ev_inputs_ok(
    ec_point384  *q,
    const p384_fe r,
    const p384_fe s,
    const u8      px[48],
    const u8      py[48]) {
  if (!p384ev_scalar_in_range(r) || !p384ev_scalar_in_range(s)) return 0;
  return p384ev_load_pubkey(q, px, py);
}

int quic_ecdsa_p384_verify(
    const u8 pub_x[48],
    const u8 pub_y[48],
    const u8 sig_r[48],
    const u8 sig_s[48],
    const u8 msg_hash[48]) {
  ec_point384 q, rpt;
  p384_fe     r, s, e, eh, u1, u2;
  quic_fp384_from_be(r, sig_r);
  quic_fp384_from_be(s, sig_s);
  if (!p384ev_inputs_ok(&q, r, s, pub_x, pub_y)) return 0;
  /* e = hash mod n (a 48-byte digest is 384 bits = field size). */
  quic_fp384_from_be(eh, msg_hash);
  quic_fp384_reduce(e, eh, quic_p384_n);
  p384ev_compute_u(u1, u2, e, r, s);
  p384ev_compute_r(&rpt, u1, u2, &q);
  return p384ev_check_r(&rpt, r);
}
