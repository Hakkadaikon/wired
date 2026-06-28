#include "p256/ecdsa_verify.h"
#include "p256/p256_point.h"

/* FIPS 186-4 Section 6.4.2. */

/* 1 if 1 <= v <= n-1. */
static int scalar_in_range(const p256_fe v)
{
    return !quic_fp_is_zero(v) && quic_fp_lt(v, quic_p256_n);
}

/* Load Q; valid only if on the curve and not infinity. */
static int load_pubkey(ec_point *q, const u8 px[32], const u8 py[32])
{
    quic_fp_from_be(q->x, px);
    quic_fp_from_be(q->y, py);
    q->inf = 0;
    return quic_ec_on_curve(q);
}

/* R = u1*G + u2*Q. */
static void compute_r(ec_point *r, const p256_fe u1, const p256_fe u2, const ec_point *q)
{
    ec_point a, b;
    u8 u1b[32], u2b[32];
    quic_fp_to_be(u1b, u1);
    quic_fp_to_be(u2b, u2);
    quic_ec_mul(&a, u1b, &quic_p256_g);
    quic_ec_mul(&b, u2b, q);
    quic_ec_add(r, &a, &b);
}

/* u1 = e*w mod n, u2 = r*w mod n with w = s^-1 mod n. */
static void compute_u(p256_fe u1, p256_fe u2, const p256_fe e, const p256_fe r, const p256_fe s)
{
    p256_fe w;
    quic_fp_inv(w, s, quic_p256_n);
    quic_fp_mul(u1, e, w, quic_p256_n);
    quic_fp_mul(u2, r, w, quic_p256_n);
}

/* valid iff R is finite and (R.x mod n) == r. */
static int check_r(const ec_point *rpt, const p256_fe r)
{
    p256_fe rx;
    if (rpt->inf) return 0;
    quic_fp_reduce(rx, rpt->x, quic_p256_n);
    return quic_fp_eq(rx, r);
}

/* Inputs accepted: r,s in range and Q a valid curve point. */
static int inputs_ok(ec_point *q, const p256_fe r, const p256_fe s,
                     const u8 px[32], const u8 py[32])
{
    if (!scalar_in_range(r) || !scalar_in_range(s)) return 0;
    return load_pubkey(q, px, py);
}

int quic_ecdsa_p256_verify(const u8 pub_x[32], const u8 pub_y[32],
                           const u8 sig_r[32], const u8 sig_s[32],
                           const u8 msg_hash[32])
{
    ec_point q, rpt;
    p256_fe r, s, e, eh, u1, u2;
    quic_fp_from_be(r, sig_r);
    quic_fp_from_be(s, sig_s);
    if (!inputs_ok(&q, r, s, pub_x, pub_y)) return 0;
    /* e = hash mod n (SHA-256 digest is 256 bits = field size). */
    quic_fp_from_be(eh, msg_hash);
    quic_fp_reduce(e, eh, quic_p256_n);
    compute_u(u1, u2, e, r, s);
    compute_r(&rpt, u1, u2, &q);
    return check_r(&rpt, r);
}
