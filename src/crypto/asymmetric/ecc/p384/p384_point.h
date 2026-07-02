#ifndef QUIC_P384_POINT_H
#define QUIC_P384_POINT_H

#include "crypto/asymmetric/ecc/p384/p384_field.h"

/* FIPS 186-4 D.1.2.4 P-384 curve y^2 = x^3 - 3x + b over GF(p).
 * Affine points; the point at infinity is flagged separately. */

typedef struct {
  p384_fe x;
  p384_fe y;
  int     inf; /* 1 = point at infinity (identity) */
} ec_point384;

extern const ec_point384 quic_p384_g; /* base point G */

void quic_p384_point_set(ec_point384 *r, const ec_point384 *p);

/* 1 if p satisfies the curve equation (or is infinity), else 0. */
int quic_p384_point_on_curve(const ec_point384 *p);

/* r = p + q, r = 2p (affine, all mod p). */
void quic_p384_point_add(
    ec_point384 *r, const ec_point384 *p, const ec_point384 *q);
void quic_p384_point_double(ec_point384 *r, const ec_point384 *p);

/* r = k * p, k big-endian 48 bytes, via Jacobian double-and-add. */
void quic_p384_point_mul(ec_point384 *r, const u8 k[48], const ec_point384 *p);

#endif
