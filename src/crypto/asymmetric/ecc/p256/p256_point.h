#ifndef QUIC_P256_POINT_H
#define QUIC_P256_POINT_H

#include "crypto/asymmetric/ecc/p256/p256_field.h"

/* FIPS 186-4 D.1.2.3 P-256 curve y^2 = x^3 - 3x + b over GF(p).
 * Affine points; the point at infinity is flagged separately. */

typedef struct {
  p256_fe x;
  p256_fe y;
  int     inf; /* 1 = point at infinity (identity) */
} ec_point;

extern const ec_point quic_p256_g; /* base point G */

void quic_ec_set(ec_point *r, const ec_point *p);

/* 1 if p satisfies the curve equation (or is infinity), else 0. */
int quic_ec_on_curve(const ec_point *p);

/* r = p + q, r = 2p (affine, all mod p). r may alias p or q. */
void quic_ec_add(ec_point *r, const ec_point *p, const ec_point *q);
void quic_ec_double(ec_point *r, const ec_point *p);

/* r = k * p, k big-endian 32 bytes, via double-and-add. */
void quic_ec_mul(ec_point *r, const u8 k[32], const ec_point *p);

#endif
