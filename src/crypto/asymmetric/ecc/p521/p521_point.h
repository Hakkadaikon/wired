#ifndef P521_POINT_H
#define P521_POINT_H

#include "crypto/asymmetric/ecc/p521/p521_field.h"

/* FIPS 186-4 D.1.2.5 P-521 curve y^2 = x^3 - 3x + b over GF(2^521 - 1). */

extern const p521_fe p521_gx;
extern const p521_fe p521_gy;

/* 1 if (x, y) satisfies the curve equation; x, y must already be < p. */
int p521_on_curve(const p521_fe x, const p521_fe y);

/* rx = affine x of u1*G + u2*Q (Shamir's trick over Jacobian coordinates),
 * u1, u2 < 2^521. Returns 0 when the sum is the point at infinity, else 1. */
int p521_mul2_x(
    p521_fe       rx,
    const p521_fe u1,
    const p521_fe u2,
    const p521_fe qx,
    const p521_fe qy);

#endif
