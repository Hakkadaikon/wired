#ifndef CRYPTO_ASYMMETRIC_ECC_P521_P521_POINT_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_P521_P521_POINT_IMPL_H

/* Internal to the p521_point*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/asymmetric/ecc/p521/p521_point.h"

/* Jacobian (X, Y, Z): x = X/Z^2, y = Y/Z^3; Z == 0 is infinity. */
typedef struct {
  p521_fe X, Y, Z;
} jac521;

/* add-2007-bl intermediates. */
typedef struct {
  p521_fe u1, u2, s1, s2, z1z1, z2z2;
} p521_addt;

void p521pt_sub(p521_fe r, const p521_fe a, const p521_fe b);
void p521pt_dbl(p521_fe r, const p521_fe a);
void p521pt_sqr(p521_fe r, const p521_fe a);
int  p521pt_is_inf(const jac521* j);
void p521pt_double(jac521* r, const jac521* p);
void p521pt_add_uv(p521_addt* t, const jac521* p, const jac521* q);
void p521pt_add_z(
    jac521*          r,
    const p521_addt* a,
    const jac521*    p,
    const jac521*    q,
    const p521_fe    h);

#endif
