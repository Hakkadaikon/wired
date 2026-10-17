#ifndef CRYPTO_ASYMMETRIC_ECC_P384_P384_POINT_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_P384_P384_POINT_IMPL_H

/* Internal to the p384_point*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/asymmetric/ecc/p384/p384_point.h"

/* Jacobian coordinates (X, Y, Z): x = X/Z^2, y = Y/Z^3; Z == 0 is infinity. */
typedef struct {
  p384_fe X, Y, Z;
} jac384;

#define FP_P384 p384_p

/* Doubling intermediates alpha, beta, gamma (borrowed limb pointers). */
typedef struct {
  const u64 *alpha, *beta, *gamma;
} p384_dblv;

/* Intermediates shared between the two halves of Jacobian addition. */
typedef struct {
  p384_fe u1, u2, s1, s2; /* cross terms */
  p384_fe z1z1, z2z2, zs; /* Z1^2, Z2^2, Z1+Z2 */
  p384_fe h, rr;          /* U2-U1, 2(S2-S1) */
} p384_addt;

void p384pt_fp_mul(p384_fe r, const p384_fe a, const p384_fe b);
void p384pt_fp_sqr(p384_fe r, const p384_fe a);
void p384pt_fp_sub(p384_fe r, const p384_fe a, const p384_fe b);
void p384pt_fp_dbl(p384_fe r, const p384_fe a);
void p384pt_jac_from_affine(jac384* j, const ec_point384* p);
void p384pt_jac_set_inf(jac384* j);
int  p384pt_jac_is_inf(const jac384* j);
void p384pt_jac_double(jac384* r, const jac384* p);
void p384pt_add_uv(p384_addt* t, const jac384* p, const jac384* q);

#endif
