#ifndef CRYPTO_ASYMMETRIC_ECC_P256_P256_POINT_IMPL_H
#define CRYPTO_ASYMMETRIC_ECC_P256_P256_POINT_IMPL_H

/* Internal to the p256_point*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "crypto/asymmetric/ecc/p256/p256_point.h"

/* Slope lambda and the source coordinates of an affine addition; copies so
 * the result point may alias an operand. */
typedef struct {
  p256_fe lam, x1, y1, x2;
} p256_slope;

/* Jacobian coordinates (X, Y, Z): x = X/Z^2, y = Y/Z^3; Z == 0 is infinity.
 * Used only by ec_mul so the scalar loop needs no per-step inversion. */
typedef struct {
  p256_fe X, Y, Z;
} jac;

#define FP_P p256_p

/* Doubling intermediates alpha, beta, gamma (borrowed limb pointers). */
typedef struct {
  const u64 *alpha, *beta, *gamma;
} p256_dblv;

/* Intermediates shared between the two halves of Jacobian addition. */
typedef struct {
  p256_fe u1, u2, s1, s2; /* cross terms */
  p256_fe z1z1, z2z2, zs; /* Z1^2, Z2^2, Z1+Z2 */
  p256_fe h, rr;          /* U2-U1, 2(S2-S1) */
} p256_addt;

void p256pt_jac_from_affine(jac* j, const ec_point* p);
void p256pt_jac_double(jac* r, const jac* p);
void p256pt_add_uv(p256_addt* t, const jac* p, const jac* q);
void p256pt_jac_to_affine(ec_point* r, const jac* j);
void p256_ladder_step(jac* r0, jac* r1);

/* Forward declarations: the inline definitions below are unordered. */
static inline void fp_cmov(p256_fe r, const p256_fe a, u64 mask);
static inline void jac_cmov(jac* r, const jac* a, u64 mask);
static inline void fp_add(p256_fe r, const p256_fe a, const p256_fe b);
static inline void p256pt_fp_mul(p256_fe r, const p256_fe a, const p256_fe b);
static inline void p256pt_fp_sqr(p256_fe r, const p256_fe a);
static inline void p256pt_fp_sub(p256_fe r, const p256_fe a, const p256_fe b);
static inline void p256pt_fp_dbl(p256_fe r, const p256_fe a);
static inline int  p256pt_jac_is_inf(const jac* j);
static inline void p256pt_jac_cswap(jac* a, jac* b, u64 mask);

/* Constant-time conditional move of one field element: r <- a if mask is
 * all-ones, unchanged if mask is 0. XOR-mask pattern, mirrors x25519.c's
 * fe_cswap (RFC 7748 5). CCN 1 (loop only, no branch). */
static inline void fp_cmov(p256_fe r, const p256_fe a, u64 mask) {
  for (usz i = 0; i < 4; i++) r[i] ^= mask & (r[i] ^ a[i]);
}

/* Conditional move of a whole Jacobian point (X, Y, Z). CCN 1. */
static inline void jac_cmov(jac* r, const jac* a, u64 mask) {
  fp_cmov(r->X, a->X, mask);
  fp_cmov(r->Y, a->Y, mask);
  fp_cmov(r->Z, a->Z, mask);
}

static inline void fp_add(p256_fe r, const p256_fe a, const p256_fe b) {
  p256_fp_add(r, (fpab){a, b}, FP_P);
}

/* The scalar loop runs thousands of these, so use the fast P-256 Solinas
 * reduction (p256_fp_mul_p) rather than the generic long-division reducer —
 * the difference is ~885ms vs a few ms per scalar multiply. */
static inline void p256pt_fp_mul(p256_fe r, const p256_fe a, const p256_fe b) {
  p256_fp_mul_p(r, a, b);
}
static inline void p256pt_fp_sqr(p256_fe r, const p256_fe a) {
  p256_fp_sqr_p(r, a);
}
static inline void p256pt_fp_sub(p256_fe r, const p256_fe a, const p256_fe b) {
  p256_fp_sub(r, (fpab){a, b}, FP_P);
}
static inline void p256pt_fp_dbl(p256_fe r, const p256_fe a) {
  fp_add(r, a, a);
}
static inline int p256pt_jac_is_inf(const jac* j) {
  return p256_fp_is_zero(j->Z);
}
/* Constant-time swap of two Jacobian points when mask is all-ones. CCN 1. */
static inline void p256pt_jac_cswap(jac* a, jac* b, u64 mask) {
  jac t = *a;
  jac_cmov(&t, b, mask);
  jac_cmov(b, a, mask);
  *a = t;
}

#endif
