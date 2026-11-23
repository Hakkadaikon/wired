#include "crypto/asymmetric/ecc/p256/p256_point_impl.h"

static void add_finish(jac* r, const p256_addt* a);
static void jac_add(jac* r, p256_addt* t);
static void jac_add_full(jac* r, const jac* a, const jac* b);

/* Finish addition given the cross terms and H = U2-U1, rr = 2(S2-S1). */
static void add_finish(jac* r, const p256_addt* a) {
  p256_fe i, j, v, t;
  p256pt_fp_dbl(t, a->h);
  p256pt_fp_sqr(i, t); /* I = (2H)^2 */
  p256pt_fp_mul(j, a->h, i);
  p256pt_fp_mul(v, a->u1, i);
  p256pt_fp_sqr(r->X, a->rr);
  p256pt_fp_sub(r->X, r->X, j);
  p256pt_fp_dbl(t, v);
  p256pt_fp_sub(r->X, r->X, t);
  p256pt_fp_sub(t, v, r->X);
  p256pt_fp_mul(t, a->rr, t);
  p256pt_fp_mul(v, a->s1, j);
  p256pt_fp_dbl(v, v);
  p256pt_fp_sub(r->Y, t, v);
  p256pt_fp_sqr(t, a->zs);
  p256pt_fp_sub(t, t, a->z1z1);
  p256pt_fp_sub(t, t, a->z2z2);
  p256pt_fp_mul(r->Z, t, a->h);
}

/* r = p + q given the cross terms; assumes p != -q, p != q. */
static void jac_add(jac* r, p256_addt* t) {
  p256pt_fp_sub(t->h, t->u2, t->u1);
  p256pt_fp_sub(t->rr, t->s2, t->s1);
  p256pt_fp_dbl(t->rr, t->rr);
  add_finish(r, t);
}

/* Convert Jacobian back to affine: x = X/Z^2, y = Y/Z^3. Constant-time: the
 * inversion always runs, and Z == 0 (infinity) inverts to 0 (0^(p-2) = 0), so
 * infinity comes out as (0, 0) with inf set. */
void p256pt_jac_to_affine(ec_point* r, const jac* j) {
  p256_fe zi, zi2, zi3;
  p256_fp_inv_p(zi, j->Z);
  p256pt_fp_sqr(zi2, zi);
  p256pt_fp_mul(zi3, zi2, zi);
  p256pt_fp_mul(r->x, j->X, zi2);
  p256pt_fp_mul(r->y, j->Y, zi3);
  r->inf = p256pt_jac_is_inf(j);
}

/* --- constant-time scalar multiply (Montgomery ladder) ------------------
 * RFC 6090 style two-accumulator ladder: a fixed 256 steps of one addition
 * and one doubling, with no branch or memory index on the scalar or on the
 * points (infinity is handled by masked moves in jac_add_full). */

/* r = a + b, constant-time, either operand may be infinity: the generic sum
 * always runs and masked moves pick b when a is infinity and a when b is.
 * For finite a == -b the formula gives H = 0, so Z3 = 2*Z1*Z2*H = 0 is
 * infinity, the right sum. a == b (H = 0 too) would need doubling, but the
 * ladder keeps r1 - r0 = P != O, so it never adds equal points. */
static void jac_add_full(jac* r, const jac* a, const jac* b) {
  u64       ainf = p256pt_inf_mask(a), binf = p256pt_inf_mask(b);
  p256_addt u;
  jac       t;
  p256pt_add_uv(&u, a, b);
  jac_add(&t, &u);
  jac_cmov(&t, b, ainf);
  jac_cmov(&t, a, binf);
  *r = t;
}

/* One Montgomery-ladder step (mirrors x25519.c's ladder_step/fe_cswap
 * pattern): computes r0+r1 and 2*r0, leaving the doubled half in r0 and the
 * sum in r1. The caller cswaps r0/r1 around this call (see ec_mul), so the
 * scalar bit only ever reaches a mask. Doubling infinity (Z = 0) yields
 * Z3 = 2*Y*Z = 0, infinity again, with no special case. */
void p256_ladder_step(jac* r0, jac* r1) {
  jac t;
  jac_add_full(&t, r0, r1);  /* t = r0 + r1 */
  p256pt_jac_double(r0, r0); /* r0 = 2*r0   */
  *r1 = t;
}
