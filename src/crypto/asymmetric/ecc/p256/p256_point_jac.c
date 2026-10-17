#include "crypto/asymmetric/ecc/p256/p256_point_impl.h"

static void add_finish(jac* r, const p256_addt* a);
static void jac_add(jac* r, p256_addt* t);
static void add_same_x_jac(jac* acc, const p256_fe s1, const p256_fe s2);
static void jac_add_step(jac* acc, const jac* base);
static int  add_full_infinity(jac* r, const jac* a, const jac* b);
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

/* Same-x case: double if s1==s2 (acc==base), else result is infinity. */
static void add_same_x_jac(jac* acc, const p256_fe s1, const p256_fe s2) {
  if (p256_fp_eq(s1, s2))
    p256pt_jac_double(acc, acc);
  else
    acc->Z[0] = acc->Z[1] = acc->Z[2] = acc->Z[3] = 0;
}

/* acc += base, handling infinity and the doubling/inverse case. */
static void jac_add_step(jac* acc, const jac* base) {
  p256_addt t;
  if (p256pt_jac_is_inf(acc)) {
    *acc = *base;
    return;
  }
  p256pt_add_uv(&t, acc, base);
  if (p256_fp_eq(t.u1, t.u2))
    add_same_x_jac(acc, t.s1, t.s2);
  else
    jac_add(acc, &t);
}

/* Convert Jacobian back to affine: x = X/Z^2, y = Y/Z^3. */
void p256pt_jac_to_affine(ec_point* r, const jac* j) {
  p256_fe zi, zi2, zi3;
  if (p256pt_jac_is_inf(j)) {
    r->inf = 1;
    return;
  }
  p256_fp_inv_p(zi, j->Z);
  p256pt_fp_sqr(zi2, zi);
  p256pt_fp_mul(zi3, zi2, zi);
  p256pt_fp_mul(r->x, j->X, zi2);
  p256pt_fp_mul(r->y, j->Y, zi3);
  r->inf = 0;
}

/* --- constant-time scalar multiply (Montgomery ladder) ------------------
 * RFC 6090 style two-accumulator ladder (side-channel countermeasure: see
 * p256_ladder_step below). Replaces the earlier add-if-bit-set double-and-add,
 * whose `if (bit) jac_add_step(...)` made execution time/cache pattern
 * correlate with the scalar's bits directly. */

/* 1 if either operand is infinity, with r set to the other one (or infinity,
 * if both are). Split out so jac_add_full stays CCN <= 2. */
static int add_full_infinity(jac* r, const jac* a, const jac* b) {
  if (p256pt_jac_is_inf(a)) {
    *r = *b;
    return 1;
  }
  if (p256pt_jac_is_inf(b)) {
    *r = *a;
    return 1;
  }
  return 0;
}

/* r = a + b, either operand (not just acc) may be infinity: jac_add_step
 * only special-cases its first argument (acc) and assumes its second
 * (base) is finite, but the ladder's r0 starts at infinity and can land on
 * either side of the sum, so both must be covered here first. */
static void jac_add_full(jac* r, const jac* a, const jac* b) {
  if (add_full_infinity(r, a, b)) return;
  *r = *a;
  jac_add_step(r, b);
}

/* One Montgomery-ladder step (RFC 6090-style two-accumulator ladder,
 * mirrors x25519.c's ladder_step/fe_cswap control pattern): unconditionally
 * computes r0+r1 and 2*r0, leaving the "doubled" half in r0 and the "added"
 * half in r1. The caller cswaps r0/r1 around this call (see ec_mul
 * below) so which accumulator ends up representing 2*acc vs acc+base never
 * depends on an explicit `if (bit)`. The if-statements inside
 * jac_add_step/p256pt_jac_double are not scalar-bit branches: they fire only on
 * the point's own algebraic state (the fixed initial r0==infinity step, or
 * an exact same-point coincidence), identical in shape on every call
 * regardless of which bit is 1 or 0. */
void p256_ladder_step(jac* r0, jac* r1) {
  jac t;
  jac_add_full(&t, r0, r1);  /* t = r0 + r1 */
  p256pt_jac_double(r0, r0); /* r0 = 2*r0   */
  *r1 = t;
}
