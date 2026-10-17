#include "crypto/asymmetric/ecc/p384/p384_point_impl.h"

static void p384pt_add_finish(jac384* r, const p384_addt* a);
static void p384pt_jac_add(jac384* r, p384_addt* t);
static void p384pt_add_same_x_jac(
    jac384* acc, const p384_fe s1, const p384_fe s2);
static void p384pt_jac_add_step(jac384* acc, const jac384* base);
static int  p384pt_scalar_bit(const u8 k[48], usz bit);
static void p384pt_ec_mul_step(
    jac384* acc, const u8 k[48], const jac384* base, usz bit);
static void p384pt_jac_to_affine(ec_point384* r, const jac384* j);
static int  p384pt_point_add_special(
    ec_point384* r, const ec_point384* p, const ec_point384* q);

/* Finish addition given the cross terms and H = U2-U1, rr = 2(S2-S1). */
static void p384pt_add_finish(jac384* r, const p384_addt* a) {
  p384_fe i, j, v, t;
  p384pt_fp_dbl(t, a->h);
  p384pt_fp_sqr(i, t); /* I = (2H)^2 */
  p384pt_fp_mul(j, a->h, i);
  p384pt_fp_mul(v, a->u1, i);
  p384pt_fp_sqr(r->X, a->rr);
  p384pt_fp_sub(r->X, r->X, j);
  p384pt_fp_dbl(t, v);
  p384pt_fp_sub(r->X, r->X, t);
  p384pt_fp_sub(t, v, r->X);
  p384pt_fp_mul(t, a->rr, t);
  p384pt_fp_mul(v, a->s1, j);
  p384pt_fp_dbl(v, v);
  p384pt_fp_sub(r->Y, t, v);
  p384pt_fp_sqr(t, a->zs);
  p384pt_fp_sub(t, t, a->z1z1);
  p384pt_fp_sub(t, t, a->z2z2);
  p384pt_fp_mul(r->Z, t, a->h);
}

/* r = p + q given the cross terms; assumes p != -q, p != q. */
static void p384pt_jac_add(jac384* r, p384_addt* t) {
  p384pt_fp_sub(t->h, t->u2, t->u1);
  p384pt_fp_sub(t->rr, t->s2, t->s1);
  p384pt_fp_dbl(t->rr, t->rr);
  p384pt_add_finish(r, t);
}

/* Same-x case: double if s1==s2 (acc==base), else infinity. */
static void p384pt_add_same_x_jac(
    jac384* acc, const p384_fe s1, const p384_fe s2) {
  if (fp384_eq(s1, s2)) {
    p384pt_jac_double(acc, acc);
  } else {
    p384pt_jac_set_inf(acc);
  }
}

/* acc += base, handling infinity and the doubling/inverse case. */
static void p384pt_jac_add_step(jac384* acc, const jac384* base) {
  p384_addt t;
  if (p384pt_jac_is_inf(acc)) {
    *acc = *base;
    return;
  }
  p384pt_add_uv(&t, acc, base);
  if (fp384_eq(t.u1, t.u2)) {
    p384pt_add_same_x_jac(acc, t.s1, t.s2);
  } else {
    p384pt_jac_add(acc, &t);
  }
}

/* Bit `bit` (MSB first) of a 48-byte big-endian scalar. */
static int p384pt_scalar_bit(const u8 k[48], usz bit) {
  return (k[bit / 8] >> (7 - (bit & 7))) & 1;
}

/* One scalar-bit step: acc = 2*acc, then += base if bit set. */
static void p384pt_ec_mul_step(
    jac384* acc, const u8 k[48], const jac384* base, usz bit) {
  p384pt_jac_double(acc, acc);
  if (p384pt_scalar_bit(k, bit)) {
    p384pt_jac_add_step(acc, base);
  }
}

/* Convert Jacobian back to affine: x = X/Z^2, y = Y/Z^3. */
static void p384pt_jac_to_affine(ec_point384* r, const jac384* j) {
  p384_fe zi, zi2, zi3;
  if (p384pt_jac_is_inf(j)) {
    r->inf = 1;
    return;
  }
  fp384_inv_p(zi, j->Z);
  p384pt_fp_sqr(zi2, zi);
  p384pt_fp_mul(zi3, zi2, zi);
  p384pt_fp_mul(r->x, j->X, zi2);
  p384pt_fp_mul(r->y, j->Y, zi3);
  r->inf = 0;
}

void p384_point_mul(ec_point384* r, const u8 k[48], const ec_point384* p) {
  jac384 acc, base;
  p384pt_jac_set_inf(&acc);
  for (usz i = 0; i < 6; i++) {
    acc.X[i] = acc.Y[i] = 0;
  }
  p384pt_jac_from_affine(&base, p);
  for (usz bit = 0; bit < 384; bit++) {
    p384pt_ec_mul_step(&acc, k, &base, bit);
  }
  p384pt_jac_to_affine(r, &acc);
}

/* Affine double via one Jacobian doubling (test/verify convenience). */
void p384_point_double(ec_point384* r, const ec_point384* p) {
  jac384 j, d;
  if (p->inf || fp384_is_zero(p->y)) {
    r->inf = 1;
    return;
  }
  p384pt_jac_from_affine(&j, p);
  p384pt_jac_double(&d, &j);
  p384pt_jac_to_affine(r, &d);
}

/* Affine add via Jacobian (handles infinity and the inverse pair). */
static int p384pt_point_add_special(
    ec_point384* r, const ec_point384* p, const ec_point384* q) {
  if (p->inf) {
    p384_point_set(r, q);
    return 1;
  }
  if (q->inf) {
    p384_point_set(r, p);
    return 1;
  }
  return 0;
}

void p384_point_add(
    ec_point384* r, const ec_point384* p, const ec_point384* q) {
  jac384 acc, base;
  if (p384pt_point_add_special(r, p, q)) {
    return;
  }
  p384pt_jac_from_affine(&acc, p);
  p384pt_jac_from_affine(&base, q);
  p384pt_jac_add_step(
      &acc, &base); /* handles p==q (double) and p==-q (infinity) */
  p384pt_jac_to_affine(r, &acc);
}
