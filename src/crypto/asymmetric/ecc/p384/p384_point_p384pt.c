#include "crypto/asymmetric/ecc/p384/p384_point_impl.h"

static void p384pt_fp_add(p384_fe r, const p384_fe a, const p384_fe b);
static void p384pt_dbl_x(p384_fe x3, const p384_fe alpha, const p384_fe beta);
static void p384pt_dbl_y(p384_fe y3, const p384_fe x3, const p384_dblv* d);

/* The scalar loop runs thousands of these, so route through the fast Solinas
 * reduction, not the generic long-division reducer. */
void p384pt_fp_mul(p384_fe r, const p384_fe a, const p384_fe b) {
  fp384_mul_p(r, a, b);
}

void p384pt_fp_sqr(p384_fe r, const p384_fe a) { fp384_sqr_p(r, a); }

void p384pt_fp_sub(p384_fe r, const p384_fe a, const p384_fe b) {
  fp384_sub(r, (fp384ab){a, b}, FP_P384);
}

static void p384pt_fp_add(p384_fe r, const p384_fe a, const p384_fe b) {
  fp384_add(r, (fp384ab){a, b}, FP_P384);
}

void p384pt_fp_dbl(p384_fe r, const p384_fe a) { p384pt_fp_add(r, a, a); }

void p384pt_jac_from_affine(jac384* j, const ec_point384* p) {
  fp384_set(j->X, p->x);
  fp384_set(j->Y, p->y);
  for (usz i = 0; i < 6; i++) j->Z[i] = 0;
  j->Z[0] = p->inf ? 0 : 1;
}

void p384pt_jac_set_inf(jac384* j) {
  for (usz i = 0; i < 6; i++) j->Z[i] = 0;
}

int p384pt_jac_is_inf(const jac384* j) { return fp384_is_zero(j->Z); }

/* X3 = alpha^2 - 8*beta. */
static void p384pt_dbl_x(p384_fe x3, const p384_fe alpha, const p384_fe beta) {
  p384_fe t;
  p384pt_fp_sqr(x3, alpha);
  p384pt_fp_dbl(t, beta);
  p384pt_fp_dbl(t, t);
  p384pt_fp_dbl(t, t); /* 8*beta */
  p384pt_fp_sub(x3, x3, t);
}

/* Y3 = alpha*(4*beta - X3) - 8*gamma^2. */
static void p384pt_dbl_y(p384_fe y3, const p384_fe x3, const p384_dblv* d) {
  p384_fe t, g2;
  p384pt_fp_dbl(t, d->beta);
  p384pt_fp_dbl(t, t); /* 4*beta */
  p384pt_fp_sub(t, t, x3);
  p384pt_fp_mul(t, d->alpha, t);
  p384pt_fp_sqr(g2, d->gamma);
  p384pt_fp_dbl(g2, g2);
  p384pt_fp_dbl(g2, g2);
  p384pt_fp_dbl(g2, g2); /* 8*gamma^2 */
  p384pt_fp_sub(y3, t, g2);
}

/* r = 2*p (a = -3 doubling, dbl-2001-b). */
void p384pt_jac_double(jac384* r, const jac384* p) {
  p384_fe delta, gamma, beta, alpha, t, s;
  p384pt_fp_sqr(delta, p->Z);
  p384pt_fp_sqr(gamma, p->Y);
  p384pt_fp_mul(beta, p->X, gamma);
  p384pt_fp_sub(t, p->X, delta);
  p384pt_fp_add(s, p->X, delta);
  p384pt_fp_mul(alpha, t, s);
  p384pt_fp_dbl(t, alpha);
  p384pt_fp_add(alpha, alpha, t); /* 3*(X-d)(X+d) */
  p384pt_dbl_x(r->X, alpha, beta);
  p384pt_fp_add(t, p->Y, p->Z);
  p384pt_fp_sqr(t, t);
  p384pt_fp_sub(t, t, gamma);
  p384pt_fp_sub(r->Z, t, delta);
  p384pt_dbl_y(r->Y, r->X, &(p384_dblv){alpha, beta, gamma});
}

/* Cross terms U1,U2,S1,S2 (plus the Z terms) for Jacobian addition. */
void p384pt_add_uv(p384_addt* t, const jac384* p, const jac384* q) {
  p384pt_fp_sqr(t->z1z1, p->Z);
  p384pt_fp_sqr(t->z2z2, q->Z);
  p384pt_fp_mul(t->u1, p->X, t->z2z2);
  p384pt_fp_mul(t->u2, q->X, t->z1z1);
  p384pt_fp_mul(t->s1, p->Y, q->Z);
  p384pt_fp_mul(t->s1, t->s1, t->z2z2);
  p384pt_fp_mul(t->s2, q->Y, p->Z);
  p384pt_fp_mul(t->s2, t->s2, t->z1z1);
  p384pt_fp_add(t->zs, p->Z, q->Z);
}
