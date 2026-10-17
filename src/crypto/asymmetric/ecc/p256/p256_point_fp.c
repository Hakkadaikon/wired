#include "crypto/asymmetric/ecc/p256/p256_point_impl.h"

static void fp_add(p256_fe r, const p256_fe a, const p256_fe b);
static void dbl_x(p256_fe x3, const p256_fe alpha, const p256_fe beta);
static void dbl_y(p256_fe y3, const p256_fe x3, const p256_dblv* d);

/* The scalar loop runs thousands of these, so use the fast P-256 Solinas
 * reduction (p256_fp_mul_p) rather than the generic long-division reducer —
 * the difference is ~885ms vs a few ms per scalar multiply. */
void p256pt_fp_mul(p256_fe r, const p256_fe a, const p256_fe b) {
  p256_fp_mul_p(r, a, b);
}

void p256pt_fp_sqr(p256_fe r, const p256_fe a) { p256_fp_sqr_p(r, a); }

void p256pt_fp_sub(p256_fe r, const p256_fe a, const p256_fe b) {
  p256_fp_sub(r, (fpab){a, b}, FP_P);
}

static void fp_add(p256_fe r, const p256_fe a, const p256_fe b) {
  p256_fp_add(r, (fpab){a, b}, FP_P);
}

void p256pt_fp_dbl(p256_fe r, const p256_fe a) { fp_add(r, a, a); }

void p256pt_jac_from_affine(jac* j, const ec_point* p) {
  p256_fp_set(j->X, p->x);
  p256_fp_set(j->Y, p->y);
  j->Z[0] = 1;
  j->Z[1] = j->Z[2] = j->Z[3] = 0;
  if (p->inf) {
    j->Z[0] = 0;
  }
}

int p256pt_jac_is_inf(const jac* j) { return p256_fp_is_zero(j->Z); }

/* X3 = alpha^2 - 8*beta; helper to keep doubling under CCN 3. */
static void dbl_x(p256_fe x3, const p256_fe alpha, const p256_fe beta) {
  p256_fe t;
  p256pt_fp_sqr(x3, alpha);
  p256pt_fp_dbl(t, beta);
  p256pt_fp_dbl(t, t);
  p256pt_fp_dbl(t, t); /* 8*beta */
  p256pt_fp_sub(x3, x3, t);
}

/* Y3 = alpha*(4*beta - X3) - 8*gamma^2. */
static void dbl_y(p256_fe y3, const p256_fe x3, const p256_dblv* d) {
  p256_fe t, g2;
  p256pt_fp_dbl(t, d->beta);
  p256pt_fp_dbl(t, t); /* 4*beta */
  p256pt_fp_sub(t, t, x3);
  p256pt_fp_mul(t, d->alpha, t);
  p256pt_fp_sqr(g2, d->gamma);
  p256pt_fp_dbl(g2, g2);
  p256pt_fp_dbl(g2, g2);
  p256pt_fp_dbl(g2, g2); /* 8*gamma^2 */
  p256pt_fp_sub(y3, t, g2);
}

/* r = 2*p (a = -3 doubling formulas, dbl-2001-b). */
void p256pt_jac_double(jac* r, const jac* p) {
  p256_fe delta, gamma, beta, alpha, t, s;
  p256pt_fp_sqr(delta, p->Z);
  p256pt_fp_sqr(gamma, p->Y);
  p256pt_fp_mul(beta, p->X, gamma);
  p256pt_fp_sub(t, p->X, delta);
  fp_add(s, p->X, delta);
  p256pt_fp_mul(alpha, t, s);
  p256pt_fp_dbl(t, alpha);
  fp_add(alpha, alpha, t); /* 3*(X-d)(X+d) */
  dbl_x(r->X, alpha, beta);
  fp_add(t, p->Y, p->Z);
  p256pt_fp_sqr(t, t);
  p256pt_fp_sub(t, t, gamma);
  p256pt_fp_sub(r->Z, t, delta);
  dbl_y(r->Y, r->X, &(p256_dblv){alpha, beta, gamma});
}

/* Cross terms U1,U2,S1,S2 (plus the Z terms) for Jacobian addition. */
void p256pt_add_uv(p256_addt* t, const jac* p, const jac* q) {
  p256pt_fp_sqr(t->z1z1, p->Z);
  p256pt_fp_sqr(t->z2z2, q->Z);
  p256pt_fp_mul(t->u1, p->X, t->z2z2);
  p256pt_fp_mul(t->u2, q->X, t->z1z1);
  p256pt_fp_mul(t->s1, p->Y, q->Z);
  p256pt_fp_mul(t->s1, t->s1, t->z2z2);
  p256pt_fp_mul(t->s2, q->Y, p->Z);
  p256pt_fp_mul(t->s2, t->s2, t->z1z1);
  fp_add(t->zs, p->Z, q->Z);
}
