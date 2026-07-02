#include "crypto/asymmetric/ecc/p384/p384_point.h"

/* FIPS 186-4 D.1.2.4 P-384 domain parameters. */
static const p384_fe p384_b = {0x2a85c8edd3ec2aefULL, 0xc656398d8a2ed19dULL,
                               0x0314088f5013875aULL, 0x181d9c6efe814112ULL,
                               0x988e056be3f82d19ULL, 0xb3312fa7e23ee7e4ULL};

const ec_point384 quic_p384_g = {
    {0x3a545e3872760ab7ULL, 0x5502f25dbf55296cULL, 0x59f741e082542a38ULL,
     0x6e1d3b628ba79b98ULL, 0x8eb1c71ef320ad74ULL, 0xaa87ca22be8b0537ULL},
    {0x7a431d7c90ea0e5fULL, 0x0a60b1ce1d7e819dULL, 0xe9da3113b5f0b8c0ULL,
     0xf8f41dbd289a147cULL, 0x5d9e98bf9292dc29ULL, 0x3617de4a96262c6fULL},
    0};

void quic_p384_point_set(ec_point384 *r, const ec_point384 *p) {
  quic_fp384_set(r->x, p->x);
  quic_fp384_set(r->y, p->y);
  r->inf = p->inf;
}

/* lhs = y^2, rhs = x^3 - 3x + b (all mod p). */
static void p384pt_rhs_lhs(p384_fe lhs, p384_fe rhs, const ec_point384 *p) {
  p384_fe x2, three_x, three = {3, 0, 0, 0, 0, 0};
  quic_fp384_sqr(lhs, p->y, quic_p384_p);
  quic_fp384_sqr(x2, p->x, quic_p384_p);
  quic_fp384_mul(rhs, (quic_fp384ab){x2, p->x}, quic_p384_p);
  quic_fp384_mul(three_x, (quic_fp384ab){three, p->x}, quic_p384_p);
  quic_fp384_sub(rhs, (quic_fp384ab){rhs, three_x}, quic_p384_p);
  quic_fp384_add(rhs, (quic_fp384ab){rhs, p384_b}, quic_p384_p);
}

int quic_p384_point_on_curve(const ec_point384 *p) {
  p384_fe lhs, rhs;
  if (p->inf) return 1;
  p384pt_rhs_lhs(lhs, rhs, p);
  return quic_fp384_eq(lhs, rhs);
}

/* Jacobian coordinates (X, Y, Z): x = X/Z^2, y = Y/Z^3; Z == 0 is infinity. */
typedef struct {
  p384_fe X, Y, Z;
} jac384;

#define FP_P384 quic_p384_p
/* The scalar loop runs thousands of these, so route through the fast Solinas
 * reduction, not the generic long-division reducer. */
static void p384pt_fp_mul(p384_fe r, const p384_fe a, const p384_fe b) {
  quic_fp384_mul_p(r, a, b);
}
static void p384pt_fp_sqr(p384_fe r, const p384_fe a) {
  quic_fp384_sqr_p(r, a);
}
static void p384pt_fp_sub(p384_fe r, const p384_fe a, const p384_fe b) {
  quic_fp384_sub(r, (quic_fp384ab){a, b}, FP_P384);
}
static void p384pt_fp_add(p384_fe r, const p384_fe a, const p384_fe b) {
  quic_fp384_add(r, (quic_fp384ab){a, b}, FP_P384);
}
static void p384pt_fp_dbl(p384_fe r, const p384_fe a) {
  p384pt_fp_add(r, a, a);
}

static void p384pt_jac_from_affine(jac384 *j, const ec_point384 *p) {
  quic_fp384_set(j->X, p->x);
  quic_fp384_set(j->Y, p->y);
  for (usz i = 0; i < 6; i++) j->Z[i] = 0;
  j->Z[0] = p->inf ? 0 : 1;
}

static void p384pt_jac_set_inf(jac384 *j) {
  for (usz i = 0; i < 6; i++) j->Z[i] = 0;
}

static int p384pt_jac_is_inf(const jac384 *j) {
  return quic_fp384_is_zero(j->Z);
}

/* X3 = alpha^2 - 8*beta. */
static void p384pt_dbl_x(p384_fe x3, const p384_fe alpha, const p384_fe beta) {
  p384_fe t;
  p384pt_fp_sqr(x3, alpha);
  p384pt_fp_dbl(t, beta);
  p384pt_fp_dbl(t, t);
  p384pt_fp_dbl(t, t); /* 8*beta */
  p384pt_fp_sub(x3, x3, t);
}

/* Doubling intermediates alpha, beta, gamma (borrowed limb pointers). */
typedef struct {
  const u64 *alpha, *beta, *gamma;
} p384_dblv;

/* Y3 = alpha*(4*beta - X3) - 8*gamma^2. */
static void p384pt_dbl_y(p384_fe y3, const p384_fe x3, const p384_dblv *d) {
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
static void p384pt_jac_double(jac384 *r, const jac384 *p) {
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

/* Intermediates shared between the two halves of Jacobian addition. */
typedef struct {
  p384_fe u1, u2, s1, s2; /* cross terms */
  p384_fe z1z1, z2z2, zs; /* Z1^2, Z2^2, Z1+Z2 */
  p384_fe h, rr;          /* U2-U1, 2(S2-S1) */
} p384_addt;

/* Cross terms U1,U2,S1,S2 (plus the Z terms) for Jacobian addition. */
static void p384pt_add_uv(p384_addt *t, const jac384 *p, const jac384 *q) {
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

/* Finish addition given the cross terms and H = U2-U1, rr = 2(S2-S1). */
static void p384pt_add_finish(jac384 *r, const p384_addt *a) {
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
static void p384pt_jac_add(jac384 *r, p384_addt *t) {
  p384pt_fp_sub(t->h, t->u2, t->u1);
  p384pt_fp_sub(t->rr, t->s2, t->s1);
  p384pt_fp_dbl(t->rr, t->rr);
  p384pt_add_finish(r, t);
}

/* Same-x case: double if s1==s2 (acc==base), else infinity. */
static void p384pt_add_same_x_jac(
    jac384 *acc, const p384_fe s1, const p384_fe s2) {
  if (quic_fp384_eq(s1, s2))
    p384pt_jac_double(acc, acc);
  else
    p384pt_jac_set_inf(acc);
}

/* acc += base, handling infinity and the doubling/inverse case. */
static void p384pt_jac_add_step(jac384 *acc, const jac384 *base) {
  p384_addt t;
  if (p384pt_jac_is_inf(acc)) {
    *acc = *base;
    return;
  }
  p384pt_add_uv(&t, acc, base);
  if (quic_fp384_eq(t.u1, t.u2))
    p384pt_add_same_x_jac(acc, t.s1, t.s2);
  else
    p384pt_jac_add(acc, &t);
}

/* Bit `bit` (MSB first) of a 48-byte big-endian scalar. */
static int p384pt_scalar_bit(const u8 k[48], usz bit) {
  return (k[bit / 8] >> (7 - (bit & 7))) & 1;
}

/* One scalar-bit step: acc = 2*acc, then += base if bit set. */
static void p384pt_ec_mul_step(
    jac384 *acc, const u8 k[48], const jac384 *base, usz bit) {
  p384pt_jac_double(acc, acc);
  if (p384pt_scalar_bit(k, bit)) p384pt_jac_add_step(acc, base);
}

/* Convert Jacobian back to affine: x = X/Z^2, y = Y/Z^3. */
static void p384pt_jac_to_affine(ec_point384 *r, const jac384 *j) {
  p384_fe zi, zi2, zi3;
  if (p384pt_jac_is_inf(j)) {
    r->inf = 1;
    return;
  }
  quic_fp384_inv_p(zi, j->Z);
  p384pt_fp_sqr(zi2, zi);
  p384pt_fp_mul(zi3, zi2, zi);
  p384pt_fp_mul(r->x, j->X, zi2);
  p384pt_fp_mul(r->y, j->Y, zi3);
  r->inf = 0;
}

void quic_p384_point_mul(ec_point384 *r, const u8 k[48], const ec_point384 *p) {
  jac384 acc, base;
  p384pt_jac_set_inf(&acc);
  for (usz i = 0; i < 6; i++) acc.X[i] = acc.Y[i] = 0;
  p384pt_jac_from_affine(&base, p);
  for (usz bit = 0; bit < 384; bit++) p384pt_ec_mul_step(&acc, k, &base, bit);
  p384pt_jac_to_affine(r, &acc);
}

/* Affine double via one Jacobian doubling (test/verify convenience). */
void quic_p384_point_double(ec_point384 *r, const ec_point384 *p) {
  jac384 j, d;
  if (p->inf || quic_fp384_is_zero(p->y)) {
    r->inf = 1;
    return;
  }
  p384pt_jac_from_affine(&j, p);
  p384pt_jac_double(&d, &j);
  p384pt_jac_to_affine(r, &d);
}

/* Affine add via Jacobian (handles infinity and the inverse pair). */
static int p384pt_point_add_special(
    ec_point384 *r, const ec_point384 *p, const ec_point384 *q) {
  if (p->inf) {
    quic_p384_point_set(r, q);
    return 1;
  }
  if (q->inf) {
    quic_p384_point_set(r, p);
    return 1;
  }
  return 0;
}

void quic_p384_point_add(
    ec_point384 *r, const ec_point384 *p, const ec_point384 *q) {
  jac384 acc, base;
  if (p384pt_point_add_special(r, p, q)) return;
  p384pt_jac_from_affine(&acc, p);
  p384pt_jac_from_affine(&base, q);
  p384pt_jac_add_step(
      &acc, &base); /* handles p==q (double) and p==-q (infinity) */
  p384pt_jac_to_affine(r, &acc);
}
