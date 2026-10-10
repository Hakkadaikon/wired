#include "crypto/asymmetric/ecc/p521/p521_point.h"

/* FIPS 186-4 D.1.2.5 (cross-checked against `openssl ecparam -name
 * secp521r1 -param_enc explicit`). */
static const p521_fe p521_b = {
    0xef451fd46b503f00ULL, 0x3573df883d2c34f1ULL, 0x1652c0bd3bb1bf07ULL,
    0x56193951ec7e937bULL, 0xb8b489918ef109e1ULL, 0xa2da725b99b315f3ULL,
    0x929a21a0b68540eeULL, 0x953eb9618e1c9a1fULL, 0x0000000000000051ULL};
const p521_fe p521_gx = {
    0xf97e7e31c2e5bd66ULL, 0x3348b3c1856a429bULL, 0xfe1dc127a2ffa8deULL,
    0xa14b5e77efe75928ULL, 0xf828af606b4d3dbaULL, 0x9c648139053fb521ULL,
    0x9e3ecb662395b442ULL, 0x858e06b70404e9cdULL, 0x00000000000000c6ULL};
const p521_fe p521_gy = {
    0x88be94769fd16650ULL, 0x353c7086a272c240ULL, 0xc550b9013fad0761ULL,
    0x97ee72995ef42640ULL, 0x17afbd17273e662cULL, 0x98f54449579b4468ULL,
    0x5c8a5fb42c7d1bd9ULL, 0x39296a789a3bc004ULL, 0x0000000000000118ULL};

static void p521pt_add(p521_fe r, const p521_fe a, const p521_fe b) {
  fp521_add(r, a, b, p521_p);
}
static void p521pt_sub(p521_fe r, const p521_fe a, const p521_fe b) {
  fp521_sub(r, a, b, p521_p);
}
static void p521pt_dbl(p521_fe r, const p521_fe a) { p521pt_add(r, a, a); }
static void p521pt_sqr(p521_fe r, const p521_fe a) { fp521_mul_p(r, a, a); }

int p521_on_curve(const p521_fe x, const p521_fe y) {
  p521_fe lhs, rhs, t;
  p521pt_sqr(lhs, y);
  p521pt_sqr(t, x);
  fp521_mul_p(rhs, t, x);
  p521pt_dbl(t, x);
  p521pt_add(t, t, x); /* 3x */
  p521pt_sub(rhs, rhs, t);
  p521pt_add(rhs, rhs, p521_b);
  return fp521_eq(lhs, rhs);
}

/* Jacobian (X, Y, Z): x = X/Z^2, y = Y/Z^3; Z == 0 is infinity. */
typedef struct {
  p521_fe X, Y, Z;
} jac521;

static int p521pt_is_inf(const jac521* j) { return fp521_is_zero(j->Z); }

/* dbl-2001-b (a = -3): alpha = 3(X-Z^2)(X+Z^2), beta = X*Y^2. */
static void p521pt_double(jac521* r, const jac521* p) {
  p521_fe delta, gamma, beta, alpha, t, s;
  p521pt_sqr(delta, p->Z);
  p521pt_sqr(gamma, p->Y);
  fp521_mul_p(beta, p->X, gamma);
  p521pt_sub(t, p->X, delta);
  p521pt_add(s, p->X, delta);
  fp521_mul_p(alpha, t, s);
  p521pt_dbl(t, alpha);
  p521pt_add(alpha, alpha, t);
  p521pt_add(t, p->Y, p->Z); /* Z3 = (Y+Z)^2 - gamma - delta */
  p521pt_sqr(t, t);
  p521pt_sub(t, t, gamma);
  p521pt_sub(r->Z, t, delta);
  p521pt_dbl(s, beta);
  p521pt_dbl(s, s); /* 4 beta */
  p521pt_sqr(r->X, alpha);
  p521pt_sub(r->X, r->X, s);
  p521pt_sub(r->X, r->X, s); /* X3 = alpha^2 - 8 beta */
  p521pt_sub(s, s, r->X);
  fp521_mul_p(s, alpha, s);
  p521pt_sqr(t, gamma);
  p521pt_dbl(t, t);
  p521pt_dbl(t, t);
  p521pt_dbl(t, t); /* 8 gamma^2 */
  p521pt_sub(r->Y, s, t);
}

/* add-2007-bl intermediates. */
typedef struct {
  p521_fe u1, u2, s1, s2, z1z1, z2z2;
} p521_addt;

static void p521pt_add_uv(p521_addt* t, const jac521* p, const jac521* q) {
  p521pt_sqr(t->z1z1, p->Z);
  p521pt_sqr(t->z2z2, q->Z);
  fp521_mul_p(t->u1, p->X, t->z2z2);
  fp521_mul_p(t->u2, q->X, t->z1z1);
  fp521_mul_p(t->s1, p->Y, q->Z);
  fp521_mul_p(t->s1, t->s1, t->z2z2);
  fp521_mul_p(t->s2, q->Y, p->Z);
  fp521_mul_p(t->s2, t->s2, t->z1z1);
}

/* r = p + q for distinct x (u1 != u2). r may alias p. */
static void p521pt_add_distinct(
    jac521* r, const p521_addt* a, const jac521* p, const jac521* q) {
  p521_fe h, rr, i, j, v, t;
  p521pt_sub(h, a->u2, a->u1);
  p521pt_sub(rr, a->s2, a->s1);
  p521pt_dbl(rr, rr);
  p521pt_add(t, p->Z, q->Z); /* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) H */
  p521pt_sqr(t, t);
  p521pt_sub(t, t, a->z1z1);
  p521pt_sub(t, t, a->z2z2);
  fp521_mul_p(r->Z, t, h);
  p521pt_dbl(t, h);
  p521pt_sqr(i, t); /* I = (2H)^2 */
  fp521_mul_p(j, h, i);
  fp521_mul_p(v, a->u1, i);
  p521pt_sqr(r->X, rr);
  p521pt_sub(r->X, r->X, j);
  p521pt_sub(r->X, r->X, v);
  p521pt_sub(r->X, r->X, v);
  p521pt_sub(t, v, r->X);
  fp521_mul_p(t, rr, t);
  fp521_mul_p(v, a->s1, j);
  p521pt_dbl(v, v);
  p521pt_sub(r->Y, t, v);
}

/* acc += q with both finite: same x means double (same y) or infinity. */
static void p521pt_add_finite(jac521* acc, const jac521* q) {
  p521_addt t;
  p521pt_add_uv(&t, acc, q);
  if (!fp521_eq(t.u1, t.u2))
    p521pt_add_distinct(acc, &t, acc, q);
  else if (fp521_eq(t.s1, t.s2))
    p521pt_double(acc, acc);
  else
    fp521_set(acc->Z, (const u64[9]){0});
}

static void p521pt_add_step(jac521* acc, const jac521* q) {
  if (p521pt_is_inf(q)) return;
  if (p521pt_is_inf(acc))
    *acc = *q;
  else
    p521pt_add_finite(acc, q);
}

static int p521pt_bit(const p521_fe a, usz i) {
  return (int)((a[i / 64] >> (i & 63)) & 1);
}

static void p521pt_from_affine(jac521* j, const p521_fe x, const p521_fe y) {
  static const p521_fe one = {1};
  fp521_set(j->X, x);
  fp521_set(j->Y, y);
  fp521_set(j->Z, one);
}

/* Table index sel = bit(u1) | bit(u2) << 1 selects G, Q, or G + Q. */
static void p521pt_shamir(jac521* acc, const jac521 tab[4], const u64* u[2]) {
  for (usz i = 521; i-- > 0;) {
    usz sel = (usz)(p521pt_bit(u[0], i) | (p521pt_bit(u[1], i) << 1));
    p521pt_double(acc, acc);
    if (sel) p521pt_add_step(acc, &tab[sel]);
  }
}

int p521_mul2_x(
    p521_fe       rx,
    const p521_fe u1,
    const p521_fe u2,
    const p521_fe qx,
    const p521_fe qy) {
  jac521     tab[4], acc = {{0}, {0}, {0}};
  const u64* u[2] = {u1, u2};
  p521_fe    zi, zi2;
  p521pt_from_affine(&tab[1], p521_gx, p521_gy);
  p521pt_from_affine(&tab[2], qx, qy);
  tab[3] = tab[1];
  p521pt_add_step(&tab[3], &tab[2]);
  p521pt_shamir(&acc, tab, u);
  if (p521pt_is_inf(&acc)) return 0;
  fp521_inv(zi, acc.Z, p521_p);
  p521pt_sqr(zi2, zi);
  fp521_mul_p(rx, acc.X, zi2);
  return 1;
}
