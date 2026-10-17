#include "crypto/asymmetric/ecc/p521/p521_point_impl.h"

static void p521pt_add(p521_fe r, const p521_fe a, const p521_fe b);
static void p521pt_dbl_ab(
    p521_fe alpha, p521_fe beta, p521_fe gamma, p521_fe delta, const jac521* p);
static void p521pt_dbl_xy(
    jac521* r, const p521_fe alpha, const p521_fe beta, const p521_fe gamma);

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

void p521pt_sub(p521_fe r, const p521_fe a, const p521_fe b) {
  fp521_sub(r, a, b, p521_p);
}

void p521pt_dbl(p521_fe r, const p521_fe a) { p521pt_add(r, a, a); }

void p521pt_sqr(p521_fe r, const p521_fe a) { fp521_mul_p(r, a, a); }

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

int p521pt_is_inf(const jac521* j) { return fp521_is_zero(j->Z); }

/* dbl-2001-b (a = -3): alpha = 3(X-Z^2)(X+Z^2), beta = X*Y^2. */
static void p521pt_dbl_ab(
    p521_fe       alpha,
    p521_fe       beta,
    p521_fe       gamma,
    p521_fe       delta,
    const jac521* p) {
  p521_fe t, s;
  p521pt_sqr(delta, p->Z);
  p521pt_sqr(gamma, p->Y);
  fp521_mul_p(beta, p->X, gamma);
  p521pt_sub(t, p->X, delta);
  p521pt_add(s, p->X, delta);
  fp521_mul_p(alpha, t, s);
  p521pt_dbl(t, alpha);
  p521pt_add(alpha, alpha, t);
}

/* X3 = alpha^2 - 8 beta, Y3 = alpha (4 beta - X3) - 8 gamma^2. */
static void p521pt_dbl_xy(
    jac521* r, const p521_fe alpha, const p521_fe beta, const p521_fe gamma) {
  p521_fe t, s;
  p521pt_dbl(s, beta);
  p521pt_dbl(s, s); /* 4 beta */
  p521pt_sqr(r->X, alpha);
  p521pt_sub(r->X, r->X, s);
  p521pt_sub(r->X, r->X, s);
  p521pt_sub(s, s, r->X);
  fp521_mul_p(s, alpha, s);
  p521pt_sqr(t, gamma);
  p521pt_dbl(t, t);
  p521pt_dbl(t, t);
  p521pt_dbl(t, t); /* 8 gamma^2 */
  p521pt_sub(r->Y, s, t);
}

void p521pt_double(jac521* r, const jac521* p) {
  p521_fe delta, gamma, beta, alpha, t;
  p521pt_dbl_ab(alpha, beta, gamma, delta, p);
  p521pt_add(t, p->Y, p->Z); /* Z3 = (Y+Z)^2 - gamma - delta */
  p521pt_sqr(t, t);
  p521pt_sub(t, t, gamma);
  p521pt_sub(r->Z, t, delta);
  p521pt_dbl_xy(r, alpha, beta, gamma);
}

void p521pt_add_uv(p521_addt* t, const jac521* p, const jac521* q) {
  p521pt_sqr(t->z1z1, p->Z);
  p521pt_sqr(t->z2z2, q->Z);
  fp521_mul_p(t->u1, p->X, t->z2z2);
  fp521_mul_p(t->u2, q->X, t->z1z1);
  fp521_mul_p(t->s1, p->Y, q->Z);
  fp521_mul_p(t->s1, t->s1, t->z2z2);
  fp521_mul_p(t->s2, q->Y, p->Z);
  fp521_mul_p(t->s2, t->s2, t->z1z1);
}

/* Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) H. r may alias p. */
void p521pt_add_z(
    jac521*          r,
    const p521_addt* a,
    const jac521*    p,
    const jac521*    q,
    const p521_fe    h) {
  p521_fe t;
  p521pt_add(t, p->Z, q->Z);
  p521pt_sqr(t, t);
  p521pt_sub(t, t, a->z1z1);
  p521pt_sub(t, t, a->z2z2);
  fp521_mul_p(r->Z, t, h);
}
