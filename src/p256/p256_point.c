#include "p256/p256_point.h"

/* FIPS 186-4 D.1.2.3 P-256 domain parameters. */
static const p256_fe p256_b = {
    0x3bce3c3e27d2604bULL, 0x651d06b0cc53b0f6ULL,
    0xb3ebbd55769886bcULL, 0x5ac635d8aa3a93e7ULL
};

const ec_point quic_p256_g = {
    {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL,
     0xf8bce6e563a440f2ULL, 0x6b17d1f2e12c4247ULL},
    {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL,
     0x8ee7eb4a7c0f9e16ULL, 0x4fe342e2fe1a7f9bULL},
    0
};

void quic_ec_set(ec_point *r, const ec_point *p)
{
    quic_fp_set(r->x, p->x);
    quic_fp_set(r->y, p->y);
    r->inf = p->inf;
}

/* y^2 mod p. */
static void rhs_lhs(p256_fe lhs, p256_fe rhs, const ec_point *p)
{
    p256_fe x2, three_x, three = {3, 0, 0, 0};
    quic_fp_sqr(lhs, p->y, quic_p256_p);                 /* y^2 */
    quic_fp_sqr(x2, p->x, quic_p256_p);                  /* x^2 */
    quic_fp_mul(rhs, x2, p->x, quic_p256_p);             /* x^3 */
    quic_fp_mul(three_x, three, p->x, quic_p256_p);      /* 3x  */
    quic_fp_sub(rhs, rhs, three_x, quic_p256_p);         /* x^3 - 3x */
    quic_fp_add(rhs, rhs, p256_b, quic_p256_p);          /* + b */
}

int quic_ec_on_curve(const ec_point *p)
{
    p256_fe lhs, rhs;
    if (p->inf) return 1;
    rhs_lhs(lhs, rhs, p);
    return quic_fp_eq(lhs, rhs);
}

/* lambda = (y2 - y1) / (x2 - x1); caller guarantees x1 != x2. */
static void slope_add(p256_fe lam, const ec_point *p, const ec_point *q)
{
    p256_fe num, den, inv;
    quic_fp_sub(num, q->y, p->y, quic_p256_p);
    quic_fp_sub(den, q->x, p->x, quic_p256_p);
    quic_fp_inv(inv, den, quic_p256_p);
    quic_fp_mul(lam, num, inv, quic_p256_p);
}

/* lambda = (3x^2 - 3) / (2y). */
static void slope_double(p256_fe lam, const ec_point *p)
{
    p256_fe x2, num, den, inv, three = {3, 0, 0, 0};
    quic_fp_sqr(x2, p->x, quic_p256_p);
    quic_fp_mul(num, three, x2, quic_p256_p);
    quic_fp_sub(num, num, three, quic_p256_p);           /* 3x^2 - 3 (a=-3) */
    quic_fp_add(den, p->y, p->y, quic_p256_p);
    quic_fp_inv(inv, den, quic_p256_p);
    quic_fp_mul(lam, num, inv, quic_p256_p);
}

/* From slope lambda and the two source x-coords, produce r = (x3,y3). */
static void from_slope(ec_point *r, const p256_fe lam, const p256_fe x1, const p256_fe y1,
                       const p256_fe x2)
{
    p256_fe x3, t;
    quic_fp_sqr(x3, lam, quic_p256_p);
    quic_fp_sub(x3, x3, x1, quic_p256_p);
    quic_fp_sub(x3, x3, x2, quic_p256_p);                /* x3 = lam^2 - x1 - x2 */
    quic_fp_sub(t, x1, x3, quic_p256_p);
    quic_fp_mul(t, lam, t, quic_p256_p);
    quic_fp_sub(r->y, t, y1, quic_p256_p);               /* y3 = lam(x1-x3) - y1 */
    quic_fp_set(r->x, x3);
    r->inf = 0;
}

void quic_ec_double(ec_point *r, const ec_point *p)
{
    p256_fe lam, x1, y1;
    if (p->inf || quic_fp_is_zero(p->y)) { r->inf = 1; return; }
    quic_fp_set(x1, p->x); quic_fp_set(y1, p->y);
    slope_double(lam, p);
    from_slope(r, lam, x1, y1, x1);
}

/* p and q are not infinity and not mutually inverse: distinct addition. */
static void add_distinct(ec_point *r, const ec_point *p, const ec_point *q)
{
    p256_fe lam, x1, y1, x2;
    quic_fp_set(x1, p->x); quic_fp_set(y1, p->y); quic_fp_set(x2, q->x);
    slope_add(lam, p, q);
    from_slope(r, lam, x1, y1, x2);
}

/* 1 if p and q have equal x but are not equal points (sum is infinity). */
static int is_inverse_pair(const ec_point *p, const ec_point *q)
{
    return quic_fp_eq(p->x, q->x) && !quic_fp_eq(p->y, q->y);
}

/* Same x: result is either infinity (inverse pair) or 2p (p == q). */
static void add_same_x(ec_point *r, const ec_point *p, const ec_point *q)
{
    if (is_inverse_pair(p, q)) r->inf = 1;
    else quic_ec_double(r, p);
}

/* Handle an infinity operand. Returns 1 if r was set, 0 if both are finite. */
static int add_infinity(ec_point *r, const ec_point *p, const ec_point *q)
{
    if (p->inf) quic_ec_set(r, q);
    else if (q->inf) quic_ec_set(r, p);
    else return 0;
    return 1;
}

void quic_ec_add(ec_point *r, const ec_point *p, const ec_point *q)
{
    if (add_infinity(r, p, q)) return;
    if (quic_fp_eq(p->x, q->x)) add_same_x(r, p, q);
    else add_distinct(r, p, q);
}

/* Jacobian coordinates (X, Y, Z): x = X/Z^2, y = Y/Z^3; Z == 0 is infinity.
 * Used only by quic_ec_mul so the scalar loop needs no per-step inversion. */
typedef struct { p256_fe X, Y, Z; } jac;

#define FP_P quic_p256_p
static void fp_mul(p256_fe r, const p256_fe a, const p256_fe b) { quic_fp_mul(r, a, b, FP_P); }
static void fp_sqr(p256_fe r, const p256_fe a) { quic_fp_sqr(r, a, FP_P); }
static void fp_sub(p256_fe r, const p256_fe a, const p256_fe b) { quic_fp_sub(r, a, b, FP_P); }
static void fp_add(p256_fe r, const p256_fe a, const p256_fe b) { quic_fp_add(r, a, b, FP_P); }
static void fp_dbl(p256_fe r, const p256_fe a) { fp_add(r, a, a); }

static void jac_from_affine(jac *j, const ec_point *p)
{
    quic_fp_set(j->X, p->x); quic_fp_set(j->Y, p->y);
    j->Z[0] = 1; j->Z[1] = j->Z[2] = j->Z[3] = 0;
    if (p->inf) { j->Z[0] = 0; }
}

static int jac_is_inf(const jac *j) { return quic_fp_is_zero(j->Z); }

/* X3 = alpha^2 - 8*beta; helper to keep doubling under CCN 3. */
static void dbl_x(p256_fe x3, const p256_fe alpha, const p256_fe beta)
{
    p256_fe t;
    fp_sqr(x3, alpha);
    fp_dbl(t, beta); fp_dbl(t, t); fp_dbl(t, t);   /* 8*beta */
    fp_sub(x3, x3, t);
}

/* Y3 = alpha*(4*beta - X3) - 8*gamma^2. */
static void dbl_y(p256_fe y3, const p256_fe alpha, const p256_fe beta, const p256_fe x3, const p256_fe gamma)
{
    p256_fe t, g2;
    fp_dbl(t, beta); fp_dbl(t, t);                 /* 4*beta */
    fp_sub(t, t, x3);
    fp_mul(t, alpha, t);
    fp_sqr(g2, gamma); fp_dbl(g2, g2); fp_dbl(g2, g2); fp_dbl(g2, g2); /* 8*gamma^2 */
    fp_sub(y3, t, g2);
}

/* r = 2*p (a = -3 doubling formulas, dbl-2001-b). */
static void jac_double(jac *r, const jac *p)
{
    p256_fe delta, gamma, beta, alpha, t, s;
    fp_sqr(delta, p->Z); fp_sqr(gamma, p->Y); fp_mul(beta, p->X, gamma);
    fp_sub(t, p->X, delta); fp_add(s, p->X, delta);
    fp_mul(alpha, t, s); fp_dbl(t, alpha); fp_add(alpha, alpha, t);   /* 3*(X-d)(X+d) */
    dbl_x(r->X, alpha, beta);
    fp_add(t, p->Y, p->Z); fp_sqr(t, t); fp_sub(t, t, gamma); fp_sub(r->Z, t, delta);
    dbl_y(r->Y, alpha, beta, r->X, gamma);
}

/* Cross terms U1,U2,S1,S2 for Jacobian addition. */
static void add_uv(p256_fe u1, p256_fe u2, p256_fe s1, p256_fe s2, const jac *p, const jac *q)
{
    p256_fe z1z1, z2z2;
    fp_sqr(z1z1, p->Z); fp_sqr(z2z2, q->Z);
    fp_mul(u1, p->X, z2z2); fp_mul(u2, q->X, z1z1);
    fp_mul(s1, p->Y, q->Z); fp_mul(s1, s1, z2z2);
    fp_mul(s2, q->Y, p->Z); fp_mul(s2, s2, z1z1);
}

/* Finish addition given H = U2-U1, rr = 2(S2-S1). */
static void add_finish(jac *r, const jac *p, const jac *q,
                       const p256_fe u1, const p256_fe s1, const p256_fe h, const p256_fe rr)
{
    p256_fe i, j, v, t;
    fp_dbl(t, h); fp_sqr(i, t);                    /* I = (2H)^2 */
    fp_mul(j, h, i); fp_mul(v, u1, i);
    fp_sqr(r->X, rr); fp_sub(r->X, r->X, j);
    fp_dbl(t, v); fp_sub(r->X, r->X, t);
    fp_sub(t, v, r->X); fp_mul(t, rr, t);
    fp_mul(v, s1, j); fp_dbl(v, v); fp_sub(r->Y, t, v);
    fp_add(t, p->Z, q->Z); fp_sqr(t, t);
    fp_sqr(v, p->Z); fp_sub(t, t, v); fp_sqr(v, q->Z); fp_sub(t, t, v);
    fp_mul(r->Z, t, h);
}

/* r = p + q in Jacobian; assumes neither is infinity and p != -q, p != q. */
static void jac_add(jac *r, const jac *p, const jac *q)
{
    p256_fe u1, u2, s1, s2, h, rr;
    add_uv(u1, u2, s1, s2, p, q);
    fp_sub(h, u2, u1); fp_sub(rr, s2, s1); fp_dbl(rr, rr);
    add_finish(r, p, q, u1, s1, h, rr);
}

/* Same-x case: double if s1==s2 (acc==base), else result is infinity. */
static void add_same_x_jac(jac *acc, const p256_fe s1, const p256_fe s2)
{
    if (quic_fp_eq(s1, s2)) jac_double(acc, acc);
    else acc->Z[0] = acc->Z[1] = acc->Z[2] = acc->Z[3] = 0;
}

/* acc += base, handling infinity and the doubling/inverse case. */
static void jac_add_step(jac *acc, const jac *base)
{
    p256_fe u1, u2, s1, s2;
    if (jac_is_inf(acc)) { *acc = *base; return; }
    add_uv(u1, u2, s1, s2, acc, base);
    if (quic_fp_eq(u1, u2)) add_same_x_jac(acc, s1, s2);
    else jac_add(acc, acc, base);
}

/* One scalar-bit step: acc = 2*acc, then += base if bit set. */
static void ec_mul_step(jac *acc, const u8 k[32], const jac *base, usz bit)
{
    jac_double(acc, acc);
    if ((k[bit / 8] >> (7 - (bit & 7))) & 1) jac_add_step(acc, base);
}

/* Convert Jacobian back to affine: x = X/Z^2, y = Y/Z^3. */
static void jac_to_affine(ec_point *r, const jac *j)
{
    p256_fe zi, zi2, zi3;
    if (jac_is_inf(j)) { r->inf = 1; return; }
    quic_fp_inv(zi, j->Z, FP_P);
    fp_sqr(zi2, zi); fp_mul(zi3, zi2, zi);
    fp_mul(r->x, j->X, zi2); fp_mul(r->y, j->Y, zi3);
    r->inf = 0;
}

void quic_ec_mul(ec_point *r, const u8 k[32], const ec_point *p)
{
    jac acc, base;
    jac_from_affine(&base, p);
    acc.Z[0] = acc.Z[1] = acc.Z[2] = acc.Z[3] = 0;   /* infinity */
    for (usz bit = 0; bit < 256; bit++) ec_mul_step(&acc, k, &base, bit);
    jac_to_affine(r, &acc);
}
