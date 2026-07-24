#include "crypto/asymmetric/ecc/p256/p256_point.h"

/* FIPS 186-4 D.1.2.3 P-256 domain parameters. */
static const p256_fe p256_b = {
    0x3bce3c3e27d2604bULL, 0x651d06b0cc53b0f6ULL, 0xb3ebbd55769886bcULL,
    0x5ac635d8aa3a93e7ULL};

const ec_point quic_p256_g = {
    {0xf4a13945d898c296ULL, 0x77037d812deb33a0ULL, 0xf8bce6e563a440f2ULL,
     0x6b17d1f2e12c4247ULL},
    {0xcbb6406837bf51f5ULL, 0x2bce33576b315eceULL, 0x8ee7eb4a7c0f9e16ULL,
     0x4fe342e2fe1a7f9bULL},
    0};

void quic_ec_set(ec_point* r, const ec_point* p) {
  quic_fp_set(r->x, p->x);
  quic_fp_set(r->y, p->y);
  r->inf = p->inf;
}

/* y^2 mod p. */
static void rhs_lhs(p256_fe lhs, p256_fe rhs, const ec_point* p) {
  p256_fe x2, three_x, three = {3, 0, 0, 0};
  quic_fp_sqr(lhs, p->y, quic_p256_p);                         /* y^2 */
  quic_fp_sqr(x2, p->x, quic_p256_p);                          /* x^2 */
  quic_fp_mul(rhs, (quic_fpab){x2, p->x}, quic_p256_p);        /* x^3 */
  quic_fp_mul(three_x, (quic_fpab){three, p->x}, quic_p256_p); /* 3x  */
  quic_fp_sub(rhs, (quic_fpab){rhs, three_x}, quic_p256_p);    /* x^3 - 3x */
  quic_fp_add(rhs, (quic_fpab){rhs, p256_b}, quic_p256_p);     /* + b */
}

int quic_ec_on_curve(const ec_point* p) {
  p256_fe lhs, rhs;
  if (p->inf) return 1;
  rhs_lhs(lhs, rhs, p);
  return quic_fp_eq(lhs, rhs);
}

/* lambda = (y2 - y1) / (x2 - x1); caller guarantees x1 != x2. */
static void slope_add(p256_fe lam, const ec_point* p, const ec_point* q) {
  p256_fe num, den, inv;
  quic_fp_sub(num, (quic_fpab){q->y, p->y}, quic_p256_p);
  quic_fp_sub(den, (quic_fpab){q->x, p->x}, quic_p256_p);
  quic_fp_inv(inv, den, quic_p256_p);
  quic_fp_mul(lam, (quic_fpab){num, inv}, quic_p256_p);
}

/* lambda = (3x^2 - 3) / (2y). */
static void slope_double(p256_fe lam, const ec_point* p) {
  p256_fe x2, num, den, inv, three = {3, 0, 0, 0};
  quic_fp_sqr(x2, p->x, quic_p256_p);
  quic_fp_mul(num, (quic_fpab){three, x2}, quic_p256_p);
  quic_fp_sub(num, (quic_fpab){num, three}, quic_p256_p); /* 3x^2 - 3 (a=-3) */
  quic_fp_add(den, (quic_fpab){p->y, p->y}, quic_p256_p);
  quic_fp_inv(inv, den, quic_p256_p);
  quic_fp_mul(lam, (quic_fpab){num, inv}, quic_p256_p);
}

/* Slope lambda and the source coordinates of an affine addition; copies so
 * the result point may alias an operand. */
typedef struct {
  p256_fe lam, x1, y1, x2;
} p256_slope;

/* From the slope and source x-coords, produce r = (x3,y3). */
static void from_slope(ec_point* r, const p256_slope* sl) {
  p256_fe x3, t;
  quic_fp_sqr(x3, sl->lam, quic_p256_p);
  quic_fp_sub(x3, (quic_fpab){x3, sl->x1}, quic_p256_p);
  quic_fp_sub(x3, (quic_fpab){x3, sl->x2}, quic_p256_p); /* lam^2 - x1 - x2 */
  quic_fp_sub(t, (quic_fpab){sl->x1, x3}, quic_p256_p);
  quic_fp_mul(t, (quic_fpab){sl->lam, t}, quic_p256_p);
  quic_fp_sub(r->y, (quic_fpab){t, sl->y1}, quic_p256_p); /* lam(x1-x3) - y1 */
  quic_fp_set(r->x, x3);
  r->inf = 0;
}

void quic_ec_double(ec_point* r, const ec_point* p) {
  p256_slope sl;
  if (p->inf || quic_fp_is_zero(p->y)) {
    r->inf = 1;
    return;
  }
  quic_fp_set(sl.x1, p->x);
  quic_fp_set(sl.y1, p->y);
  quic_fp_set(sl.x2, p->x);
  slope_double(sl.lam, p);
  from_slope(r, &sl);
}

/* p and q are not infinity and not mutually inverse: distinct addition. */
static void add_distinct(ec_point* r, const ec_point* p, const ec_point* q) {
  p256_slope sl;
  quic_fp_set(sl.x1, p->x);
  quic_fp_set(sl.y1, p->y);
  quic_fp_set(sl.x2, q->x);
  slope_add(sl.lam, p, q);
  from_slope(r, &sl);
}

/* 1 if p and q have equal x but are not equal points (sum is infinity). */
static int is_inverse_pair(const ec_point* p, const ec_point* q) {
  return quic_fp_eq(p->x, q->x) && !quic_fp_eq(p->y, q->y);
}

/* Same x: result is either infinity (inverse pair) or 2p (p == q). */
static void add_same_x(ec_point* r, const ec_point* p, const ec_point* q) {
  if (is_inverse_pair(p, q))
    r->inf = 1;
  else
    quic_ec_double(r, p);
}

/* Handle an infinity operand. Returns 1 if r was set, 0 if both are finite. */
static int add_infinity(ec_point* r, const ec_point* p, const ec_point* q) {
  if (p->inf)
    quic_ec_set(r, q);
  else if (q->inf)
    quic_ec_set(r, p);
  else
    return 0;
  return 1;
}

void quic_ec_add(ec_point* r, const ec_point* p, const ec_point* q) {
  if (add_infinity(r, p, q)) return;
  if (quic_fp_eq(p->x, q->x))
    add_same_x(r, p, q);
  else
    add_distinct(r, p, q);
}

/* Jacobian coordinates (X, Y, Z): x = X/Z^2, y = Y/Z^3; Z == 0 is infinity.
 * Used only by quic_ec_mul so the scalar loop needs no per-step inversion. */
typedef struct {
  p256_fe X, Y, Z;
} jac;

#define FP_P quic_p256_p
/* The scalar loop runs thousands of these, so use the fast P-256 Solinas
 * reduction (quic_fp_mul_p) rather than the generic long-division reducer —
 * the difference is ~885ms vs a few ms per scalar multiply. */
static void fp_mul(p256_fe r, const p256_fe a, const p256_fe b) {
  quic_fp_mul_p(r, a, b);
}
static void fp_sqr(p256_fe r, const p256_fe a) { quic_fp_sqr_p(r, a); }
static void fp_sub(p256_fe r, const p256_fe a, const p256_fe b) {
  quic_fp_sub(r, (quic_fpab){a, b}, FP_P);
}
static void fp_add(p256_fe r, const p256_fe a, const p256_fe b) {
  quic_fp_add(r, (quic_fpab){a, b}, FP_P);
}
static void fp_dbl(p256_fe r, const p256_fe a) { fp_add(r, a, a); }

static void jac_from_affine(jac* j, const ec_point* p) {
  quic_fp_set(j->X, p->x);
  quic_fp_set(j->Y, p->y);
  j->Z[0] = 1;
  j->Z[1] = j->Z[2] = j->Z[3] = 0;
  if (p->inf) {
    j->Z[0] = 0;
  }
}

static int jac_is_inf(const jac* j) { return quic_fp_is_zero(j->Z); }

/* X3 = alpha^2 - 8*beta; helper to keep doubling under CCN 3. */
static void dbl_x(p256_fe x3, const p256_fe alpha, const p256_fe beta) {
  p256_fe t;
  fp_sqr(x3, alpha);
  fp_dbl(t, beta);
  fp_dbl(t, t);
  fp_dbl(t, t); /* 8*beta */
  fp_sub(x3, x3, t);
}

/* Doubling intermediates alpha, beta, gamma (borrowed limb pointers). */
typedef struct {
  const u64 *alpha, *beta, *gamma;
} p256_dblv;

/* Y3 = alpha*(4*beta - X3) - 8*gamma^2. */
static void dbl_y(p256_fe y3, const p256_fe x3, const p256_dblv* d) {
  p256_fe t, g2;
  fp_dbl(t, d->beta);
  fp_dbl(t, t); /* 4*beta */
  fp_sub(t, t, x3);
  fp_mul(t, d->alpha, t);
  fp_sqr(g2, d->gamma);
  fp_dbl(g2, g2);
  fp_dbl(g2, g2);
  fp_dbl(g2, g2); /* 8*gamma^2 */
  fp_sub(y3, t, g2);
}

/* r = 2*p (a = -3 doubling formulas, dbl-2001-b). */
static void jac_double(jac* r, const jac* p) {
  p256_fe delta, gamma, beta, alpha, t, s;
  fp_sqr(delta, p->Z);
  fp_sqr(gamma, p->Y);
  fp_mul(beta, p->X, gamma);
  fp_sub(t, p->X, delta);
  fp_add(s, p->X, delta);
  fp_mul(alpha, t, s);
  fp_dbl(t, alpha);
  fp_add(alpha, alpha, t); /* 3*(X-d)(X+d) */
  dbl_x(r->X, alpha, beta);
  fp_add(t, p->Y, p->Z);
  fp_sqr(t, t);
  fp_sub(t, t, gamma);
  fp_sub(r->Z, t, delta);
  dbl_y(r->Y, r->X, &(p256_dblv){alpha, beta, gamma});
}

/* Intermediates shared between the two halves of Jacobian addition. */
typedef struct {
  p256_fe u1, u2, s1, s2; /* cross terms */
  p256_fe z1z1, z2z2, zs; /* Z1^2, Z2^2, Z1+Z2 */
  p256_fe h, rr;          /* U2-U1, 2(S2-S1) */
} p256_addt;

/* Cross terms U1,U2,S1,S2 (plus the Z terms) for Jacobian addition. */
static void add_uv(p256_addt* t, const jac* p, const jac* q) {
  fp_sqr(t->z1z1, p->Z);
  fp_sqr(t->z2z2, q->Z);
  fp_mul(t->u1, p->X, t->z2z2);
  fp_mul(t->u2, q->X, t->z1z1);
  fp_mul(t->s1, p->Y, q->Z);
  fp_mul(t->s1, t->s1, t->z2z2);
  fp_mul(t->s2, q->Y, p->Z);
  fp_mul(t->s2, t->s2, t->z1z1);
  fp_add(t->zs, p->Z, q->Z);
}

/* Finish addition given the cross terms and H = U2-U1, rr = 2(S2-S1). */
static void add_finish(jac* r, const p256_addt* a) {
  p256_fe i, j, v, t;
  fp_dbl(t, a->h);
  fp_sqr(i, t); /* I = (2H)^2 */
  fp_mul(j, a->h, i);
  fp_mul(v, a->u1, i);
  fp_sqr(r->X, a->rr);
  fp_sub(r->X, r->X, j);
  fp_dbl(t, v);
  fp_sub(r->X, r->X, t);
  fp_sub(t, v, r->X);
  fp_mul(t, a->rr, t);
  fp_mul(v, a->s1, j);
  fp_dbl(v, v);
  fp_sub(r->Y, t, v);
  fp_sqr(t, a->zs);
  fp_sub(t, t, a->z1z1);
  fp_sub(t, t, a->z2z2);
  fp_mul(r->Z, t, a->h);
}

/* r = p + q given the cross terms; assumes p != -q, p != q. */
static void jac_add(jac* r, p256_addt* t) {
  fp_sub(t->h, t->u2, t->u1);
  fp_sub(t->rr, t->s2, t->s1);
  fp_dbl(t->rr, t->rr);
  add_finish(r, t);
}

/* Same-x case: double if s1==s2 (acc==base), else result is infinity. */
static void add_same_x_jac(jac* acc, const p256_fe s1, const p256_fe s2) {
  if (quic_fp_eq(s1, s2))
    jac_double(acc, acc);
  else
    acc->Z[0] = acc->Z[1] = acc->Z[2] = acc->Z[3] = 0;
}

/* acc += base, handling infinity and the doubling/inverse case. */
static void jac_add_step(jac* acc, const jac* base) {
  p256_addt t;
  if (jac_is_inf(acc)) {
    *acc = *base;
    return;
  }
  add_uv(&t, acc, base);
  if (quic_fp_eq(t.u1, t.u2))
    add_same_x_jac(acc, t.s1, t.s2);
  else
    jac_add(acc, &t);
}

/* Convert Jacobian back to affine: x = X/Z^2, y = Y/Z^3. */
static void jac_to_affine(ec_point* r, const jac* j) {
  p256_fe zi, zi2, zi3;
  if (jac_is_inf(j)) {
    r->inf = 1;
    return;
  }
  quic_fp_inv_p(zi, j->Z);
  fp_sqr(zi2, zi);
  fp_mul(zi3, zi2, zi);
  fp_mul(r->x, j->X, zi2);
  fp_mul(r->y, j->Y, zi3);
  r->inf = 0;
}

/* --- constant-time scalar multiply (Montgomery ladder) ------------------
 * RFC 6090 style two-accumulator ladder (side-channel countermeasure: see
 * p256_ladder_step below). Replaces the earlier add-if-bit-set double-and-add,
 * whose `if (bit) jac_add_step(...)` made execution time/cache pattern
 * correlate with the scalar's bits directly. */

/* Constant-time conditional move of one field element: r <- a if mask is
 * all-ones, unchanged if mask is 0. XOR-mask pattern, mirrors x25519.c's
 * fe_cswap (RFC 7748 5). CCN 1 (loop only, no branch). */
static void fp_cmov(p256_fe r, const p256_fe a, u64 mask) {
  for (usz i = 0; i < 4; i++) r[i] ^= mask & (r[i] ^ a[i]);
}

/* Conditional move of a whole Jacobian point (X, Y, Z). CCN 1. */
static void jac_cmov(jac* r, const jac* a, u64 mask) {
  fp_cmov(r->X, a->X, mask);
  fp_cmov(r->Y, a->Y, mask);
  fp_cmov(r->Z, a->Z, mask);
}

/* Constant-time swap of two Jacobian points when mask is all-ones. CCN 1. */
static void jac_cswap(jac* a, jac* b, u64 mask) {
  jac t = *a;
  jac_cmov(&t, b, mask);
  jac_cmov(b, a, mask);
  *a = t;
}

/* 1 if either operand is infinity, with r set to the other one (or infinity,
 * if both are). Split out so jac_add_full stays CCN <= 2. */
static int add_full_infinity(jac* r, const jac* a, const jac* b) {
  if (jac_is_inf(a)) {
    *r = *b;
    return 1;
  }
  if (jac_is_inf(b)) {
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
 * half in r1. The caller cswaps r0/r1 around this call (see quic_ec_mul
 * below) so which accumulator ends up representing 2*acc vs acc+base never
 * depends on an explicit `if (bit)`. The if-statements inside
 * jac_add_step/jac_double are not scalar-bit branches: they fire only on
 * the point's own algebraic state (the fixed initial r0==infinity step, or
 * an exact same-point coincidence), identical in shape on every call
 * regardless of which bit is 1 or 0. */
static void p256_ladder_step(jac* r0, jac* r1) {
  jac t;
  jac_add_full(&t, r0, r1); /* t = r0 + r1 */
  jac_double(r0, r0);       /* r0 = 2*r0   */
  *r1 = t;
}

/* r = k * p, constant-time: no branch keys off a scalar bit directly (see
 * p256_ladder_step). k big-endian 32 bytes. */
void quic_ec_mul(ec_point* r, const u8 k[32], const ec_point* p) {
  jac r0 = {{0}, {0}, {0}}; /* infinity */
  jac r1;
  u64 swap = 0;
  jac_from_affine(&r1, p);
  for (usz i = 0; i < 256; i++) {
    u64 bit = (k[i / 8] >> (7 - (i & 7))) & 1; /* MSB-first, big-endian */
    swap ^= bit;
    jac_cswap(&r0, &r1, (u64)0 - swap);
    swap = bit;
    p256_ladder_step(&r0, &r1);
  }
  jac_cswap(&r0, &r1, (u64)0 - swap);
  jac_to_affine(r, &r0);
}
