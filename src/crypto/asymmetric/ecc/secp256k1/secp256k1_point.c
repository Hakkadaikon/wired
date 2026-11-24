#include "crypto/asymmetric/ecc/secp256k1/secp256k1_impl.h"

/* Shared terms of a Jacobian add (add-2007-bl, a = 0 needs no change). */
typedef struct {
  p256_fe u1, s1, h, r;
} secp256k1_addt;

static int  secp256k1_is_inf(const secp256k1_pt* a);
static int  secp256k1_both_finite(const secp256k1_pt* a, const secp256k1_pt* b);
static void secp256k1_add_terms(
    secp256k1_addt* t, const secp256k1_pt* a, const secp256k1_pt* b);
static void secp256k1_add_general(
    secp256k1_pt*         o,
    const secp256k1_pt*   a,
    const secp256k1_pt*   b,
    const secp256k1_addt* t);
static void secp256k1_add_same_x(
    secp256k1_pt* o, const secp256k1_pt* a, const secp256k1_addt* t);
static void secp256k1_add_finite(
    secp256k1_pt* o, const secp256k1_pt* a, const secp256k1_pt* b);

static int secp256k1_is_inf(const secp256k1_pt* a) {
  return p256_fp_is_zero(a->z);
}

static int secp256k1_both_finite(const secp256k1_pt* a, const secp256k1_pt* b) {
  return !secp256k1_is_inf(a) && !secp256k1_is_inf(b);
}

/* dbl-2009-l (a = 0): A = X^2, B = Y^2, C = B^2, D = 2((X + B)^2 - A - C),
 * E = 3A, X3 = E^2 - 2D, Y3 = E(D - X3) - 8C, Z3 = 2YZ. z == 0 stays 0, and
 * y == 0 cannot occur (n is odd: no point of order 2). */
void secp256k1_dbl(secp256k1_pt* r, const secp256k1_pt* a) {
  p256_fe A, B, C, D, E, t;
  secp256k1_fe_sqr(A, a->x);
  secp256k1_fe_sqr(B, a->y);
  secp256k1_fe_sqr(C, B);
  secp256k1_fe_add(t, a->x, B);
  secp256k1_fe_sqr(t, t);
  secp256k1_fe_sub(t, t, A);
  secp256k1_fe_sub(t, t, C);
  secp256k1_fe_add(D, t, t);
  secp256k1_fe_add(E, A, A);
  secp256k1_fe_add(E, E, A);
  secp256k1_fe_mul(r->z, a->y, a->z);
  secp256k1_fe_add(r->z, r->z, r->z);
  secp256k1_fe_sqr(t, E);
  secp256k1_fe_sub(t, t, D);
  secp256k1_fe_sub(r->x, t, D);
  secp256k1_fe_sub(t, D, r->x);
  secp256k1_fe_mul(t, E, t);
  secp256k1_fe_add(C, C, C);
  secp256k1_fe_add(C, C, C);
  secp256k1_fe_add(C, C, C);
  secp256k1_fe_sub(r->y, t, C);
}

/* U1 = X1 Z2^2, U2 = X2 Z1^2, S1 = Y1 Z2^3, S2 = Y2 Z1^3, H = U2 - U1,
 * r = S2 - S1. */
static void secp256k1_add_terms(
    secp256k1_addt* t, const secp256k1_pt* a, const secp256k1_pt* b) {
  p256_fe z1z1, z2z2, u2, s2;
  secp256k1_fe_sqr(z1z1, a->z);
  secp256k1_fe_sqr(z2z2, b->z);
  secp256k1_fe_mul(t->u1, a->x, z2z2);
  secp256k1_fe_mul(u2, b->x, z1z1);
  secp256k1_fe_mul(t->s1, a->y, b->z);
  secp256k1_fe_mul(t->s1, t->s1, z2z2);
  secp256k1_fe_mul(s2, b->y, a->z);
  secp256k1_fe_mul(s2, s2, z1z1);
  secp256k1_fe_sub(t->h, u2, t->u1);
  secp256k1_fe_sub(t->r, s2, t->s1);
}

/* X3 = r^2 - H^3 - 2 U1 H^2, Y3 = r(U1 H^2 - X3) - S1 H^3, Z3 = Z1 Z2 H. */
static void secp256k1_add_general(
    secp256k1_pt*         o,
    const secp256k1_pt*   a,
    const secp256k1_pt*   b,
    const secp256k1_addt* t) {
  p256_fe hh, hhh, v, x3, y3;
  secp256k1_fe_sqr(hh, t->h);
  secp256k1_fe_mul(hhh, t->h, hh);
  secp256k1_fe_mul(v, t->u1, hh);
  secp256k1_fe_sqr(x3, t->r);
  secp256k1_fe_sub(x3, x3, hhh);
  secp256k1_fe_sub(x3, x3, v);
  secp256k1_fe_sub(x3, x3, v);
  secp256k1_fe_sub(y3, v, x3);
  secp256k1_fe_mul(y3, t->r, y3);
  secp256k1_fe_mul(hhh, t->s1, hhh);
  secp256k1_fe_sub(o->y, y3, hhh);
  secp256k1_fe_mul(o->z, a->z, b->z);
  secp256k1_fe_mul(o->z, o->z, t->h);
  p256_fp_set(o->x, x3);
}

/* Same x: a == b doubles, a == -b gives infinity. */
static void secp256k1_add_same_x(
    secp256k1_pt* o, const secp256k1_pt* a, const secp256k1_addt* t) {
  if (p256_fp_is_zero(t->r)) {
    secp256k1_dbl(o, a);
    return;
  }
  bytes_memset(o->z, 0, sizeof(o->z));
}

static void secp256k1_add_finite(
    secp256k1_pt* o, const secp256k1_pt* a, const secp256k1_pt* b) {
  secp256k1_addt t;
  secp256k1_add_terms(&t, a, b);
  if (p256_fp_is_zero(t.h)) {
    secp256k1_add_same_x(o, a, &t);
    return;
  }
  secp256k1_add_general(o, a, b, &t);
}

void secp256k1_add(
    secp256k1_pt* r, const secp256k1_pt* a, const secp256k1_pt* b) {
  secp256k1_pt o = *b;
  if (!secp256k1_is_inf(a)) {
    o = *a;
  }
  if (secp256k1_both_finite(a, b)) {
    secp256k1_add_finite(&o, a, b);
  }
  *r = o;
}
