#include "crypto/asymmetric/ecc/p521/p521_point_impl.h"

static void p521pt_add_xy(
    jac521* r, const p521_addt* a, const p521_fe h, const p521_fe rr);
static void p521pt_add_distinct(
    jac521* r, const p521_addt* a, const jac521* p, const jac521* q);
static void p521pt_add_finite(jac521* acc, const jac521* q);
static void p521pt_add_step(jac521* acc, const jac521* q);
static int  p521pt_bit(const p521_fe a, usz i);
static void p521pt_from_affine(jac521* j, const p521_fe x, const p521_fe y);
static void p521pt_shamir(jac521* acc, const jac521 tab[4], const u64* u[2]);

/* X3 = r^2 - J - 2V, Y3 = r (V - X3) - 2 S1 J with I = (2H)^2. */
static void p521pt_add_xy(
    jac521* r, const p521_addt* a, const p521_fe h, const p521_fe rr) {
  p521_fe i, j, v, t;
  p521pt_dbl(t, h);
  p521pt_sqr(i, t);
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

/* r = p + q for distinct x (u1 != u2). r may alias p. */
static void p521pt_add_distinct(
    jac521* r, const p521_addt* a, const jac521* p, const jac521* q) {
  p521_fe h, rr;
  p521pt_sub(h, a->u2, a->u1);
  p521pt_sub(rr, a->s2, a->s1);
  p521pt_dbl(rr, rr);
  p521pt_add_z(r, a, p, q, h);
  p521pt_add_xy(r, a, h, rr);
}

/* acc += q with both finite: same x means double (same y) or infinity. */
static void p521pt_add_finite(jac521* acc, const jac521* q) {
  p521_addt t;
  p521pt_add_uv(&t, acc, q);
  if (!fp521_eq(t.u1, t.u2)) {
    p521pt_add_distinct(acc, &t, acc, q);
  } else if (fp521_eq(t.s1, t.s2)) {
    p521pt_double(acc, acc);
  } else {
    fp521_set(acc->Z, (const u64[9]){0});
  }
}

static void p521pt_add_step(jac521* acc, const jac521* q) {
  if (p521pt_is_inf(q)) {
    return;
  }
  if (p521pt_is_inf(acc)) {
    *acc = *q;
  } else {
    p521pt_add_finite(acc, q);
  }
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
    if (sel) {
      p521pt_add_step(acc, &tab[sel]);
    }
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
  if (p521pt_is_inf(&acc)) {
    return 0;
  }
  fp521_inv(zi, acc.Z, p521_p);
  p521pt_sqr(zi2, zi);
  fp521_mul_p(rx, acc.X, zi2);
  return 1;
}
