#include "crypto/asymmetric/ecc/p521/p521_field_impl.h"

static int  fe9_bit(const p521_fe a, usz i);
static void fe9_shr1(p521_fe a);
static void fe9_half(p521_fe x, const p521_fe m);
static void fp521_inv_even(p521_fe u, p521_fe x, const p521_fe m);
static void fp521_inv_step(fp521_invst* s, const p521_fe m);
static int  fp521_inv_done(const fp521_invst* s);

static int fe9_bit(const p521_fe a, usz i) {
  return (int)((a[i / 64] >> (i & 63)) & 1);
}

void fp521_mul(p521_fe r, const p521_fe a, const p521_fe b, const p521_fe m) {
  p521_fe acc = {0};
  for (usz i = 521; i-- > 0;) {
    fp521_add(acc, acc, acc, m);
    if (fe9_bit(a, i)) {
      fp521_add(acc, acc, b, m);
    }
  }
  fp521_set(r, acc);
}

static void fe9_shr1(p521_fe a) {
  for (usz i = 0; i < 8; i++) {
    a[i] = (a[i] >> 1) | (a[i + 1] << 63);
  }
  a[8] >>= 1;
}

/* x = x / 2 mod m (m odd). */
static void fe9_half(p521_fe x, const p521_fe m) {
  if (x[0] & 1) {
    fp521_fe9_add_raw(x, x, m);
  }
  fe9_shr1(x);
}

/* Strip twos from u, halving x alongside to keep the invariant. */
static void fp521_inv_even(p521_fe u, p521_fe x, const p521_fe m) {
  while (!(u[0] & 1)) {
    fe9_shr1(u);
    fe9_half(x, m);
  }
}

static void fp521_inv_step(fp521_invst* s, const p521_fe m) {
  fp521_inv_even(s->u, s->x1, m);
  fp521_inv_even(s->v, s->x2, m);
  if (fp521_fe9_ge(s->u, s->v)) {
    fp521_fe9_sub_raw(s->u, s->u, s->v);
    fp521_sub(s->x1, s->x1, s->x2, m);
  } else {
    fp521_fe9_sub_raw(s->v, s->v, s->u);
    fp521_sub(s->x2, s->x2, s->x1, m);
  }
}

static int fp521_inv_done(const fp521_invst* s) {
  return fp521_eq(s->u, fp521_one) || fp521_eq(s->v, fp521_one);
}

/* Guide to ECC, Algorithm 2.22. */
void fp521_inv(p521_fe r, const p521_fe a, const p521_fe m) {
  fp521_invst s = {{0}, {0}, {1}, {0}};
  fp521_set(s.u, a);
  fp521_set(s.v, m);
  while (!fp521_inv_done(&s)) {
    fp521_inv_step(&s, m);
  }
  fp521_set(r, fp521_eq(s.u, fp521_one) ? s.x1 : s.x2);
}

void fp521_from_be(p521_fe r, const u8 b[66]) {
  for (usz i = 0; i < 9; i++) {
    r[i] = 0;
  }
  for (usz k = 0; k < 66; k++) {
    r[k / 8] |= (u64)b[65 - k] << (8 * (k & 7));
  }
}

void fp521_to_be(u8 b[66], const p521_fe a) {
  for (usz k = 0; k < 66; k++) {
    b[65 - k] = (u8)(a[k / 8] >> (8 * (k & 7)));
  }
}
