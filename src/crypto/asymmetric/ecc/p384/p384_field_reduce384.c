#include "crypto/asymmetric/ecc/p384/p384_field_impl.h"

static void reduce384_add_half(p384_fe r, const u64 w[12]);
static void reduce384_sub_half(p384_fe r, const u64 w[12]);
static void fp384_reduce_p(p384_fe r, const u64 w[12]);
static void fp384_set_one(p384_fe r);

/* r = s1 + 2*s2 + s3 + s4 + s5 + s6 + s7 (the additive terms). */
static void reduce384_add_half(p384_fe r, const u64 w[12]) {
  p384_fe t;
  fp384_build_term384(r, w, 0); /* s1 */
  fp384_build_term384(t, w, 1);
  fp384_add_p(r, t);
  fp384_add_p(r, t); /* 2*s2 */
  for (usz k = 2; k < 7; k++) {
    fp384_build_term384(t, w, k);
    fp384_add_p(r, t); /* s3..s7 */
  }
}

/* r -= s8 + s9 + s10 (the subtractive terms). */
static void reduce384_sub_half(p384_fe r, const u64 w[12]) {
  p384_fe t;
  for (usz k = 7; k < 10; k++) {
    fp384_build_term384(t, w, k);
    fp384_sub_p(r, t);
  }
}

static void fp384_reduce_p(p384_fe r, const u64 w[12]) {
  reduce384_add_half(r, w);
  reduce384_sub_half(r, w);
}

void fp384_mul_p(p384_fe r, const p384_fe a, const p384_fe b) {
  u64 w[12];
  fp384_fe6_mul_wide(w, a, b);
  fp384_reduce_p(r, w);
}

void fp384_sqr_p(p384_fe r, const p384_fe a) { fp384_mul_p(r, a, a); }

/* Set r to the field element 1. */
static void fp384_set_one(p384_fe r) {
  static const p384_fe one = {1, 0, 0, 0, 0, 0};
  fp384_set(r, one);
}

/* Bit i (0 = LSB) of a 384-bit little-endian value. */
int fp384_ebit(const p384_fe e, usz i) {
  return (int)((e[i / 64] >> (i & 63)) & 1);
}

/* r = a^(m-2) mod m via square-and-multiply (Fermat), generic reducer. */
void fp384_inv(p384_fe r, const p384_fe a, const p384_fe m) {
  p384_fe base, e, two = {2, 0, 0, 0, 0, 0};
  fp384_fe6_sub_raw(e, m, two);
  fp384_set(base, a);
  fp384_set_one(r);
  for (usz bit = 0; bit < 384; bit++) {
    if (fp384_ebit(e, bit)) fp384_mul(r, (fp384ab){r, base}, m);
    fp384_sqr(base, base, m);
  }
}

/* a^(p-2) mod p via the fast Solinas mul/sqr. */
void fp384_inv_p(p384_fe r, const p384_fe a) {
  p384_fe base, e, two = {2, 0, 0, 0, 0, 0};
  fp384_fe6_sub_raw(e, p384_p, two);
  fp384_set(base, a);
  fp384_set_one(r);
  for (usz bit = 0; bit < 384; bit++) {
    if (fp384_ebit(e, bit)) fp384_mul_p(r, r, base);
    fp384_sqr_p(base, base);
  }
}
