#include "test.h"

static void bn_small(bn* a, u64 x) {
  for (usz i = 0; i < BN_LIMBS; i++) a->v[i] = 0;
  a->v[0] = x;
}

/* Classic worked example: 4^13 mod 497 = 445. */
static void test_modexp_known(void) {
  bn base, exp, mod, out;
  bn_small(&base, 4);
  bn_small(&exp, 13);
  bn_small(&mod, 497);
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 445);
  for (usz i = 1; i < BN_LIMBS; i++) CHECK(out.v[i] == 0);
}

/* exp 0 -> 1; exp 1 -> base. */
static void test_modexp_edges(void) {
  bn base, exp, mod, out;
  bn_small(&base, 7);
  bn_small(&mod, 100);
  bn_small(&exp, 0);
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 1);
  bn_small(&exp, 1);
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 7);
}

/* Textbook RSA (n=3233, e=17, d=2753): signature s=65^d mod n=588 recovers
 * the message under s^e mod n=65. This is exactly RSA verify's core step. */
static void test_modexp_rsa_small(void) {
  bn s, e, n, out;
  bn_small(&s, 588);
  bn_small(&e, 17);
  bn_small(&n, 3233);
  bn_modexp(&out, &s, (bn_expmod){&e, &n});
  CHECK(out.v[0] == 65);
  for (usz i = 1; i < BN_LIMBS; i++) CHECK(out.v[i] == 0);
}

/* Carry across the limb 0 -> 1 boundary: (2^64-1)^2 mod 2^128 =
 * 0xfffffffffffffffe_0000000000000001. */
static void test_modexp_limb_boundary_square(void) {
  bn base, exp, mod, out;
  bn_small(&base, 0xffffffffffffffffULL);
  bn_small(&exp, 2);
  bn_small(&mod, 0);
  mod.v[2] = 1; /* 2^128 */
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 1);
  CHECK(out.v[1] == 0xfffffffffffffffeULL);
  for (usz i = 2; i < BN_LIMBS; i++) CHECK(out.v[i] == 0);
}

/* All-ones two-limb operand: (2^128-1)^2 mod 2^256 = 2^256 - 2^129 + 1. */
static void test_modexp_all_ones_two_limbs(void) {
  bn base, exp, mod, out;
  bn_small(&base, 0xffffffffffffffffULL);
  base.v[1] = 0xffffffffffffffffULL;
  bn_small(&exp, 2);
  bn_small(&mod, 0);
  mod.v[4] = 1; /* 2^256 */
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 1 && out.v[1] == 0);
  CHECK(out.v[2] == 0xfffffffffffffffeULL);
  CHECK(out.v[3] == 0xffffffffffffffffULL);
}

/* Full-width all-ones modulus m = 2^4096-1 with base m-1: the top-limb
 * shift-out / add-carry / subtract-borrow paths all run at their 2^64-1
 * boundaries. (m-1)^2 mod m = 1 and (m-1)^3 mod m = m-1. */
static void test_modexp_all_ones_full_width(void) {
  bn base, exp, mod, out;
  for (usz i = 0; i < BN_LIMBS; i++) {
    mod.v[i]  = 0xffffffffffffffffULL;
    base.v[i] = 0xffffffffffffffffULL;
  }
  base.v[0] = 0xfffffffffffffffeULL; /* base = m - 1 */
  bn_small(&exp, 2);
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 1);
  for (usz i = 1; i < BN_LIMBS; i++) CHECK(out.v[i] == 0);
  bn_small(&exp, 3);
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(bn_cmp(&out, &base) == 0);
}

/* Cross-checked against arbitrary-precision arithmetic:
 * (2^64-1)^5 mod (2^192-237) = 0xe2_fffffffffffffb64_0000000000000941. */
static void test_modexp_cross_checked(void) {
  bn base, exp, mod, out;
  bn_small(&base, 0xffffffffffffffffULL);
  bn_small(&exp, 5);
  bn_small(&mod, 0xffffffffffffff13ULL); /* 2^192 - 237 */
  mod.v[1] = 0xffffffffffffffffULL;
  mod.v[2] = 0xffffffffffffffffULL;
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 0x941);
  CHECK(out.v[1] == 0xfffffffffffffb64ULL);
  CHECK(out.v[2] == 0xe2);
  for (usz i = 3; i < BN_LIMBS; i++) CHECK(out.v[i] == 0);
}

/* The modulus itself and m-1 as operands, and a single all-ones limb as the
 * modulus: m^e mod m = 0 (the add-then-reduce path with r + m), (m-1)^1 = m-1
 * (no spurious reduction), (m-1)^2 mod (2^64-1) = 1 (the carry out of limb 0
 * is the only carry). */
static void test_modexp_modulus_as_operand(void) {
  bn base, exp, mod, out;
  for (usz i = 0; i < BN_LIMBS; i++) mod.v[i] = 0xffffffffffffffffULL;
  base = mod;
  bn_small(&exp, 3);
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(bn_is_zero(&out) == 1);
  base.v[0] = 0xfffffffffffffffeULL; /* m - 1 */
  bn_small(&exp, 1);
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(bn_cmp(&out, &base) == 0);
  bn_small(&mod, 0xffffffffffffffffULL);
  bn_small(&base, 0xfffffffffffffffeULL);
  bn_small(&exp, 2);
  bn_modexp(&out, &base, (bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 1);
  for (usz i = 1; i < BN_LIMBS; i++) CHECK(out.v[i] == 0);
}

void test_modexp(void) {
  test_modexp_known();
  test_modexp_edges();
  test_modexp_rsa_small();
  test_modexp_limb_boundary_square();
  test_modexp_all_ones_two_limbs();
  test_modexp_all_ones_full_width();
  test_modexp_cross_checked();
  test_modexp_modulus_as_operand();
}
