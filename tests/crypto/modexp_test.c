#include "test.h"

static void bn_small(quic_bn* a, u64 x) {
  for (usz i = 0; i < QUIC_BN_LIMBS; i++) a->v[i] = 0;
  a->v[0] = x;
}

/* Classic worked example: 4^13 mod 497 = 445. */
static void test_modexp_known(void) {
  quic_bn base, exp, mod, out;
  bn_small(&base, 4);
  bn_small(&exp, 13);
  bn_small(&mod, 497);
  quic_bn_modexp(&out, &base, (quic_bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 445);
  for (usz i = 1; i < QUIC_BN_LIMBS; i++) CHECK(out.v[i] == 0);
}

/* exp 0 -> 1; exp 1 -> base. */
static void test_modexp_edges(void) {
  quic_bn base, exp, mod, out;
  bn_small(&base, 7);
  bn_small(&mod, 100);
  bn_small(&exp, 0);
  quic_bn_modexp(&out, &base, (quic_bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 1);
  bn_small(&exp, 1);
  quic_bn_modexp(&out, &base, (quic_bn_expmod){&exp, &mod});
  CHECK(out.v[0] == 7);
}

/* Textbook RSA (n=3233, e=17, d=2753): signature s=65^d mod n=588 recovers
 * the message under s^e mod n=65. This is exactly RSA verify's core step. */
static void test_modexp_rsa_small(void) {
  quic_bn s, e, n, out;
  bn_small(&s, 588);
  bn_small(&e, 17);
  bn_small(&n, 3233);
  quic_bn_modexp(&out, &s, (quic_bn_expmod){&e, &n});
  CHECK(out.v[0] == 65);
  for (usz i = 1; i < QUIC_BN_LIMBS; i++) CHECK(out.v[i] == 0);
}

void test_modexp(void) {
  test_modexp_known();
  test_modexp_edges();
  test_modexp_rsa_small();
}
