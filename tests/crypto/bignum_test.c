#include "test.h"

/* be<->limb round-trips and preserves byte order. */
static void test_bn_be_roundtrip(void) {
  u8 be[256], out[256];
  for (usz i = 0; i < 256; i++) be[i] = (u8)(i + 1);
  quic_bn a;
  quic_bn_from_be(&a, be, 256);
  quic_bn_to_be(&a, out, 256);
  for (usz i = 0; i < 256; i++) CHECK(out[i] == be[i]);

  /* most significant byte sits in the top limb */
  CHECK((a.v[31] >> 56) == 0x01);
  /* least significant byte in limb 0 */
  CHECK((a.v[0] & 0xff) == 0x00); /* be[255] = 256 wrapped = 0x00 */
}

/* short big-endian input zero-extends; value compares correctly. */
static void test_bn_from_be_short(void) {
  u8      be[3] = {0x01, 0x00, 0x00}; /* 65536 */
  quic_bn a;
  quic_bn_from_be(&a, be, 3);
  CHECK(a.v[0] == 0x10000);
  for (usz i = 1; i < QUIC_BN_LIMBS; i++) CHECK(a.v[i] == 0);
}

static void test_bn_cmp_zero(void) {
  quic_bn a, b;
  u8      x[1] = {0}, y[1] = {5};
  quic_bn_from_be(&a, x, 1);
  quic_bn_from_be(&b, y, 1);
  CHECK(quic_bn_is_zero(&a) == 1);
  CHECK(quic_bn_is_zero(&b) == 0);
  CHECK(quic_bn_cmp(&a, &b) == -1);
  CHECK(quic_bn_cmp(&b, &a) == 1);
  CHECK(quic_bn_cmp(&a, &a) == 0);

  /* high-limb difference dominates */
  quic_bn c = b;
  c.v[31]   = 1;
  CHECK(quic_bn_cmp(&c, &b) == 1);
}

void test_bignum(void) {
  test_bn_be_roundtrip();
  test_bn_from_be_short();
  test_bn_cmp_zero();
}
