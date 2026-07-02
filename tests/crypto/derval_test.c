#include "crypto/pki/encoding/asn1/derval.h"

#include "test.h"

/* rsaEncryption 1.2.840.113549.1.1.1 = OID value 2a 86 48 86 f7 0d 01 01 01. */
static void test_derval_oid_equal(void) {
  const u8  rsa[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
  const u8  exp[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01};
  quic_span e     = quic_span_of(exp, sizeof(exp));
  CHECK(quic_der_oid_equal(quic_span_of(rsa, sizeof(rsa)), e) == 1);
  /* differing last byte */
  const u8 other[] = {0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b};
  CHECK(quic_der_oid_equal(quic_span_of(other, sizeof(other)), e) == 0);
  /* length mismatch */
  CHECK(quic_der_oid_equal(quic_span_of(rsa, sizeof(rsa) - 1), e) == 0);
}

static void test_derval_uint(void) {
  u64      out;
  const u8 one[] = {0x01};
  CHECK(quic_der_uint(one, 1, &out) == 1 && out == 1);
  /* 0x0100 = 256 */
  const u8 t256[] = {0x01, 0x00};
  CHECK(quic_der_uint(t256, 2, &out) == 1 && out == 256);
  /* leading 0x00 pad keeps 0x80 positive: value 128 */
  const u8 p128[] = {0x00, 0x80};
  CHECK(quic_der_uint(p128, 2, &out) == 1 && out == 128);
  /* full 8 octets */
  const u8 max8[] = {0x7f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
  CHECK(quic_der_uint(max8, 8, &out) == 1 && out == 0x7fffffffffffffffULL);
  /* 9 significant octets after pad strip -> too wide */
  const u8 wide[] = {0x00, 0x01, 0, 0, 0, 0, 0, 0, 0, 0};
  CHECK(quic_der_uint(wide, sizeof(wide), &out) == 0);
}

static void test_derval_uint_reject(void) {
  u64 out;
  /* negative: top bit set, no pad */
  const u8 neg[] = {0x80};
  CHECK(quic_der_uint(neg, 1, &out) == 0);
  /* empty value */
  CHECK(quic_der_uint(neg, 0, &out) == 0);
}

void test_derval(void) {
  test_derval_oid_equal();
  test_derval_uint();
  test_derval_uint_reject();
}
