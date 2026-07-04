#include "crypto/pki/encoding/eckey/eckey.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "eckey_golden.h"
#include "test.h"

/* RFC 5915 3. SEC1 ECPrivateKey DER yields the 32-byte scalar. */
static void test_eckey_sec1_golden(void) {
  u8 out[32];
  CHECK(
      wired_eckey_p256_priv(
          quic_span_of(quic_eckey_sec1_der, sizeof(quic_eckey_sec1_der)),
          out) == 1);
  CHECK(quic_ct_diff32(out, quic_eckey_priv) == 0);
}

/* RFC 5958 2. The same key wrapped in PKCS#8 yields the same scalar. */
static void test_eckey_pkcs8_golden(void) {
  u8 out[32];
  CHECK(
      wired_eckey_p256_priv(
          quic_span_of(quic_eckey_pkcs8_der, sizeof(quic_eckey_pkcs8_der)),
          out) == 1);
  CHECK(quic_ct_diff32(out, quic_eckey_priv) == 0);
}

/* Copy the SEC1 golden and overwrite one byte at off. */
static quic_span mutated(u8* buf, usz off, u8 v) {
  quic_memcpy(buf, quic_eckey_sec1_der, sizeof(quic_eckey_sec1_der));
  buf[off] = v;
  return quic_span_of(buf, sizeof(quic_eckey_sec1_der));
}

/* Broken outer tag and unsupported version INTEGER are rejected. */
static void test_eckey_bad_structure(void) {
  u8 buf[sizeof(quic_eckey_sec1_der)];
  u8 out[32];
  /* SEC1 layout: [0]=SEQUENCE, [4]=version, [6]=scalar length. */
  CHECK(quic_eckey_sec1_der[4] == 0x01 && quic_eckey_sec1_der[6] == 0x20);
  CHECK(wired_eckey_p256_priv(mutated(buf, 0, 0x31), out) == 0);
  CHECK(wired_eckey_p256_priv(mutated(buf, 4, 0x02), out) == 0);
}

/* A private key OCTET STRING of 31 or 33 bytes is not a P-256 scalar. */
static void test_eckey_bad_scalar_len(void) {
  u8 buf[sizeof(quic_eckey_sec1_der)];
  u8 out[32];
  CHECK(wired_eckey_p256_priv(mutated(buf, 6, 0x1f), out) == 0);
  CHECK(wired_eckey_p256_priv(mutated(buf, 6, 0x21), out) == 0);
}

/* Truncated DER is rejected. */
static void test_eckey_truncated(void) {
  u8 out[32];
  CHECK(wired_eckey_p256_priv(quic_span_of(quic_eckey_sec1_der, 10), out) == 0);
  CHECK(wired_eckey_p256_priv(quic_span_of(0, 0), out) == 0);
}

void test_eckey(void) {
  test_eckey_sec1_golden();
  test_eckey_pkcs8_golden();
  test_eckey_bad_structure();
  test_eckey_bad_scalar_len();
  test_eckey_truncated();
}
