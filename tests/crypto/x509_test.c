#include "crypto/pki/encoding/x509/x509.h"

#include "crypto/pki/encoding/asn1/derval.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1. The three top-level fields are split out of a real cert. */
static void test_x509_parse_golden(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_x509_golden, sizeof(quic_x509_golden)), &c) == 1);
  /* tbsCertificate spans offset 4..309 (header included). */
  CHECK(c.tbs.p == quic_x509_golden + 4 && c.tbs.n == 305);
  /* signatureAlgorithm OID is ecdsa-with-SHA256. */
  CHECK(
      quic_der_oid_equal(
          c.sig_alg_oid,
          quic_span_of(quic_oid_ecdsa_sha256, sizeof(quic_oid_ecdsa_sha256))) ==
      1);
  /* signatureValue BIT STRING value is 71 octets (at offset 323). */
  CHECK(c.sig.p == quic_x509_golden + 323 && c.sig.n == 71);
}

static void test_x509_truncated(void) {
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(quic_x509_golden, 10), &c) == 0);
  CHECK(quic_x509_parse(quic_span_of(quic_x509_golden, 0), &c) == 0);
}

/* A SEQUENCE whose first element is an INTEGER (not the tbs SEQUENCE). */
static void test_x509_not_tbs_seq(void) {
  const u8  bad[] = {0x30, 0x03, 0x02, 0x01, 0x05};
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(bad, sizeof(bad)), &c) == 0);
}

/* Top-level tag is not SEQUENCE. */
static void test_x509_not_seq(void) {
  const u8  bad[] = {0x02, 0x01, 0x05};
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(bad, sizeof(bad)), &c) == 0);
}

void test_x509(void) {
  test_x509_parse_golden();
  test_x509_truncated();
  test_x509_not_tbs_seq();
  test_x509_not_seq();
}
