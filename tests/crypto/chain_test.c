#include "crypto/pki/encoding/x509/chain.h"

#include "chain_golden.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"

/* A self-signed cert: its own issuer equals its own subject (byte for byte). */
static void test_self_signed_issuer_equals_subject(void) {
  quic_x509 c;
  quic_span iss, sub;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_chain_golden1, sizeof(quic_chain_golden1)), &c) ==
      1);
  CHECK(quic_x509_issuer(c.tbs, &iss) == 1);
  CHECK(quic_x509_subject(c.tbs, &sub) == 1);
  CHECK(quic_x509_dn_equal(iss, sub) == 1);
}

/* cert1 issuer (CN=example.com) differs from cert2 subject (CN=other.example).
 */
static void test_distinct_dn_not_equal(void) {
  quic_x509 a, b;
  quic_span iss, sub;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_chain_golden1, sizeof(quic_chain_golden1)), &a) ==
      1);
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_chain_golden2, sizeof(quic_chain_golden2)), &b) ==
      1);
  CHECK(quic_x509_issuer(a.tbs, &iss) == 1);
  CHECK(quic_x509_subject(b.tbs, &sub) == 1);
  CHECK(quic_x509_dn_equal(iss, sub) == 0);
}

/* The extracted Name is the full SEQUENCE (header included, RDNSequence). */
static void test_dn_is_sequence_tlv(void) {
  quic_x509 c;
  quic_span iss;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_chain_golden1, sizeof(quic_chain_golden1)), &c) ==
      1);
  CHECK(quic_x509_issuer(c.tbs, &iss) == 1);
  CHECK(iss.p[0] == 0x30 && iss.p[1] + 2u == iss.n);
}

/* A tbs SEQUENCE too short to hold issuer never resolves it. */
static void test_short_tbs(void) {
  const u8  tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  quic_span iss;
  CHECK(quic_x509_issuer(quic_span_of(tbs, sizeof(tbs)), &iss) == 0);
}

void test_chain(void) {
  test_self_signed_issuer_equals_subject();
  test_distinct_dn_not_equal();
  test_dn_is_sequence_tlv();
  test_short_tbs();
}
