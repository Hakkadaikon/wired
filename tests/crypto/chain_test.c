#include "crypto/pki/encoding/x509/chain.h"

#include "chain_golden.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"

/* A self-signed cert: its own issuer equals its own subject (byte for byte). */
static void test_self_signed_issuer_equals_subject(void) {
  x509       c;
  wired_span iss, sub;
  CHECK(
      x509_parse(wired_span_of(chain_golden1, sizeof(chain_golden1)), &c) == 1);
  CHECK(x509_issuer(c.tbs, &iss) == 1);
  CHECK(x509_subject(c.tbs, &sub) == 1);
  CHECK(x509_dn_equal(iss, sub) == 1);
}

/* cert1 issuer (CN=example.com) differs from cert2 subject (CN=other.example).
 */
static void test_distinct_dn_not_equal(void) {
  x509       a, b;
  wired_span iss, sub;
  CHECK(
      x509_parse(wired_span_of(chain_golden1, sizeof(chain_golden1)), &a) == 1);
  CHECK(
      x509_parse(wired_span_of(chain_golden2, sizeof(chain_golden2)), &b) == 1);
  CHECK(x509_issuer(a.tbs, &iss) == 1);
  CHECK(x509_subject(b.tbs, &sub) == 1);
  CHECK(x509_dn_equal(iss, sub) == 0);
}

/* The extracted Name is the full SEQUENCE (header included, RDNSequence). */
static void test_dn_is_sequence_tlv(void) {
  x509       c;
  wired_span iss;
  CHECK(
      x509_parse(wired_span_of(chain_golden1, sizeof(chain_golden1)), &c) == 1);
  CHECK(x509_issuer(c.tbs, &iss) == 1);
  CHECK(iss.p[0] == 0x30 && iss.p[1] + 2u == iss.n);
}

/* A tbs SEQUENCE too short to hold issuer never resolves it. */
static void test_short_tbs(void) {
  const u8   tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  wired_span iss;
  CHECK(x509_issuer(wired_span_of(tbs, sizeof(tbs)), &iss) == 0);
}

/* RFC 5280 4.1: issuer and subject are Name SEQUENCEs. A tbs that ends
 * after validity has no subject; one whose issuer is a SET has no issuer. */
static void test_name_missing_or_not_sequence(void) {
  static const u8 no_subject[] = {0x30, 0x09, 0x02, 0x01, 0x01, 0x30,
                                  0x00, 0x30, 0x00, 0x30, 0x00};
  static const u8 set_issuer[] = {0x30, 0x07, 0x02, 0x01, 0x01,
                                  0x30, 0x00, 0x31, 0x00};
  wired_span      dn;
  CHECK(x509_issuer(wired_span_of(no_subject, sizeof(no_subject)), &dn) == 1);
  CHECK(x509_subject(wired_span_of(no_subject, sizeof(no_subject)), &dn) == 0);
  CHECK(x509_issuer(wired_span_of(set_issuer, sizeof(set_issuer)), &dn) == 0);
}

void test_chain(void) {
  test_name_missing_or_not_sequence();
  test_self_signed_issuer_equals_subject();
  test_distinct_dn_not_equal();
  test_dn_is_sequence_tlv();
  test_short_tbs();
}
