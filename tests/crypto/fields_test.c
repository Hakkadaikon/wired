#include "crypto/pki/cert/tbscert/fields.h"

#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1.2. Every field boundary is pulled from the real tbs. The
 * offsets below are hand-verified against the golden DER. */
static void test_fields_golden(void) {
  x509 c;
  CHECK(x509_parse(wired_span_of(x509_golden, sizeof(x509_golden)), &c) == 1);
  tbscert t;
  CHECK(tbscert_parse(c.tbs, &t) == 1);

  /* version [0] EXPLICIT inner INTEGER value = 0x02 (v3), at offset 12. */
  CHECK(t.version.p == x509_golden + 12 && t.version.n == 1);
  CHECK(t.version.p[0] == 0x02);
  /* serialNumber, 20 octets at offset 15. */
  CHECK(t.serial.p == x509_golden + 15 && t.serial.n == 20);
  /* signature AlgorithmIdentifier value at offset 37, 10 octets. */
  CHECK(t.sig_alg.p == x509_golden + 37 && t.sig_alg.n == 10);
  /* extensions [3] inner SEQUENCE value at offset 228, 81 octets. */
  CHECK(t.extensions.p == x509_golden + 228 && t.extensions.n == 81);
}

/* The structured issuer/subject/validity/spki views must match the existing
 * x509 part outputs exactly. */
static void test_fields_match_parts(void) {
  tbscert    t;
  wired_span tbs = wired_span_of(x509_golden + 4, 305);
  CHECK(tbscert_parse(tbs, &t) == 1);

  wired_span issuer, subject;
  CHECK(x509_issuer(tbs, &issuer) == 1);
  CHECK(x509_subject(tbs, &subject) == 1);
  /* chain views include the header; t views are value-only: header is 2. */
  CHECK(t.issuer.p == issuer.p + 2 && t.issuer.n + 2 == issuer.n);
  CHECK(t.subject.p == subject.p + 2 && t.subject.n + 2 == subject.n);

  wired_span oid, key;
  CHECK(x509_public_key(tbs, &oid, &key) == 1);
  /* spki value at offset 135, 89 octets; the BIT STRING key sits inside it. */
  CHECK(t.spki.p == x509_golden + 135 && t.spki.n == 89);
  CHECK(key.p >= t.spki.p && key.p < t.spki.p + t.spki.n);
}

static void test_fields_truncated(void) {
  tbscert t;
  /* Too short to read the tbs SEQUENCE header. */
  CHECK(tbscert_parse(wired_span_of(x509_golden + 4, 3), &t) == 0);
}

/* A tbs SEQUENCE with too few elements never fills the mandatory body. */
static void test_fields_short_tbs(void) {
  const u8 tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  tbscert  t;
  CHECK(tbscert_parse(wired_span_of(tbs, sizeof(tbs)), &t) == 0);
}

void test_fields(void) {
  test_fields_golden();
  test_fields_match_parts();
  test_fields_truncated();
  test_fields_short_tbs();
}
