#include "crypto/pki/cert/tbscert/fields.h"

#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1.2. Every field boundary is pulled from the real tbs. The
 * offsets below are hand-verified against the golden DER. */
static void test_fields_golden(void) {
  quic_x509 c;
  CHECK(quic_x509_parse(quic_x509_golden, sizeof(quic_x509_golden), &c) == 1);
  quic_tbscert t;
  CHECK(quic_tbscert_parse(c.tbs, c.tbs_len, &t) == 1);

  /* version [0] EXPLICIT inner INTEGER value = 0x02 (v3), at offset 12. */
  CHECK(t.version == quic_x509_golden + 12 && t.version_len == 1);
  CHECK(t.version[0] == 0x02);
  /* serialNumber, 20 octets at offset 15. */
  CHECK(t.serial == quic_x509_golden + 15 && t.serial_len == 20);
  /* signature AlgorithmIdentifier value at offset 37, 10 octets. */
  CHECK(t.sig_alg == quic_x509_golden + 37 && t.sig_alg_len == 10);
  /* extensions [3] inner SEQUENCE value at offset 228, 81 octets. */
  CHECK(t.extensions == quic_x509_golden + 228 && t.extensions_len == 81);
}

/* The structured issuer/subject/validity/spki views must match the existing
 * x509 part outputs exactly. */
static void test_fields_match_parts(void) {
  quic_tbscert t;
  CHECK(quic_tbscert_parse(quic_x509_golden + 4, 305, &t) == 1);

  const u8 *issuer, *subject;
  usz       ilen, slen;
  CHECK(quic_x509_issuer(quic_x509_golden + 4, 305, &issuer, &ilen) == 1);
  CHECK(quic_x509_subject(quic_x509_golden + 4, 305, &subject, &slen) == 1);
  /* chain views include the header; t views are value-only: header is 2. */
  CHECK(t.issuer == issuer + 2 && t.issuer_len + 2 == ilen);
  CHECK(t.subject == subject + 2 && t.subject_len + 2 == slen);

  const u8 *oid, *key;
  usz       oid_len, key_len;
  CHECK(
      quic_x509_public_key(
          quic_x509_golden + 4, 305, &oid, &oid_len, &key, &key_len) == 1);
  /* spki value at offset 135, 89 octets; the BIT STRING key sits inside it. */
  CHECK(t.spki == quic_x509_golden + 135 && t.spki_len == 89);
  CHECK(key >= t.spki && key < t.spki + t.spki_len);
}

static void test_fields_truncated(void) {
  quic_tbscert t;
  /* Too short to read the tbs SEQUENCE header. */
  CHECK(quic_tbscert_parse(quic_x509_golden + 4, 3, &t) == 0);
}

/* A tbs SEQUENCE with too few elements never fills the mandatory body. */
static void test_fields_short_tbs(void) {
  const u8     tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  quic_tbscert t;
  CHECK(quic_tbscert_parse(tbs, sizeof(tbs), &t) == 0);
}

void test_fields(void) {
  test_fields_golden();
  test_fields_match_parts();
  test_fields_truncated();
  test_fields_short_tbs();
}
