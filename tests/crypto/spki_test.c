#include "crypto/pki/encoding/x509/spki.h"

#include "crypto/pki/encoding/x509/x509.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1.2.7. The EC public key is pulled out of the real tbs. */
static void test_spki_golden(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_x509_golden, sizeof(quic_x509_golden)), &c) == 1);

  quic_span oid, key;
  CHECK(quic_x509_public_key(c.tbs, &oid, &key) == 1);
  /* algorithm is id-ecPublicKey, not rsaEncryption. */
  CHECK(quic_x509_is_ec(oid) == 1);
  CHECK(quic_x509_is_rsa(oid) == 0);
  /* subjectPublicKey BIT STRING value is 66 octets (at offset 158). */
  CHECK(key.p == quic_x509_golden + 158 && key.n == 66);
  /* BIT STRING leads with the unused-bits count 0x00, then 0x04 (point). */
  CHECK(key.p[0] == 0x00 && key.p[1] == 0x04);
}

static void test_spki_truncated(void) {
  quic_span oid, key;
  /* tbs too short to even read its own SEQUENCE header. */
  CHECK(
      quic_x509_public_key(quic_span_of(quic_x509_golden + 4, 3), &oid, &key) ==
      0);
}

/* A tbs SEQUENCE with too few elements never reaches the SPKI slot. */
static void test_spki_short_tbs(void) {
  const u8  tbs[] = {0x30, 0x03, 0x02, 0x01, 0x02};
  quic_span oid, key;
  CHECK(quic_x509_public_key(quic_span_of(tbs, sizeof(tbs)), &oid, &key) == 0);
}

void test_spki(void) {
  test_spki_golden();
  test_spki_truncated();
  test_spki_short_tbs();
}
