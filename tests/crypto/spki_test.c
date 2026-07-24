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

/* RFC 8410 3. id-X25519 = 1.3.101.110, id-X448 = 1.3.101.111,
 * id-Ed25519 = 1.3.101.112, id-Ed448 = 1.3.101.113: the OID arc 1.3.101.x
 * DER-encodes as 0x2b, 0x65, x (both arcs < 128, so each is one octet; the
 * first two arcs 1,3 collapse to 40*1+3 = 43 = 0x2b per X.690 8.19.4). */
static const u8 oid_x25519_bytes[]  = {0x2b, 0x65, 0x6e};
static const u8 oid_x448_bytes[]    = {0x2b, 0x65, 0x6f};
static const u8 oid_ed25519_bytes[] = {0x2b, 0x65, 0x70};
static const u8 oid_ed448_bytes[]   = {0x2b, 0x65, 0x71};

static void test_spki_is_x25519(void) {
  quic_span oid = quic_span_of(oid_x25519_bytes, sizeof(oid_x25519_bytes));
  CHECK(quic_x509_is_x25519(oid) == 1);
  CHECK(quic_x509_is_x448(oid) == 0);
  CHECK(quic_x509_is_ed25519(oid) == 0);
  CHECK(quic_x509_is_ed448(oid) == 0);
}

static void test_spki_is_x448(void) {
  quic_span oid = quic_span_of(oid_x448_bytes, sizeof(oid_x448_bytes));
  CHECK(quic_x509_is_x448(oid) == 1);
  CHECK(quic_x509_is_x25519(oid) == 0);
}

static void test_spki_is_ed25519(void) {
  quic_span oid = quic_span_of(oid_ed25519_bytes, sizeof(oid_ed25519_bytes));
  CHECK(quic_x509_is_ed25519(oid) == 1);
  CHECK(quic_x509_is_ed448(oid) == 0);
}

static void test_spki_is_ed448(void) {
  quic_span oid = quic_span_of(oid_ed448_bytes, sizeof(oid_ed448_bytes));
  CHECK(quic_x509_is_ed448(oid) == 1);
  CHECK(quic_x509_is_ed25519(oid) == 0);
}

void test_spki(void) {
  test_spki_golden();
  test_spki_truncated();
  test_spki_short_tbs();
  test_spki_is_x25519();
  test_spki_is_x448();
  test_spki_is_ed25519();
  test_spki_is_ed448();
}
