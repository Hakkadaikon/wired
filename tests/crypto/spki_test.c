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

/* RFC 5480 2.1.2. id-ecDH = 1.3.132.1.12, id-ecMQV = 1.3.132.1.13 (both
 * hand-encoded and cross-checked: 1.3.132 -> 0x2b 0x81 0x04 per X.690
 * 8.19.4/8.19.2 (40*1+3=43=0x2b; 132 >= 128 so base-128 0x81 0x04), then
 * schemes(1) ecdh(12)/ecmqv(13) as single octets 0x01 0x0c / 0x01 0x0d). */
static const u8 oid_ecdh_bytes[]  = {0x2b, 0x81, 0x04, 0x01, 0x0c};
static const u8 oid_ecmqv_bytes[] = {0x2b, 0x81, 0x04, 0x01, 0x0d};
static const u8 oid_p256_bytes[]  = {0x2a, 0x86, 0x48, 0xce,
                                     0x3d, 0x03, 0x01, 0x07};
static const u8 oid_ec_bytes[]    = {0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01};

static void test_spki_is_ecdh(void) {
  CHECK(
      quic_x509_is_ecdh(quic_span_of(oid_ecdh_bytes, sizeof(oid_ecdh_bytes))) ==
      1);
  CHECK(
      quic_x509_is_ecmqv(
          quic_span_of(oid_ecdh_bytes, sizeof(oid_ecdh_bytes))) == 0);
  CHECK(
      quic_x509_is_ecdh(quic_span_of(oid_ec_bytes, sizeof(oid_ec_bytes))) == 0);
}

static void test_spki_is_ecmqv(void) {
  CHECK(
      quic_x509_is_ecmqv(
          quic_span_of(oid_ecmqv_bytes, sizeof(oid_ecmqv_bytes))) == 1);
  CHECK(
      quic_x509_is_ecdh(
          quic_span_of(oid_ecmqv_bytes, sizeof(oid_ecmqv_bytes))) == 0);
}

/* Five NULL elements standing in for serialNumber..subject, so
 * quic_x509_tbs_cursor's skip(SPKI_SKIP=5) lands on subjectPublicKeyInfo. */
#define SPT_DUMMY5 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00
/* subjectPublicKey BIT STRING: unused-bits 0, then a 64-byte filler (content
 * doesn't matter -- these tests only exercise the algorithm/params path). */
#define SPT_KEY_BITS                                                          \
  0x03, 0x42, 0x00, 0x04, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,     \
      0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, \
      0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, \
      0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, \
      0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, \
      0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f

/* tbs = dummy5 ++ SPKI { AlgorithmIdentifier { id-ecDH, prime256v1 }, key }.
 * ECParameters (prime256v1) present, as RFC 5480 2.1.2 requires. */
static const u8 spt_tbs_ecdh_with_params[] = {
    0x30, 0x63, SPT_DUMMY5, 0x30, 0x57, 0x30, 0x11,        0x06, 0x05,
    0x2b, 0x81, 0x04,       0x01, 0x0c, 0x06, 0x08,        0x2a, 0x86,
    0x48, 0xce, 0x3d,       0x03, 0x01, 0x07, SPT_KEY_BITS};

/* Same, but AlgorithmIdentifier carries only the id-ecDH OID: ECParameters
 * absent, which RFC 5480 2.1.2 forbids for id-ecDH. */
static const u8 spt_tbs_ecdh_no_params[] = {
    0x30, 0x59, SPT_DUMMY5, 0x30, 0x4d, 0x30, 0x07,        0x06,
    0x05, 0x2b, 0x81,       0x04, 0x01, 0x0c, SPT_KEY_BITS};

/* id-ecPublicKey (unrestricted) with prime256v1 params: the MUST-present
 * rule doesn't apply to this OID, so params-absent would also be fine, but
 * this fixture keeps them to double as a "not id-ecDH/id-ecMQV" control. */
static const u8 spt_tbs_ec_with_params[] = {
    0x30, 0x65, SPT_DUMMY5, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07,
    0x2a, 0x86, 0x48,       0xce, 0x3d, 0x02, 0x01, 0x06, 0x08,
    0x2a, 0x86, 0x48,       0xce, 0x3d, 0x03, 0x01, 0x07, SPT_KEY_BITS};

static void test_ec_curve_ecdh_reads_params(void) {
  quic_span curve_oid;
  CHECK(
      quic_x509_ec_curve(
          quic_span_of(
              spt_tbs_ecdh_with_params, sizeof(spt_tbs_ecdh_with_params)),
          &curve_oid) == 1);
  CHECK(quic_x509_is_p256(curve_oid) == 1);
}

static void test_restricted_params_ecdh_with_params_ok(void) {
  CHECK(
      quic_x509_ec_restricted_params_ok(quic_span_of(
          spt_tbs_ecdh_with_params, sizeof(spt_tbs_ecdh_with_params))) == 1);
}

/* RFC 5480 2.1.2: id-ecDH MUST carry ECParameters; absent is rejected. */
static void test_restricted_params_ecdh_no_params_rejected(void) {
  CHECK(
      quic_x509_ec_restricted_params_ok(quic_span_of(
          spt_tbs_ecdh_no_params, sizeof(spt_tbs_ecdh_no_params))) == 0);
}

/* id-ecPublicKey (not restricted): the MUST-present rule doesn't apply, so
 * this always passes regardless of ECParameters. */
static void test_restricted_params_unrestricted_alg_ok(void) {
  CHECK(
      quic_x509_ec_restricted_params_ok(quic_span_of(
          spt_tbs_ec_with_params, sizeof(spt_tbs_ec_with_params))) == 1);
}

void test_spki(void) {
  test_spki_golden();
  test_spki_truncated();
  test_spki_short_tbs();
  test_spki_is_x25519();
  test_spki_is_x448();
  test_spki_is_ed25519();
  test_spki_is_ed448();
  test_spki_is_ecdh();
  test_spki_is_ecmqv();
  test_ec_curve_ecdh_reads_params();
  test_restricted_params_ecdh_with_params_ok();
  test_restricted_params_ecdh_no_params_rejected();
  test_restricted_params_unrestricted_alg_ok();
}
