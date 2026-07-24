#include "crypto/pki/encoding/x509/keyusage.h"

#include "test.h"

/* Six NULL elements standing in for serialNumber..subjectPublicKeyInfo, so
 * quic_x509_tbs_cursor's skip(6) lands past them. */
#define KUT_DUMMY6 \
  0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00

/* id-ce-keyUsage = 2.5.29.15, extnValue OCTET STRING wrapping a KeyUsage
 * BIT STRING whose single data octet is `bits` (unused-bits count 2, so
 * only bit0..bit5 -- digitalSignature..keyCertSign -- are meaningful). */
#define KUT_EXT_KU(bits) \
  0x30, 0x0b, 0x06, 0x03, 0x55, 0x1d, 0x0f, 0x04, 0x04, 0x03, 0x02, 0x02, (bits)

/* tbs = dummy6 ++ [3] { SEQUENCE { one keyUsage Extension } }. */
#define KUT_TBS(bits) \
  0x30, 0x1d, KUT_DUMMY6, 0xa3, 0x0f, 0x30, 0x0d, KUT_EXT_KU(bits)

static const u8 kut_tbs_no_ext[]       = {0x30, 0x0c, KUT_DUMMY6};
static const u8 kut_tbs_certsign[]     = {KUT_TBS(0x04)}; /* bit5 set */
static const u8 kut_tbs_digitalsig[]   = {KUT_TBS(0x80)}; /* bit0 set only */
static const u8 kut_tbs_all_low6[]     = {KUT_TBS(0xfc)}; /* bit0..5 all set */
static const u8 kut_tbs_keyagreement[] = {KUT_TBS(0x08)}; /* bit4 set only */
static const u8 kut_tbs_nonrepud[]     = {KUT_TBS(0x40)}; /* bit1 set only */
static const u8 kut_tbs_crlsign[]      = {KUT_TBS(0x02)}; /* bit6 set only */

/* RFC 5280 4.2.1.3: keyUsage absent is unconstrained, so signing is
 * permitted by default. */
static void test_can_sign_no_extension(void) {
  CHECK(
      quic_x509_can_sign_certs(
          quic_span_of(kut_tbs_no_ext, sizeof(kut_tbs_no_ext))) == 1);
}

/* keyCertSign (bit5) set: permitted. */
static void test_can_sign_certsign_set(void) {
  CHECK(
      quic_x509_can_sign_certs(
          quic_span_of(kut_tbs_certsign, sizeof(kut_tbs_certsign))) == 1);
}

/* Only digitalSignature (bit0) set, keyCertSign absent: rejected. */
static void test_can_sign_certsign_unset(void) {
  CHECK(
      quic_x509_can_sign_certs(
          quic_span_of(kut_tbs_digitalsig, sizeof(kut_tbs_digitalsig))) == 0);
}

/* Every bit in the encoded octet set (0..5), including keyCertSign among
 * others: permitted. */
static void test_can_sign_certsign_among_others(void) {
  CHECK(
      quic_x509_can_sign_certs(
          quic_span_of(kut_tbs_all_low6, sizeof(kut_tbs_all_low6))) == 1);
}

/* RFC 8410 5: keyUsage absent is unconstrained, so key agreement is
 * permitted by default. */
static void test_keyagreement_no_extension(void) {
  CHECK(
      quic_x509_keyagreement_ok(
          quic_span_of(kut_tbs_no_ext, sizeof(kut_tbs_no_ext))) == 1);
}

/* keyAgreement (bit4) set: permitted. */
static void test_keyagreement_bit_set(void) {
  CHECK(
      quic_x509_keyagreement_ok(quic_span_of(
          kut_tbs_keyagreement, sizeof(kut_tbs_keyagreement))) == 1);
}

/* keyCertSign set but not keyAgreement: rejected. */
static void test_keyagreement_bit_unset(void) {
  CHECK(
      quic_x509_keyagreement_ok(
          quic_span_of(kut_tbs_certsign, sizeof(kut_tbs_certsign))) == 0);
}

/* RFC 8410 5: keyUsage absent is unconstrained, so an end-entity Ed25519/
 * Ed448 cert may sign by default. */
static void test_ed_leaf_sig_no_extension(void) {
  CHECK(
      quic_x509_ed_leaf_sig_ok(
          quic_span_of(kut_tbs_no_ext, sizeof(kut_tbs_no_ext))) == 1);
}

/* digitalSignature (bit0) alone: permitted. */
static void test_ed_leaf_sig_digitalsignature(void) {
  CHECK(
      quic_x509_ed_leaf_sig_ok(
          quic_span_of(kut_tbs_digitalsig, sizeof(kut_tbs_digitalsig))) == 1);
}

/* nonRepudiation (bit1) alone: permitted. */
static void test_ed_leaf_sig_nonrepudiation(void) {
  CHECK(
      quic_x509_ed_leaf_sig_ok(
          quic_span_of(kut_tbs_nonrepud, sizeof(kut_tbs_nonrepud))) == 1);
}

/* Neither digitalSignature nor nonRepudiation, only keyAgreement: rejected.
 */
static void test_ed_leaf_sig_neither(void) {
  CHECK(
      quic_x509_ed_leaf_sig_ok(quic_span_of(
          kut_tbs_keyagreement, sizeof(kut_tbs_keyagreement))) == 0);
}

/* RFC 8410 5: keyUsage absent is unconstrained, so a CA Ed25519/Ed448 cert
 * is admissible by default. */
static void test_ed_ca_no_extension(void) {
  CHECK(
      quic_x509_ed_ca_ok(
          quic_span_of(kut_tbs_no_ext, sizeof(kut_tbs_no_ext))) == 1);
}

/* keyCertSign (bit5) alone: permitted for a CA Ed25519/Ed448 cert. */
static void test_ed_ca_keycertsign(void) {
  CHECK(
      quic_x509_ed_ca_ok(
          quic_span_of(kut_tbs_certsign, sizeof(kut_tbs_certsign))) == 1);
}

/* cRLSign (bit6) alone: permitted for a CA Ed25519/Ed448 cert. */
static void test_ed_ca_crlsign(void) {
  CHECK(
      quic_x509_ed_ca_ok(
          quic_span_of(kut_tbs_crlsign, sizeof(kut_tbs_crlsign))) == 1);
}

/* Only keyAgreement, none of the admissible CA bits: rejected. */
static void test_ed_ca_none_admissible(void) {
  CHECK(
      quic_x509_ed_ca_ok(quic_span_of(
          kut_tbs_keyagreement, sizeof(kut_tbs_keyagreement))) == 0);
}

void test_keyusage(void) {
  test_can_sign_no_extension();
  test_can_sign_certsign_set();
  test_can_sign_certsign_unset();
  test_can_sign_certsign_among_others();
  test_keyagreement_no_extension();
  test_keyagreement_bit_set();
  test_keyagreement_bit_unset();
  test_ed_leaf_sig_no_extension();
  test_ed_leaf_sig_digitalsignature();
  test_ed_leaf_sig_nonrepudiation();
  test_ed_leaf_sig_neither();
  test_ed_ca_no_extension();
  test_ed_ca_keycertsign();
  test_ed_ca_crlsign();
  test_ed_ca_none_admissible();
}
