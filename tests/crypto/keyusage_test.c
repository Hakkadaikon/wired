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

static const u8 kut_tbs_no_ext[]     = {0x30, 0x0c, KUT_DUMMY6};
static const u8 kut_tbs_certsign[]   = {KUT_TBS(0x04)}; /* bit5 set */
static const u8 kut_tbs_digitalsig[] = {KUT_TBS(0x80)}; /* bit0 set only */
static const u8 kut_tbs_all_low6[]   = {KUT_TBS(0xfc)}; /* bit0..5 all set */

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

void test_keyusage(void) {
  test_can_sign_no_extension();
  test_can_sign_certsign_set();
  test_can_sign_certsign_unset();
  test_can_sign_certsign_among_others();
}
