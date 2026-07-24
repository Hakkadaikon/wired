#include "crypto/pki/encoding/x509/keyid.h"

#include "test.h"
#include "x509_golden.h"

/* Six NULL elements standing in for serialNumber..subjectPublicKeyInfo, so
 * quic_x509_tbs_cursor's skip(6) lands past them. */
#define KEYIDT_DUMMY6 \
  0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00

static const u8 keyidt_tbs_no_ext[] = {0x30, 0x0c, KEYIDT_DUMMY6};

/* RFC 5280 4.2.1.2. subjectKeyIdentifier extension (2.5.29.14), extnValue
 * is KeyIdentifier ::= OCTET STRING (here 4 arbitrary octets: DE AD BE EF).
 * tbs = dummy6 ++ [3] { SEQUENCE { Extension } }. */
static const u8 keyidt_tbs_skid[] = {
    0x30, 0x1f, KEYIDT_DUMMY6, 0xa3, 0x11, 0x30, 0x0f, 0x30, 0x0d, 0x06, 0x03,
    0x55, 0x1d, 0x0e,          0x04, 0x06, 0x04, 0x04, 0xde, 0xad, 0xbe, 0xef};

/* RFC 5280 4.2.1.1. authorityKeyIdentifier extension (2.5.29.35), extnValue
 * wraps AuthorityKeyIdentifier ::= SEQUENCE { keyIdentifier [0]
 * KeyIdentifier OPTIONAL, ... }. keyIdentifier here is BE EF CA FE. */
static const u8 keyidt_tbs_akid[] = {
    0x30, 0x21, KEYIDT_DUMMY6, 0xa3, 0x13, 0x30, 0x11, 0x30,
    0x0f, 0x06, 0x03,          0x55, 0x1d, 0x23, 0x04, 0x08,
    0x30, 0x06, 0x80,          0x04, 0xbe, 0xef, 0xca, 0xfe};

/* RFC 5280 4.2.1.1/4.2.1.2: the implementation shall recognize the
 * authority and subject key identifier extensions. Recognition means
 * locating the extnValue by its extnID; RFC 5280 4.2.1.2 does not require
 * key-identifier matching during path validation. */
static void test_skid_found(void) {
  quic_span val;
  CHECK(
      quic_x509_subject_key_id(
          quic_span_of(keyidt_tbs_skid, sizeof(keyidt_tbs_skid)), &val) == 1);
  CHECK(val.n == 6);
}

static void test_akid_found(void) {
  quic_span val;
  CHECK(
      quic_x509_authority_key_id(
          quic_span_of(keyidt_tbs_akid, sizeof(keyidt_tbs_akid)), &val) == 1);
  CHECK(val.n == 8);
}

static void test_skid_absent(void) {
  quic_span val;
  CHECK(
      quic_x509_subject_key_id(
          quic_span_of(keyidt_tbs_no_ext, sizeof(keyidt_tbs_no_ext)), &val) ==
      0);
}

static void test_akid_absent(void) {
  quic_span val;
  CHECK(
      quic_x509_authority_key_id(
          quic_span_of(keyidt_tbs_no_ext, sizeof(keyidt_tbs_no_ext)), &val) ==
      0);
}

/* A real certificate (the golden cert) carries both extensions; both must be
 * recognized from the same tbs. */
static void test_golden_cert_has_both(void) {
  quic_x509 c;
  quic_span val;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_x509_golden, sizeof(quic_x509_golden)), &c) == 1);
  CHECK(quic_x509_subject_key_id(c.tbs, &val) == 1);
  CHECK(val.n == 22);
  CHECK(quic_x509_authority_key_id(c.tbs, &val) == 1);
  CHECK(val.n == 24);
}

void test_keyid(void) {
  test_skid_found();
  test_akid_found();
  test_skid_absent();
  test_akid_absent();
  test_golden_cert_has_both();
}
