#include "crypto/pki/encoding/x509/eku.h"

#include "test.h"

/* Six NULL elements standing in for serialNumber..subjectPublicKeyInfo, so
 * quic_x509_tbs_cursor's skip(6) lands past them. */
#define EKUT_DUMMY6 \
  0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00

/* id-kp-clientAuth = 1.3.6.1.5.5.7.3.2 (RFC 5280 4.2.1.12), used only as a
 * "some other purpose" OID to prove non-membership. */
static const u8 ekut_oid_client_auth[] = {0x2b, 0x06, 0x01, 0x05,
                                          0x05, 0x07, 0x03, 0x02};

static const u8 ekut_tbs_no_ext[] = {0x30, 0x0c, EKUT_DUMMY6};

/* id-ce-extKeyUsage = 2.5.29.37, extnValue OCTET STRING wrapping an empty
 * SEQUENCE OF KeyPurposeId. tbs = dummy6 ++ [3] { SEQUENCE { Extension } }. */
static const u8 ekut_tbs_empty[] = {0x30, 0x1b, EKUT_DUMMY6, 0xa3, 0x0d, 0x30,
                                    0x0b, 0x30, 0x09,        0x06, 0x03, 0x55,
                                    0x1d, 0x25, 0x04,        0x02, 0x30, 0x00};

/* extKeyUsage containing only id-kp-serverAuth (1.3.6.1.5.5.7.3.1). */
static const u8 ekut_tbs_server_auth[] = {
    0x30, 0x25, EKUT_DUMMY6, 0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x1d,        0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08,
    0x2b, 0x06, 0x01,        0x05, 0x05, 0x07, 0x03, 0x01};

/* extKeyUsage containing only id-kp-clientAuth (1.3.6.1.5.5.7.3.2). */
static const u8 ekut_tbs_client_auth[] = {
    0x30, 0x25, EKUT_DUMMY6, 0xa3, 0x17, 0x30, 0x15, 0x30, 0x13, 0x06,
    0x03, 0x55, 0x1d,        0x25, 0x04, 0x0c, 0x30, 0x0a, 0x06, 0x08,
    0x2b, 0x06, 0x01,        0x05, 0x05, 0x07, 0x03, 0x02};

/* extKeyUsage containing clientAuth then serverAuth. */
static const u8 ekut_tbs_both[] = {
    0x30, 0x2f, EKUT_DUMMY6, 0xa3, 0x21, 0x30, 0x1f, 0x30, 0x1d, 0x06,
    0x03, 0x55, 0x1d,        0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08,
    0x2b, 0x06, 0x01,        0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08,
    0x2b, 0x06, 0x01,        0x05, 0x05, 0x07, 0x03, 0x01};

static quic_span server_auth(void) {
  return quic_span_of(
      quic_x509_oid_server_auth, sizeof(quic_x509_oid_server_auth));
}

/* RFC 5280 4.2.1.12: extKeyUsage absent is unrestricted, so any purpose is
 * allowed. */
static void test_eku_no_extension_allows(void) {
  CHECK(
      quic_x509_eku_allows(
          quic_span_of(ekut_tbs_no_ext, sizeof(ekut_tbs_no_ext)),
          server_auth()) == 1);
}

/* An empty KeyPurposeId list permits nothing. */
static void test_eku_empty_rejects(void) {
  CHECK(
      quic_x509_eku_allows(
          quic_span_of(ekut_tbs_empty, sizeof(ekut_tbs_empty)),
          server_auth()) == 0);
}

/* serverAuth listed: allowed. */
static void test_eku_server_auth_present_allows(void) {
  CHECK(
      quic_x509_eku_allows(
          quic_span_of(ekut_tbs_server_auth, sizeof(ekut_tbs_server_auth)),
          server_auth()) == 1);
}

/* Only clientAuth listed: serverAuth is not allowed. */
static void test_eku_server_auth_absent_rejects(void) {
  CHECK(
      quic_x509_eku_allows(
          quic_span_of(ekut_tbs_client_auth, sizeof(ekut_tbs_client_auth)),
          server_auth()) == 0);
}

/* serverAuth among multiple KeyPurposeIds: allowed. */
static void test_eku_server_auth_among_others_allows(void) {
  CHECK(
      quic_x509_eku_allows(
          quic_span_of(ekut_tbs_both, sizeof(ekut_tbs_both)), server_auth()) ==
      1);
}

/* Querying a purpose that is absent even though the list is non-empty and
 * contains a different purpose (clientAuth). */
static void test_eku_client_auth_query_absent(void) {
  CHECK(
      quic_x509_eku_allows(
          quic_span_of(ekut_tbs_server_auth, sizeof(ekut_tbs_server_auth)),
          quic_span_of(ekut_oid_client_auth, sizeof(ekut_oid_client_auth))) ==
      0);
}

void test_eku(void) {
  test_eku_no_extension_allows();
  test_eku_empty_rejects();
  test_eku_server_auth_present_allows();
  test_eku_server_auth_absent_rejects();
  test_eku_server_auth_among_others_allows();
  test_eku_client_auth_query_absent();
}
