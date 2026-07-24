#include "crypto/pki/encoding/x509/x509.h"

#include "crypto/pki/encoding/asn1/derval.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1. The three top-level fields are split out of a real cert. */
static void test_x509_parse_golden(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(quic_x509_golden, sizeof(quic_x509_golden)), &c) == 1);
  /* tbsCertificate spans offset 4..309 (header included). */
  CHECK(c.tbs.p == quic_x509_golden + 4 && c.tbs.n == 305);
  /* signatureAlgorithm OID is ecdsa-with-SHA256. */
  CHECK(
      quic_der_oid_equal(
          c.sig_alg_oid,
          quic_span_of(quic_oid_ecdsa_sha256, sizeof(quic_oid_ecdsa_sha256))) ==
      1);
  /* signatureValue BIT STRING value is 71 octets (at offset 323). */
  CHECK(c.sig.p == quic_x509_golden + 323 && c.sig.n == 71);
}

static void test_x509_truncated(void) {
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(quic_x509_golden, 10), &c) == 0);
  CHECK(quic_x509_parse(quic_span_of(quic_x509_golden, 0), &c) == 0);
}

/* A SEQUENCE whose first element is an INTEGER (not the tbs SEQUENCE). */
static void test_x509_not_tbs_seq(void) {
  const u8  bad[] = {0x30, 0x03, 0x02, 0x01, 0x05};
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(bad, sizeof(bad)), &c) == 0);
}

/* Top-level tag is not SEQUENCE. */
static void test_x509_not_seq(void) {
  const u8  bad[] = {0x02, 0x01, 0x05};
  quic_x509 c;
  CHECK(quic_x509_parse(quic_span_of(bad, sizeof(bad)), &c) == 0);
}

/* Six NULL elements standing in for serialNumber..subjectPublicKeyInfo, so
 * quic_x509_tbs_cursor's skip(6) lands past them. */
#define X509T_DUMMY6 \
  0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00

/* A tbs SEQUENCE with no [3] extensions element at all. */
static const u8 x509t_tbs_no_ext[] = {0x30, 0x0c, X509T_DUMMY6};

/* id-ce-basicConstraints = 2.5.29.19, critical TRUE, extnValue OCTET STRING
 * wrapping an empty SEQUENCE (value not inspected by this test). */
#define X509T_EXT_BC_CRIT \
  0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff, 0x04, 0x00

/* An extnID this SDK does not know (2.5.29.99), critical TRUE. */
#define X509T_EXT_UNKNOWN_CRIT \
  0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x63, 0x01, 0x01, 0xff, 0x04, 0x00

/* The same unknown extnID, critical FALSE (explicit). */
#define X509T_EXT_UNKNOWN_NONCRIT \
  0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x63, 0x01, 0x01, 0x00, 0x04, 0x00

/* The same unknown extnID with critical omitted (DER default FALSE). */
#define X509T_EXT_UNKNOWN_DEFAULT \
  0x30, 0x07, 0x06, 0x03, 0x55, 0x1d, 0x63, 0x04, 0x00

/* id-ce-certificatePolicies = 2.5.29.32, critical TRUE. This SDK has no
 * logic to interpret policy OIDs (RFC 5280 4.2.1.4), so a critical instance
 * must be rejected the same way any unrecognized critical extension is
 * (4.2.1.4 "unable to interpret ... MUST reject"). */
#define X509T_EXT_CERT_POLICIES_CRIT \
  0x30, 0x0a, 0x06, 0x03, 0x55, 0x1d, 0x20, 0x01, 0x01, 0xff, 0x04, 0x00

/* tbs = dummy6 ++ [3] { SEQUENCE { one Extension } }. */
static const u8 x509t_tbs_bc_crit[] = {0x30, 0x1c, X509T_DUMMY6,     0xa3, 0x0e,
                                       0x30, 0x0c, X509T_EXT_BC_CRIT};

static const u8 x509t_tbs_unknown_crit[] = {
    0x30, 0x1c, X509T_DUMMY6, 0xa3, 0x0e, 0x30, 0x0c, X509T_EXT_UNKNOWN_CRIT};

static const u8 x509t_tbs_unknown_noncrit[] = {
    0x30, 0x1c, X509T_DUMMY6, 0xa3,
    0x0e, 0x30, 0x0c,         X509T_EXT_UNKNOWN_NONCRIT};

static const u8 x509t_tbs_unknown_default[] = {
    0x30, 0x19, X509T_DUMMY6, 0xa3,
    0x0b, 0x30, 0x09,         X509T_EXT_UNKNOWN_DEFAULT};

/* tbs = dummy6 ++ [3] { SEQUENCE { known-critical, unknown-critical } }. */
static const u8 x509t_tbs_cert_policies_crit[] = {
    0x30, 0x1c, X509T_DUMMY6, 0xa3,
    0x0e, 0x30, 0x0c,         X509T_EXT_CERT_POLICIES_CRIT};

static const u8 x509t_tbs_mixed[] = {
    0x30,
    0x28,
    X509T_DUMMY6,
    0xa3,
    0x1a,
    0x30,
    0x18,
    X509T_EXT_BC_CRIT,
    X509T_EXT_UNKNOWN_CRIT};

/* RFC 5280 4.2: no extensions at all is not a rejection. */
static void test_unknown_critical_no_extensions(void) {
  CHECK(
      quic_x509_has_unknown_critical(
          quic_span_of(x509t_tbs_no_ext, sizeof(x509t_tbs_no_ext))) == 0);
}

/* A known critical extension (basicConstraints) does not trigger rejection.
 */
static void test_unknown_critical_known_ext_ok(void) {
  CHECK(
      quic_x509_has_unknown_critical(
          quic_span_of(x509t_tbs_bc_crit, sizeof(x509t_tbs_bc_crit))) == 0);
}

/* RFC 5280 4.2: an unrecognized extnID marked critical TRUE is rejected. */
static void test_unknown_critical_rejects(void) {
  CHECK(
      quic_x509_has_unknown_critical(quic_span_of(
          x509t_tbs_unknown_crit, sizeof(x509t_tbs_unknown_crit))) == 1);
}

/* An unrecognized extnID marked critical FALSE is not rejected. */
static void test_unknown_noncritical_ok(void) {
  CHECK(
      quic_x509_has_unknown_critical(quic_span_of(
          x509t_tbs_unknown_noncrit, sizeof(x509t_tbs_unknown_noncrit))) == 0);
}

/* An unrecognized extnID with critical omitted defaults to FALSE (X.690
 * DEFAULT), so it is not rejected. */
static void test_unknown_critical_default_false(void) {
  CHECK(
      quic_x509_has_unknown_critical(quic_span_of(
          x509t_tbs_unknown_default, sizeof(x509t_tbs_unknown_default))) == 0);
}

/* RFC 5280 4.2.1.4: a critical certificate policies extension cannot be
 * interpreted by this SDK (no policyOID semantics), so it is rejected via
 * the same unknown-critical path as any other unrecognized critical
 * extension. */
static void test_critical_certificate_policies_rejects(void) {
  CHECK(
      quic_x509_has_unknown_critical(quic_span_of(
          x509t_tbs_cert_policies_crit,
          sizeof(x509t_tbs_cert_policies_crit))) == 1);
}

/* One known-critical and one unknown-critical extension: rejected because of
 * the second. */
static void test_unknown_critical_mixed_rejects(void) {
  CHECK(
      quic_x509_has_unknown_critical(
          quic_span_of(x509t_tbs_mixed, sizeof(x509t_tbs_mixed))) == 1);
}

void test_x509(void) {
  test_x509_parse_golden();
  test_x509_truncated();
  test_x509_not_tbs_seq();
  test_x509_not_seq();
  test_unknown_critical_no_extensions();
  test_unknown_critical_known_ext_ok();
  test_unknown_critical_rejects();
  test_unknown_noncritical_ok();
  test_unknown_critical_default_false();
  test_critical_certificate_policies_rejects();
  test_unknown_critical_mixed_rejects();
}
