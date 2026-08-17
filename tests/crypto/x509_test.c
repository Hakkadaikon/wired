#include "crypto/pki/encoding/x509/x509.h"

#include "crypto/pki/encoding/asn1/derval.h"
#include "test.h"
#include "x509_golden.h"

/* RFC 5280 4.1. The three top-level fields are split out of a real cert. */
static void test_x509_parse_golden(void) {
  x509 c;
  CHECK(x509_parse(wired_span_of(x509_golden, sizeof(x509_golden)), &c) == 1);
  /* tbsCertificate spans offset 4..309 (header included). */
  CHECK(c.tbs.p == x509_golden + 4 && c.tbs.n == 305);
  /* signatureAlgorithm OID is ecdsa-with-SHA256. */
  CHECK(
      der_oid_equal(
          c.sig_alg_oid, wired_span_of(
                             x509_golden_oid_ecdsa_sha256,
                             sizeof(x509_golden_oid_ecdsa_sha256))) == 1);
  /* signatureValue BIT STRING value is 71 octets (at offset 323). */
  CHECK(c.sig.p == x509_golden + 323 && c.sig.n == 71);
}

static void test_x509_truncated(void) {
  x509 c;
  CHECK(x509_parse(wired_span_of(x509_golden, 10), &c) == 0);
  CHECK(x509_parse(wired_span_of(x509_golden, 0), &c) == 0);
}

/* A SEQUENCE whose first element is an INTEGER (not the tbs SEQUENCE). */
static void test_x509_not_tbs_seq(void) {
  const u8 bad[] = {0x30, 0x03, 0x02, 0x01, 0x05};
  x509     c;
  CHECK(x509_parse(wired_span_of(bad, sizeof(bad)), &c) == 0);
}

/* Top-level tag is not SEQUENCE. */
static void test_x509_not_seq(void) {
  const u8 bad[] = {0x02, 0x01, 0x05};
  x509     c;
  CHECK(x509_parse(wired_span_of(bad, sizeof(bad)), &c) == 0);
}

/* Six NULL elements standing in for serialNumber..subjectPublicKeyInfo, so
 * x509_tbs_cursor's skip(6) lands past them. */
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

/* id-ce-certificatePolicies = 2.5.29.32, critical TRUE. This SDK interprets
 * certificatePolicies (RFC 5280 4.2.1.4, via x509_policy_tree), so a
 * critical instance is a known extension and does not itself trigger
 * unknown-critical rejection. */
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
      x509_has_unknown_critical(
          wired_span_of(x509t_tbs_no_ext, sizeof(x509t_tbs_no_ext))) == 0);
}

/* A known critical extension (basicConstraints) does not trigger rejection.
 */
static void test_unknown_critical_known_ext_ok(void) {
  CHECK(
      x509_has_unknown_critical(
          wired_span_of(x509t_tbs_bc_crit, sizeof(x509t_tbs_bc_crit))) == 0);
}

/* RFC 5280 4.2: an unrecognized extnID marked critical TRUE is rejected. */
static void test_unknown_critical_rejects(void) {
  CHECK(
      x509_has_unknown_critical(wired_span_of(
          x509t_tbs_unknown_crit, sizeof(x509t_tbs_unknown_crit))) == 1);
}

/* An unrecognized extnID marked critical FALSE is not rejected. */
static void test_unknown_noncritical_ok(void) {
  CHECK(
      x509_has_unknown_critical(wired_span_of(
          x509t_tbs_unknown_noncrit, sizeof(x509t_tbs_unknown_noncrit))) == 0);
}

/* An unrecognized extnID with critical omitted defaults to FALSE (X.690
 * DEFAULT), so it is not rejected. */
static void test_unknown_critical_default_false(void) {
  CHECK(
      x509_has_unknown_critical(wired_span_of(
          x509t_tbs_unknown_default, sizeof(x509t_tbs_unknown_default))) == 0);
}

/* RFC 5280 4.2.1.4: a critical certificatePolicies extension is a known
 * extnID (this SDK interprets it via x509_policy_tree), so it does not
 * trigger unknown-critical rejection on its own. */
static void test_critical_certificate_policies_known(void) {
  CHECK(
      x509_has_unknown_critical(wired_span_of(
          x509t_tbs_cert_policies_crit,
          sizeof(x509t_tbs_cert_policies_crit))) == 0);
}

/* One known-critical and one unknown-critical extension: rejected because of
 * the second. */
static void test_unknown_critical_mixed_rejects(void) {
  CHECK(
      x509_has_unknown_critical(
          wired_span_of(x509t_tbs_mixed, sizeof(x509t_tbs_mixed))) == 1);
}

/* RFC 5280 4.1: issuerUniqueID [1] IMPLICIT BIT STRING, one arbitrary octet
 * (0x00 unused-bits count, 0xff data). */
#define X509T_ISSUER_UID 0xa1, 0x03, 0x03, 0x02, 0x00, 0xff
/* RFC 5280 4.1: subjectUniqueID [2] IMPLICIT BIT STRING, same shape. */
#define X509T_SUBJECT_UID 0xa2, 0x03, 0x03, 0x02, 0x00, 0xff

/* tbs = dummy6 ++ issuerUniqueID[1] ++ [3] { one known-critical ext }. A v2/v3
 * cert carrying only issuerUniqueID must still resolve its extensions. */
static const u8 x509t_tbs_uid1_ext[] = {
    0x30, 0x22, X509T_DUMMY6, X509T_ISSUER_UID, 0xa3,
    0x0e, 0x30, 0x0c,         X509T_EXT_BC_CRIT};

/* tbs = dummy6 ++ issuerUniqueID[1] ++ subjectUniqueID[2] ++ [3] { ext }. */
static const u8 x509t_tbs_uid12_ext[] = {
    0x30, 0x28, X509T_DUMMY6, X509T_ISSUER_UID, X509T_SUBJECT_UID, 0xa3,
    0x0e, 0x30, 0x0c,         X509T_EXT_BC_CRIT};

/* tbs = dummy6 ++ subjectUniqueID[2] only ++ [3] { ext }. issuerUniqueID may
 * be absent while subjectUniqueID is present (both are independently
 * OPTIONAL). */
static const u8 x509t_tbs_uid2_ext[] = {
    0x30, 0x22, X509T_DUMMY6, X509T_SUBJECT_UID, 0xa3,
    0x0e, 0x30, 0x0c,         X509T_EXT_BC_CRIT};

/* RFC 5280 4.1: a certificate carrying issuerUniqueID [1] must still reach
 * and correctly classify its extensions instead of the [1] element being
 * mistaken for (or blocking discovery of) the [3] extensions element. */
static void test_unique_id_issuer_only_reaches_extensions(void) {
  CHECK(
      x509_has_unknown_critical(
          wired_span_of(x509t_tbs_uid1_ext, sizeof(x509t_tbs_uid1_ext))) == 0);
}

/* Both issuerUniqueID and subjectUniqueID present: extensions still reached.
 */
static void test_unique_id_both_reaches_extensions(void) {
  CHECK(
      x509_has_unknown_critical(wired_span_of(
          x509t_tbs_uid12_ext, sizeof(x509t_tbs_uid12_ext))) == 0);
}

/* subjectUniqueID alone (no issuerUniqueID): extensions still reached. */
static void test_unique_id_subject_only_reaches_extensions(void) {
  CHECK(
      x509_has_unknown_critical(
          wired_span_of(x509t_tbs_uid2_ext, sizeof(x509t_tbs_uid2_ext))) == 0);
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
  test_critical_certificate_policies_known();
  test_unknown_critical_mixed_rejects();
  test_unique_id_issuer_only_reaches_extensions();
  test_unique_id_both_reaches_extensions();
  test_unique_id_subject_only_reaches_extensions();
}
