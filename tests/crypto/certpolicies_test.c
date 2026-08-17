#include "crypto/pki/encoding/x509/certpolicies.h"

#include "crypto/pki/encoding/asn1/derval.h"
#include "test.h"

/* All fixtures generated and byte-verified with a small Python DER builder
 * (see nameconstraints_test.c). tbs = dummy6 ++ [3] { one
 * certificatePolicies extension listing the named PolicyInformation
 * OID(s) }. policy_x/policy_y are arbitrary distinct OIDs (1.3.3.4.5 /
 * 1.3.3.4.6), unrelated to any real policy registry. */

static const u8 cpt_tbs_no_ext[] = {
    0x30, 0x0c, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
};

static const u8 cpt_tbs_any_policy[] = {
    0x30, 0x23, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x15, 0x30, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0a, 0x30, 0x08, 0x30,
    0x06, 0x06, 0x04, 0x55, 0x1d, 0x20, 0x00,
};

static const u8 cpt_tbs_policy_x[] = {
    0x30, 0x23, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x15, 0x30, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0a, 0x30, 0x08, 0x30,
    0x06, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x05,
};

static const u8 cpt_tbs_policy_xy[] = {
    0x30, 0x2b, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x1d, 0x30, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x1d,
    0x20, 0x04, 0x12, 0x30, 0x10, 0x30, 0x06, 0x06, 0x04, 0x2a, 0x03, 0x04,
    0x05, 0x30, 0x06, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x06,
};

static const u8 cpt_oid_policy_x[] = {0x2a, 0x03, 0x04, 0x05};

/* RFC 5280 4.2.1.4: no certificatePolicies extension. */
static void test_cp_absent(void) {
  quic_x509_policy_set set;
  CHECK(
      quic_x509_cert_policies(
          wired_span_of(cpt_tbs_no_ext, sizeof(cpt_tbs_no_ext)), &set) == 0);
}

/* A single anyPolicy entry is read and recognized. */
static void test_cp_any_policy(void) {
  quic_x509_policy_set set;
  CHECK(
      quic_x509_cert_policies(
          wired_span_of(cpt_tbs_any_policy, sizeof(cpt_tbs_any_policy)),
          &set) == 1);
  CHECK(set.n == 1);
  CHECK(quic_x509_policy_set_has_any(&set) == 1);
}

/* A single non-anyPolicy OID is read and not mistaken for anyPolicy. */
static void test_cp_single_policy(void) {
  quic_x509_policy_set set;
  CHECK(
      quic_x509_cert_policies(
          wired_span_of(cpt_tbs_policy_x, sizeof(cpt_tbs_policy_x)), &set) ==
      1);
  CHECK(set.n == 1);
  CHECK(quic_x509_policy_set_has_any(&set) == 0);
  CHECK(
      quic_der_oid_equal(
          set.oid[0],
          wired_span_of(cpt_oid_policy_x, sizeof(cpt_oid_policy_x))) == 1);
}

/* Two PolicyInformation entries are both read. */
static void test_cp_two_policies(void) {
  quic_x509_policy_set set;
  CHECK(
      quic_x509_cert_policies(
          wired_span_of(cpt_tbs_policy_xy, sizeof(cpt_tbs_policy_xy)), &set) ==
      1);
  CHECK(set.n == 2);
}

void test_certpolicies(void) {
  test_cp_absent();
  test_cp_any_policy();
  test_cp_single_policy();
  test_cp_two_policies();
}
