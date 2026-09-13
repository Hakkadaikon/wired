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
  x509_policy_set set;
  CHECK(
      x509_cert_policies(
          wired_span_of(cpt_tbs_no_ext, sizeof(cpt_tbs_no_ext)), &set) == 0);
}

/* A single anyPolicy entry is read and recognized. */
static void test_cp_any_policy(void) {
  x509_policy_set set;
  CHECK(
      x509_cert_policies(
          wired_span_of(cpt_tbs_any_policy, sizeof(cpt_tbs_any_policy)),
          &set) == 1);
  CHECK(set.n == 1);
  CHECK(x509_policy_set_has_any(&set) == 1);
}

/* A single non-anyPolicy OID is read and not mistaken for anyPolicy. */
static void test_cp_single_policy(void) {
  x509_policy_set set;
  CHECK(
      x509_cert_policies(
          wired_span_of(cpt_tbs_policy_x, sizeof(cpt_tbs_policy_x)), &set) ==
      1);
  CHECK(set.n == 1);
  CHECK(x509_policy_set_has_any(&set) == 0);
  CHECK(
      der_oid_equal(
          set.oid[0],
          wired_span_of(cpt_oid_policy_x, sizeof(cpt_oid_policy_x))) == 1);
}

/* Two PolicyInformation entries are both read. */
static void test_cp_two_policies(void) {
  x509_policy_set set;
  CHECK(
      x509_cert_policies(
          wired_span_of(cpt_tbs_policy_xy, sizeof(cpt_tbs_policy_xy)), &set) ==
      1);
  CHECK(set.n == 2);
}

/* RFC 5280 4.2.1.4 does not bound the PolicyInformation count; this SDK caps
 * storage at X509_CERT_POLICY_MAX (8) and drops entries past it rather than
 * overflowing the fixed-capacity array (CVE-2023-0464 class: unbounded
 * per-certificate policy count). 9 distinct single-byte-arc OIDs (0..8),
 * built by extending the two-policy fixture's shape. */
static const u8 cpt_tbs_policy_9[] = {
    0x30, 0x48, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0xa3, 0x3a, 0x30, 0x38, 0x30, 0x36, 0x06, 0x03,
    0x55, 0x1d, 0x20, 0x04, 0x2f, 0x30, 0x2d, 0x30, 0x03, 0x06, 0x01,
    0x00, 0x30, 0x03, 0x06, 0x01, 0x01, 0x30, 0x03, 0x06, 0x01, 0x02,
    0x30, 0x03, 0x06, 0x01, 0x03, 0x30, 0x03, 0x06, 0x01, 0x04, 0x30,
    0x03, 0x06, 0x01, 0x05, 0x30, 0x03, 0x06, 0x01, 0x06, 0x30, 0x03,
    0x06, 0x01, 0x07, 0x30, 0x03, 0x06, 0x01, 0x08,
};

static void test_cp_cap_drops_overflow(void) {
  x509_policy_set set;
  CHECK(
      x509_cert_policies(
          wired_span_of(cpt_tbs_policy_9, sizeof(cpt_tbs_policy_9)), &set) ==
      1);
  CHECK(set.n == X509_CERT_POLICY_MAX);
}

/* RFC 5280 4.2.1.4 / CVE-2023-0465 class: a malformed PolicyInformation
 * element (no leading OID -- here a BOOLEAN instead) is skipped, not
 * treated as extension-scan failure; the two well-formed siblings around it
 * are still read. This is what makes V-0586's "safe" claim checkable: a
 * single bad entry cannot make x509_cert_policies silently return 0 (and
 * thus be treated the same as "extension absent" instead of "some entries
 * dropped"). */
static const u8 cpt_tbs_policy_malformed_middle[] = {
    0x30, 0x2e, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x20, 0x30, 0x1e, 0x30, 0x1c, 0x06, 0x03, 0x55, 0x1d,
    0x20, 0x04, 0x15, 0x30, 0x13, 0x30, 0x06, 0x06, 0x04, 0x2a, 0x03, 0x04,
    0x05, 0x01, 0x01, 0xff, 0x30, 0x06, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x06,
};

static void test_cp_scan_skips_malformed_entry(void) {
  x509_policy_set set;
  CHECK(
      x509_cert_policies(
          wired_span_of(
              cpt_tbs_policy_malformed_middle,
              sizeof(cpt_tbs_policy_malformed_middle)),
          &set) == 1);
  CHECK(set.n == 2);
  CHECK(x509_policy_set_has_any(&set) == 0);
}

void test_certpolicies(void) {
  test_cp_absent();
  test_cp_any_policy();
  test_cp_single_policy();
  test_cp_two_policies();
  test_cp_cap_drops_overflow();
  test_cp_scan_skips_malformed_entry();
}
