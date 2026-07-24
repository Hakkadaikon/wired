#include "crypto/pki/encoding/x509/nameconstraints.h"

#include "test.h"

/* All fixtures below were generated and byte-verified with a small Python
 * DER builder (tag+length-prefix TLVs composed bottom-up), not hand-counted,
 * to avoid the length-arithmetic mistakes that plague hand-written nested
 * DER. Structure of each:
 *   nct_name_a       = Name { RDN { commonName = "A" } }
 *   nct_name_a_child = Name { RDN { commonName = "A" }, RDN { OU = "x" } }
 *   nct_name_b       = Name { RDN { commonName = "B" } }
 *   tbs = dummy6 (six NULLs, see x509_test.c) ++ [3] { extensions } where
 *   the nameConstraints extension carries one GeneralSubtree whose base is
 *   the directoryName [4] nct_name_a. */

static const u8 nct_name_a[] = {
    0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x01, 0x41,
};

static const u8 nct_name_a_child[] = {
    0x30, 0x18, 0x31, 0x0a, 0x30, 0x08, 0x06, 0x03, 0x55,
    0x04, 0x03, 0x13, 0x01, 0x41, 0x31, 0x0a, 0x30, 0x08,
    0x06, 0x03, 0x55, 0x04, 0x0b, 0x13, 0x01, 0x78,
};

static const u8 nct_name_b[] = {
    0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x01, 0x42,
};

/* dummy6, no [3] extensions element at all. */
static const u8 nct_tbs_no_ext[] = {
    0x30, 0x0c, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
};

/* dummy6 ++ [3] { nameConstraints { permittedSubtrees [0] { subtree
 * directoryName=nct_name_a } } }. */
static const u8 nct_tbs_permitted_a[] = {
    0x30, 0x31, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0xa3, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x1d, 0x1e, 0x04, 0x18, 0x30, 0x16, 0xa0, 0x14, 0x30, 0x12,
    0x30, 0x10, 0xa4, 0x0e, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x01, 0x41,
};

/* Same shape, excludedSubtrees [1] instead of permittedSubtrees [0]. */
static const u8 nct_tbs_excluded_a[] = {
    0x30, 0x31, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0xa3, 0x23, 0x30, 0x21, 0x30, 0x1f, 0x06, 0x03,
    0x55, 0x1d, 0x1e, 0x04, 0x18, 0x30, 0x16, 0xa1, 0x14, 0x30, 0x12,
    0x30, 0x10, 0xa4, 0x0e, 0x30, 0x0c, 0x31, 0x0a, 0x30, 0x08, 0x06,
    0x03, 0x55, 0x04, 0x03, 0x13, 0x01, 0x41,
};

/* RFC 5280 4.2.1.10: no nameConstraints extension imposes no restriction. */
static void test_nc_absent_permits(void) {
  CHECK(
      quic_x509_name_constraints_permit(
          quic_span_of(nct_tbs_no_ext, sizeof(nct_tbs_no_ext)),
          quic_span_of(nct_name_a, sizeof(nct_name_a))) == 1);
}

/* permittedSubtrees admits a subject Name equal to the subtree base. */
static void test_nc_permitted_exact_match_ok(void) {
  CHECK(
      quic_x509_name_constraints_permit(
          quic_span_of(nct_tbs_permitted_a, sizeof(nct_tbs_permitted_a)),
          quic_span_of(nct_name_a, sizeof(nct_name_a))) == 1);
}

/* permittedSubtrees admits a subject Name with an extra RDN below the base
 * (a subtree member, not just the base itself). */
static void test_nc_permitted_child_ok(void) {
  CHECK(
      quic_x509_name_constraints_permit(
          quic_span_of(nct_tbs_permitted_a, sizeof(nct_tbs_permitted_a)),
          quic_span_of(nct_name_a_child, sizeof(nct_name_a_child))) == 1);
}

/* permittedSubtrees rejects a subject Name outside every permitted subtree.
 */
static void test_nc_permitted_unrelated_rejected(void) {
  CHECK(
      quic_x509_name_constraints_permit(
          quic_span_of(nct_tbs_permitted_a, sizeof(nct_tbs_permitted_a)),
          quic_span_of(nct_name_b, sizeof(nct_name_b))) == 0);
}

/* excludedSubtrees rejects a subject Name inside the excluded subtree. */
static void test_nc_excluded_match_rejected(void) {
  CHECK(
      quic_x509_name_constraints_permit(
          quic_span_of(nct_tbs_excluded_a, sizeof(nct_tbs_excluded_a)),
          quic_span_of(nct_name_a, sizeof(nct_name_a))) == 0);
}

/* excludedSubtrees does not restrict a subject Name outside it. */
static void test_nc_excluded_unrelated_ok(void) {
  CHECK(
      quic_x509_name_constraints_permit(
          quic_span_of(nct_tbs_excluded_a, sizeof(nct_tbs_excluded_a)),
          quic_span_of(nct_name_b, sizeof(nct_name_b))) == 1);
}

void test_nameconstraints(void) {
  test_nc_absent_permits();
  test_nc_permitted_exact_match_ok();
  test_nc_permitted_child_ok();
  test_nc_permitted_unrelated_rejected();
  test_nc_excluded_match_rejected();
  test_nc_excluded_unrelated_ok();
}
