#include "crypto/pki/encoding/x509/policyconstraints.h"

#include "test.h"

/* All fixtures generated and byte-verified with a small Python DER builder
 * (see nameconstraints_test.c). tbs = dummy6 (six NULLs, see x509_test.c)
 * ++ [3] { one extension }. */

static const u8 pct_tbs_no_ext[] = {
    0x30, 0x0c, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
};

/* policyConstraints { requireExplicitPolicy [0] 3 }. */
static const u8 pct_tbs_reqexp3[] = {
    0x30, 0x1e, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0xa3, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x1d, 0x24, 0x04, 0x05, 0x30, 0x03, 0x80, 0x01, 0x03,
};

/* policyConstraints present but its SEQUENCE is empty (neither
 * requireExplicitPolicy nor inhibitPolicyMapping encoded). */
static const u8 pct_tbs_reqexp_absent_field[] = {
    0x30, 0x1b, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x0d, 0x30, 0x0b, 0x30, 0x09,
    0x06, 0x03, 0x55, 0x1d, 0x24, 0x04, 0x02, 0x30, 0x00,
};

/* policyConstraints { requireExplicitPolicy [0] <negative INTEGER content,
 * top bit set -- malformed SkipCerts> }. */
static const u8 pct_tbs_reqexp_malformed[] = {
    0x30, 0x1e, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0xa3, 0x10, 0x30, 0x0e, 0x30, 0x0c, 0x06, 0x03,
    0x55, 0x1d, 0x24, 0x04, 0x05, 0x30, 0x03, 0x80, 0x01, 0xff,
};

/* inhibitAnyPolicy extnValue = bare INTEGER 2. */
static const u8 pct_tbs_inhibit_any2[] = {
    0x30, 0x1c, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x0e, 0x30, 0x0c, 0x30, 0x0a,
    0x06, 0x03, 0x55, 0x1d, 0x36, 0x04, 0x03, 0x02, 0x01, 0x02,
};

/* inhibitAnyPolicy extnValue = OCTET STRING (not an INTEGER) -- malformed. */
static const u8 pct_tbs_inhibit_any_malformed[] = {
    0x30, 0x1c, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x0e, 0x30, 0x0c, 0x30, 0x0a,
    0x06, 0x03, 0x55, 0x1d, 0x36, 0x04, 0x03, 0x04, 0x01, 0x01,
};

/* RFC 5280 4.2.1.11: no policyConstraints extension is unconstrained. */
static void test_reqexp_absent_ext_is_none(void) {
  CHECK(
      quic_x509_require_explicit_policy(quic_span_of(
          pct_tbs_no_ext, sizeof(pct_tbs_no_ext))) == QUIC_X509_SKIPCERTS_NONE);
}

/* requireExplicitPolicy present and set to 3. */
static void test_reqexp_value_read(void) {
  CHECK(
      quic_x509_require_explicit_policy(
          quic_span_of(pct_tbs_reqexp3, sizeof(pct_tbs_reqexp3))) == 3);
}

/* policyConstraints present but the requireExplicitPolicy field itself is
 * absent: unconstrained (RFC 5280 4.2.1.11, the field is OPTIONAL). */
static void test_reqexp_field_absent_is_none(void) {
  CHECK(
      quic_x509_require_explicit_policy(quic_span_of(
          pct_tbs_reqexp_absent_field, sizeof(pct_tbs_reqexp_absent_field))) ==
      QUIC_X509_SKIPCERTS_NONE);
}

/* A malformed (negative) requireExplicitPolicy fails closed. */
static void test_reqexp_malformed_rejects(void) {
  CHECK(
      quic_x509_require_explicit_policy(quic_span_of(
          pct_tbs_reqexp_malformed, sizeof(pct_tbs_reqexp_malformed))) ==
      QUIC_X509_SKIPCERTS_MALFORMED);
}

/* RFC 5280 4.2.1.14: no inhibitAnyPolicy extension is unconstrained. */
static void test_inhibit_any_absent_is_none(void) {
  CHECK(
      quic_x509_inhibit_any_policy(quic_span_of(
          pct_tbs_no_ext, sizeof(pct_tbs_no_ext))) == QUIC_X509_SKIPCERTS_NONE);
}

/* inhibitAnyPolicy present and set to 2. */
static void test_inhibit_any_value_read(void) {
  CHECK(
      quic_x509_inhibit_any_policy(quic_span_of(
          pct_tbs_inhibit_any2, sizeof(pct_tbs_inhibit_any2))) == 2);
}

/* A malformed (non-INTEGER) inhibitAnyPolicy fails closed. */
static void test_inhibit_any_malformed_rejects(void) {
  CHECK(
      quic_x509_inhibit_any_policy(quic_span_of(
          pct_tbs_inhibit_any_malformed,
          sizeof(pct_tbs_inhibit_any_malformed))) ==
      QUIC_X509_SKIPCERTS_MALFORMED);
}

void test_policyconstraints(void) {
  test_reqexp_absent_ext_is_none();
  test_reqexp_value_read();
  test_reqexp_field_absent_is_none();
  test_reqexp_malformed_rejects();
  test_inhibit_any_absent_is_none();
  test_inhibit_any_value_read();
  test_inhibit_any_malformed_rejects();
}
