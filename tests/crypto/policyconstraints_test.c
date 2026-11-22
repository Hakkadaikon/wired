#include "crypto/pki/encoding/x509/policyconstraints.h"

#include "castore_pc_golden.h"
#include "common/bytes/util/bytes.h"
#include "crypto/pki/encoding/x509/x509.h"
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
      x509_require_explicit_policy(wired_span_of(
          pct_tbs_no_ext, sizeof(pct_tbs_no_ext))) == X509_SKIPCERTS_NONE);
}

/* requireExplicitPolicy present and set to 3. */
static void test_reqexp_value_read(void) {
  CHECK(
      x509_require_explicit_policy(
          wired_span_of(pct_tbs_reqexp3, sizeof(pct_tbs_reqexp3))) == 3);
}

/* policyConstraints present but the requireExplicitPolicy field itself is
 * absent: unconstrained (RFC 5280 4.2.1.11, the field is OPTIONAL). */
static void test_reqexp_field_absent_is_none(void) {
  CHECK(
      x509_require_explicit_policy(wired_span_of(
          pct_tbs_reqexp_absent_field, sizeof(pct_tbs_reqexp_absent_field))) ==
      X509_SKIPCERTS_NONE);
}

/* A malformed (negative) requireExplicitPolicy fails closed. */
static void test_reqexp_malformed_rejects(void) {
  CHECK(
      x509_require_explicit_policy(wired_span_of(
          pct_tbs_reqexp_malformed, sizeof(pct_tbs_reqexp_malformed))) ==
      X509_SKIPCERTS_MALFORMED);
}

/* RFC 5280 4.2.1.14: no inhibitAnyPolicy extension is unconstrained. */
static void test_inhibit_any_absent_is_none(void) {
  CHECK(
      x509_inhibit_any_policy(wired_span_of(
          pct_tbs_no_ext, sizeof(pct_tbs_no_ext))) == X509_SKIPCERTS_NONE);
}

/* inhibitAnyPolicy present and set to 2. */
static void test_inhibit_any_value_read(void) {
  CHECK(
      x509_inhibit_any_policy(wired_span_of(
          pct_tbs_inhibit_any2, sizeof(pct_tbs_inhibit_any2))) == 2);
}

/* A malformed (non-INTEGER) inhibitAnyPolicy fails closed. */
static void test_inhibit_any_malformed_rejects(void) {
  CHECK(
      x509_inhibit_any_policy(wired_span_of(
          pct_tbs_inhibit_any_malformed,
          sizeof(pct_tbs_inhibit_any_malformed))) == X509_SKIPCERTS_MALFORMED);
}

/* Copy n bytes of src into buf and overwrite one byte at off. */
static wired_span pct_mut(u8* buf, const u8* src, usz n, usz off, u8 v) {
  bytes_memcpy(buf, src, n);
  buf[off] = v;
  return wired_span_of(buf, n);
}

/* RFC 5280 4.2.1.11: a PolicyConstraints that leads with [1]
 * inhibitPolicyMapping (reqexp3[29] 0x80 -> 0x81) carries no
 * requireExplicitPolicy. */
static void test_reqexp_led_by_inhibit_mapping_is_none(void) {
  u8 buf[sizeof(pct_tbs_reqexp3)];
  CHECK(
      x509_require_explicit_policy(pct_mut(
          buf, pct_tbs_reqexp3, sizeof(buf), 29, 0x81)) == X509_SKIPCERTS_NONE);
}

/* RFC 5280 4.2.1.11: the same [1] field read as inhibitPolicyMapping is
 * 3; the unmutated [0] carries no inhibitPolicyMapping. */
static void test_inhibit_mapping_value_read(void) {
  u8 buf[sizeof(pct_tbs_reqexp3)];
  CHECK(
      x509_inhibit_policy_mapping(
          pct_mut(buf, pct_tbs_reqexp3, sizeof(buf), 29, 0x81)) == 3);
  CHECK(
      x509_inhibit_policy_mapping(wired_span_of(
          pct_tbs_reqexp3, sizeof(pct_tbs_reqexp3))) == X509_SKIPCERTS_NONE);
}

/* RFC 5280 4.2.1.14: an inhibitAnyPolicy extnValue whose TLV overruns
 * (length octet [28] 1 -> 5) fails closed. */
static void test_inhibit_any_truncated_rejects(void) {
  u8 buf[sizeof(pct_tbs_inhibit_any_malformed)];
  CHECK(
      x509_inhibit_any_policy(
          pct_mut(buf, pct_tbs_inhibit_any_malformed, sizeof(buf), 28, 0x05)) ==
      X509_SKIPCERTS_MALFORMED);
}

/* RFC 5280 4.2: a critical policyConstraints whose value is not a SEQUENCE
 * (pc_mid2[277] 0x30 -> 0x31) cannot be processed, so it is reported as an
 * unprocessed critical extension. */
static void test_pc_critical_malformed_is_unprocessed(void) {
  u8   buf[sizeof(castore_pc_mid2_der)];
  x509 c;
  CHECK(castore_pc_mid2_der[277] == 0x30);
  CHECK(
      x509_parse(
          pct_mut(buf, castore_pc_mid2_der, sizeof(buf), 277, 0x31), &c) == 1);
  CHECK(x509_pc_unprocessed_critical(c.tbs) == 1);
}

/* Critical policyConstraints fixtures (same builder): { [0] with a length
 * overrunning the SEQUENCE }, { [1] 0, [0] 0 } (out of order), { [0] 0,
 * [0] 0 } (duplicate), and the well-formed { [0] 2, [1] 1 }. */
static const u8 pct_tbs_crit_overrun[] = {
    0x30, 0x21, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x13, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
    0x24, 0x01, 0x01, 0xff, 0x04, 0x05, 0x30, 0x03, 0x80, 0x05, 0x00,
};

static const u8 pct_tbs_crit_out_of_order[] = {
    0x30, 0x24, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12,
    0x06, 0x03, 0x55, 0x1d, 0x24, 0x01, 0x01, 0xff, 0x04, 0x08,
    0x30, 0x06, 0x81, 0x01, 0x00, 0x80, 0x01, 0x00,
};

static const u8 pct_tbs_crit_duplicate[] = {
    0x30, 0x24, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12,
    0x06, 0x03, 0x55, 0x1d, 0x24, 0x01, 0x01, 0xff, 0x04, 0x08,
    0x30, 0x06, 0x80, 0x01, 0x00, 0x80, 0x01, 0x00,
};

static const u8 pct_tbs_crit_both[] = {
    0x30, 0x24, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x16, 0x30, 0x14, 0x30, 0x12,
    0x06, 0x03, 0x55, 0x1d, 0x24, 0x01, 0x01, 0xff, 0x04, 0x08,
    0x30, 0x06, 0x80, 0x01, 0x02, 0x81, 0x01, 0x01,
};

/* Both fields read MALFORMED and the critical extension is unprocessed. */
static void pct_check_malformed(wired_span tbs) {
  CHECK(x509_require_explicit_policy(tbs) == X509_SKIPCERTS_MALFORMED);
  CHECK(x509_inhibit_policy_mapping(tbs) == X509_SKIPCERTS_MALFORMED);
  CHECK(x509_pc_unprocessed_critical(tbs) == 1);
}

/* RFC 5280 4.2 / 4.2.1.11: a critical PolicyConstraints whose elements do
 * not exactly fill the SEQUENCE, come out of order, or repeat a field
 * cannot be processed and fails closed; { [0] 2, [1] 1 } reads both. */
static void test_pc_strict_shape(void) {
  wired_span ok = wired_span_of(pct_tbs_crit_both, sizeof(pct_tbs_crit_both));
  pct_check_malformed(
      wired_span_of(pct_tbs_crit_overrun, sizeof(pct_tbs_crit_overrun)));
  pct_check_malformed(wired_span_of(
      pct_tbs_crit_out_of_order, sizeof(pct_tbs_crit_out_of_order)));
  pct_check_malformed(
      wired_span_of(pct_tbs_crit_duplicate, sizeof(pct_tbs_crit_duplicate)));
  CHECK(x509_require_explicit_policy(ok) == 2);
  CHECK(x509_inhibit_policy_mapping(ok) == 1);
  CHECK(x509_pc_unprocessed_critical(ok) == 0);
}

void test_policyconstraints(void) {
  test_reqexp_led_by_inhibit_mapping_is_none();
  test_inhibit_mapping_value_read();
  test_pc_strict_shape();
  test_inhibit_any_truncated_rejects();
  test_pc_critical_malformed_is_unprocessed();
  test_reqexp_absent_ext_is_none();
  test_reqexp_value_read();
  test_reqexp_field_absent_is_none();
  test_reqexp_malformed_rejects();
  test_inhibit_any_absent_is_none();
  test_inhibit_any_value_read();
  test_inhibit_any_malformed_rejects();
}
