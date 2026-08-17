#include "crypto/pki/encoding/x509/policytree.h"

#include "test.h"

/* Same fixture shapes as certpolicies_test.c (regenerated locally to keep
 * this file's test list self-contained); tbs = dummy6 ++ [3] { one
 * certificatePolicies extension }. */

static const u8 pt_tbs_no_ext[] = {
    0x30, 0x0c, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
};

static const u8 pt_tbs_any_policy[] = {
    0x30, 0x23, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x15, 0x30, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0a, 0x30, 0x08, 0x30,
    0x06, 0x06, 0x04, 0x55, 0x1d, 0x20, 0x00,
};

static const u8 pt_tbs_policy_x[] = {
    0x30, 0x23, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x15, 0x30, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0a, 0x30, 0x08, 0x30,
    0x06, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x05,
};

static const u8 pt_tbs_policy_y[] = {
    0x30, 0x23, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0x05, 0x00, 0xa3, 0x15, 0x30, 0x13, 0x30, 0x11,
    0x06, 0x03, 0x55, 0x1d, 0x20, 0x04, 0x0a, 0x30, 0x08, 0x30,
    0x06, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x06,
};

/* certificatePolicies { anyPolicy, policy_x } -- both a wildcard and one
 * explicit policy. */
static const u8 pt_tbs_any_and_policy_x[] = {
    0x30, 0x2b, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00,
    0x05, 0x00, 0xa3, 0x1d, 0x30, 0x1b, 0x30, 0x19, 0x06, 0x03, 0x55, 0x1d,
    0x20, 0x04, 0x12, 0x30, 0x10, 0x30, 0x06, 0x06, 0x04, 0x55, 0x1d, 0x20,
    0x00, 0x30, 0x06, 0x06, 0x04, 0x2a, 0x03, 0x04, 0x05,
};

/* RFC 5280 6.1.2: the initial tree is the root node "anyPolicy" (non-empty).
 */
static void test_tree_init_nonempty(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  CHECK(x509_policy_tree_nonempty(&t) == 1);
}

/* RFC 5280 6.1.3 (d)(1): a certificate with no certificatePolicies extension
 * at all prunes the tree to empty. */
static void test_tree_fold_no_ext_empties(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_no_ext, sizeof(pt_tbs_no_ext)), 0);
  CHECK(x509_policy_tree_nonempty(&t) == 0);
}

/* An anyPolicy statement does not narrow (nor empty) the tree. */
static void test_tree_fold_any_policy_stays_nonempty(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_any_policy, sizeof(pt_tbs_any_policy)), 0);
  CHECK(x509_policy_tree_nonempty(&t) == 1);
}

/* A specific policy statement narrows the root anyPolicy to that policy
 * (still non-empty). */
static void test_tree_fold_specific_narrows_nonempty(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_policy_x, sizeof(pt_tbs_policy_x)), 0);
  CHECK(x509_policy_tree_nonempty(&t) == 1);
}

/* Two certificates asserting disjoint specific policies (no policy mapping)
 * intersect to empty: the second certificate does not carry policy_x. */
static void test_tree_fold_disjoint_policies_empties(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_policy_x, sizeof(pt_tbs_policy_x)), 0);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_policy_y, sizeof(pt_tbs_policy_y)), 0);
  CHECK(x509_policy_tree_nonempty(&t) == 0);
}

/* The same specific policy asserted twice intersects to itself (stays
 * non-empty). */
static void test_tree_fold_same_policy_twice_stays_nonempty(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_policy_x, sizeof(pt_tbs_policy_x)), 0);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_policy_x, sizeof(pt_tbs_policy_x)), 0);
  CHECK(x509_policy_tree_nonempty(&t) == 1);
}

/* Once pruned to empty, the tree stays empty (monotonic pruning) even when a
 * later certificate asserts anyPolicy. */
static void test_tree_fold_empty_is_monotonic(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_no_ext, sizeof(pt_tbs_no_ext)), 0);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_any_policy, sizeof(pt_tbs_any_policy)), 0);
  CHECK(x509_policy_tree_nonempty(&t) == 0);
}

/* RFC 5280 6.1.3 (d)(2): once inhibit_anypolicy has taken effect (the
 * caller passes any_inhibited=1), an anyPolicy statement is treated as if
 * absent -- the tree narrows to the certificate's explicit set instead of
 * staying unconstrained. */
static void test_tree_fold_any_policy_inhibited_narrows(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  x509_policy_tree_fold(
      &t, wired_span_of(pt_tbs_any_policy, sizeof(pt_tbs_any_policy)), 1);
  CHECK(x509_policy_tree_nonempty(&t) == 0);
}

/* An anyPolicy + policy_x statement, inhibited: anyPolicy is stripped but
 * policy_x survives, so the tree narrows to {policy_x} (still non-empty). */
static void test_tree_fold_any_and_specific_inhibited_keeps_specific(void) {
  x509_policy_tree t;
  x509_policy_tree_init(&t);
  x509_policy_tree_fold(
      &t,
      wired_span_of(pt_tbs_any_and_policy_x, sizeof(pt_tbs_any_and_policy_x)),
      1);
  CHECK(x509_policy_tree_nonempty(&t) == 1);
}

void test_policytree(void) {
  test_tree_init_nonempty();
  test_tree_fold_no_ext_empties();
  test_tree_fold_any_policy_stays_nonempty();
  test_tree_fold_specific_narrows_nonempty();
  test_tree_fold_disjoint_policies_empties();
  test_tree_fold_same_policy_twice_stays_nonempty();
  test_tree_fold_empty_is_monotonic();
  test_tree_fold_any_policy_inhibited_narrows();
  test_tree_fold_any_and_specific_inhibited_keeps_specific();
}
