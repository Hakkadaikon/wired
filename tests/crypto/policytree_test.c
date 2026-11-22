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
/* certificatePolicies listing nine OIDs (arcs 0..8), one past
 * X509_CERT_POLICY_MAX (same bytes as certpolicies_test.c). */
static const u8 pt_tbs_policy_9[] = {
    0x30, 0x48, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05, 0x00, 0x05,
    0x00, 0x05, 0x00, 0xa3, 0x3a, 0x30, 0x38, 0x30, 0x36, 0x06, 0x03,
    0x55, 0x1d, 0x20, 0x04, 0x2f, 0x30, 0x2d, 0x30, 0x03, 0x06, 0x01,
    0x00, 0x30, 0x03, 0x06, 0x01, 0x01, 0x30, 0x03, 0x06, 0x01, 0x02,
    0x30, 0x03, 0x06, 0x01, 0x03, 0x30, 0x03, 0x06, 0x01, 0x04, 0x30,
    0x03, 0x06, 0x01, 0x05, 0x30, 0x03, 0x06, 0x01, 0x06, 0x30, 0x03,
    0x06, 0x01, 0x07, 0x30, 0x03, 0x06, 0x01, 0x08,
};

static const u8 pt_oid_x[] = {0x2a, 0x03, 0x04, 0x05};
static const u8 pt_oid_y[] = {0x2a, 0x03, 0x04, 0x06};

#define PT_SPAN(a) wired_span_of(a, sizeof(a))

/* x509_policy_graph_init then fold each tbs in order with any_ok. */
static void pt_fold(
    x509_policy_graph* g, const wired_span* tbs, usz n, int any_ok) {
  x509_policy_graph_init(g);
  for (usz i = 0; i < n; i++) {
    x509_policy_graph_fold(g, tbs[i], any_ok);
  }
}

static int pt_nonempty(const wired_span* tbs, usz n, int any_ok) {
  x509_policy_graph g;
  pt_fold(&g, tbs, n, any_ok);
  return x509_policy_graph_nonempty(&g, 0);
}

/* RFC 9618 5.2: the initial graph is the anyPolicy root, so the
 * authorities-constrained set is {anyPolicy}. */
static void test_graph_init_any(void) {
  x509_policy_graph g;
  x509_policy_graph_init(&g);
  CHECK(x509_policy_graph_nonempty(&g, 0) == 1);
  CHECK(x509_policy_graph_has(&g, 0, PT_SPAN(x509_oid_any_policy)) == 1);
}

/* RFC 5280 6.1.3 (e): no certificatePolicies sets the graph to NULL, and a
 * later anyPolicy cannot revive it. */
static void test_graph_no_ext_nulls(void) {
  wired_span t[2] = {PT_SPAN(pt_tbs_no_ext), PT_SPAN(pt_tbs_any_policy)};
  CHECK(pt_nonempty(t, 1, 1) == 0);
  CHECK(pt_nonempty(t, 2, 1) == 0);
}

/* RFC 9618 5.3 (d)(2): an anyPolicy statement keeps the anyPolicy chain;
 * with anyPolicy not allowed it adds nothing and the graph empties. */
static void test_graph_any_policy(void) {
  wired_span t[1] = {PT_SPAN(pt_tbs_any_policy)};
  CHECK(pt_nonempty(t, 1, 1) == 1);
  CHECK(pt_nonempty(t, 1, 0) == 0);
}

/* RFC 9618 5.3 (d)(1)(ii): policy_x hangs off the anyPolicy root, so it is
 * an authorities-constrained policy and anyPolicy no longer is. */
static void test_graph_specific_under_any(void) {
  wired_span        t[1] = {PT_SPAN(pt_tbs_policy_x)};
  x509_policy_graph g;
  pt_fold(&g, t, 1, 1);
  CHECK(x509_policy_graph_has(&g, 0, PT_SPAN(pt_oid_x)) == 1);
  CHECK(x509_policy_graph_has(&g, 0, PT_SPAN(x509_oid_any_policy)) == 0);
}

/* RFC 9618 5.3 (d)(1)(i): policy_x twice matches its parent; policy_x then
 * policy_y matches nothing and the graph empties. */
static void test_graph_match_and_mismatch(void) {
  wired_span same[2] = {PT_SPAN(pt_tbs_policy_x), PT_SPAN(pt_tbs_policy_x)};
  wired_span diff[2] = {PT_SPAN(pt_tbs_policy_x), PT_SPAN(pt_tbs_policy_y)};
  CHECK(pt_nonempty(same, 2, 1) == 1);
  CHECK(pt_nonempty(diff, 2, 1) == 0);
}

/* { anyPolicy, policy_x } with anyPolicy not allowed keeps policy_x. */
static void test_graph_any_and_specific_inhibited(void) {
  wired_span t[1] = {PT_SPAN(pt_tbs_any_and_policy_x)};
  CHECK(pt_nonempty(t, 1, 0) == 1);
}

/* RFC 9618 5.5 (g)(6): a user-initial-policy-set {policy_y} intersects the
 * authorities-constrained {policy_x} to empty; {policy_x} keeps it. */
static void test_graph_user_set(void) {
  wired_span        t[1] = {PT_SPAN(pt_tbs_policy_x)};
  x509_policy_graph g;
  x509_policy_set   x = {.n = 1}, y = {.n = 1};
  x.oid[0] = PT_SPAN(pt_oid_x);
  y.oid[0] = PT_SPAN(pt_oid_y);
  pt_fold(&g, t, 1, 1);
  CHECK(x509_policy_graph_nonempty(&g, &x) == 1);
  CHECK(x509_policy_graph_nonempty(&g, &y) == 0);
}

/* A certificatePolicies truncated at X509_CERT_POLICY_MAX marks the graph
 * overflowed: the path is rejected rather than judged on a partial set. */
static void test_graph_truncated_overflows(void) {
  wired_span        t[1] = {PT_SPAN(pt_tbs_policy_9)};
  x509_policy_graph g;
  pt_fold(&g, t, 1, 1);
  CHECK(g.overflow == 1);
}

/* RFC 5280 6.1.3 (d) runs only while the graph is not NULL: a truncated
 * certificatePolicies after a NULL graph leaves it NULL, not overflowed. */
static void test_graph_null_ignores_truncation(void) {
  wired_span        t[2] = {PT_SPAN(pt_tbs_no_ext), PT_SPAN(pt_tbs_policy_9)};
  x509_policy_graph g;
  pt_fold(&g, t, 2, 1);
  CHECK(g.overflow == 0);
  CHECK(x509_policy_graph_nonempty(&g, 0) == 0);
}

void test_policytree(void) {
  test_graph_init_any();
  test_graph_no_ext_nulls();
  test_graph_any_policy();
  test_graph_specific_under_any();
  test_graph_match_and_mismatch();
  test_graph_any_and_specific_inhibited();
  test_graph_user_set();
  test_graph_truncated_overflows();
  test_graph_null_ignores_truncation();
}
