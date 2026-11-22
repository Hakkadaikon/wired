#include "crypto/pki/trust/castore/pathvalidate_impl.h"

static void skipcerts_lower(u64* counter, u64 v);
static int  skipcerts_apply(u64 v, u64* counter);
static void skipcerts_decrement(u64* counter);
static void policy_decrement(castore_policy_ctr* c);
static int  policy_constraints(wired_span tbs, castore_policy_ctr* c);
static int  policy_prepare(
    wired_span          tbs,
    int                 self_issued,
    x509_policy_graph*  g,
    castore_policy_ctr* c);
static int policy_wrapup_counters(wired_span tbs, castore_policy_ctr* c);
static int policy_any_ok(
    const castore_policy_ctr* c, int self_issued, int last);
static u64 policy_initial(int set);
static int policy_wrapup_ok(
    const castore_policy_ctr* c,
    const x509_policy_graph*  g,
    const x509_policy_set*    user);

/* Lower *counter to v if v is smaller (a SkipCerts constraint only ever
 * tightens, RFC 5280 6.1.4 (i)/(j)); no-op if v carries
 * X509_SKIPCERTS_NONE (the "absent" sentinel, larger than any real
 * path length). */
static void skipcerts_lower(u64* counter, u64 v) {
  if (v < *counter) {
    *counter = v;
  }
}

/* Lower *counter to the SkipCerts value v; rejects (0) a malformed one. */
static int skipcerts_apply(u64 v, u64* counter) {
  if (v == X509_SKIPCERTS_MALFORMED) {
    return 0;
  }
  skipcerts_lower(counter, v);
  return 1;
}

/* Decrement *counter by 1 unless it is already at its floor 0. */
static void skipcerts_decrement(u64* counter) {
  if (*counter != 0) {
    (*counter)--;
  }
}

/* RFC 5280 6.1.4 (h): a certificate that is not self-issued decrements
 * explicit_policy, policy_mapping and inhibit_anyPolicy. */
static void policy_decrement(castore_policy_ctr* c) {
  skipcerts_decrement(&c->explicit_policy);
  skipcerts_decrement(&c->policy_mapping);
  skipcerts_decrement(&c->inhibit_any);
}

/* RFC 5280 6.1.4 (i)/(j): policyConstraints requireExplicitPolicy /
 * inhibitPolicyMapping and inhibitAnyPolicy lower their counters. */
static int policy_constraints(wired_span tbs, castore_policy_ctr* c) {
  if (!skipcerts_apply(
          x509_require_explicit_policy(tbs), &c->explicit_policy)) {
    return 0;
  }
  if (!skipcerts_apply(x509_inhibit_policy_mapping(tbs), &c->policy_mapping)) {
    return 0;
  }
  return skipcerts_apply(x509_inhibit_any_policy(tbs), &c->inhibit_any);
}

/* RFC 5280 6.1.4 (a)/(b) and (h)-(j) for certificate i < n, in that
 * order: mappings use policy_mapping as left by certificate i-1, then the
 * counters are decremented and finally lowered by i's own constraints. */
static int policy_prepare(
    wired_span          tbs,
    int                 self_issued,
    x509_policy_graph*  g,
    castore_policy_ctr* c) {
  if (!x509_policy_graph_map(g, tbs, c->policy_mapping > 0)) {
    return 0;
  }
  if (!self_issued) {
    policy_decrement(c);
  }
  return policy_constraints(tbs, c);
}

/* RFC 5280 6.1.5 (a)/(b) for certificate n: decrement explicit_policy, and
 * a requireExplicitPolicy of 0 sets it to 0. */
static int policy_wrapup_counters(wired_span tbs, castore_policy_ctr* c) {
  u64 v = x509_require_explicit_policy(tbs);
  if (v == X509_SKIPCERTS_MALFORMED) {
    return 0;
  }
  skipcerts_decrement(&c->explicit_policy);
  if (v == 0) {
    c->explicit_policy = 0;
  }
  return 1;
}

/* RFC 9618 5.3 (d)(2): anyPolicy is processed when "(a) inhibit_anyPolicy
 * is greater than 0 or (b) i<n and the certificate is self-issued". */
static int policy_any_ok(
    const castore_policy_ctr* c, int self_issued, int last) {
  return c->inhibit_any > 0 || (!last && self_issued);
}

/* RFC 5280 6.1.3 (d)/(e) then 6.1.4 (certificate i < n) or 6.1.5 (a)/(b)
 * (last, certificate n) for one certificate, walked from the trust
 * anchor's issued certificate towards the leaf. */
int castore_policy_step(
    wired_span cert, x509_policy_graph* g, castore_policy_ctr* c, int last) {
  x509 x;
  int  self_issued = castore_cert_self_issued(cert);
  if (!x509_parse(cert, &x)) {
    return 0;
  }
  x509_policy_graph_fold(g, x.tbs, policy_any_ok(c, self_issued, last));
  if (last) {
    return policy_wrapup_counters(x.tbs, c);
  }
  return policy_prepare(x.tbs, self_issued, g, c);
}

/* RFC 5280 6.1.2 (d)-(f): a counter starts at 0 when its initial-* input
 * is set, else at n+1 (X509_SKIPCERTS_NONE). */
static u64 policy_initial(int set) {
  if (set) {
    return 0;
  }
  return X509_SKIPCERTS_NONE;
}

/* RFC 9618 5.5: "If either (1) the value of explicit_policy is greater than
 * zero, or (2) the user_constrained_policy_set is not empty, then path
 * processing has succeeded". The graph decides only when explicit_policy
 * is 0, so a graph that outgrew its bound (policytree.h) fails the path
 * only then -- it can never turn a rejection into an acceptance. */
static int policy_wrapup_ok(
    const castore_policy_ctr* c,
    const x509_policy_graph*  g,
    const x509_policy_set*    user) {
  if (c->explicit_policy != 0) {
    return 1;
  }
  if (g->overflow) {
    return 0;
  }
  return x509_policy_graph_nonempty(g, user);
}

/* RFC 5280 6.1.2-6.1.5 with the RFC 9618 graph: certs[n_walk-1] is the
 * trust anchor's issued certificate (6.1's "certificate 1"), certs[0] the
 * leaf (certificate n). The caller leaves a presented copy of the anchor
 * itself out of n_walk (policy_walk_len). 6.1.3 (f)'s per-certificate check
 * is left to the wrap-up: the graph never revives once NULL and
 * explicit_policy never grows, so a path failing (f) fails 6.1.5 too. */
int castore_policy_run(
    const wired_span*        certs,
    usz                      n_walk,
    const castore_policy_in* in,
    x509_policy_graph*       g) {
  castore_policy_ctr c;
  c.explicit_policy = policy_initial(in->explicit_policy);
  c.policy_mapping  = policy_initial(in->map_inhibit);
  c.inhibit_any     = policy_initial(in->any_inhibit);
  x509_policy_graph_init(g);
  for (usz i = n_walk; i-- > 0;) {
    if (!castore_policy_step(certs[i], g, &c, i == 0)) {
      return 0;
    }
  }
  return policy_wrapup_ok(&c, g, in->user_set);
}

/* This SDK's own inputs: any-policy and no initial-* flag set. */
int castore_policy_processing_ok(const wired_span* certs, usz n_walk) {
  castore_policy_in in = {0};
  x509_policy_graph g;
  return castore_policy_run(certs, n_walk, &in, &g);
}
