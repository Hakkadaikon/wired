#include "crypto/pki/encoding/x509/policytree.h"

#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/policytree_impl.h"

/* Pair k of m maps idp to p. */
static int pt_maps_to(
    const x509_policy_maps* m, usz k, wired_span idp, wired_span p) {
  return der_oid_equal(m->idp[k], idp) && der_oid_equal(m->sdp[k], p);
}

/* p is a subjectDomainPolicy m gives for idp. */
static int pt_mapped_has(
    const x509_policy_maps* m, wired_span idp, wired_span p) {
  for (usz k = 0; k < m->n; k++) {
    if (pt_maps_to(m, k, idp, p)) {
      return 1;
    }
  }
  return 0;
}

/* p is in node nd's expected_policy_set (RFC 9618 5.2 (3)). */
static int pt_expects(
    const x509_policy_graph* g, const x509_policy_node* nd, wired_span p) {
  if (nd->mapped) {
    return pt_mapped_has(&g->maps, nd->oid, p);
  }
  return der_oid_equal(nd->oid, p);
}

/* RFC 9618 5.3 (d)(1)(i): the auth bits of parent_nodes, the depth i-1
 * nodes expecting p; 0 when there are none (every node's auth is
 * non-zero). */
static u32 pt_parents(const x509_policy_graph* g, wired_span p) {
  u32 a = 0;
  for (usz i = 0; i < g->lvl.n; i++) {
    if (pt_expects(g, &g->lvl.node[i], p)) {
      a |= g->lvl.node[i].auth;
    }
  }
  return a;
}

/* RFC 9618 5.3 (d)(1)(ii): unmatched p hangs off the anyPolicy node of
 * depth i-1, if any, as a new valid_policy_node_set member. */
static u32 pt_unmatched(x509_policy_graph* g, wired_span p) {
  if (!policytree_has_any(g)) {
    return 0;
  }
  return policytree_auth_bit(g, p);
}

/* RFC 9618 5.3 (d)(1) for one policy P-OID != anyPolicy. */
static void pt_policy(
    x509_policy_graph* g, x509_policy_level* next, wired_span p) {
  u32 a = pt_parents(g, p);
  if (a == 0) {
    a = pt_unmatched(g, p);
  }
  if (a != 0) {
    policytree_put(g, next, p, a, 0);
  }
}

/* RFC 9618 5.3 (d)(1) over the certificate's policies. */
static void pt_policies(
    x509_policy_graph* g, x509_policy_level* next, const x509_policy_set* cp) {
  for (usz i = 0; i < cp->n; i++) {
    if (!der_oid_equal(cp->oid[i], x509_any_policy_oid())) {
      pt_policy(g, next, cp->oid[i]);
    }
  }
}

/* RFC 9618 5.3 (d)(2) for one expected P-OID: "if P-OID does not appear
 * as the valid_policy of some node at depth i, create a single child node"
 * whose parents are the nodes expecting it (policytree_put skips the
 * existing one). */
static void pt_any_child(
    x509_policy_graph* g, x509_policy_level* next, wired_span p) {
  policytree_put(g, next, p, pt_parents(g, p), 0);
}

/* The mapped expected_policy_set of node idp. */
static void pt_mapped_expected(
    x509_policy_graph* g, x509_policy_level* next, wired_span idp) {
  for (usz k = 0; k < g->maps.n; k++) {
    if (der_oid_equal(g->maps.idp[k], idp)) {
      pt_any_child(g, next, g->maps.sdp[k]);
    }
  }
}

/* RFC 9618 5.3 (d)(2): every P-OID of every depth i-1 expected set. */
static void pt_expected_all(x509_policy_graph* g, x509_policy_level* next) {
  for (usz i = 0; i < g->lvl.n; i++) {
    const x509_policy_node* nd = &g->lvl.node[i];
    if (nd->mapped) {
      pt_mapped_expected(g, next, nd->oid);
    } else {
      pt_any_child(g, next, nd->oid);
    }
  }
}

/* RFC 9618 5.3 (d)(2): anyPolicy is listed and allowed. */
static int pt_any_applies(const x509_policy_set* cp, int any_ok) {
  return any_ok && x509_policy_set_has_any(cp);
}

/* RFC 9618 5.3 (d) with certificatePolicies cp: depth i replaces depth
 * i-1, whose nodes without children simply drop out ((d)(3)). A cp
 * truncated at X509_CERT_POLICY_MAX overflows the graph. */
static void pt_fold_present(
    x509_policy_graph* g, const x509_policy_set* cp, int any_ok) {
  x509_policy_level next;
  next.n = 0;
  pt_policies(g, &next, cp);
  if (pt_any_applies(cp, any_ok)) {
    pt_expected_all(g, &next);
  }
  g->overflow |= cp->truncated;
  g->lvl    = next;
  g->maps.n = 0;
}

void x509_policy_graph_fold(x509_policy_graph* g, wired_span tbs, int any_ok) {
  x509_policy_set cp;
  if (g->lvl.n == 0) {
    return; /* (d) needs a non-NULL graph, (e) keeps it NULL */
  }
  if (!x509_cert_policies(tbs, &cp)) {
    g->lvl.n = 0;
    return;
  }
  pt_fold_present(g, &cp, any_ok);
}
