#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/policytree.h"
#include "crypto/pki/encoding/x509/policytree_impl.h"

/* Index of oid in s[0..n), or n if absent. */
usz policytree_oid_index(const wired_span* s, usz n, wired_span oid) {
  for (usz i = 0; i < n; i++) {
    if (der_oid_equal(s[i], oid)) {
      return i;
    }
  }
  return n;
}

/* Index of the node whose valid_policy is oid in l, or l->n if none. */
usz policytree_find(const x509_policy_level* l, wired_span oid) {
  for (usz i = 0; i < l->n; i++) {
    if (der_oid_equal(l->node[i].oid, oid)) {
      return i;
    }
  }
  return l->n;
}

/* The current depth has the anyPolicy node. */
int policytree_has_any(const x509_policy_graph* g) {
  return policytree_find(&g->lvl, x509_any_policy_oid()) < g->lvl.n;
}

/* RFC 9618 5.5 (g)(2): the auth bit for a new valid_policy_node_set member
 * oid (a child of the anyPolicy node), shared by every member with that
 * valid_policy. Running out of bits overflows the graph. */
u32 policytree_auth_bit(x509_policy_graph* g, wired_span oid) {
  usz k = policytree_oid_index(g->auth_oid, g->n_auth, oid);
  if (k < g->n_auth) {
    return 1u << k;
  }
  if (g->n_auth >= X509_POLICY_AUTH_MAX) {
    g->overflow = 1;
    return 1;
  }
  g->auth_oid[g->n_auth] = oid;
  return 1u << g->n_auth++;
}

/* Add node oid to l unless l already has one (RFC 9618 5.2: "at most one
 * node at depth x whose valid_policy is P-OID"); a full level overflows. */
void policytree_put(
    x509_policy_graph* g,
    x509_policy_level* l,
    wired_span         oid,
    u32                auth,
    u8                 mapped) {
  if (policytree_find(l, oid) < l->n) {
    return;
  }
  if (l->n >= X509_POLICY_NODES_MAX) {
    g->overflow = 1;
    return;
  }
  l->node[l->n].oid    = oid;
  l->node[l->n].auth   = auth;
  l->node[l->n].mapped = mapped;
  l->n++;
}

void x509_policy_graph_init(x509_policy_graph* g) {
  g->lvl.n          = 0;
  g->maps.n         = 0;
  g->maps.truncated = 0;
  g->n_auth         = 0;
  g->overflow       = 0;
  policytree_put(
      g, &g->lvl, x509_any_policy_oid(),
      policytree_auth_bit(g, x509_any_policy_oid()), 0);
}
