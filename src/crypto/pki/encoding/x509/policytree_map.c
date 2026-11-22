#include "crypto/pki/encoding/asn1/derval.h"
#include "crypto/pki/encoding/x509/policytree.h"
#include "crypto/pki/encoding/x509/policytree_impl.h"

/* RFC 9618 5.4 (b)(3)(i): delete the node idp of depth i, if any (the
 * last node moves into its slot; order carries no meaning). Its childless
 * ancestors drop out implicitly ((b)(3)(ii)). */
static void ptm_delete(x509_policy_graph* g, wired_span idp) {
  usz i = policytree_find(&g->lvl, idp);
  if (i == g->lvl.n) {
    return;
  }
  g->lvl.n--;
  g->lvl.node[i] = g->lvl.node[g->lvl.n];
}

/* RFC 9618 5.4 (b)(1)/(2): the node idp takes the mapping's expected set;
 * without one, a depth-i anyPolicy node gives idp a new node under the
 * depth i-1 anyPolicy node, so idp is a valid_policy_node_set member. */
static void ptm_keep(x509_policy_graph* g, wired_span idp) {
  usz i = policytree_find(&g->lvl, idp);
  if (i < g->lvl.n) {
    g->lvl.node[i].mapped = 1;
    return;
  }
  if (policytree_has_any(g)) {
    policytree_put(g, &g->lvl, idp, policytree_auth_bit(g, idp), 1);
  }
}

/* RFC 9618 5.4 (b) for one issuerDomainPolicy (a repeated one is
 * idempotent). */
static void ptm_one(x509_policy_graph* g, wired_span idp, int map_ok) {
  if (map_ok) {
    ptm_keep(g, idp);
  } else {
    ptm_delete(g, idp);
  }
}

/* Mappings past X509_POLICY_MAPS_MAX overflow a non-NULL graph. */
static void ptm_note_truncated(x509_policy_graph* g) {
  if (g->lvl.n > 0) {
    g->overflow |= g->maps.truncated;
  }
}

int x509_policy_graph_map(x509_policy_graph* g, wired_span tbs, int map_ok) {
  if (x509_policy_mappings(tbs, &g->maps) < 0) {
    return 0;
  }
  ptm_note_truncated(g);
  for (usz k = 0; k < g->maps.n; k++) {
    ptm_one(g, g->maps.idp[k], map_ok);
  }
  return 1;
}

/* RFC 9618 5.5 (g)(4)(i): the authority_constrained_policy_set as auth
 * bits -- the members the depth-n nodes descend from (bit 0: the depth-n
 * anyPolicy node). */
static u32 ptm_authority(const x509_policy_graph* g) {
  u32 a = 0;
  for (usz i = 0; i < g->lvl.n; i++) {
    a |= g->lvl.node[i].auth;
  }
  return a;
}

/* oid is in the authority_constrained_policy_set a. */
static int ptm_in_authority(const x509_policy_graph* g, u32 a, wired_span oid) {
  usz k = policytree_oid_index(g->auth_oid, g->n_auth, oid);
  return k < g->n_auth && (a >> k) & 1u;
}

/* RFC 9618 5.5 (g)(6): a user-initial-policy-set member survives if the
 * authorities constrain to it or to anyPolicy. */
static int ptm_user_keeps(const x509_policy_graph* g, u32 a, wired_span oid) {
  return (a & 1u) || ptm_in_authority(g, a, oid);
}

/* oid is in the user-initial-policy-set user. */
static int ptm_in_user(const x509_policy_set* user, wired_span oid) {
  return policytree_oid_index(user->oid, user->n, oid) < user->n;
}

int x509_policy_graph_has(
    const x509_policy_graph* g, const x509_policy_set* user, wired_span oid) {
  u32 a = ptm_authority(g);
  if (!user) {
    return ptm_in_authority(g, a, oid);
  }
  return ptm_in_user(user, oid) && ptm_user_keeps(g, a, oid);
}

/* Some member of user is in the user_constrained_policy_set. */
static int ptm_user_any(
    const x509_policy_graph* g, const x509_policy_set* user) {
  for (usz i = 0; i < user->n; i++) {
    if (x509_policy_graph_has(g, user, user->oid[i])) {
      return 1;
    }
  }
  return 0;
}

int x509_policy_graph_nonempty(
    const x509_policy_graph* g, const x509_policy_set* user) {
  if (!user) {
    return g->lvl.n > 0;
  }
  return ptm_user_any(g, user);
}
