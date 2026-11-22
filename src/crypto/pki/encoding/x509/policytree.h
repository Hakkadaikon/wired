#ifndef X509_POLICYTREE_H
#define X509_POLICYTREE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/encoding/x509/certpolicies.h"
#include "crypto/pki/encoding/x509/policymap.h"

/* RFC 9618 4.1: the valid_policy_graph holds at most one node per policy
 * OID per depth, so a depth has at most |certificatePolicies| (<=
 * X509_CERT_POLICY_MAX) + |expected policies of the depth above| + |that
 * certificate's mappings| (<= X509_POLICY_MAPS_MAX) nodes. This SDK keeps
 * at most this many per depth; a path that needs more marks the graph
 * overflowed (castore rejects it when explicit_policy is 0, the only case
 * the graph decides), so the work per certificate is bounded by
 * NODES x NODES x MAPS OID comparisons and the whole walk is linear in the
 * path length -- never the RFC 5280 tree's exponential growth (RFC 9618 3,
 * CVE-2023-0464). */
#define X509_POLICY_NODES_MAX 32
/* Distinct valid_policy_node_set OIDs (RFC 9618 5.5 (g)(2)/(3)) a path may
 * introduce, anyPolicy included (bit 0); more is an overflow. */
#define X509_POLICY_AUTH_MAX 32

/** One valid_policy_graph node (RFC 9618 5.2). Qualifiers are not kept
 * (5.2 (a): "Implementations MAY omit qualifiers"). expected_policy_set is
 * {oid} unless mapped, in which case it is the subjectDomainPolicy values
 * the graph's maps give for oid (RFC 5280 6.1.4 (b)). Instead of parent
 * links the node carries auth: the bit set (over x509_policy_graph's
 * auth_oid) of the valid_policy_node_set members it descends from, i.e.
 * the nodes on its paths whose single parent is anyPolicy, or anyPolicy
 * itself (bit 0) on the all-anyPolicy chain. That is all 6.1.5 (g) needs,
 * and pruning (6.1.3 (d)(3), 6.1.4 (b)(3)(ii)) becomes implicit: only
 * nodes of the current depth contribute. */
typedef struct {
  wired_span oid;
  u32        auth;
  u8         mapped;
} x509_policy_node;

/** The nodes of one depth. */
typedef struct {
  x509_policy_node node[X509_POLICY_NODES_MAX];
  usz              n;
} x509_policy_level;

/** RFC 9618 5.2 valid_policy_graph state across a path walk: the deepest
 * depth's nodes (n == 0 is the NULL graph), the mappings of the
 * certificate at that depth, the auth bit table, and the overflow flag
 * (a bound was exceeded: the graph's verdict is unknown). */
typedef struct {
  x509_policy_level lvl;
  x509_policy_maps  maps;
  wired_span        auth_oid[X509_POLICY_AUTH_MAX];
  usz               n_auth;
  int               overflow;
} x509_policy_graph;

/* RFC 9618 5.2: the single depth-0 node anyPolicy / {anyPolicy}. */
void x509_policy_graph_init(x509_policy_graph* g);

/* RFC 9618 5.3 (d)/(e) for certificate i: build depth i from its
 * certificatePolicies. any_ok is the caller's "(a) inhibit_anyPolicy is
 * greater than 0 or (b) i<n and the certificate is self-issued" for
 * (d)(2). */
void x509_policy_graph_fold(x509_policy_graph* g, wired_span tbs, int any_ok);

/* RFC 5280 6.1.4 (a) / RFC 9618 5.4 (b) for certificate i < n: apply its
 * policyMappings to depth i. map_ok is "policy_mapping is greater than 0":
 * mapped nodes get the mapping's expected set, otherwise they are
 * deleted. Returns 0 (path rejected) on a malformed policyMappings or one
 * naming anyPolicy, else 1. */
int x509_policy_graph_map(x509_policy_graph* g, wired_span tbs, int map_ok);

/* RFC 9618 5.5 (g): 1 if oid is in the user_constrained_policy_set for
 * user-initial-policy-set user (NULL: any-policy, where it equals the
 * authority_constrained_policy_set; anyPolicy itself is a member iff the
 * depth-n anyPolicy node exists). */
int x509_policy_graph_has(
    const x509_policy_graph* g, const x509_policy_set* user, wired_span oid);

/* RFC 9618 5.5: 1 if the user_constrained_policy_set is not empty. */
int x509_policy_graph_nonempty(
    const x509_policy_graph* g, const x509_policy_set* user);

#endif
