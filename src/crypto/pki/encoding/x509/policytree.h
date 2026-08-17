#ifndef X509_POLICYTREE_H
#define X509_POLICYTREE_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "crypto/pki/encoding/x509/certpolicies.h"

/** RFC 5280 6.1.2/6.1.3(d)/6.1.5(g). A flattened approximation of
 * valid_policy_tree, adequate for this SDK's single use (server-certificate
 * validation with user-initial-policy-set = {anyPolicy}, so nothing ever
 * needs to test "is policy P in the tree" for a caller-supplied P -- only
 * "is the tree non-empty" at requireExplicitPolicy wrap-up matters, RFC 5280
 * 6.1.5 (g)(iii) with initial-explicit-policy unset and no expected_policy
 * intersection to report). Policy mapping (policyMappings extension) is not
 * implemented: this tracks a flat admissible-OID set rather than a tree of
 * (issuer-domain-policy, expected-policy-set) pairs, which is exact as long
 * as no certificate in the path re-maps a policy OID (RFC 5280 6.1.3 (d)
 * degenerates to plain set intersection when policy mapping is absent, which
 * is the common case this SDK targets). is_any=1 represents the root node
 * "anyPolicy" (RFC 5280 6.1.2's initialization); once narrowed to an
 * explicit OID set (is_any=0), the set only ever shrinks via intersection,
 * matching the tree's monotonic pruning. */
typedef struct {
  x509_policy_set set;
  int             is_any;
} x509_policy_tree;

/* RFC 5280 6.1.2. The initial state before certificate 1 is processed: the
 * tree is the single root node "anyPolicy". */
void x509_policy_tree_init(x509_policy_tree* t);

/* RFC 5280 6.1.3 (d). Fold one certificate's tbs into the tree, in path
 * order from the trust anchor's issued certificate towards the leaf.
 * any_inhibited is the caller's inhibit_anypolicy state (RFC 5280 6.1.4 (j))
 * evaluated BEFORE this certificate's own position in the path is applied
 * to it (6.1.3 (d)(2): "unless ... inhibit_anypolicy ... indicates that
 * anyPolicy is not considered for this certificate"), i.e. 1 once the
 * running inhibit_anypolicy counter has reached 0 at this certificate:
 *   - no certificatePolicies extension: the tree becomes empty (no policy
 *     statement to match against, so no child nodes are added -- 6.1.3
 *     (d)(1)(i) applied with an empty "match" set);
 *   - certificatePolicies present, containing anyPolicy, and anyPolicy is
 *     NOT inhibited: the tree is unchanged (an anyPolicy statement adds no
 *     constraint);
 *   - certificatePolicies present, no anyPolicy (or anyPolicy present but
 *     inhibited, treated the same as "no anyPolicy" per 6.1.3 (d)(2)): the
 *     tree narrows to its intersection with the certificate's explicit
 *     policy OID set (or becomes exactly that set, the first time the
 *     root's anyPolicy narrows). An already-empty tree stays empty
 *     (monotonic). */
void x509_policy_tree_fold(
    x509_policy_tree* t, wired_span tbs, int any_inhibited);

/* 1 if the tree is non-empty (root anyPolicy, or a narrowed set with at
 * least one surviving OID); 0 if pruned to empty. RFC 5280 6.1.5 (g): a
 * requireExplicitPolicy in effect at wrap-up requires this to be 1. */
int x509_policy_tree_nonempty(const x509_policy_tree* t);

#endif
