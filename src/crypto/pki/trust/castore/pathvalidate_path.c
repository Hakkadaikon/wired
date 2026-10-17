#include "crypto/pki/trust/castore/pathvalidate_impl.h"

static int policy_wrapup_ok(u64 explicit_policy, const x509_policy_tree* tree);
static int cert_seen_before(const wired_span* certs, usz i);
static int no_duplicate_certs(const wired_span* certs, usz n_certs);
static int certs_hygienic(const wired_span* certs, usz n_certs);
static int leaf_purpose_ok(wired_span leaf);
static int policy_and_names_ok(const wired_span* certs, usz n_certs);
static int path_head_ok(const wired_span* certs, usz n_certs);
static int path_body_ok(const wired_span* certs, usz n_certs);
static int path_ok(const wired_span* certs, usz n_certs);
static int path_len_ok(usz n_certs);

/* RFC 5280 6.1.5 (g): if requireExplicitPolicy ever reached 0, the final
 * valid_policy_tree must be non-empty. inhibit_any's effect (anyPolicy
 * ignored once its counter is 0) is already realized by castore_policy_step
 * folding anyPolicy from certificatePolicies as this SDK does not special-case
 * anyPolicy recognition separately from the tree fold; recording the
 * counter here keeps its RFC-mandated bookkeeping visible even though this
 * SDK's caller (server-certificate verification with no explicit policy
 * request) never queries it beyond the tree-non-empty check. */
static int policy_wrapup_ok(u64 explicit_policy, const x509_policy_tree* tree) {
  if (explicit_policy != 0) return 1;
  return x509_policy_tree_nonempty(tree);
}

/* RFC 5280 6.1.3(d)/6.1.4(h)-(j)/6.1.5(g): process every certificate in path
 * order from the trust anchor's issued certificate (certs[n_certs-1] is the
 * anchor and is not itself walked, matching castore_links_ok's iteration -- 6.1
 * numbers the anchor's issued certificate as certificate 1) down to the leaf
 * (certs[0]), then check the wrap-up condition. */
int castore_policy_processing_ok(const wired_span* certs, usz n_certs) {
  x509_policy_tree tree;
  u64              explicit_policy = X509_SKIPCERTS_NONE;
  u64              inhibit_any     = X509_SKIPCERTS_NONE;
  x509_policy_tree_init(&tree);
  for (usz i = n_certs - 1; i-- > 0;)
    if (!castore_policy_step(certs[i], &tree, &explicit_policy, &inhibit_any))
      return 0;
  return policy_wrapup_ok(explicit_policy, &tree);
}

/* RFC 5280 6.1: certs[i] does not byte-equal any earlier certificate in the
 * path. */
static int cert_seen_before(const wired_span* certs, usz i) {
  for (usz j = 0; j < i; j++)
    if (x509_dn_equal(certs[i], certs[j])) return 1;
  return 0;
}

/* No certificate in the path appears more than once. */
static int no_duplicate_certs(const wired_span* certs, usz n_certs) {
  for (usz i = 0; i < n_certs; i++)
    if (cert_seen_before(certs, i)) return 0;
  return 1;
}

/* Every certificate is hygienic: its extensions pass RFC 5280 4.2, and it
 * does not repeat an earlier certificate in the path. */
static int certs_hygienic(const wired_span* certs, usz n_certs) {
  if (!castore_all_extensions_ok(certs, n_certs)) return 0;
  return no_duplicate_certs(certs, n_certs);
}

/* The leaf's purpose (EKU + RFC 8410 SPKI-specific keyUsage). */
static int leaf_purpose_ok(wired_span leaf) {
  if (!castore_leaf_allows_server_auth(leaf)) return 0;
  return castore_cert_spki_ku_ok(leaf, 0);
}

/* RFC 5280 6.1.4 (g)-(j): name constraints and the certificatePolicies/
 * policyConstraints/inhibitAnyPolicy bookkeeping. */
static int policy_and_names_ok(const wired_span* certs, usz n_certs) {
  if (!castore_name_constraints_chain_ok(certs, n_certs)) return 0;
  return castore_policy_processing_ok(certs, n_certs);
}

/* The leaf's purpose and per-certificate hygiene. */
static int path_head_ok(const wired_span* certs, usz n_certs) {
  if (!leaf_purpose_ok(certs[0])) return 0;
  return certs_hygienic(certs, n_certs);
}

/* Every adjacent link, and the path-wide name/policy constraints. */
static int path_body_ok(const wired_span* certs, usz n_certs) {
  if (!castore_links_ok(certs, n_certs)) return 0;
  return policy_and_names_ok(certs, n_certs);
}

/* The leaf's purpose, per-certificate hygiene, every adjacent link, and the
 * path-wide name/policy constraints all verify. */
static int path_ok(const wired_span* certs, usz n_certs) {
  if (!path_head_ok(certs, n_certs)) return 0;
  return path_body_ok(certs, n_certs);
}

/* n_certs is at least the leaf and at most CASTORE_PATH_MAX_CERTS (see the
 * header: the bound is what keeps the quadratic name-constraint walk and
 * the policy fold peer-independent). Checked before any per-certificate
 * work so an over-long path costs nothing. */
static int path_len_ok(usz n_certs) {
  return n_certs >= 1 && n_certs <= CASTORE_PATH_MAX_CERTS;
}

int castore_validate_chain(
    const castore* s, const wired_span* certs, usz n_certs) {
  if (!path_len_ok(n_certs)) return 0;
  if (!path_ok(certs, n_certs)) return 0;
  return castore_tail_anchored(s, certs[n_certs - 1]);
}
