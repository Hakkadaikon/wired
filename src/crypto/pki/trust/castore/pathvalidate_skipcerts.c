#include "crypto/pki/trust/castore/pathvalidate_impl.h"

static int  cert_pathlen_ok(wired_span cert, usz below);
static usz  non_self_issued_below(const wired_span* certs, usz i);
static int  step_ok(const wired_span* certs, usz i);
static int  subject_admitted(wired_span issuer, wired_span child);
static int  issuer_constrains_below(const wired_span* certs, usz j);
static void skipcerts_lower(u64* counter, u64 v);
static int  apply_require_explicit(wired_span tbs, u64* explicit_policy);
static int  apply_inhibit_any(wired_span tbs, u64* inhibit_any);
static void skipcerts_decrement(u64* counter);
static void decrement_if_not_self_issued(
    wired_span cert, u64* explicit_policy, u64* inhibit_any);
static int policy_step_constraints(
    wired_span tbs, u64* explicit_policy, u64* inhibit_any);

/* RFC 5280 6.1. The tail must chain to a registered CA trust anchor: a root
 * whose subject equals the tail's issuer, and which signs the tail. */
int castore_tail_anchored(const castore* s, wired_span tail) {
  wired_span iss, root;
  if (!castore_cert_issuer(tail, &iss)) return 0;
  if (!castore_find_ca_anchor(s, iss, &root)) return 0;
  return castore_verify_signed_by(tail, root);
}

/* RFC 5280 6.1.4 (m). The issuer's pathLenConstraint must admit the number of
 * intermediate certs below it (the leaf is not counted). */
static int cert_pathlen_ok(wired_span cert, usz below) {
  x509 c;
  if (!x509_parse(cert, &c)) return 0;
  return x509_pathlen_allows(c.tbs, below);
}

/* RFC 5280 6.1.4 (h)/(l): "If the certificate was not self-issued, verify
 * that max_path_length is greater than zero and decrement max_path_length by
 * 1" -- a self-issued intermediate (e.g. a CA's own re-issued/rollover
 * certificate) does not consume path length. certs[1..i] are the
 * intermediates strictly between the leaf and issuer certs[i+1]; count only
 * those that are not self-issued. */
static usz non_self_issued_below(const wired_span* certs, usz i) {
  usz below = 0;
  for (usz j = 1; j <= i; j++)
    if (!castore_cert_self_issued(certs[j])) below++;
  return below;
}

/* One step: the link verifies and the issuer certs[i+1] admits the
 * non-self-issued intermediates between it and the leaf. */
static int step_ok(const wired_span* certs, usz i) {
  if (!castore_link_ok(certs[i], certs[i + 1])) return 0;
  return cert_pathlen_ok(certs[i + 1], non_self_issued_below(certs, i));
}

/* Every adjacent leaf-to-tail link binds and verifies. */
int castore_links_ok(const wired_span* certs, usz n) {
  for (usz i = 0; i + 1 < n; i++)
    if (!step_ok(certs, i)) return 0;
  return 1;
}

/* RFC 5280 6.1.4 (g): the whole child certificate -- subject Name, SAN
 * dNSName/iPAddress/URI entries, and the CN fallback -- must fall within
 * issuer's nameConstraints (see nameconstraints.h for the matching rules
 * and scope). */
static int subject_admitted(wired_span issuer, wired_span child) {
  x509 ci, cc;
  if (!x509_parse(issuer, &ci)) return 0;
  if (!x509_parse(child, &cc)) return 0;
  return x509_name_constraints_admit(ci.tbs, cc.tbs);
}

/* RFC 5280 6.1.4 (g): issuer certs[j]'s nameConstraints applies to every
 * certificate below it in the path (nearer the leaf): certs[0..j). Checking
 * each issuer independently against every certificate below it realizes
 * 6.1.4 (g)'s accumulated state exactly: a name lies within the running
 * intersection of permitted subtrees iff it lies within every issuer's own
 * permitted set, and within the union of excluded subtrees iff some
 * issuer's own excluded set covers it. */
static int issuer_constrains_below(const wired_span* certs, usz j) {
  for (usz k = 0; k < j; k++)
    if (!subject_admitted(certs[j], certs[k])) return 0;
  return 1;
}

/* Every issuer certificate's nameConstraints (if any) admits every
 * certificate below it in the path. certs[0] (the leaf) issues nothing, so
 * j starts at 1; certs[n_certs-1] (the trust anchor) DOES participate up to
 * and including n_certs-1, unlike castore_policy_processing_ok's walk -- a
 * trust anchor's own nameConstraints are conventionally enforced against every
 * certificate it (directly or transitively) issued, matching common
 * implementations (verified against OpenSSL 3.0.13 `verify`, which reports
 * "permitted subtree violation" for a leaf outside the trust anchor's own
 * nameConstraints). RFC 5280 6.1's certificate-policies bookkeeping, by
 * contrast, treats the trust anchor purely as the source of the initial
 * state (6.1.2), not as a numbered "certificate i" to fold in. */
int castore_name_constraints_chain_ok(const wired_span* certs, usz n_certs) {
  for (usz j = 1; j < n_certs; j++)
    if (!issuer_constrains_below(certs, j)) return 0;
  return 1;
}

/* Lower *counter to v if v is smaller (a SkipCerts constraint only ever
 * tightens, RFC 5280 6.1.4 (i)/(j)); no-op if v carries
 * X509_SKIPCERTS_NONE (the "absent" sentinel, larger than any real
 * path length). */
static void skipcerts_lower(u64* counter, u64 v) {
  if (v < *counter) *counter = v;
}

/* RFC 5280 6.1.4 (i)(1): PolicyConstraints.requireExplicitPolicy, if
 * present, lowers *explicit_policy to its value. Rejects (0) on a malformed
 * policyConstraints extension. */
static int apply_require_explicit(wired_span tbs, u64* explicit_policy) {
  u64 v = x509_require_explicit_policy(tbs);
  if (v == X509_SKIPCERTS_MALFORMED) return 0;
  skipcerts_lower(explicit_policy, v);
  return 1;
}

/* RFC 5280 6.1.4 (j): InhibitAnyPolicy, if present, lowers *inhibit_any to
 * its value. Rejects (0) on a malformed extension. */
static int apply_inhibit_any(wired_span tbs, u64* inhibit_any) {
  u64 v = x509_inhibit_any_policy(tbs);
  if (v == X509_SKIPCERTS_MALFORMED) return 0;
  skipcerts_lower(inhibit_any, v);
  return 1;
}

/* Decrement *counter by 1 unless it is already at its floor 0. */
static void skipcerts_decrement(u64* counter) {
  if (*counter != 0) (*counter)--;
}

/* RFC 5280 6.1.4 (h)/(l): a non-self-issued certificate consumes one unit of
 * both counters (policy_mapping's counter is not modeled, this SDK does not
 * implement policyMappings). */
static void decrement_if_not_self_issued(
    wired_span cert, u64* explicit_policy, u64* inhibit_any) {
  if (castore_cert_self_issued(cert)) return;
  skipcerts_decrement(explicit_policy);
  skipcerts_decrement(inhibit_any);
}

/* RFC 5280 6.1.4 (i)/(j): a certificate's own policyConstraints and
 * inhibitAnyPolicy extensions, applied to the running counters. */
static int policy_step_constraints(
    wired_span tbs, u64* explicit_policy, u64* inhibit_any) {
  if (!apply_require_explicit(tbs, explicit_policy)) return 0;
  return apply_inhibit_any(tbs, inhibit_any);
}

/* RFC 5280 6.1.3 (d) / 6.1.4 (h)-(j), one certificate's contribution in path
 * order from the trust anchor's issued certificate towards the leaf: fold
 * its certificatePolicies into the tree, apply its own
 * policyConstraints/inhibitAnyPolicy (6.1.4 (i)/(j) read a cert's own
 * constraints before that cert's position decrements the counters, matching
 * the RFC's per-certificate step order), then decrement for a
 * non-self-issued hop. */
int castore_policy_step(
    wired_span        cert,
    x509_policy_tree* tree,
    u64*              explicit_policy,
    u64*              inhibit_any) {
  x509 c;
  if (!x509_parse(cert, &c)) return 0;
  x509_policy_tree_fold(tree, c.tbs, *inhibit_any == 0);
  if (!policy_step_constraints(c.tbs, explicit_policy, inhibit_any)) return 0;
  decrement_if_not_self_issued(cert, explicit_policy, inhibit_any);
  return 1;
}
