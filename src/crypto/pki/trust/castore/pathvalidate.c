#include "crypto/pki/trust/castore/pathvalidate.h"

#include "crypto/pki/encoding/x509/basicconstraints.h"
#include "crypto/pki/encoding/x509/chain.h"
#include "crypto/pki/encoding/x509/eku.h"
#include "crypto/pki/encoding/x509/keyusage.h"
#include "crypto/pki/encoding/x509/nameconstraints.h"
#include "crypto/pki/encoding/x509/policyconstraints.h"
#include "crypto/pki/encoding/x509/policytree.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/chainverify.h"

/* RFC 5280 4.2.1.12. The leaf (certs[0], the end-entity server certificate)
 * must permit id-kp-serverAuth: extKeyUsage absent is unrestricted, present
 * without serverAuth rejects. The only caller of validate_chain in this SDK
 * is server-certificate verification (see pathvalidate.h). */
static int leaf_allows_server_auth(wired_span leaf) {
  quic_x509 c;
  if (!quic_x509_parse(leaf, &c)) return 0;
  return quic_x509_eku_allows(
      c.tbs, wired_span_of(
                 quic_x509_oid_server_auth, sizeof(quic_x509_oid_server_auth)));
}

/* RFC 5280 4.1.2.4. View cert's issuer Name (header included). */
static int cert_issuer(wired_span cert, wired_span* dn) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return quic_x509_issuer(c.tbs, dn);
}

/* RFC 5280 4.1.2.6. View cert's subject Name (header included). */
static int cert_subject(wired_span cert, wired_span* dn) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return quic_x509_subject(c.tbs, dn);
}

/* RFC 5280 6.1.3. certs[i]'s issuer equals certs[i+1]'s subject. */
static int names_chain(wired_span child, wired_span parent) {
  wired_span iss, subj;
  if (!cert_issuer(child, &iss)) return 0;
  if (!cert_subject(parent, &subj)) return 0;
  return quic_x509_dn_equal(iss, subj);
}

/* RFC 5280 6.1: "a certificate is self-issued if the DNs that appear in the
 * subject and issuer fields are identical". Malformed Name fields are not
 * self-issued (fails open into being counted, the strict side). */
static int cert_self_issued(wired_span cert) {
  wired_span iss, subj;
  if (!cert_issuer(cert, &iss)) return 0;
  if (!cert_subject(cert, &subj)) return 0;
  return quic_x509_dn_equal(iss, subj);
}

/* RFC 5280 4.2. cert carries no unrecognized critical extension. */
static int cert_known_critical_ok(wired_span cert) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return !quic_x509_has_unknown_critical(c.tbs);
}

/* Every certificate in the path (leaf through tail) is free of unrecognized
 * critical extensions (RFC 5280 4.2 MUST reject). */
static int no_unknown_critical(const wired_span* certs, usz n_certs) {
  for (usz i = 0; i < n_certs; i++)
    if (!cert_known_critical_ok(certs[i])) return 0;
  return 1;
}

/* RFC 5280 4.2.1.3/6.1.4. An issuer cert is a CA and, if keyUsage is
 * present, asserts keyCertSign (absent keyUsage is unconstrained). */
static int cert_can_issue(wired_span cert) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  if (!quic_x509_is_ca(c.tbs)) return 0;
  return quic_x509_can_sign_certs(c.tbs);
}

/* View cert's tbs and its SPKI algorithm OID. */
static int cert_spki_oid(wired_span cert, wired_span* tbs, wired_span* oid) {
  quic_x509  c;
  wired_span key;
  if (!quic_x509_parse(cert, &c)) return 0;
  if (!quic_x509_public_key(c.tbs, oid, &key)) return 0;
  *tbs = c.tbs;
  return 1;
}

/* RFC 8410 3. oid is id-X25519 or id-X448. */
static int is_x25519_family(wired_span oid) {
  return quic_x509_is_x25519(oid) || quic_x509_is_x448(oid);
}

/* RFC 8410 3. oid is id-Ed25519 or id-Ed448. */
static int is_ed_family(wired_span oid) {
  return quic_x509_is_ed25519(oid) || quic_x509_is_ed448(oid);
}

/* RFC 8410 5. If tbs's SPKI is id-X25519/id-X448, keyUsage (if present) must
 * assert keyAgreement. Any other algorithm is unconstrained by this check. */
static int x25519_family_ok(wired_span tbs, wired_span oid) {
  if (!is_x25519_family(oid)) return 1;
  return quic_x509_keyagreement_ok(tbs);
}

/* RFC 8410 5. If tbs's SPKI is id-Ed25519/id-Ed448, keyUsage (if present)
 * must admit the role-appropriate bits: leaf sign bits for an end-entity
 * cert, the wider CA bit set for an issuer. Any other algorithm is
 * unconstrained by this check. */
static int ed_family_ok(wired_span tbs, wired_span oid, int is_ca) {
  if (!is_ed_family(oid)) return 1;
  if (is_ca) return quic_x509_ed_ca_ok(tbs);
  return quic_x509_ed_leaf_sig_ok(tbs);
}

/* RFC 8410 5. cert's SPKI-specific keyUsage constraint, if its algorithm is
 * id-X25519/X448/Ed25519/Ed448; unconstrained for any other algorithm
 * (RFC 5280's keyCertSign/EKU checks cover those separately). */
static int cert_spki_ku_ok(wired_span cert, int is_ca) {
  wired_span tbs, oid;
  if (!cert_spki_oid(cert, &tbs, &oid)) return 0;
  if (!x25519_family_ok(tbs, oid)) return 0;
  return ed_family_ok(tbs, oid, is_ca);
}

/* RFC 5280 6.1.4/RFC 8410 5. parent is a CA permitted to sign certificates
 * with an admissible SPKI-specific keyUsage. */
static int parent_may_issue(wired_span parent) {
  if (!cert_can_issue(parent)) return 0;
  return cert_spki_ku_ok(parent, 1);
}

/* RFC 5280 6.1.3/6.1.4. One link: name binding, the parent may issue certs,
 * and the parent signs the child. */
static int link_ok(wired_span child, wired_span parent) {
  if (!names_chain(child, parent)) return 0;
  if (!parent_may_issue(parent)) return 0;
  return quic_castore_verify_signed_by(child, parent);
}

/* RFC 5280 6.1.4. Find the registered anchor for issuer name and require it
 * to be a CA permitted to issue certs. */
static int find_ca_anchor(
    const quic_castore* s, wired_span iss, wired_span* root) {
  if (!quic_castore_find_by_subject(s, iss, root)) return 0;
  return cert_can_issue(*root);
}

/* RFC 5280 6.1. The tail must chain to a registered CA trust anchor: a root
 * whose subject equals the tail's issuer, and which signs the tail. */
static int tail_anchored(const quic_castore* s, wired_span tail) {
  wired_span iss, root;
  if (!cert_issuer(tail, &iss)) return 0;
  if (!find_ca_anchor(s, iss, &root)) return 0;
  return quic_castore_verify_signed_by(tail, root);
}

/* RFC 5280 6.1.4 (m). The issuer's pathLenConstraint must admit the number of
 * intermediate certs below it (the leaf is not counted). */
static int cert_pathlen_ok(wired_span cert, usz below) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  return quic_x509_pathlen_allows(c.tbs, below);
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
    if (!cert_self_issued(certs[j])) below++;
  return below;
}

/* One step: the link verifies and the issuer certs[i+1] admits the
 * non-self-issued intermediates between it and the leaf. */
static int step_ok(const wired_span* certs, usz i) {
  if (!link_ok(certs[i], certs[i + 1])) return 0;
  return cert_pathlen_ok(certs[i + 1], non_self_issued_below(certs, i));
}

/* Every adjacent leaf-to-tail link binds and verifies. */
static int links_ok(const wired_span* certs, usz n) {
  for (usz i = 0; i + 1 < n; i++)
    if (!step_ok(certs, i)) return 0;
  return 1;
}

/* RFC 5280 6.1.4 (g): child's subject Name must fall within issuer's
 * nameConstraints (directoryName form; see nameconstraints.h for the exact
 * matching rule and scope). */
static int subject_admitted(wired_span issuer, wired_span child) {
  wired_span subj;
  quic_x509  c;
  if (!cert_subject(child, &subj)) return 0;
  if (!quic_x509_parse(issuer, &c)) return 0;
  return quic_x509_name_constraints_permit(c.tbs, subj);
}

/* RFC 5280 6.1.4 (g): issuer certs[j]'s nameConstraints applies to every
 * certificate below it in the path (nearer the leaf): certs[0..j). */
static int issuer_constrains_below(const wired_span* certs, usz j) {
  for (usz k = 0; k < j; k++)
    if (!subject_admitted(certs[j], certs[k])) return 0;
  return 1;
}

/* Every issuer certificate's nameConstraints (if any) admits every
 * certificate below it in the path. certs[0] (the leaf) issues nothing, so
 * j starts at 1; certs[n_certs-1] (the trust anchor) DOES participate up to
 * and including n_certs-1, unlike policy_processing_ok's walk -- a trust
 * anchor's own nameConstraints are conventionally enforced against every
 * certificate it (directly or transitively) issued, matching common
 * implementations (verified against OpenSSL 3.0.13 `verify`, which reports
 * "permitted subtree violation" for a leaf outside the trust anchor's own
 * nameConstraints). RFC 5280 6.1's certificate-policies bookkeeping, by
 * contrast, treats the trust anchor purely as the source of the initial
 * state (6.1.2), not as a numbered "certificate i" to fold in. */
static int name_constraints_chain_ok(const wired_span* certs, usz n_certs) {
  for (usz j = 1; j < n_certs; j++)
    if (!issuer_constrains_below(certs, j)) return 0;
  return 1;
}

/* Lower *counter to v if v is smaller (a SkipCerts constraint only ever
 * tightens, RFC 5280 6.1.4 (i)/(j)); no-op if v carries
 * QUIC_X509_SKIPCERTS_NONE (the "absent" sentinel, larger than any real
 * path length). */
static void skipcerts_lower(u64* counter, u64 v) {
  if (v < *counter) *counter = v;
}

/* RFC 5280 6.1.4 (i)(1): PolicyConstraints.requireExplicitPolicy, if
 * present, lowers *explicit_policy to its value. Rejects (0) on a malformed
 * policyConstraints extension. */
static int apply_require_explicit(wired_span tbs, u64* explicit_policy) {
  u64 v = quic_x509_require_explicit_policy(tbs);
  if (v == QUIC_X509_SKIPCERTS_MALFORMED) return 0;
  skipcerts_lower(explicit_policy, v);
  return 1;
}

/* RFC 5280 6.1.4 (j): InhibitAnyPolicy, if present, lowers *inhibit_any to
 * its value. Rejects (0) on a malformed extension. */
static int apply_inhibit_any(wired_span tbs, u64* inhibit_any) {
  u64 v = quic_x509_inhibit_any_policy(tbs);
  if (v == QUIC_X509_SKIPCERTS_MALFORMED) return 0;
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
  if (cert_self_issued(cert)) return;
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
static int policy_step(
    wired_span             cert,
    quic_x509_policy_tree* tree,
    u64*                   explicit_policy,
    u64*                   inhibit_any) {
  quic_x509 c;
  if (!quic_x509_parse(cert, &c)) return 0;
  quic_x509_policy_tree_fold(tree, c.tbs, *inhibit_any == 0);
  if (!policy_step_constraints(c.tbs, explicit_policy, inhibit_any)) return 0;
  decrement_if_not_self_issued(cert, explicit_policy, inhibit_any);
  return 1;
}

/* RFC 5280 6.1.5 (g): if requireExplicitPolicy ever reached 0, the final
 * valid_policy_tree must be non-empty. inhibit_any's effect (anyPolicy
 * ignored once its counter is 0) is already realized by policy_step folding
 * anyPolicy from certificatePolicies as this SDK does not special-case
 * anyPolicy recognition separately from the tree fold; recording the
 * counter here keeps its RFC-mandated bookkeeping visible even though this
 * SDK's caller (server-certificate verification with no explicit policy
 * request) never queries it beyond the tree-non-empty check. */
static int policy_wrapup_ok(
    u64 explicit_policy, const quic_x509_policy_tree* tree) {
  if (explicit_policy != 0) return 1;
  return quic_x509_policy_tree_nonempty(tree);
}

/* RFC 5280 6.1.3(d)/6.1.4(h)-(j)/6.1.5(g): process every certificate in path
 * order from the trust anchor's issued certificate (certs[n_certs-1] is the
 * anchor and is not itself walked, matching links_ok's iteration -- 6.1
 * numbers the anchor's issued certificate as certificate 1) down to the leaf
 * (certs[0]), then check the wrap-up condition. */
static int policy_processing_ok(const wired_span* certs, usz n_certs) {
  quic_x509_policy_tree tree;
  u64                   explicit_policy = QUIC_X509_SKIPCERTS_NONE;
  u64                   inhibit_any     = QUIC_X509_SKIPCERTS_NONE;
  quic_x509_policy_tree_init(&tree);
  for (usz i = n_certs - 1; i-- > 0;)
    if (!policy_step(certs[i], &tree, &explicit_policy, &inhibit_any)) return 0;
  return policy_wrapup_ok(explicit_policy, &tree);
}

/* RFC 5280 6.1: certs[i] does not byte-equal any earlier certificate in the
 * path. */
static int cert_seen_before(const wired_span* certs, usz i) {
  for (usz j = 0; j < i; j++)
    if (quic_x509_dn_equal(certs[i], certs[j])) return 1;
  return 0;
}

/* No certificate in the path appears more than once. */
static int no_duplicate_certs(const wired_span* certs, usz n_certs) {
  for (usz i = 0; i < n_certs; i++)
    if (cert_seen_before(certs, i)) return 0;
  return 1;
}

/* Every certificate is hygienic: no unknown-critical extension, and it does
 * not repeat an earlier certificate in the path. */
static int certs_hygienic(const wired_span* certs, usz n_certs) {
  if (!no_unknown_critical(certs, n_certs)) return 0;
  return no_duplicate_certs(certs, n_certs);
}

/* The leaf's purpose (EKU + RFC 8410 SPKI-specific keyUsage). */
static int leaf_purpose_ok(wired_span leaf) {
  if (!leaf_allows_server_auth(leaf)) return 0;
  return cert_spki_ku_ok(leaf, 0);
}

/* RFC 5280 6.1.4 (g)-(j): name constraints and the certificatePolicies/
 * policyConstraints/inhibitAnyPolicy bookkeeping. */
static int policy_and_names_ok(const wired_span* certs, usz n_certs) {
  if (!name_constraints_chain_ok(certs, n_certs)) return 0;
  return policy_processing_ok(certs, n_certs);
}

/* The leaf's purpose and per-certificate hygiene. */
static int path_head_ok(const wired_span* certs, usz n_certs) {
  if (!leaf_purpose_ok(certs[0])) return 0;
  return certs_hygienic(certs, n_certs);
}

/* Every adjacent link, and the path-wide name/policy constraints. */
static int path_body_ok(const wired_span* certs, usz n_certs) {
  if (!links_ok(certs, n_certs)) return 0;
  return policy_and_names_ok(certs, n_certs);
}

/* The leaf's purpose, per-certificate hygiene, every adjacent link, and the
 * path-wide name/policy constraints all verify. */
static int path_ok(const wired_span* certs, usz n_certs) {
  if (!path_head_ok(certs, n_certs)) return 0;
  return path_body_ok(certs, n_certs);
}

int quic_castore_validate_chain(
    const quic_castore* s, const wired_span* certs, usz n_certs) {
  if (n_certs < 1) return 0;
  if (!path_ok(certs, n_certs)) return 0;
  return tail_anchored(s, certs[n_certs - 1]);
}
