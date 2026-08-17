#include "crypto/pki/trust/castore/pathvalidate.h"

#include "castore_golden.h"
#include "castore_ku_golden.h"
#include "castore_nc_golden.h"
#include "castore_pc_golden.h"
#include "castore_selfissued_golden.h"
#include "crypto/pki/trust/castore/castore.h"
#include "test.h"

#define PV_SPAN(der) wired_span_of(der, sizeof(der))

static castore_entry pv_roots[4];

static void store_with_root(castore* s) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, PV_SPAN(castore_root_der)) == 1);
}

/* RFC 5280 6.1. A correct [leaf, root] path to a registered anchor validates.
 */
static void test_valid_chain(void) {
  castore    s;
  wired_span certs[2] = {PV_SPAN(castore_leaf_der), PV_SPAN(castore_root_der)};
  store_with_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 1);
}

/* A single self-signed root that is itself the anchor validates. */
static void test_lone_root_chain(void) {
  castore    s;
  wired_span certs[1] = {PV_SPAN(castore_root_der)};
  store_with_root(&s);
  CHECK(castore_validate_chain(&s, certs, 1) == 1);
}

/* Root not registered: no anchor, so the path fails. */
static void test_unregistered_root_fails(void) {
  castore    s;
  wired_span certs[2] = {PV_SPAN(castore_leaf_der), PV_SPAN(castore_root_der)};
  castore_init(&s, pv_roots, 4);
  CHECK(castore_validate_chain(&s, certs, 2) == 0);
}

/* Issuer/subject mismatch between adjacent certs breaks the link. The leaf is
 * paired with itself as a bogus parent (subject CN=leaf.example does not equal
 * the leaf's issuer CN=Test Root CA). */
static void test_name_mismatch_fails(void) {
  castore    s;
  wired_span certs[2] = {PV_SPAN(castore_leaf_der), PV_SPAN(castore_leaf_der)};
  store_with_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 0);
}

/* A tampered leaf signature fails even with a matching name and anchor. */
static void test_tampered_signature_fails(void) {
  castore s;
  u8      leaf[sizeof(castore_leaf_der)];
  for (usz i = 0; i < sizeof(leaf); i++) leaf[i] = castore_leaf_der[i];
  leaf[sizeof(leaf) - 1] ^= 0xff; /* last signature octet */
  wired_span certs[2] = {PV_SPAN(leaf), PV_SPAN(castore_root_der)};
  store_with_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 0);
}

/* RFC 5280 6.1.4: a non-CA cert used as an issuer must break the chain, even
 * when names chain and every signature verifies. mid is basicConstraints
 * CA:FALSE, so [leaf2, mid, root2] is rejected only because mid is not a CA. */
static void test_non_ca_intermediate_fails(void) {
  castore    s;
  wired_span certs[3] = {
      PV_SPAN(castore_leaf2_der), PV_SPAN(castore_mid_der),
      PV_SPAN(castore_root2_der)};
  castore_init(&s, pv_roots, 4);
  CHECK(castore_add(&s, PV_SPAN(castore_root2_der)) == 1);
  CHECK(castore_validate_chain(&s, certs, 3) == 0);
}

static void store_with_root3(castore* s) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, PV_SPAN(castore_root3_der)) == 1);
}

/* RFC 5280 4.2.1.9: the leaf is not an intermediate certificate, so a
 * pathlen:0 CA may issue it directly. [leafm, mid3, root3] validates. */
static void test_pathlen_zero_direct_leaf_ok(void) {
  castore    s;
  wired_span certs[3] = {
      PV_SPAN(castore_leafm_der), PV_SPAN(castore_mid3_der),
      PV_SPAN(castore_root3_der)};
  store_with_root3(&s);
  CHECK(castore_validate_chain(&s, certs, 3) == 1);
}

/* RFC 5280 6.1.4 (m): mid3 asserts pathlen:0, so a further CA below it (sub3)
 * must break the path. Every name, CA flag, and signature in
 * [leaf3, sub3, mid3, root3] is valid; only the length constraint rejects. */
static void test_pathlen_zero_sub_ca_fails(void) {
  castore    s;
  wired_span certs[4] = {
      PV_SPAN(castore_leaf3_der), PV_SPAN(castore_sub3_der),
      PV_SPAN(castore_mid3_der), PV_SPAN(castore_root3_der)};
  store_with_root3(&s);
  CHECK(castore_validate_chain(&s, certs, 4) == 0);
}

/* RFC 5280 6.1: the same certificate must not appear more than once in the
 * path. [root, root] would otherwise validate: root is self-signed (its
 * issuer equals its subject) and is a registered anchor, so without a
 * duplicate check the repeated root would both link to itself and anchor. */
static void test_duplicate_cert_fails(void) {
  castore    s;
  wired_span certs[2] = {PV_SPAN(castore_root_der), PV_SPAN(castore_root_der)};
  store_with_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 0);
}

/* The duplicate appears at the tail of a longer, otherwise-valid path. */
static void test_duplicate_cert_at_tail_fails(void) {
  castore    s;
  wired_span certs[3] = {
      PV_SPAN(castore_leaf_der), PV_SPAN(castore_root_der),
      PV_SPAN(castore_root_der)};
  store_with_root(&s);
  CHECK(castore_validate_chain(&s, certs, 3) == 0);
}

static void store_with_ku_root(castore* s) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, PV_SPAN(castore_ku_root_der)) == 1);
}

/* RFC 8410 5: an end-entity id-Ed25519 cert whose keyUsage asserts only
 * keyAgreement (neither digitalSignature nor nonRepudiation) must be
 * rejected as a leaf. */
static void test_ed_leaf_keyusage_rejects(void) {
  castore    s;
  wired_span certs[2] = {
      PV_SPAN(castore_ku_ed_leaf_reject_der), PV_SPAN(castore_ku_root_der)};
  store_with_ku_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 0);
}

/* The same shape with digitalSignature set (and extKeyUsage serverAuth)
 * validates: the ECDSA root can verify the Ed25519 leaf's ecdsa-with-SHA256
 * outer signature regardless of the leaf's own SPKI algorithm. */
static void test_ed_leaf_keyusage_accepts(void) {
  castore    s;
  wired_span certs[2] = {
      PV_SPAN(castore_ku_ed_leaf_ok_der), PV_SPAN(castore_ku_root_der)};
  store_with_ku_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 1);
}

/* RFC 8410 5: an id-X25519 cert whose keyUsage is present without
 * keyAgreement must be rejected. */
static void test_x25519_leaf_keyusage_rejects(void) {
  castore    s;
  wired_span certs[2] = {
      PV_SPAN(castore_ku_x25519_leaf_reject_der), PV_SPAN(castore_ku_root_der)};
  store_with_ku_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 0);
}

/* An id-X25519 leaf with keyAgreement set, and no extKeyUsage restriction,
 * validates. */
static void test_x25519_leaf_keyusage_accepts(void) {
  castore    s;
  wired_span certs[2] = {
      PV_SPAN(castore_ku_x25519_leaf_ok_der), PV_SPAN(castore_ku_root_der)};
  store_with_ku_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 1);
}

/* RFC 8410 5: an issuer whose SPKI is id-Ed25519 and whose keyUsage is
 * present but asserts none of the admissible CA bits (digitalSignature,
 * nonRepudiation, keyCertSign, cRLSign) must be rejected as an issuer. The
 * rejection fires in parent_may_issue before signature verification (this
 * SDK's chainverify has no Ed25519 signature support), so any well-formed
 * leaf span exercises the path. */
static void test_ed_ca_keyusage_rejects(void) {
  castore    s;
  wired_span certs[2] = {
      PV_SPAN(castore_ku_ed_leaf_ok_der),
      PV_SPAN(castore_ku_ed_mid_reject_der)};
  store_with_ku_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 0);
}

static void store_with_si_root(castore* s) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, PV_SPAN(castore_si_root_der)) == 1);
}

/* RFC 5280 6.1.4 (h)/(l): a self-issued intermediate does not consume
 * pathLenConstraint. mid asserts pathlen:0; mid2 is a self-issued reissue of
 * mid (same subject/issuer DN "CN=Test Mid CA", a key-rollover certificate)
 * sitting strictly between leaf and mid. [leaf, mid2, mid, root] must
 * validate: the only non-self-issued intermediate below mid is none (mid2 is
 * excluded), so mid's pathlen:0 is satisfied. */
static void test_self_issued_excluded_from_pathlen(void) {
  castore    s;
  wired_span certs[4] = {
      PV_SPAN(castore_si_leaf_der), PV_SPAN(castore_si_mid2_der),
      PV_SPAN(castore_si_mid_der), PV_SPAN(castore_si_root_der)};
  store_with_si_root(&s);
  CHECK(castore_validate_chain(&s, certs, 4) == 1);
}

static void store_with_nc_root(castore* s) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, PV_SPAN(castore_nc_root_der)) == 1);
}

/* RFC 5280 4.2.1.10/6.1.4 (g): root's critical nameConstraints permits only
 * directoryName O=Good Org; a leaf whose subject falls within that subtree
 * validates. */
static void test_name_constraints_permitted_subject_ok(void) {
  castore    s;
  wired_span certs[2] = {
      PV_SPAN(castore_nc_leaf_ok_der), PV_SPAN(castore_nc_root_der)};
  store_with_nc_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 1);
}

/* Same root, a leaf whose subject (O=Bad Org) falls outside every permitted
 * subtree must be rejected (RFC 5280 6.1.4 (g)(1)), even though its
 * signature, EKU, and every other check pass -- OpenSSL's own `verify`
 * rejects this exact pair with "permitted subtree violation". */
static void test_name_constraints_excluded_subject_rejects(void) {
  castore    s;
  wired_span certs[2] = {
      PV_SPAN(castore_nc_leaf_bad_der), PV_SPAN(castore_nc_root_der)};
  store_with_nc_root(&s);
  CHECK(castore_validate_chain(&s, certs, 2) == 0);
}

static void store_with_pc_root(castore* s) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, PV_SPAN(castore_pc_root_der)) == 1);
}

/* RFC 5280 6.1.4 (i)/6.1.5 (g): mid2 asserts requireExplicitPolicy:0 and its
 * own certificatePolicies=policy_x; leaf3 asserts the same policy_x, so the
 * valid_policy_tree approximation's intersection stays non-empty and the
 * wrap-up condition (explicit_policy==0 requires a non-empty tree) is
 * satisfied. */
static void test_require_explicit_policy_matching_policy_ok(void) {
  castore    s;
  wired_span certs[3] = {
      PV_SPAN(castore_pc_leaf3_der), PV_SPAN(castore_pc_mid2_der),
      PV_SPAN(castore_pc_root_der)};
  store_with_pc_root(&s);
  CHECK(castore_validate_chain(&s, certs, 3) == 1);
}

/* Same mid2 (requireExplicitPolicy:0, policy_x), but leaf4 asserts a
 * disjoint policy_y: the tree intersects to empty, so the wrap-up condition
 * fails and the path must be rejected. */
static void test_require_explicit_policy_disjoint_policy_rejects(void) {
  castore    s;
  wired_span certs[3] = {
      PV_SPAN(castore_pc_leaf4_der), PV_SPAN(castore_pc_mid2_der),
      PV_SPAN(castore_pc_root_der)};
  store_with_pc_root(&s);
  CHECK(castore_validate_chain(&s, certs, 3) == 0);
}

void test_pathvalidate(void) {
  test_valid_chain();
  test_lone_root_chain();
  test_unregistered_root_fails();
  test_name_mismatch_fails();
  test_tampered_signature_fails();
  test_non_ca_intermediate_fails();
  test_pathlen_zero_direct_leaf_ok();
  test_pathlen_zero_sub_ca_fails();
  test_duplicate_cert_fails();
  test_duplicate_cert_at_tail_fails();
  test_ed_leaf_keyusage_rejects();
  test_ed_leaf_keyusage_accepts();
  test_x25519_leaf_keyusage_rejects();
  test_x25519_leaf_keyusage_accepts();
  test_ed_ca_keyusage_rejects();
  test_self_issued_excluded_from_pathlen();
  test_name_constraints_permitted_subject_ok();
  test_name_constraints_excluded_subject_rejects();
  test_require_explicit_policy_matching_policy_ok();
  test_require_explicit_policy_disjoint_policy_rejects();
}
