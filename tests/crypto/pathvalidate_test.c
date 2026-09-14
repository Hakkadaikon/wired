#include "crypto/pki/trust/castore/pathvalidate.h"

#include "castore_golden.h"
#include "castore_ku_golden.h"
#include "castore_nc_golden.h"
#include "castore_ncsan_golden.h"
#include "castore_ncx_golden.h"
#include "castore_pc_golden.h"
#include "castore_selfissued_golden.h"
#include "crypto/asymmetric/ecc/ecdsasig/sig_value.h"
#include "crypto/asymmetric/ecc/p256/p256_field.h"
#include "crypto/asymmetric/ecc/p256/p256_point.h"
#include "crypto/asymmetric/ecc/p256sign/sign.h"
#include "crypto/pki/cert/p256cert/enc.h"
#include "crypto/pki/cert/p256cert/spki.h"
#include "crypto/pki/cert/p256cert/tbs.h"
#include "crypto/pki/encoding/asn1/der.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/symmetric/hash/hash/sha256.h"
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

static void store_with_ncsan_root(castore* s) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, PV_SPAN(castore_ncsan_root_der)) == 1);
}

/* RFC 5280 6.1.4 (g): intermediate A's dNSName nameConstraints binds every
 * certificate further down the path, across intermediate B which carries no
 * nameConstraints of its own. A leaf SAN outside A's permitted subtree
 * (evil.test vs example.com) must be rejected -- OpenSSL verify rejects this
 * exact chain with "permitted subtree violation". */
static void test_nc_dns_inherited_across_intermediate_rejects(void) {
  castore    s;
  wired_span certs[4] = {
      PV_SPAN(castore_ncsan_leaf_evil_der), PV_SPAN(castore_ncsan_b_der),
      PV_SPAN(castore_ncsan_a_der), PV_SPAN(castore_ncsan_root_der)};
  store_with_ncsan_root(&s);
  CHECK(castore_validate_chain(&s, certs, 4) == 0);
}

/* The same chain with a leaf SAN inside A's permitted subtree validates
 * (OpenSSL verify: OK). */
static void test_nc_dns_inherited_across_intermediate_ok(void) {
  castore    s;
  wired_span certs[4] = {
      PV_SPAN(castore_ncsan_leaf_ok_der), PV_SPAN(castore_ncsan_b_der),
      PV_SPAN(castore_ncsan_a_der), PV_SPAN(castore_ncsan_root_der)};
  store_with_ncsan_root(&s);
  CHECK(castore_validate_chain(&s, certs, 4) == 1);
}

/* RFC 5280 6.1.4 (g)(2): a leaf inside A's permitted subtree but inside its
 * excluded one (x.bad.example.com) is rejected across B as well -- the
 * excluded union and permitted intersection both accumulate down the chain
 * (OpenSSL verify: "excluded subtree violation"). */
static void test_nc_dns_excluded_inherited_rejects(void) {
  castore    s;
  wired_span certs[4] = {
      PV_SPAN(castore_ncsan_leaf_excl_der), PV_SPAN(castore_ncsan_b_der),
      PV_SPAN(castore_ncsan_a_der), PV_SPAN(castore_ncsan_root_der)};
  store_with_ncsan_root(&s);
  CHECK(castore_validate_chain(&s, certs, 4) == 0);
}

static void store_with_ncx_root(castore* s) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, PV_SPAN(castore_ncx_root_der)) == 1);
}

/* RFC 5280 6.1.4 (g): intermediate a carries only an excludedSubtrees
 * (bad.example.com), intermediate b only a permittedSubtrees
 * (example.com). The running excluded union still binds a leaf inside b's
 * permitted subtree (OpenSSL verify: "excluded subtree violation"). */
static void test_ncx_excluded_in_a_survives_permitted_in_b(void) {
  castore    s;
  wired_span certs[4] = {
      PV_SPAN(castore_ncx_leaf_excl_der), PV_SPAN(castore_ncx_b_der),
      PV_SPAN(castore_ncx_a_der), PV_SPAN(castore_ncx_root_der)};
  store_with_ncx_root(&s);
  CHECK(castore_validate_chain(&s, certs, 4) == 0);
}

/* b's permittedSubtrees is not lost because a (above it) had only an
 * excludedSubtrees: a leaf outside example.com is rejected (OpenSSL
 * verify: "permitted subtree violation"). */
static void test_ncx_permitted_in_b_after_excluded_only_a_rejects(void) {
  castore    s;
  wired_span certs[4] = {
      PV_SPAN(castore_ncx_leaf_evil_der), PV_SPAN(castore_ncx_b_der),
      PV_SPAN(castore_ncx_a_der), PV_SPAN(castore_ncx_root_der)};
  store_with_ncx_root(&s);
  CHECK(castore_validate_chain(&s, certs, 4) == 0);
}

/* A leaf inside b's permitted subtree and outside a's excluded one
 * validates (OpenSSL verify: OK). */
static void test_ncx_intersection_ok(void) {
  castore    s;
  wired_span certs[4] = {
      PV_SPAN(castore_ncx_leaf_ok_der), PV_SPAN(castore_ncx_b_der),
      PV_SPAN(castore_ncx_a_der), PV_SPAN(castore_ncx_root_der)};
  store_with_ncx_root(&s);
  CHECK(castore_validate_chain(&s, certs, 4) == 1);
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

/* ---- Runtime P-256 self-issued CA builder. Every certificate it emits has
 * subject == issuer == "CN=cap", basicConstraints CA:TRUE, and is signed by
 * the one pvc_priv key, so any sequence of them chains (RFC 5280 6.1.3 name
 * binding + 6.1.4 self-issued hops) and only the serial tells them apart --
 * the cheapest way to make an arbitrarily long path that is otherwise
 * valid. n_ext copies of the basicConstraints Extension are emitted (2 =
 * the RFC 5280 4.2 duplicate-extension violation). ---- */

static const u8 pvc_priv[32] = {0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
                                0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
                                0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21,
                                0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29};
/* Name { RDN { commonName = PrintableString "cap" } }. */
static const u8 pvc_name[] = {0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03,
                              0x55, 0x04, 0x03, 0x13, 0x03, 'c',  'a',  'p'};
/* Validity { UTCTime 200101000000Z, UTCTime 300101000000Z }. */
static const u8 pvc_validity[] = {0x30, 0x1e, 0x17, 0x0d, '2', '0', '0', '1',
                                  '0',  '1',  '0',  '0',  '0', '0', '0', '0',
                                  'Z',  0x17, 0x0d, '3',  '0', '0', '1', '0',
                                  '1',  '0',  '0',  '0',  '0', '0', '0', 'Z'};
/* Extension { basicConstraints, critical TRUE, OCTET { SEQ { cA TRUE } } }. */
static const u8 pvc_ext_ca[]  = {0x30, 0x0f, 0x06, 0x03, 0x55, 0x1d,
                                 0x13, 0x01, 0x01, 0xff, 0x04, 0x05,
                                 0x30, 0x03, 0x01, 0x01, 0xff};
static const u8 pvc_version[] = {0xa0, 0x03, 0x02, 0x01, 0x02};

/* [3] EXPLICIT { SEQUENCE OF n_ext copies of pvc_ext_ca }. */
static usz pvc_extensions(usz n_ext, wired_obuf* out) {
  u8           list[64], seq[80];
  wired_obuf   so = obuf_of(seq, sizeof(seq));
  p256cert_enc e  = {list, sizeof(list), 0, 1};
  for (usz i = 0; i < n_ext; i++)
    p256cert_put_pre(&e, wired_span_of(pvc_ext_ca, sizeof(pvc_ext_ca)));
  p256cert_enc w = p256cert_loaded(seq, p256cert_wrap(&e, DER_SEQUENCE, &so));
  return p256cert_wrap(&w, 0xa3, out);
}

/* RFC 5280 4.1. tbsCertificate for one self-issued CA cert. */
static usz pvc_tbs(u8 serial, usz n_ext, wired_obuf* out) {
  u8           x[32], y[32], alg[16], spki[128], exts[96], body[512];
  ec_point     q;
  wired_obuf   ao = obuf_of(alg, sizeof(alg));
  wired_obuf   so = obuf_of(spki, sizeof(spki));
  wired_obuf   xo = obuf_of(exts, sizeof(exts));
  p256cert_enc e  = {body, sizeof(body), 0, 1};
  ec_mul(&q, pvc_priv, &p256_g);
  p256_fp_to_be(x, q.x);
  p256_fp_to_be(y, q.y);
  CHECK(p256cert_spki(x, y, &so) == 1);
  p256cert_put_pre(&e, wired_span_of(pvc_version, sizeof(pvc_version)));
  p256cert_put(&e, DER_INTEGER, wired_span_of(&serial, 1));
  p256cert_put_pre(&e, wired_span_of(alg, p256cert_sigalg(&ao)));
  p256cert_put_pre(&e, wired_span_of(pvc_name, sizeof(pvc_name)));
  p256cert_put_pre(&e, wired_span_of(pvc_validity, sizeof(pvc_validity)));
  p256cert_put_pre(&e, wired_span_of(pvc_name, sizeof(pvc_name)));
  p256cert_put_pre(&e, wired_span_of(spki, so.len));
  p256cert_put_pre(&e, wired_span_of(exts, pvc_extensions(n_ext, &xo)));
  return p256cert_wrap(&e, DER_SEQUENCE, out);
}

/* Certificate { tbs, ecdsa-with-SHA256, BIT STRING sig } into out. */
static wired_span pvc_cert(u8 serial, usz n_ext, u8* out, usz cap) {
  u8           tbs[512], alg[16], sig[80], bits[81], sv[96], body[768];
  u8           hash[32], r[32], s[32];
  wired_obuf   to = obuf_of(tbs, sizeof(tbs));
  wired_obuf   ao = obuf_of(alg, sizeof(alg));
  wired_obuf   vo = obuf_of(sv, sizeof(sv));
  wired_obuf   oo = obuf_of(out, cap);
  usz          sn = 0;
  p256cert_enc e  = {body, sizeof(body), 0, 1};
  CHECK(pvc_tbs(serial, n_ext, &to) != 0);
  wired_sha256(tbs, to.len, hash);
  CHECK(p256sign_sign(pvc_priv, hash, r, s) == 1);
  CHECK(ecdsasig_encode(r, s, sig, sizeof(sig), &sn) == 1);
  bits[0] = 0x00;
  for (usz i = 0; i < sn; i++) bits[1 + i] = sig[i];
  p256cert_enc b = p256cert_loaded(bits, 1 + sn);
  p256cert_put_pre(&e, wired_span_of(tbs, to.len));
  p256cert_put_pre(&e, wired_span_of(alg, p256cert_sigalg(&ao)));
  p256cert_put_pre(
      &e, wired_span_of(sv, p256cert_wrap(&b, DER_BIT_STRING, &vo)));
  CHECK(p256cert_wrap(&e, DER_SEQUENCE, &oo) != 0);
  return wired_span_of(out, oo.len);
}

#define PVC_CERT_CAP 640
static u8 pvc_der[CASTORE_PATH_MAX_CERTS + 2][PVC_CERT_CAP];

/* Store anchored on the serial-0 CA; certs[i] = serial i+1, i < n. */
static void pvc_chain(castore* s, wired_span* certs, usz n) {
  castore_init(s, pv_roots, 4);
  CHECK(castore_add(s, pvc_cert(0, 1, pvc_der[0], PVC_CERT_CAP)) == 1);
  for (usz i = 0; i < n; i++)
    certs[i] = pvc_cert((u8)(i + 1), 1, pvc_der[i + 1], PVC_CERT_CAP);
}

/* A path of exactly CASTORE_PATH_MAX_CERTS self-issued CA certs is within
 * the bound and validates (boundary: the longest admitted path). */
static void test_chain_at_cap_ok(void) {
  castore    s;
  wired_span certs[CASTORE_PATH_MAX_CERTS + 1];
  pvc_chain(&s, certs, CASTORE_PATH_MAX_CERTS + 1);
  CHECK(castore_validate_chain(&s, certs, CASTORE_PATH_MAX_CERTS) == 1);
}

/* One certificate more than CASTORE_PATH_MAX_CERTS -- every link valid,
 * every cert a CA, the tail anchored -- must be rejected outright: the path
 * length is the multiplier of name-constraint/policy work
 * (CVE-2018-16875 / CVE-2024-34702 class), so it fails closed. */
static void test_chain_over_cap_rejects(void) {
  castore    s;
  wired_span certs[CASTORE_PATH_MAX_CERTS + 1];
  pvc_chain(&s, certs, CASTORE_PATH_MAX_CERTS + 1);
  CHECK(castore_validate_chain(&s, certs, CASTORE_PATH_MAX_CERTS + 1) == 0);
}

/* RFC 5280 4.2: "A certificate MUST NOT include more than one instance of a
 * particular extension." A cert carrying basicConstraints twice is rejected
 * even though each instance is individually valid (CVE-2024-12243 class). */
static void test_duplicate_extension_rejects(void) {
  castore    s;
  wired_span certs[1];
  pvc_chain(&s, certs, 0);
  certs[0] = pvc_cert(1, 2, pvc_der[1], PVC_CERT_CAP);
  CHECK(castore_validate_chain(&s, certs, 1) == 0);
  certs[0] = pvc_cert(1, 1, pvc_der[1], PVC_CERT_CAP);
  CHECK(castore_validate_chain(&s, certs, 1) == 1);
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
  test_nc_dns_inherited_across_intermediate_rejects();
  test_nc_dns_inherited_across_intermediate_ok();
  test_nc_dns_excluded_inherited_rejects();
  test_ncx_excluded_in_a_survives_permitted_in_b();
  test_ncx_permitted_in_b_after_excluded_only_a_rejects();
  test_ncx_intersection_ok();
  test_require_explicit_policy_matching_policy_ok();
  test_require_explicit_policy_disjoint_policy_rejects();
  test_chain_at_cap_ok();
  test_chain_over_cap_rejects();
  test_duplicate_extension_rejects();
}
