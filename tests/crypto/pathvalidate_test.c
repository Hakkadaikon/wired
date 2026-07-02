#include "crypto/pki/trust/castore/pathvalidate.h"

#include "castore_golden.h"
#include "crypto/pki/trust/castore/castore.h"
#include "test.h"

#define PV_SPAN(der) quic_span_of(der, sizeof(der))

static quic_castore_entry pv_roots[4];

static void store_with_root(quic_castore *s) {
  quic_castore_init(s, pv_roots, 4);
  CHECK(quic_castore_add(s, PV_SPAN(quic_castore_root_der)) == 1);
}

/* RFC 5280 6.1. A correct [leaf, root] path to a registered anchor validates.
 */
static void test_valid_chain(void) {
  quic_castore s;
  quic_span    certs[2] = {
      PV_SPAN(quic_castore_leaf_der), PV_SPAN(quic_castore_root_der)};
  store_with_root(&s);
  CHECK(quic_castore_validate_chain(&s, certs, 2) == 1);
}

/* A single self-signed root that is itself the anchor validates. */
static void test_lone_root_chain(void) {
  quic_castore s;
  quic_span    certs[1] = {PV_SPAN(quic_castore_root_der)};
  store_with_root(&s);
  CHECK(quic_castore_validate_chain(&s, certs, 1) == 1);
}

/* Root not registered: no anchor, so the path fails. */
static void test_unregistered_root_fails(void) {
  quic_castore s;
  quic_span    certs[2] = {
      PV_SPAN(quic_castore_leaf_der), PV_SPAN(quic_castore_root_der)};
  quic_castore_init(&s, pv_roots, 4);
  CHECK(quic_castore_validate_chain(&s, certs, 2) == 0);
}

/* Issuer/subject mismatch between adjacent certs breaks the link. The leaf is
 * paired with itself as a bogus parent (subject CN=leaf.example does not equal
 * the leaf's issuer CN=Test Root CA). */
static void test_name_mismatch_fails(void) {
  quic_castore s;
  quic_span    certs[2] = {
      PV_SPAN(quic_castore_leaf_der), PV_SPAN(quic_castore_leaf_der)};
  store_with_root(&s);
  CHECK(quic_castore_validate_chain(&s, certs, 2) == 0);
}

/* A tampered leaf signature fails even with a matching name and anchor. */
static void test_tampered_signature_fails(void) {
  quic_castore s;
  u8           leaf[sizeof(quic_castore_leaf_der)];
  for (usz i = 0; i < sizeof(leaf); i++) leaf[i] = quic_castore_leaf_der[i];
  leaf[sizeof(leaf) - 1] ^= 0xff; /* last signature octet */
  quic_span certs[2] = {PV_SPAN(leaf), PV_SPAN(quic_castore_root_der)};
  store_with_root(&s);
  CHECK(quic_castore_validate_chain(&s, certs, 2) == 0);
}

/* RFC 5280 6.1.4: a non-CA cert used as an issuer must break the chain, even
 * when names chain and every signature verifies. mid is basicConstraints
 * CA:FALSE, so [leaf2, mid, root2] is rejected only because mid is not a CA. */
static void test_non_ca_intermediate_fails(void) {
  quic_castore s;
  quic_span    certs[3] = {
      PV_SPAN(quic_castore_leaf2_der), PV_SPAN(quic_castore_mid_der),
      PV_SPAN(quic_castore_root2_der)};
  quic_castore_init(&s, pv_roots, 4);
  CHECK(quic_castore_add(&s, PV_SPAN(quic_castore_root2_der)) == 1);
  CHECK(quic_castore_validate_chain(&s, certs, 3) == 0);
}

static void store_with_root3(quic_castore *s) {
  quic_castore_init(s, pv_roots, 4);
  CHECK(quic_castore_add(s, PV_SPAN(quic_castore_root3_der)) == 1);
}

/* RFC 5280 4.2.1.9: the leaf is not an intermediate certificate, so a
 * pathlen:0 CA may issue it directly. [leafm, mid3, root3] validates. */
static void test_pathlen_zero_direct_leaf_ok(void) {
  quic_castore s;
  quic_span    certs[3] = {
      PV_SPAN(quic_castore_leafm_der), PV_SPAN(quic_castore_mid3_der),
      PV_SPAN(quic_castore_root3_der)};
  store_with_root3(&s);
  CHECK(quic_castore_validate_chain(&s, certs, 3) == 1);
}

/* RFC 5280 6.1.4 (m): mid3 asserts pathlen:0, so a further CA below it (sub3)
 * must break the path. Every name, CA flag, and signature in
 * [leaf3, sub3, mid3, root3] is valid; only the length constraint rejects. */
static void test_pathlen_zero_sub_ca_fails(void) {
  quic_castore s;
  quic_span    certs[4] = {
      PV_SPAN(quic_castore_leaf3_der), PV_SPAN(quic_castore_sub3_der),
      PV_SPAN(quic_castore_mid3_der), PV_SPAN(quic_castore_root3_der)};
  store_with_root3(&s);
  CHECK(quic_castore_validate_chain(&s, certs, 4) == 0);
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
}
