#include "crypto/pki/trust/castore/pathvalidate.h"

#include "castore_golden.h"
#include "crypto/pki/trust/castore/castore.h"
#include "test.h"

static void store_with_root(quic_castore *s) {
  quic_castore_init(s);
  CHECK(
      quic_castore_add(
          s, quic_castore_root_der, sizeof(quic_castore_root_der)) == 1);
}

/* RFC 5280 6.1. A correct [leaf, root] path to a registered anchor validates.
 */
static void test_valid_chain(void) {
  quic_castore s;
  const u8    *certs[2] = {quic_castore_leaf_der, quic_castore_root_der};
  usz lens[2] = {sizeof(quic_castore_leaf_der), sizeof(quic_castore_root_der)};
  store_with_root(&s);
  CHECK(quic_castore_validate_chain(&s, certs, lens, 2) == 1);
}

/* A single self-signed root that is itself the anchor validates. */
static void test_lone_root_chain(void) {
  quic_castore s;
  const u8    *certs[1] = {quic_castore_root_der};
  usz          lens[1]  = {sizeof(quic_castore_root_der)};
  store_with_root(&s);
  CHECK(quic_castore_validate_chain(&s, certs, lens, 1) == 1);
}

/* Root not registered: no anchor, so the path fails. */
static void test_unregistered_root_fails(void) {
  quic_castore s;
  const u8    *certs[2] = {quic_castore_leaf_der, quic_castore_root_der};
  usz lens[2] = {sizeof(quic_castore_leaf_der), sizeof(quic_castore_root_der)};
  quic_castore_init(&s);
  CHECK(quic_castore_validate_chain(&s, certs, lens, 2) == 0);
}

/* Issuer/subject mismatch between adjacent certs breaks the link. The leaf is
 * paired with itself as a bogus parent (subject CN=leaf.example does not equal
 * the leaf's issuer CN=Test Root CA). */
static void test_name_mismatch_fails(void) {
  quic_castore s;
  const u8    *certs[2] = {quic_castore_leaf_der, quic_castore_leaf_der};
  usz lens[2] = {sizeof(quic_castore_leaf_der), sizeof(quic_castore_leaf_der)};
  store_with_root(&s);
  CHECK(quic_castore_validate_chain(&s, certs, lens, 2) == 0);
}

/* A tampered leaf signature fails even with a matching name and anchor. */
static void test_tampered_signature_fails(void) {
  quic_castore s;
  u8           leaf[sizeof(quic_castore_leaf_der)];
  const u8    *certs[2];
  usz          lens[2];
  for (usz i = 0; i < sizeof(leaf); i++) leaf[i] = quic_castore_leaf_der[i];
  leaf[sizeof(leaf) - 1] ^= 0xff; /* last signature octet */
  certs[0] = leaf;
  lens[0]  = sizeof(leaf);
  certs[1] = quic_castore_root_der;
  lens[1]  = sizeof(quic_castore_root_der);
  store_with_root(&s);
  CHECK(quic_castore_validate_chain(&s, certs, lens, 2) == 0);
}

/* RFC 5280 6.1.4: a non-CA cert used as an issuer must break the chain, even
 * when names chain and every signature verifies. mid is basicConstraints
 * CA:FALSE, so [leaf2, mid, root2] is rejected only because mid is not a CA. */
static void test_non_ca_intermediate_fails(void) {
  quic_castore s;
  const u8    *certs[3] = {
      quic_castore_leaf2_der, quic_castore_mid_der, quic_castore_root2_der};
  usz lens[3] = {
      sizeof(quic_castore_leaf2_der), sizeof(quic_castore_mid_der),
      sizeof(quic_castore_root2_der)};
  quic_castore_init(&s);
  CHECK(
      quic_castore_add(
          &s, quic_castore_root2_der, sizeof(quic_castore_root2_der)) == 1);
  CHECK(quic_castore_validate_chain(&s, certs, lens, 3) == 0);
}

void test_pathvalidate(void) {
  test_valid_chain();
  test_lone_root_chain();
  test_unregistered_root_fails();
  test_name_mismatch_fails();
  test_tampered_signature_fails();
  test_non_ca_intermediate_fails();
}
