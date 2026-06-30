#include "crypto/pki/trust/castore/chainverify.h"

#include "castore_golden.h"
#include "test.h"

/* RFC 5280 6.1.3. The leaf is signed by the root's key. */
static void test_leaf_signed_by_root(void) {
  CHECK(
      quic_castore_verify_signed_by(
          quic_castore_leaf_der, sizeof(quic_castore_leaf_der),
          quic_castore_root_der, sizeof(quic_castore_root_der)) == 1);
}

/* The self-signed root verifies under its own key. */
static void test_root_self_signature(void) {
  CHECK(
      quic_castore_verify_signed_by(
          quic_castore_root_der, sizeof(quic_castore_root_der),
          quic_castore_root_der, sizeof(quic_castore_root_der)) == 1);
}

/* Wrong issuer key (the leaf is not signed by the leaf's own key). */
static void test_leaf_not_signed_by_leaf(void) {
  CHECK(
      quic_castore_verify_signed_by(
          quic_castore_leaf_der, sizeof(quic_castore_leaf_der),
          quic_castore_leaf_der, sizeof(quic_castore_leaf_der)) == 0);
}

/* Tampering a tbs byte breaks the signature. */
static void test_tampered_tbs_fails(void) {
  u8 leaf[sizeof(quic_castore_leaf_der)];
  for (usz i = 0; i < sizeof(leaf); i++) leaf[i] = quic_castore_leaf_der[i];
  leaf[40] ^= 0xff; /* inside the tbsCertificate */
  CHECK(
      quic_castore_verify_signed_by(
          leaf, sizeof(leaf), quic_castore_root_der,
          sizeof(quic_castore_root_der)) == 0);
}

void test_chainverify(void) {
  test_leaf_signed_by_root();
  test_root_self_signature();
  test_leaf_not_signed_by_leaf();
  test_tampered_tbs_fails();
}
