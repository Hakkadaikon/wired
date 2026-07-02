#include "crypto/pki/trust/castore/chainverify.h"

#include "castore_golden.h"
#include "test.h"

static quic_span chv_leaf_span(void) {
  return quic_span_of(quic_castore_leaf_der, sizeof(quic_castore_leaf_der));
}

static quic_span chv_root_span(void) {
  return quic_span_of(quic_castore_root_der, sizeof(quic_castore_root_der));
}

/* RFC 5280 6.1.3. The leaf is signed by the root's key. */
static void test_leaf_signed_by_root(void) {
  CHECK(quic_castore_verify_signed_by(chv_leaf_span(), chv_root_span()) == 1);
}

/* The self-signed root verifies under its own key. */
static void test_root_self_signature(void) {
  CHECK(quic_castore_verify_signed_by(chv_root_span(), chv_root_span()) == 1);
}

/* Wrong issuer key (the leaf is not signed by the leaf's own key). */
static void test_leaf_not_signed_by_leaf(void) {
  CHECK(quic_castore_verify_signed_by(chv_leaf_span(), chv_leaf_span()) == 0);
}

/* Tampering a tbs byte breaks the signature. */
static void test_tampered_tbs_fails(void) {
  u8 leaf[sizeof(quic_castore_leaf_der)];
  for (usz i = 0; i < sizeof(leaf); i++) leaf[i] = quic_castore_leaf_der[i];
  leaf[40] ^= 0xff; /* inside the tbsCertificate */
  CHECK(
      quic_castore_verify_signed_by(
          quic_span_of(leaf, sizeof(leaf)), chv_root_span()) == 0);
}

/* RFC 5280 4.1.1.2: the inner tbsCertificate.signatureAlgorithm must equal the
 * outer signatureAlgorithm. Flip one byte of the OUTER sigAlg OID only (index
 * 331, the 0x2a of the final 30 0a 06 08 2a 86 48 ce 3d 04 03 02 block). That
 * byte is outside the tbsCertificate, so the signature still verifies -- only
 * the inner/outer mismatch can cause rejection. */
static void test_sigalg_mismatch_fails(void) {
  u8 leaf[sizeof(quic_castore_leaf_der)];
  for (usz i = 0; i < sizeof(leaf); i++) leaf[i] = quic_castore_leaf_der[i];
  leaf[331] ^= 0x01; /* outer sigAlg OID value byte */
  CHECK(
      quic_castore_verify_signed_by(
          quic_span_of(leaf, sizeof(leaf)), chv_root_span()) == 0);
}

void test_chainverify(void) {
  test_leaf_signed_by_root();
  test_root_self_signature();
  test_leaf_not_signed_by_leaf();
  test_tampered_tbs_fails();
  test_sigalg_mismatch_fails();
}
