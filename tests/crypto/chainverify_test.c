#include "crypto/pki/trust/castore/chainverify.h"

#include "castore_golden.h"
#include "chv_sha512_golden.h"
#include "test.h"

static wired_span chv_leaf_span(void) {
  return wired_span_of(castore_leaf_der, sizeof(castore_leaf_der));
}

static wired_span chv_root_span(void) {
  return wired_span_of(castore_root_der, sizeof(castore_root_der));
}

/* RFC 5280 6.1.3. The leaf is signed by the root's key. */
static void test_leaf_signed_by_root(void) {
  CHECK(castore_verify_signed_by(chv_leaf_span(), chv_root_span()) == 1);
}

/* The self-signed root verifies under its own key. */
static void test_root_self_signature(void) {
  CHECK(castore_verify_signed_by(chv_root_span(), chv_root_span()) == 1);
}

/* Wrong issuer key (the leaf is not signed by the leaf's own key). */
static void test_leaf_not_signed_by_leaf(void) {
  CHECK(castore_verify_signed_by(chv_leaf_span(), chv_leaf_span()) == 0);
}

/* Tampering a tbs byte breaks the signature. */
static void test_tampered_tbs_fails(void) {
  u8 leaf[sizeof(castore_leaf_der)];
  for (usz i = 0; i < sizeof(leaf); i++) leaf[i] = castore_leaf_der[i];
  leaf[40] ^= 0xff; /* inside the tbsCertificate */
  CHECK(
      castore_verify_signed_by(
          wired_span_of(leaf, sizeof(leaf)), chv_root_span()) == 0);
}

/* RFC 5280 4.1.1.2: the inner tbsCertificate.signatureAlgorithm must equal the
 * outer signatureAlgorithm. Flip one byte of the OUTER sigAlg OID only (index
 * 331, the 0x2a of the final 30 0a 06 08 2a 86 48 ce 3d 04 03 02 block). That
 * byte is outside the tbsCertificate, so the signature still verifies -- only
 * the inner/outer mismatch can cause rejection. */
static void test_sigalg_mismatch_fails(void) {
  u8 leaf[sizeof(castore_leaf_der)];
  for (usz i = 0; i < sizeof(leaf); i++) leaf[i] = castore_leaf_der[i];
  leaf[331] ^= 0x01; /* outer sigAlg OID value byte */
  CHECK(
      castore_verify_signed_by(
          wired_span_of(leaf, sizeof(leaf)), chv_root_span()) == 0);
}

/* RFC 5758 3.2 ecdsa-with-SHA512 (OpenSSL-signed): the 64-byte digest is cut
 * to the group order's leftmost bytes (FIPS 186-4 6.4) on P-384 and P-256. */
static void test_ecdsa_sha512_self_signed(void) {
  wired_span c384 =
      wired_span_of(chv_p384_sha512_der, sizeof(chv_p384_sha512_der));
  wired_span c256 =
      wired_span_of(chv_p256_sha512_der, sizeof(chv_p256_sha512_der));
  CHECK(castore_verify_signed_by(c384, c384) == 1);
  CHECK(castore_verify_signed_by(c256, c256) == 1);
}

void test_chainverify(void) {
  test_ecdsa_sha512_self_signed();
  test_leaf_signed_by_root();
  test_root_self_signature();
  test_leaf_not_signed_by_leaf();
  test_tampered_tbs_fails();
  test_sigalg_mismatch_fails();
}
