#include "crypto/pki/encoding/x509/validity.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "rsachain_golden.h"
#include "test.h"

static quic_castore_entry rct_roots[2];

/* Validate a one-cert wire chain [leaf] against a single-root store. */
static int rct_validate(
    const u8 *root, usz root_len, const u8 *leaf, usz leaf_len) {
  quic_castore s;
  quic_span    certs[1] = {quic_span_of(leaf, leaf_len)};
  quic_castore_init(&s, rct_roots, 2);
  CHECK(quic_castore_add(&s, quic_span_of(root, root_len)) == 1);
  return quic_castore_validate_chain(&s, certs, 1);
}

/* sha256WithRSAEncryption under an RSA-2048 root verifies; a tampered
 * signature does not. */
static void test_rsachain_sha256(void) {
  u8 bad[sizeof(quic_rsachain_rleaf256_der)];
  CHECK(
      rct_validate(
          quic_rsachain_rroot_der, sizeof(quic_rsachain_rroot_der),
          quic_rsachain_rleaf256_der, sizeof(quic_rsachain_rleaf256_der)) == 1);
  for (usz i = 0; i < sizeof(bad); i++) bad[i] = quic_rsachain_rleaf256_der[i];
  bad[sizeof(bad) - 1] ^= 0x01;
  CHECK(
      rct_validate(
          quic_rsachain_rroot_der, sizeof(quic_rsachain_rroot_der), bad,
          sizeof(bad)) == 0);
}

/* sha384WithRSAEncryption verifies (the SHA-384 digest path). */
static void test_rsachain_sha384(void) {
  CHECK(
      rct_validate(
          quic_rsachain_rroot_der, sizeof(quic_rsachain_rroot_der),
          quic_rsachain_rleaf384_der, sizeof(quic_rsachain_rleaf384_der)) == 1);
}

/* An RSA-4096 root verifies (the widened bignum). */
static void test_rsachain_4096(void) {
  CHECK(
      rct_validate(
          quic_rsachain_r4root_der, sizeof(quic_rsachain_r4root_der),
          quic_rsachain_r4leaf_der, sizeof(quic_rsachain_r4leaf_der)) == 1);
}

/* ecdsa-with-SHA384 over a P-256 issuer verifies (FIPS 186-4 leftmost-32
 * truncation). */
static void test_ecchain_sha384(void) {
  CHECK(
      rct_validate(
          quic_rsachain_ecroot_der, sizeof(quic_rsachain_ecroot_der),
          quic_rsachain_ecleaf384_der,
          sizeof(quic_rsachain_ecleaf384_der)) == 1);
}

/* sha224WithRSAEncryption carries a VALID signature but sits outside the
 * allowlist: the chain must reject on the OID alone. */
static void test_rsachain_sha224_rejected(void) {
  CHECK(
      rct_validate(
          quic_rsachain_rroot_der, sizeof(quic_rsachain_rroot_der),
          quic_rsachain_rleaf224_der, sizeof(quic_rsachain_rleaf224_der)) == 0);
}

/* GeneralizedTime bounds (notAfter 2060-09-21) admit 2055 and reject 2061. */
static void test_gentime_validity(void) {
  quic_x509 c;
  CHECK(
      quic_x509_parse(
          quic_span_of(
              quic_rsachain_gentime_der, sizeof(quic_rsachain_gentime_der)),
          &c) == 1);
  CHECK(quic_x509_validity_ok(c.tbs, 20550101000000ULL) == 1);
  CHECK(quic_x509_validity_ok(c.tbs, 20610101000000ULL) == 0);
}

void test_rsachain(void) {
  test_rsachain_sha256();
  test_rsachain_sha384();
  test_rsachain_4096();
  test_ecchain_sha384();
  test_rsachain_sha224_rejected();
  test_gentime_validity();
}
