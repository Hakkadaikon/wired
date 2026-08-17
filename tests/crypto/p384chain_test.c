#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "p384chain_golden.h"
#include "test.h"

static castore_entry pc_roots[2];

/* The intermediate's SPKI names prime256v1; the root's names secp384r1. */
static void test_p384_named_curve(void) {
  x509       c;
  wired_span oid;
  CHECK(
      x509_parse(
          wired_span_of(p384chain_root_der, sizeof(p384chain_root_der)), &c) ==
      1);
  CHECK(x509_ec_curve(c.tbs, &oid) == 1);
  CHECK(x509_is_p384(oid) == 1);
  CHECK(x509_is_p256(oid) == 0);
  CHECK(
      x509_parse(
          wired_span_of(p384chain_int_der, sizeof(p384chain_int_der)), &c) ==
      1);
  CHECK(x509_ec_curve(c.tbs, &oid) == 1);
  CHECK(x509_is_p256(oid) == 1);
}

/* The P-384 root's SPKI yields a 98-byte uncompressed point. */
static void test_p384_ec_pubkey384(void) {
  x509       c;
  wired_span alg, key;
  u8         x[48], y[48];
  CHECK(
      x509_parse(
          wired_span_of(p384chain_root_der, sizeof(p384chain_root_der)), &c) ==
      1);
  CHECK(x509_public_key(c.tbs, &alg, &key) == 1);
  CHECK(key.n == 98);
  CHECK(x509_ec_pubkey384(key, x, y) == 1);
  /* the 66-byte P-256 accessor must reject a P-384 key */
  {
    u8 x32[32], y32[32];
    CHECK(x509_ec_pubkey(key, x32, y32) == 0);
  }
}

/* RFC 5280 6.1: the mixed real-web chain [leaf, int] anchors to the P-384
 * root in the store (ecdsa-with-SHA384 issuer link included). */
static void test_p384_mixed_chain(void) {
  castore    s;
  wired_span certs[2] = {
      wired_span_of(p384chain_leaf_der, sizeof(p384chain_leaf_der)),
      wired_span_of(p384chain_int_der, sizeof(p384chain_int_der))};
  castore_init(&s, pc_roots, 2);
  CHECK(
      castore_add(
          &s, wired_span_of(p384chain_root_der, sizeof(p384chain_root_der))) ==
      1);
  CHECK(castore_validate_chain(&s, certs, 2) == 1);
}

/* An all-P-384 leaf signed directly by the P-384 root validates. */
static void test_p384_full_chain(void) {
  castore    s;
  wired_span certs[1] = {
      wired_span_of(p384chain_leaf384_der, sizeof(p384chain_leaf384_der))};
  castore_init(&s, pc_roots, 2);
  CHECK(
      castore_add(
          &s, wired_span_of(p384chain_root_der, sizeof(p384chain_root_der))) ==
      1);
  CHECK(castore_validate_chain(&s, certs, 1) == 1);
}

/* A tampered P-384 root signature over the intermediate breaks the chain. */
static void test_p384_tampered(void) {
  castore    s;
  u8         leaf384[sizeof(p384chain_leaf384_der)];
  wired_span certs[1] = {wired_span_of(leaf384, sizeof(leaf384))};
  for (usz i = 0; i < sizeof(leaf384); i++)
    leaf384[i] = p384chain_leaf384_der[i];
  leaf384[sizeof(leaf384) - 1] ^= 0x01;
  castore_init(&s, pc_roots, 2);
  CHECK(
      castore_add(
          &s, wired_span_of(p384chain_root_der, sizeof(p384chain_root_der))) ==
      1);
  CHECK(castore_validate_chain(&s, certs, 1) == 0);
}

void test_p384chain(void) {
  test_p384_named_curve();
  test_p384_ec_pubkey384();
  test_p384_mixed_chain();
  test_p384_full_chain();
  test_p384_tampered();
}
