#include "crypto/pki/encoding/x509/ec_pubkey.h"
#include "crypto/pki/encoding/x509/spki.h"
#include "crypto/pki/encoding/x509/x509.h"
#include "crypto/pki/trust/castore/castore.h"
#include "crypto/pki/trust/castore/pathvalidate.h"
#include "p521chain_golden.h"
#include "test.h"

static castore_entry p5c_roots[1];

#define P5C_SPAN(a) wired_span_of(a, sizeof(a))

/* The root's SPKI names secp521r1 (RFC 5480 2.1.1.1) and yields a 134-byte
 * uncompressed point that only the P-521 accessor takes. */
static void test_p521_root_spki(void) {
  x509       c;
  wired_span oid, alg, key;
  u8         x[66], y[66], x48[48], y48[48];
  CHECK(x509_parse(P5C_SPAN(p521chain_root_der), &c) == 1);
  CHECK(x509_ec_curve(c.tbs, &oid) == 1);
  CHECK(x509_is_p521(oid) == 1);
  CHECK(x509_is_p384(oid) == 0);
  CHECK(x509_public_key(c.tbs, &alg, &key) == 1);
  CHECK(key.n == 134);
  CHECK(x509_ec_pubkey521(key, x, y) == 1);
  CHECK(x509_ec_pubkey384(key, x48, y48) == 0);
  key.n--;
  CHECK(x509_ec_pubkey521(key, x, y) == 0);
}

/* One leaf directly under the P-521 root; 1 if the chain validates. */
static int p5c_validate(const u8* leaf, usz n) {
  castore    s;
  wired_span certs[1] = {wired_span_of(leaf, n)};
  castore_init(&s, p5c_roots, 1);
  CHECK(castore_add(&s, P5C_SPAN(p521chain_root_der)) == 1);
  return castore_validate_chain(&s, certs, 1);
}

/* RFC 5280 6.1: leaves signed by the P-521 root with ecdsa-with-SHA512,
 * -SHA256 and -SHA384 (RFC 5758 3.2) all validate. */
static void test_p521_chains(void) {
  CHECK(p5c_validate(p521chain_leaf521_der, sizeof p521chain_leaf521_der));
  CHECK(p5c_validate(p521chain_leaf256_der, sizeof p521chain_leaf256_der));
  CHECK(p5c_validate(p521chain_leaf384_der, sizeof p521chain_leaf384_der));
}

/* A flipped bit in the root's signature over the leaf breaks the chain. */
static void test_p521_tampered(void) {
  u8 leaf[sizeof(p521chain_leaf521_der)];
  for (usz i = 0; i < sizeof leaf; i++) leaf[i] = p521chain_leaf521_der[i];
  leaf[sizeof leaf - 1] ^= 0x01;
  CHECK(p5c_validate(leaf, sizeof leaf) == 0);
}

void test_p521chain(void) {
  test_p521_root_spki();
  test_p521_chains();
  test_p521_tampered();
}
