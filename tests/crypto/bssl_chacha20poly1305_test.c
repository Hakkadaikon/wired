#include "crypto/bssl_aead_run.h"
#include "vectors/boringssl/chacha20_poly1305_tests.h"

/* Source: tests/vectors/boringssl/chacha20_poly1305_tests.txt (BoringSSL
 * dd73e69, crypto/cipher/test/chacha20_poly1305_tests.txt). Failures print
 * file:line_first-line_last of the case. */

static usz bssl_chacha20poly1305_seal(
    const u8* key, const u8* nonce, wired_span ad, wired_span pt, u8* out) {
  chapoly_ctx c = {key, nonce, ad};
  return chapoly_seal(&c, pt, out);
}

static int bssl_chacha20poly1305_open(
    const u8* key, const u8* nonce, wired_span ad, wired_span ct, u8* pt) {
  chapoly_ctx c = {key, nonce, ad};
  return chapoly_open(&c, ct, pt);
}

static void test_bssl_chacha20poly1305(void) {
  bssl_run r = {
      "chacha20_poly1305_tests.txt",
      bssl_chacha20_poly1305_tests_attrs,
      bssl_chacha20poly1305_seal,
      bssl_chacha20poly1305_open,
      32,
      0,
      0,
      0};
  bssl_loop(
      &r, bssl_chacha20_poly1305_tests_cases,
      sizeof bssl_chacha20_poly1305_tests_cases /
          sizeof bssl_chacha20_poly1305_tests_cases[0]);
}
