#include "crypto/bssl_aead_run.h"
#include "vectors/boringssl/aes_256_gcm_tests.h"

/* Source: tests/vectors/boringssl/aes_256_gcm_tests.txt (BoringSSL
 * dd73e69, crypto/cipher/test/aes_256_gcm_tests.txt). Failures print
 * file:line_first-line_last of the case. */

static usz bssl_aes256gcm_seal(
    const u8* key, const u8* nonce, wired_span ad, wired_span pt, u8* out) {
  aes256 a;
  aes256_init(&a, key);
  gcm256_ctx g = {&a, nonce, ad};
  return gcm256_seal(&g, pt, out);
}

static int bssl_aes256gcm_open(
    const u8* key, const u8* nonce, wired_span ad, wired_span ct, u8* pt) {
  aes256 a;
  aes256_init(&a, key);
  gcm256_ctx g = {&a, nonce, ad};
  return gcm256_open(&g, ct, pt);
}

static void test_bssl_aes256gcm(void) {
  bssl_run r = {
      "aes_256_gcm_tests.txt",
      bssl_aes_256_gcm_tests_attrs,
      bssl_aes256gcm_seal,
      bssl_aes256gcm_open,
      32,
      0,
      0,
      0};
  bssl_loop(
      &r, bssl_aes_256_gcm_tests_cases,
      sizeof bssl_aes_256_gcm_tests_cases /
          sizeof bssl_aes_256_gcm_tests_cases[0]);
}
