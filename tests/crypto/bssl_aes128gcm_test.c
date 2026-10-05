#include "crypto/bssl_aead_run.h"
#include "vectors/boringssl/aes_128_gcm_tests.h"

/* Source: tests/vectors/boringssl/aes_128_gcm_tests.txt (BoringSSL
 * dd73e69, crypto/cipher/test/aes_128_gcm_tests.txt). Failures print
 * file:line_first-line_last of the case. */

static usz bssl_aes128gcm_seal(
    const u8* key, const u8* nonce, wired_span ad, wired_span pt, u8* out) {
  aes128 a;
  aes128_init(&a, key);
  gcm_ctx g = {&a, nonce, ad};
  return gcm_seal(&g, pt, out);
}

static int bssl_aes128gcm_open(
    const u8* key, const u8* nonce, wired_span ad, wired_span ct, u8* pt) {
  aes128 a;
  aes128_init(&a, key);
  gcm_ctx g = {&a, nonce, ad};
  return gcm_open(&g, ct, pt);
}

static void test_bssl_aes128gcm(void) {
  bssl_run r = {
      "aes_128_gcm_tests.txt",
      bssl_aes_128_gcm_tests_attrs,
      bssl_aes128gcm_seal,
      bssl_aes128gcm_open,
      16,
      0,
      0,
      0};
  bssl_loop(
      &r, bssl_aes_128_gcm_tests_cases,
      sizeof bssl_aes_128_gcm_tests_cases /
          sizeof bssl_aes_128_gcm_tests_cases[0]);
}
