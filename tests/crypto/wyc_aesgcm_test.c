#include "crypto/wyc_run.h"
#include "vectors/wycheproof/aes_gcm_test.h"

/* Source: tests/vectors/wycheproof/aes_gcm_test.json (Wycheproof
 * C2SP/wycheproof 3fa63dd0, testvectors_v1/aes_gcm_test.json). AES-128 and
 * AES-256 are exercised; AES-192 is not implemented by wired (skip), nor is
 * a non-96-bit IV (invalid: rejected by construction, valid: skip). */

static usz wyc_aes128_seal(
    const u8* key, const u8* nonce, wired_span ad, wired_span pt, u8* out) {
  aes128 a;
  aes128_init(&a, key);
  gcm_ctx g = {&a, nonce, ad};
  return gcm_seal(&g, pt, out);
}

static int wyc_aes128_open(
    const u8* key, const u8* nonce, wired_span ad, wired_span ct, u8* pt) {
  aes128 a;
  aes128_init(&a, key);
  gcm_ctx g = {&a, nonce, ad};
  return gcm_open(&g, ct, pt);
}

static usz wyc_aes256_seal(
    const u8* key, const u8* nonce, wired_span ad, wired_span pt, u8* out) {
  aes256 a;
  aes256_init(&a, key);
  gcm256_ctx g = {&a, nonce, ad};
  return gcm256_seal(&g, pt, out);
}

static int wyc_aes256_open(
    const u8* key, const u8* nonce, wired_span ad, wired_span ct, u8* pt) {
  aes256 a;
  aes256_init(&a, key);
  gcm256_ctx g = {&a, nonce, ad};
  return gcm256_open(&g, ct, pt);
}

static int wyc_aesgcm_case(const bssl_attr* a, const wyc_case* c) {
  static const wyc_aead_ops ops128 = {wyc_aes128_seal, wyc_aes128_open, 128};
  static const wyc_aead_ops ops256 = {wyc_aes256_seal, wyc_aes256_open, 256};
  u32                       bits   = wyc_num(wyc_get(a, c, "g.keySize"));
  const wyc_aead_ops*       ops    = bits == 128 ? &ops128 : 0;
  ops                              = bits == 256 ? &ops256 : ops;
  return wyc_aead_case(ops, a, c);
}

#define WYC_AESGCM_N \
  (sizeof wyc_aes_gcm_test_cases / sizeof wyc_aes_gcm_test_cases[0])

void test_wyc_aesgcm(void) {
  static wyc_stats s;
  s.file = "aes_gcm_test.json";
  s.prim = "aes_gcm";
  /* Loop over every case of aes_gcm_test.json; each is identified by tcId. */
  wyc_loop(
      &s, wyc_aes_gcm_test_attrs, wyc_aes_gcm_test_cases, WYC_AESGCM_N,
      wyc_aesgcm_case);
}

void test_wyc_aesgcm_invalid_ModifiedTag_rejected(void) {
  /* aes_gcm_test.json invalid cases flagged ModifiedTag, by tcId. */
  wyc_flag_loop(
      "aes_gcm_test.json", "ModifiedTag", wyc_aes_gcm_test_attrs,
      wyc_aes_gcm_test_cases, WYC_AESGCM_N, wyc_aesgcm_case);
}
