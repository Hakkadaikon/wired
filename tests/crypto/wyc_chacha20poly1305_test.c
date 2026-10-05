#include "crypto/wyc_run.h"
#include "vectors/wycheproof/chacha20_poly1305_test.h"

/* Source: tests/vectors/wycheproof/chacha20_poly1305_test.json (Wycheproof
 * C2SP/wycheproof 3fa63dd0, testvectors_v1). wired takes a 96-bit nonce and
 * 256-bit key only: InvalidNonceSize cases are rejected by construction. */

static usz wyc_chapoly_seal(
    const u8* key, const u8* nonce, wired_span ad, wired_span pt, u8* out) {
  chapoly_ctx c = {key, nonce, ad};
  return chapoly_seal(&c, pt, out);
}

static int wyc_chapoly_open(
    const u8* key, const u8* nonce, wired_span ad, wired_span ct, u8* pt) {
  chapoly_ctx c = {key, nonce, ad};
  return chapoly_open(&c, ct, pt);
}

static int wyc_chapoly_case(const bssl_attr* a, const wyc_case* c) {
  static const wyc_aead_ops ops = {wyc_chapoly_seal, wyc_chapoly_open, 256};
  return wyc_aead_case(&ops, a, c);
}

#define WYC_CHAPOLY_N                        \
  (sizeof wyc_chacha20_poly1305_test_cases / \
   sizeof wyc_chacha20_poly1305_test_cases[0])

void test_wyc_chacha20poly1305(void) {
  static wyc_stats s;
  s.file = "chacha20_poly1305_test.json";
  s.prim = "chacha20_poly1305";
  /* Loop over every case of chacha20_poly1305_test.json, by tcId. */
  wyc_loop(
      &s, wyc_chacha20_poly1305_test_attrs, wyc_chacha20_poly1305_test_cases,
      WYC_CHAPOLY_N, wyc_chapoly_case);
}

void test_wyc_chacha20poly1305_invalid_ModifiedTag_rejected(void) {
  /* chacha20_poly1305_test.json invalid cases flagged ModifiedTag. */
  wyc_flag_loop(
      "chacha20_poly1305_test.json", "ModifiedTag",
      wyc_chacha20_poly1305_test_attrs, wyc_chacha20_poly1305_test_cases,
      WYC_CHAPOLY_N, wyc_chapoly_case);
}
