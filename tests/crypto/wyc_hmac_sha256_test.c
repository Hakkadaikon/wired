#include "crypto/symmetric/hash/hash/hmac.h"
#include "crypto/wyc_run.h"
#include "vectors/wycheproof/hmac_sha256_test.h"

/* Source: tests/vectors/wycheproof/hmac_sha256_test.json (Wycheproof
 * C2SP/wycheproof 3fa63dd0, testvectors_v1). Verify = the computed MAC,
 * truncated to the group's tagSize, equals the JSON tag (constant time). */

#define WYC_HM_KEY 1024

static int wyc_hmac_case(const bssl_attr* a, const wyc_case* c) {
  u8  key[WYC_HM_KEY], msg[WYC_HM_KEY], tag[SHA256_DIGEST], got[SHA256_DIGEST];
  ssz kl = bssl_bytes(wyc_get(a, c, "key"), key, sizeof key);
  ssz ml = bssl_bytes(wyc_get(a, c, "msg"), msg, sizeof msg);
  ssz tl = bssl_bytes(wyc_get(a, c, "tag"), tag, sizeof tag);
  u32 tn = wyc_num(wyc_get(a, c, "g.tagSize")) / 8;
  if (kl < 0 || ml < 0 || tl < 0 || tn > SHA256_DIGEST) return WYC_BAD;
  hmac_sha256_truncated(
      wired_span_of(key, (usz)kl), wired_span_of(msg, (usz)ml), got, tn);
  return (u32)tl == tn && wyc_eq(got, tag, tn) ? WYC_OK : WYC_REJ;
}

#define WYC_HMAC_N \
  (sizeof wyc_hmac_sha256_test_cases / sizeof wyc_hmac_sha256_test_cases[0])

void test_wyc_hmac_sha256(void) {
  static wyc_stats s;
  s.file = "hmac_sha256_test.json";
  s.prim = "hmac_sha256";
  /* Loop over every case of hmac_sha256_test.json, identified by tcId. */
  wyc_loop(
      &s, wyc_hmac_sha256_test_attrs, wyc_hmac_sha256_test_cases, WYC_HMAC_N,
      wyc_hmac_case);
}

void test_wyc_hmac_invalid_ModifiedTag_rejected(void) {
  /* hmac_sha256_test.json invalid cases flagged ModifiedTag, by tcId. */
  wyc_flag_loop(
      "hmac_sha256_test.json", "ModifiedTag", wyc_hmac_sha256_test_attrs,
      wyc_hmac_sha256_test_cases, WYC_HMAC_N, wyc_hmac_case);
}
