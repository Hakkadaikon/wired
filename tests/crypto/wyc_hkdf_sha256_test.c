#include "crypto/kdf/hkdf/hkdf.h"
#include "crypto/wyc_run.h"
#include "vectors/wycheproof/hkdf_sha256_test.h"

/* Source: tests/vectors/wycheproof/hkdf_sha256_test.json (Wycheproof
 * C2SP/wycheproof 3fa63dd0, testvectors_v1). okm = Expand(Extract(salt, ikm),
 * info, size); size > 255*32 must be refused (RFC 5869 2.3). */

#define WYC_HK_IN 512

static int wyc_hkdf_case(const bssl_attr* a, const wyc_case* c) {
  static u8 okm[WYC_BUF], want[WYC_BUF];
  u8        ikm[WYC_HK_IN], salt[WYC_HK_IN], info[WYC_HK_IN], prk[HKDF_PRK];
  ssz       il = bssl_bytes(wyc_get(a, c, "ikm"), ikm, sizeof ikm);
  ssz       sl = bssl_bytes(wyc_get(a, c, "salt"), salt, sizeof salt);
  ssz       nl = bssl_bytes(wyc_get(a, c, "info"), info, sizeof info);
  ssz       wl = bssl_bytes(wyc_get(a, c, "okm"), want, sizeof want);
  u32       n  = wyc_num(wyc_get(a, c, "size"));
  if (il < 0 || sl < 0 || nl < 0 || wl < 0 || n > WYC_BUF) return WYC_BAD;
  hkdf_extract(wired_span_of(salt, (usz)sl), wired_span_of(ikm, (usz)il), prk);
  if (!hkdf_expand(prk, wired_span_of(info, (usz)nl), wired_mspan_of(okm, n)))
    return WYC_REJ;
  return (u32)wl == n && wyc_eq(okm, want, n) ? WYC_OK : WYC_REJ;
}

void test_wyc_hkdf_sha256(void) {
  static wyc_stats s;
  s.file = "hkdf_sha256_test.json";
  s.prim = "hkdf_sha256";
  /* Loop over every case of hkdf_sha256_test.json, identified by tcId. */
  wyc_loop(
      &s, wyc_hkdf_sha256_test_attrs, wyc_hkdf_sha256_test_cases,
      sizeof wyc_hkdf_sha256_test_cases / sizeof wyc_hkdf_sha256_test_cases[0],
      wyc_hkdf_case);
}
