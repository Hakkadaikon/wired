#include "crypto/wyc_rsa_run.h"
#include "vectors/wycheproof/rsa_pss_2048_sha256_mgf1_32_test.h"
#include "vectors/wycheproof/rsa_pss_3072_sha256_mgf1_32_test.h"
#include "vectors/wycheproof/rsa_pss_4096_sha256_mgf1_32_test.h"

/* Wycheproof C2SP/wycheproof testvectors_v1 @
 * 3fa63dd0344abb611f1fb1d77e119938603ea230, RSASSA-PSS SHA-256 / MGF1-SHA-256
 * / sLen 32 (RFC 8017 8.1.2). Cases are identified by tcId. The requested
 * invalid-case flags (LowOrderPublic, ...) do not occur in these files. */

#define WYC_PSS(name)                                           \
  {                                                             \
      #name ".json",                                            \
      wyc_##name##_attrs,                                       \
      wyc_##name##_cases,                                       \
      sizeof wyc_##name##_cases / sizeof wyc_##name##_cases[0], \
      rsa_pss_verify,                                           \
      0}

void test_wyc_rsa_pss(void) {
  static const wyc_rsa_run runs[] = {
      WYC_PSS(rsa_pss_2048_sha256_mgf1_32_test),
      WYC_PSS(rsa_pss_3072_sha256_mgf1_32_test),
      WYC_PSS(rsa_pss_4096_sha256_mgf1_32_test),
  };
  for (usz i = 0; i < sizeof runs / sizeof runs[0]; i++) wyc_rsa_loop(&runs[i]);
}
