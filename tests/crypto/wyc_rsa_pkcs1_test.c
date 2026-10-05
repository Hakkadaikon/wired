#include "crypto/wyc_rsa_run.h"
#include "vectors/wycheproof/rsa_signature_2048_sha256_test.h"
#include "vectors/wycheproof/rsa_signature_2048_sha384_test.h"
#include "vectors/wycheproof/rsa_signature_2048_sha512_test.h"
#include "vectors/wycheproof/rsa_signature_3072_sha256_test.h"
#include "vectors/wycheproof/rsa_signature_3072_sha384_test.h"
#include "vectors/wycheproof/rsa_signature_3072_sha512_test.h"
#include "vectors/wycheproof/rsa_signature_4096_sha256_test.h"
#include "vectors/wycheproof/rsa_signature_4096_sha384_test.h"
#include "vectors/wycheproof/rsa_signature_4096_sha512_test.h"

/* Wycheproof C2SP/wycheproof testvectors_v1 @
 * 3fa63dd0344abb611f1fb1d77e119938603ea230, RSASSA-PKCS1-v1_5 (RFC 8017
 * 8.2.2). Cases are identified by tcId. None of LowOrderPublic,
 * NonCanonical, ZeroOrderPublic, SmallPublicKey, ModifiedTag or ShortMac is
 * present on an invalid case in these files (SmallPublicKey only on valid
 * ones), so no flag-named test exists; other flags are printed per failure. */

#define WYC_PKCS1(name)                                         \
  {                                                             \
      #name ".json",                                            \
      wyc_##name##_attrs,                                       \
      wyc_##name##_cases,                                       \
      sizeof wyc_##name##_cases / sizeof wyc_##name##_cases[0], \
      rsa_pkcs1_verify,                                         \
      0}

void test_wyc_rsa_pkcs1(void) {
  static const wyc_rsa_run runs[] = {
      WYC_PKCS1(rsa_signature_2048_sha256_test),
      WYC_PKCS1(rsa_signature_2048_sha384_test),
      WYC_PKCS1(rsa_signature_2048_sha512_test),
      WYC_PKCS1(rsa_signature_3072_sha256_test),
      WYC_PKCS1(rsa_signature_3072_sha384_test),
      WYC_PKCS1(rsa_signature_3072_sha512_test),
      WYC_PKCS1(rsa_signature_4096_sha256_test),
      WYC_PKCS1(rsa_signature_4096_sha384_test),
      WYC_PKCS1(rsa_signature_4096_sha512_test),
  };
  for (usz i = 0; i < sizeof runs / sizeof runs[0]; i++) wyc_rsa_loop(&runs[i]);
}
