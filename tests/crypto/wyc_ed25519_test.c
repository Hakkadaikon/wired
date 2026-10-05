#include "crypto/asymmetric/ecc/ed25519/ed25519.h"
#include "crypto/wyc_pk_run.h"
#include "vectors/wycheproof/ed25519_test.h"

/* Wycheproof testvectors_v1/ed25519_test.json @ 3fa63dd0 (cases by tcId).
 * (The requested eddsa_test.json is named ed25519_test.json in v1.) */

#define WYC_ED_MSG 1024 /* longest msg in the file is 1023 bytes */
#define WYC_ED_N \
  ((u32)(sizeof wyc_ed25519_test_cases / sizeof wyc_ed25519_test_cases[0]))

static int wyc_ed_run(const wyc_case* c) {
  const bssl_attr* a = wyc_ed25519_test_attrs;
  static u8        msg[WYC_ED_MSG];
  u8               pk[32], sig[96];
  ssz              m = bssl_bytes(wyc_get(a, c, "msg"), msg, sizeof msg);
  ssz              s = bssl_bytes(wyc_get(a, c, "sig"), sig, sizeof sig);
  ssz              p = bssl_bytes(wyc_get(a, c, "g.publicKey.pk"), pk, 32);
  if (m < 0 || s < 0 || p != 32) return WYC_PK_BROKEN;
  /* a signature that is not 64 bytes can never be accepted */
  if (s != 64) return WYC_PK_REJECT;
  return ed25519_verify(sig, msg, (usz)m, pk) ? WYC_PK_ACCEPT : WYC_PK_REJECT;
}

static void wyc_ed_flag(const char* name, const char* flag) {
  wyc_pk_flag_rejected(
      name, wyc_ed25519_test_cases, WYC_ED_N, wyc_ed_run, flag);
}

void test_wyc_ed25519(void) {
  /* ed25519_test.json */
  wyc_pk_tally t = {.prim = "ed25519", .file = "ed25519_test.json"};
  wyc_pk_all(&t, wyc_ed25519_test_cases, WYC_ED_N, wyc_ed_run);
  /* ed25519_test.json, result=invalid cases per flag */
  wyc_ed_flag(
      "test_wyc_ed25519_invalid_SignatureMalleability_rejected",
      "SignatureMalleability");
  wyc_ed_flag(
      "test_wyc_ed25519_invalid_CompressedSignature_rejected",
      "CompressedSignature");
  wyc_ed_flag(
      "test_wyc_ed25519_invalid_InvalidEncoding_rejected", "InvalidEncoding");
  wyc_ed_flag(
      "test_wyc_ed25519_invalid_TruncatedSignature_rejected",
      "TruncatedSignature");
  wyc_ed_flag(
      "test_wyc_ed25519_invalid_SignatureWithGarbage_rejected",
      "SignatureWithGarbage");
}
