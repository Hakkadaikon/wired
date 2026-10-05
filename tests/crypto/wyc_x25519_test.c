#include "crypto/wyc_pk_run.h"
#include "tls/handshake/core/tls/x25519.h"
#include "vectors/wycheproof/x25519_test.h"

/* Wycheproof testvectors_v1/x25519_test.json @ 3fa63dd0 (cases by tcId).
 * Output must equal "shared" whenever wired accepts; a 0 return (RFC 7748
 * 6.1 all-zero secret) is a rejection. The file has no result=invalid case
 * (LowOrderPublic / SmallPublicKey / NonCanonicalPublic / ZeroSharedSecret
 * are all result=acceptable), so there is no *_invalid_*_rejected test. */

static int wyc_x_run(const wyc_case* c) {
  const bssl_attr* a = wyc_x25519_test_attrs;
  u8               k[32], p[32], want[32], out[32];
  int              ok = bssl_bytes(wyc_get(a, c, "private"), k, 32) == 32;
  ok                  = bssl_bytes(wyc_get(a, c, "public"), p, 32) == 32 && ok;
  ok = bssl_bytes(wyc_get(a, c, "shared"), want, 32) == 32 && ok;
  if (!ok) return WYC_PK_BROKEN;
  if (!wired_x25519(out, k, p)) return WYC_PK_REJECT;
  u8 d = 0;
  for (usz i = 0; i < 32; i++) d |= (u8)(out[i] ^ want[i]);
  return d ? WYC_PK_BROKEN : WYC_PK_ACCEPT;
}

void test_wyc_x25519(void) {
  /* x25519_test.json */
  wyc_pk_tally t = {.prim = "x25519", .file = "x25519_test.json"};
  wyc_pk_all(
      &t, wyc_x25519_test_cases,
      (u32)(sizeof wyc_x25519_test_cases / sizeof wyc_x25519_test_cases[0]),
      wyc_x_run);
}
