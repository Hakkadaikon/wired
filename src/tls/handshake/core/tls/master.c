#include "tls/handshake/core/tls/master.h"

#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/schedule.h"

void tls_master_secret_suite(u16 suite, const u8* hs_secret, u8* out) {
  const tls_hash* h                  = tls_hash_of(suite);
  u8              zero[TLS_HASH_MAX] = {0};
  u8              derived[TLS_HASH_MAX];
  /* RFC 8446 7.1: derived = Derive-Secret(Handshake, "derived", ""). */
  derive_secret_in in = {
      hs_secret, wired_span_of((const u8*)"derived", 7), wired_span_of(zero, 0),
      suite};
  tls_derive_secret(&in, derived);
  /* Master Secret = HKDF-Extract(derived, 0), 0 being Hash.length zeros. */
  h->extract(wired_span_of(derived, h->len), wired_span_of(zero, h->len), out);
}

void tls_master_secret(const u8* hs_secret, u8* out) {
  tls_master_secret_suite(TLS_AES_128_GCM_SHA256, hs_secret, out);
}
