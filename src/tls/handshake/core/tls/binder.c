#include "tls/handshake/core/tls/binder.h"

#include "common/bytes/util/ct.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/schedule.h"

/* binder_key = Derive-Secret(HKDF-Extract(0, psk), "res binder", ""). */
static void binder_key_suite(u16 suite, const u8* psk, u8* out) {
  const tls_hash* h                  = tls_hash_of(suite);
  u8              zero[TLS_HASH_MAX] = {0};
  u8              early[TLS_HASH_MAX];
  /* early_secret = HKDF-Extract(0, PSK). */
  h->extract(wired_span_of(zero, h->len), wired_span_of(psk, h->len), early);
  derive_secret_in in = {
      early, wired_span_of((const u8*)"res binder", 10), wired_span_of(zero, 0),
      suite};
  tls_derive_secret(&in, out);
}

void tls_binder_key(const u8* psk, u8* out) {
  binder_key_suite(TLS_AES_128_GCM_SHA256, psk, out);
}

void tls_binder_compute_suite(
    u16 suite, const u8* psk, wired_span truncated_ch, u8* out) {
  u8 binder_key[TLS_HASH_MAX];
  u8 thash[TLS_HASH_MAX];
  binder_key_suite(suite, psk, binder_key);
  tls_hash_of(suite)->digest(truncated_ch.p, truncated_ch.n, thash);
  /* finished_key = HKDF-Expand-Label(binder_key, "finished", "",
   * Hash.length); binder = HMAC(finished_key, thash) -- identical
   * construction to the Finished MAC (RFC 8446 4.4.4), reused verbatim. */
  tls_finished_verify_data_suite(suite, binder_key, thash, out);
}

int tls_binder_verify_suite(
    u16 suite, const u8* psk, wired_span truncated_ch, const u8* received) {
  u8 want[TLS_HASH_MAX];
  tls_binder_compute_suite(suite, psk, truncated_ch, want);
  return ct_diffn(want, received, tls_hash_of(suite)->len) == 0;
}

void tls_binder_compute(const u8* psk, wired_span truncated_ch, u8* out) {
  tls_binder_compute_suite(TLS_AES_128_GCM_SHA256, psk, truncated_ch, out);
}

int tls_binder_verify(
    const u8* psk, wired_span truncated_ch, const u8* received) {
  return tls_binder_verify_suite(
      TLS_AES_128_GCM_SHA256, psk, truncated_ch, received);
}
