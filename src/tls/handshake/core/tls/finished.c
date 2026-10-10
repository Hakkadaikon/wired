#include "tls/handshake/core/tls/finished.h"

#include "common/bytes/util/ct.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/suitehash.h"

void tls_finished_verify_data_suite(
    u16 suite, const u8* base_key, const u8* transcript_hash, u8* out) {
  const tls_hash* h = tls_hash_of(suite);
  u8              finished_key[TLS_HASH_MAX];
  hkdf_label      l = {"finished", 8, {0, 0}};
  h->expand_label(base_key, &l, wired_mspan_of(finished_key, h->len));
  h->mac(
      wired_span_of(finished_key, h->len),
      wired_span_of(transcript_hash, h->len), out);
}

int tls_finished_check_suite(
    u16       suite,
    const u8* base_key,
    const u8* transcript_hash,
    const u8* received) {
  u8 want[TLS_HASH_MAX];
  tls_finished_verify_data_suite(suite, base_key, transcript_hash, want);
  return ct_diffn(want, received, tls_hash_of(suite)->len) == 0;
}

void tls_finished_verify_data(
    const u8* base_key, const u8* transcript_hash, u8* out) {
  tls_finished_verify_data_suite(
      TLS_AES_128_GCM_SHA256, base_key, transcript_hash, out);
}

int tls_finished_check(
    const u8* base_key, const u8* transcript_hash, const u8* received) {
  return tls_finished_check_suite(
      TLS_AES_128_GCM_SHA256, base_key, transcript_hash, received);
}
