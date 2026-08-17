#include "tls/handshake/core/tls/finished.h"

#include "crypto/symmetric/hash/hash/hmac.h"

void tls_finished_verify_data(
    const u8 base_key[QUIC_HKDF_PRK],
    const u8 transcript_hash[QUIC_SHA256_DIGEST],
    u8       out[QUIC_TLS_VERIFY_DATA]) {
  u8         finished_key[QUIC_SHA256_DIGEST];
  hkdf_label l = {"finished", 8, {0, 0}};
  hkdf_expand_label(
      base_key, &l, wired_mspan_of(finished_key, QUIC_SHA256_DIGEST));
  hmac_sha256(
      wired_span_of(finished_key, QUIC_SHA256_DIGEST),
      wired_span_of(transcript_hash, QUIC_SHA256_DIGEST), out);
}

/* Constant-time 32-byte digest comparison: 0 if equal. */
static u8 digest_diff(const u8 a[32], const u8 b[32]) {
  u8 d = 0;
  for (usz i = 0; i < 32; i++) d |= a[i] ^ b[i];
  return d;
}

int tls_finished_check(
    const u8 base_key[QUIC_HKDF_PRK],
    const u8 transcript_hash[QUIC_SHA256_DIGEST],
    const u8 received[QUIC_TLS_VERIFY_DATA]) {
  u8 want[QUIC_TLS_VERIFY_DATA];
  tls_finished_verify_data(base_key, transcript_hash, want);
  return digest_diff(want, received) == 0;
}
