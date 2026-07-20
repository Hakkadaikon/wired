#include "tls/handshake/core/tls/binder.h"

#include "common/bytes/util/ct.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/schedule.h"

void quic_tls_binder_key(const u8 psk[QUIC_HKDF_PRK], u8 out[QUIC_HKDF_PRK]) {
  u8 zero[QUIC_HKDF_PRK] = {0};
  u8 early[QUIC_HKDF_PRK];
  /* early_secret = HKDF-Extract(0, PSK). */
  quic_hkdf_extract(
      quic_span_of(zero, QUIC_HKDF_PRK), quic_span_of(psk, QUIC_HKDF_PRK),
      early);
  /* binder_key = Derive-Secret(early_secret, "res binder", ""). */
  quic_derive_secret_in in = {
      early, quic_span_of((const u8*)"res binder", 10), quic_span_of(zero, 0)};
  quic_tls_derive_secret(&in, out);
}

void quic_tls_binder_compute(
    const u8  psk[QUIC_HKDF_PRK],
    quic_span truncated_ch,
    u8        out[QUIC_HKDF_PRK]) {
  u8 binder_key[QUIC_HKDF_PRK];
  u8 thash[QUIC_SHA256_DIGEST];
  quic_tls_binder_key(psk, binder_key);
  quic_sha256(truncated_ch.p, truncated_ch.n, thash);
  /* finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32);
   * binder = HMAC(finished_key, thash) -- identical construction to the
   * Finished MAC (RFC 8446 4.4.4), reused verbatim. */
  quic_tls_finished_verify_data(binder_key, thash, out);
}

int quic_tls_binder_verify(
    const u8  psk[QUIC_HKDF_PRK],
    quic_span truncated_ch,
    const u8  received[QUIC_HKDF_PRK]) {
  u8 want[QUIC_HKDF_PRK];
  quic_tls_binder_compute(psk, truncated_ch, want);
  return quic_ct_diff32(want, received) == 0;
}
