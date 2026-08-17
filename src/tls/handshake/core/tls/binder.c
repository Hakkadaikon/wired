#include "tls/handshake/core/tls/binder.h"

#include "common/bytes/util/ct.h"
#include "crypto/symmetric/hash/hash/sha256.h"
#include "tls/handshake/core/tls/finished.h"
#include "tls/handshake/core/tls/schedule.h"

void tls_binder_key(const u8 psk[HKDF_PRK], u8 out[HKDF_PRK]) {
  u8 zero[HKDF_PRK] = {0};
  u8 early[HKDF_PRK];
  /* early_secret = HKDF-Extract(0, PSK). */
  hkdf_extract(
      wired_span_of(zero, HKDF_PRK), wired_span_of(psk, HKDF_PRK), early);
  /* binder_key = Derive-Secret(early_secret, "res binder", ""). */
  derive_secret_in in = {
      early, wired_span_of((const u8*)"res binder", 10),
      wired_span_of(zero, 0)};
  tls_derive_secret(&in, out);
}

void tls_binder_compute(
    const u8 psk[HKDF_PRK], wired_span truncated_ch, u8 out[HKDF_PRK]) {
  u8 binder_key[HKDF_PRK];
  u8 thash[SHA256_DIGEST];
  tls_binder_key(psk, binder_key);
  wired_sha256(truncated_ch.p, truncated_ch.n, thash);
  /* finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32);
   * binder = HMAC(finished_key, thash) -- identical construction to the
   * Finished MAC (RFC 8446 4.4.4), reused verbatim. */
  tls_finished_verify_data(binder_key, thash, out);
}

int tls_binder_verify(
    const u8   psk[HKDF_PRK],
    wired_span truncated_ch,
    const u8   received[HKDF_PRK]) {
  u8 want[HKDF_PRK];
  tls_binder_compute(psk, truncated_ch, want);
  return ct_diff32(want, received) == 0;
}
