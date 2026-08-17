#include "tls/handshake/core/tls/exporter.h"

#include "crypto/symmetric/hash/hash/sha256.h"
#include "tls/handshake/core/tls/schedule.h"

/* RFC 8446 7.1 key schedule diagram: exporter_master_secret =
 * Derive-Secret(Master Secret, "exp master", ClientHello...server
 * Finished). */
void tls_exporter_master_secret(
    const u8  master[HKDF_PRK],
    const u8* transcript,
    usz       transcript_len,
    u8        out[HKDF_PRK]) {
  derive_secret_in dsi = {
      master, wired_span_of((const u8*)"exp master", 10),
      wired_span_of(transcript, transcript_len)};
  tls_derive_secret(&dsi, out);
}

/* RFC 8446 7.5: TLS-Exporter(label, context_value, key_length) =
 * HKDF-Expand-Label(Derive-Secret(Secret, label, ""), "exporter",
 * Hash(context_value), key_length). */
int tls_exporter(
    const u8    secret[HKDF_PRK],
    wired_span  label,
    wired_span  context,
    wired_mspan okm) {
  u8               derived[HKDF_PRK];
  u8               ctx_hash[SHA256_DIGEST];
  derive_secret_in dsi = {secret, label, {0, 0}};
  hkdf_label       l   = {"exporter", 8, {0, 0}};
  tls_derive_secret(&dsi, derived);
  wired_sha256(context.p, context.n, ctx_hash);
  l.ctx = wired_span_of(ctx_hash, sizeof ctx_hash);
  return hkdf_expand_label(derived, &l, okm);
}
