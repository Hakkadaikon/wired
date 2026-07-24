#include "tls/handshake/core/tls/exporter.h"

#include "crypto/symmetric/hash/hash/sha256.h"
#include "tls/handshake/core/tls/schedule.h"

/* RFC 8446 7.1 key schedule diagram: exporter_master_secret =
 * Derive-Secret(Master Secret, "exp master", ClientHello...server
 * Finished). */
void quic_tls_exporter_master_secret(
    const u8  master[QUIC_HKDF_PRK],
    const u8* transcript,
    usz       transcript_len,
    u8        out[QUIC_HKDF_PRK]) {
  quic_derive_secret_in dsi = {
      master, quic_span_of((const u8*)"exp master", 10),
      quic_span_of(transcript, transcript_len)};
  quic_tls_derive_secret(&dsi, out);
}

/* RFC 8446 7.5: TLS-Exporter(label, context_value, key_length) =
 * HKDF-Expand-Label(Derive-Secret(Secret, label, ""), "exporter",
 * Hash(context_value), key_length). */
int quic_tls_exporter(
    const u8   secret[QUIC_HKDF_PRK],
    quic_span  label,
    quic_span  context,
    quic_mspan okm) {
  u8                    derived[QUIC_HKDF_PRK];
  u8                    ctx_hash[QUIC_SHA256_DIGEST];
  quic_derive_secret_in dsi = {secret, label, {0, 0}};
  quic_hkdf_label       l   = {"exporter", 8, {0, 0}};
  quic_tls_derive_secret(&dsi, derived);
  quic_sha256(context.p, context.n, ctx_hash);
  l.ctx = quic_span_of(ctx_hash, sizeof ctx_hash);
  return quic_hkdf_expand_label(derived, &l, okm);
}
