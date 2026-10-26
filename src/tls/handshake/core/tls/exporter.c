#include "tls/handshake/core/tls/exporter.h"

#include "tls/handshake/core/tls/schedule.h"
#include "tls/handshake/core/tls/suitehash.h"

/* RFC 8446 7.1 key schedule diagram: exporter_master_secret =
 * Derive-Secret(Master Secret, "exp master", ClientHello...server
 * Finished). */
void tls_exporter_master_secret_suite(
    u16       suite,
    const u8* master,
    const u8* transcript,
    usz       transcript_len,
    u8*       out) {
  derive_secret_in dsi = {
      master, wired_span_of((const u8*)"exp master", 10),
      wired_span_of(transcript, transcript_len), suite};
  tls_derive_secret(&dsi, out);
}

void tls_exporter_master_secret(
    const u8* master, const u8* transcript, usz transcript_len, u8* out) {
  tls_exporter_master_secret_suite(0, master, transcript, transcript_len, out);
}

/* RFC 8446 7.5: TLS-Exporter(label, context_value, key_length) =
 * HKDF-Expand-Label(Derive-Secret(Secret, label, ""), "exporter",
 * Hash(context_value), key_length), over suite's hash (7.1: every secret
 * is Hash.length bytes). */
int tls_exporter_suite(
    u16         suite,
    const u8*   secret,
    wired_span  label,
    wired_span  context,
    wired_mspan okm) {
  const tls_hash*  h = tls_hash_of(suite);
  u8               derived[TLS_HASH_MAX];
  u8               ctx_hash[TLS_HASH_MAX];
  derive_secret_in dsi = {secret, label, {0, 0}, suite};
  hkdf_label       l   = {"exporter", 8, {0, 0}};
  if (!tls_derive_secret(&dsi, derived)) {
    return 0;
  }
  h->digest(context.p, context.n, ctx_hash);
  l.ctx = wired_span_of(ctx_hash, h->len);
  return h->expand_label(derived, &l, okm);
}

int tls_exporter(
    const u8    secret[HKDF_PRK],
    wired_span  label,
    wired_span  context,
    wired_mspan okm) {
  return tls_exporter_suite(0, secret, label, context, okm);
}
