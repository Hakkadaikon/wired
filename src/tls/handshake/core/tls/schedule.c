#include "tls/handshake/core/tls/schedule.h"

void quic_tls_derive_secret(
    const u8    secret[QUIC_HKDF_PRK],
    const char *label,
    usz         label_len,
    const u8   *messages,
    usz         messages_len,
    u8          out[QUIC_HKDF_PRK]) {
  u8 thash[QUIC_SHA256_DIGEST];
  quic_sha256(messages, messages_len, thash);
  quic_hkdf_label l = {label, label_len, {thash, sizeof(thash)}};
  quic_hkdf_expand_label(secret, &l, quic_mspan_of(out, QUIC_HKDF_PRK));
}

void quic_tls_handshake_secret(const u8 ecdhe[32], u8 out[QUIC_HKDF_PRK]) {
  u8 zero[QUIC_HKDF_PRK] = {0};
  u8 early[QUIC_HKDF_PRK];
  u8 derived[QUIC_HKDF_PRK];
  /* Early Secret = HKDF-Extract(0, 0). */
  quic_hkdf_extract(
      quic_span_of(zero, QUIC_HKDF_PRK), quic_span_of(zero, QUIC_HKDF_PRK),
      early);
  /* derived = Derive-Secret(Early, "derived", "") -- empty transcript. */
  quic_tls_derive_secret(early, "derived", 7, zero, 0, derived);
  /* Handshake Secret = HKDF-Extract(derived, ECDHE). */
  quic_hkdf_extract(
      quic_span_of(derived, QUIC_HKDF_PRK), quic_span_of(ecdhe, 32), out);
}

/* Expand one packet-protection field (RFC 9001 5.1 labels) from a secret. */
static void hs_field(
    const u8    secret[QUIC_HKDF_PRK],
    const char *label,
    usz         label_len,
    u8         *out,
    usz         len) {
  quic_hkdf_label l = {label, label_len, {0, 0}};
  quic_hkdf_expand_label(secret, &l, quic_mspan_of(out, len));
}

/* Expand the QUIC key/iv/hp triple from a traffic secret. */
static void protection_keys(
    const u8 ts[QUIC_HKDF_PRK], quic_initial_keys *out) {
  hs_field(ts, "quic key", 8, out->key, QUIC_INITIAL_KEY);
  hs_field(ts, "quic iv", 7, out->iv, QUIC_INITIAL_IV);
  hs_field(ts, "quic hp", 7, out->hp, QUIC_INITIAL_HP);
}

void quic_tls_handshake_keys(
    const u8           hs_secret[QUIC_HKDF_PRK],
    const u8          *transcript,
    usz                transcript_len,
    int                is_server,
    quic_initial_keys *out) {
  const char *label = is_server ? "s hs traffic" : "c hs traffic";
  u8          ts[QUIC_HKDF_PRK];
  quic_tls_derive_secret(hs_secret, label, 12, transcript, transcript_len, ts);
  protection_keys(ts, out);
}

void quic_tls_early_keys(
    const u8           psk[QUIC_HKDF_PRK],
    const u8          *client_hello,
    usz                client_hello_len,
    quic_initial_keys *out) {
  u8 zero[QUIC_HKDF_PRK] = {0};
  u8 early[QUIC_HKDF_PRK];
  u8 ts[QUIC_HKDF_PRK];
  /* Early Secret = HKDF-Extract(0, PSK). */
  quic_hkdf_extract(
      quic_span_of(zero, QUIC_HKDF_PRK), quic_span_of(psk, QUIC_HKDF_PRK),
      early);
  /* client_early_traffic_secret over the ClientHello. */
  quic_tls_derive_secret(
      early, "c e traffic", 11, client_hello, client_hello_len, ts);
  protection_keys(ts, out);
}
