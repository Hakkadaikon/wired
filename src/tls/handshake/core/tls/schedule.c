#include "tls/handshake/core/tls/schedule.h"

void quic_tls_derive_secret(
    const quic_derive_secret_in* in, u8 out[QUIC_HKDF_PRK]) {
  u8 thash[QUIC_SHA256_DIGEST];
  quic_sha256(in->messages.p, in->messages.n, thash);
  quic_hkdf_label l = {
      (const char*)in->label.p, in->label.n, {thash, sizeof(thash)}};
  quic_hkdf_expand_label(in->secret, &l, quic_mspan_of(out, QUIC_HKDF_PRK));
}

/* A literal ASCII label plus its length, before folding into a span. */
typedef struct {
  const char* s;
  usz         len;
} ascii_label;

/* Build the derive-secret input for a literal ASCII label. */
static quic_derive_secret_in derive_in(
    const u8* secret, ascii_label label, quic_span messages) {
  quic_derive_secret_in in;
  in.secret   = secret;
  in.label    = quic_span_of((const u8*)label.s, label.len);
  in.messages = messages;
  return in;
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
  {
    quic_derive_secret_in in =
        derive_in(early, (ascii_label){"derived", 7}, quic_span_of(zero, 0));
    quic_tls_derive_secret(&in, derived);
  }
  /* Handshake Secret = HKDF-Extract(derived, ECDHE). */
  quic_hkdf_extract(
      quic_span_of(derived, QUIC_HKDF_PRK), quic_span_of(ecdhe, 32), out);
}

/* Expand one packet-protection field (RFC 9001 5.1 labels) from a secret. */
static void hs_field(
    const u8 secret[QUIC_HKDF_PRK], quic_span label, quic_mspan out) {
  quic_hkdf_label l = {(const char*)label.p, label.n, {0, 0}};
  quic_hkdf_expand_label(secret, &l, out);
}

/* Expand the QUIC key/iv/hp triple from a traffic secret. */
static void protection_keys(
    const u8 ts[QUIC_HKDF_PRK], quic_initial_keys* out) {
  hs_field(
      ts, quic_span_of((const u8*)"quic key", 8),
      quic_mspan_of(out->key, QUIC_INITIAL_KEY));
  hs_field(
      ts, quic_span_of((const u8*)"quic iv", 7),
      quic_mspan_of(out->iv, QUIC_INITIAL_IV));
  hs_field(
      ts, quic_span_of((const u8*)"quic hp", 7),
      quic_mspan_of(out->hp, QUIC_INITIAL_HP));
}

void quic_tls_handshake_keys(
    const quic_handshake_keys_in* in, quic_initial_keys* out) {
  const char*           label = in->is_server ? "s hs traffic" : "c hs traffic";
  u8                    ts[QUIC_HKDF_PRK];
  quic_derive_secret_in dsi =
      derive_in(in->hs_secret, (ascii_label){label, 12}, in->transcript);
  quic_tls_derive_secret(&dsi, ts);
  protection_keys(ts, out);
}

void quic_tls_early_keys(
    const u8           psk[QUIC_HKDF_PRK],
    const u8*          client_hello,
    usz                client_hello_len,
    quic_initial_keys* out) {
  u8 zero[QUIC_HKDF_PRK] = {0};
  u8 early[QUIC_HKDF_PRK];
  u8 ts[QUIC_HKDF_PRK];
  /* Early Secret = HKDF-Extract(0, PSK). */
  quic_hkdf_extract(
      quic_span_of(zero, QUIC_HKDF_PRK), quic_span_of(psk, QUIC_HKDF_PRK),
      early);
  /* client_early_traffic_secret over the ClientHello. */
  {
    quic_derive_secret_in in = derive_in(
        early, (ascii_label){"c e traffic", 11},
        quic_span_of(client_hello, client_hello_len));
    quic_tls_derive_secret(&in, ts);
  }
  protection_keys(ts, out);
}
