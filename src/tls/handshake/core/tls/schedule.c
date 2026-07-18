#include "tls/handshake/core/tls/schedule.h"

#include "tls/handshake/core/tls/aead_params.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/hp_select.h"

/* RFC 9001 5.1: AEAD key length for `suite` (quic_aead_key_len), falling back
 * to the AES-128 length on an unrecognized suite so this never expands 0
 * bytes. */
static usz resolved_key_len(u16 suite) {
  usz n = quic_aead_key_len(suite);
  return n ? n : QUIC_INITIAL_KEY;
}

/* RFC 9001 5.4.3: header-protection key length for `suite` (quic_hp_key_len
 * mirrors the AEAD key length per suite), same fallback as resolved_key_len.
 */
static usz resolved_hp_len(u16 suite) {
  usz n = quic_hp_key_len(suite);
  return n ? n : QUIC_INITIAL_HP;
}

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

/* out->key/out->hp are sized QUIC_AEAD_KEY_MAX to hold either suite (see
 * initial.h); a suite shorter than that (AES_128_GCM_SHA256) leaves a tail
 * the HKDF expand never touches. Zero it so out is always a fully
 * deterministic value, not partly whatever the caller's buffer held before
 * (two independent derivations of the same AES keys must compare equal
 * byte-for-byte, not just in the bytes AES actually uses). */
static void protection_keys_zero_tail(
    quic_initial_keys* out, usz key_len, usz hp_len) {
  for (usz i = key_len; i < QUIC_AEAD_KEY_MAX; i++) out->key[i] = 0;
  for (usz i = hp_len; i < QUIC_AEAD_KEY_MAX; i++) out->hp[i] = 0;
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
  protection_keys_zero_tail(out, QUIC_INITIAL_KEY, QUIC_INITIAL_HP);
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

/* Expand the QUIC key/iv/hp triple from a traffic secret, sized for suite
 * (RFC 8446 B.4; AES_128_GCM_SHA256 key=16/hp=16, CHACHA20_POLY1305_SHA256
 * key=32/hp=32 -- RFC 9001 5.1/5.4.3). */
static void protection_keys_suite(
    const u8 ts[QUIC_HKDF_PRK], u16 suite, quic_initial_keys* out) {
  usz key_len = resolved_key_len(suite), hp_len = resolved_hp_len(suite);
  hs_field(
      ts, quic_span_of((const u8*)"quic key", 8),
      quic_mspan_of(out->key, key_len));
  hs_field(
      ts, quic_span_of((const u8*)"quic iv", 7),
      quic_mspan_of(out->iv, QUIC_INITIAL_IV));
  hs_field(
      ts, quic_span_of((const u8*)"quic hp", 7),
      quic_mspan_of(out->hp, hp_len));
  protection_keys_zero_tail(out, key_len, hp_len);
}

void quic_tls_handshake_keys_suite(
    const quic_handshake_keys_in* in, u16 suite, quic_initial_keys* out) {
  const char*           label = in->is_server ? "s hs traffic" : "c hs traffic";
  u8                    ts[QUIC_HKDF_PRK];
  quic_derive_secret_in dsi =
      derive_in(in->hs_secret, (ascii_label){label, 12}, in->transcript);
  quic_tls_derive_secret(&dsi, ts);
  protection_keys_suite(ts, suite, out);
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
