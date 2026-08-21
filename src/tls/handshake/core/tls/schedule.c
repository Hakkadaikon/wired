#include "tls/handshake/core/tls/schedule.h"

#include "tls/handshake/core/tls/aead_params.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/hp_select.h"
#include "transport/version/version/v2keys.h"

/* RFC 9001 5.1: AEAD key length for `suite` (aead_key_len), falling back
 * to the AES-128 length on an unrecognized suite so this never expands 0
 * bytes. */
static usz resolved_key_len(u16 suite) {
  usz n = aead_key_len(suite);
  return n ? n : INITIAL_KEY;
}

/* RFC 9001 5.4.3: header-protection key length for `suite` (hp_key_len
 * mirrors the AEAD key length per suite), same fallback as resolved_key_len.
 */
static usz resolved_hp_len(u16 suite) {
  usz n = hp_key_len(suite);
  return n ? n : INITIAL_HP;
}

void tls_derive_secret(const derive_secret_in* in, u8 out[HKDF_PRK]) {
  u8 thash[SHA256_DIGEST];
  wired_sha256(in->messages.p, in->messages.n, thash);
  hkdf_label l = {
      (const char*)in->label.p, in->label.n, {thash, sizeof(thash)}};
  hkdf_expand_label(in->secret, &l, wired_mspan_of(out, HKDF_PRK));
}

/* A literal ASCII label plus its length, before folding into a span. */
typedef struct {
  const char* s;
  usz         len;
} ascii_label;

/* Build the derive-secret input for a literal ASCII label. */
static derive_secret_in derive_in(
    const u8* secret, ascii_label label, wired_span messages) {
  derive_secret_in in;
  in.secret   = secret;
  in.label    = wired_span_of((const u8*)label.s, label.len);
  in.messages = messages;
  return in;
}

/* RFC 8446 7.1: Handshake Secret = HKDF-Extract(Derive-Secret(early,
 * "derived", ""), ECDHE), given an already-computed Early Secret. Shared by
 * the no-PSK (Early = HKDF-Extract(0,0)) and PSK-resumption (Early =
 * HKDF-Extract(0, PSK)) branches below -- only the Early Secret input
 * differs between them. */
static void handshake_secret_from_early(
    const u8 early[HKDF_PRK], const u8 ecdhe[32], u8 out[HKDF_PRK]) {
  u8 zero[HKDF_PRK] = {0};
  u8 derived[HKDF_PRK];
  /* derived = Derive-Secret(Early, "derived", "") -- empty transcript. */
  derive_secret_in in =
      derive_in(early, (ascii_label){"derived", 7}, wired_span_of(zero, 0));
  tls_derive_secret(&in, derived);
  /* Handshake Secret = HKDF-Extract(derived, ECDHE). */
  hkdf_extract(wired_span_of(derived, HKDF_PRK), wired_span_of(ecdhe, 32), out);
}

void tls_handshake_secret(const u8 ecdhe[32], u8 out[HKDF_PRK]) {
  u8 zero[HKDF_PRK] = {0};
  u8 early[HKDF_PRK];
  /* Early Secret = HKDF-Extract(0, 0). */
  hkdf_extract(
      wired_span_of(zero, HKDF_PRK), wired_span_of(zero, HKDF_PRK), early);
  handshake_secret_from_early(early, ecdhe, out);
}

void tls_handshake_secret_psk(
    const u8 psk[HKDF_PRK], const u8 ecdhe[32], u8 out[HKDF_PRK]) {
  u8 zero[HKDF_PRK] = {0};
  u8 early[HKDF_PRK];
  /* Early Secret = HKDF-Extract(0, PSK). */
  hkdf_extract(
      wired_span_of(zero, HKDF_PRK), wired_span_of(psk, HKDF_PRK), early);
  handshake_secret_from_early(early, ecdhe, out);
}

/* Expand one packet-protection field (RFC 9001 5.1 labels) from a secret. */
static void hs_field(
    const u8 secret[HKDF_PRK], wired_span label, wired_mspan out) {
  hkdf_label l = {(const char*)label.p, label.n, {0, 0}};
  hkdf_expand_label(secret, &l, out);
}

/* out->key/out->hp are sized AEAD_KEY_MAX to hold either suite (see
 * initial.h); a suite shorter than that (AES_128_GCM_SHA256) leaves a tail
 * the HKDF expand never touches. Zero it so out is always a fully
 * deterministic value, not partly whatever the caller's buffer held before
 * (two independent derivations of the same AES keys must compare equal
 * byte-for-byte, not just in the bytes AES actually uses). */
static void protection_keys_zero_tail(
    initial_keys* out, usz key_len, usz hp_len) {
  for (usz i = key_len; i < AEAD_KEY_MAX; i++) out->key[i] = 0;
  for (usz i = hp_len; i < AEAD_KEY_MAX; i++) out->hp[i] = 0;
}

/* The "<quic |quicv2 ><suffix>" packet-protection label for `version`
 * (RFC 9001 5.1 / RFC 9369 3.3.1; 0/unknown falls back to v1's prefix). */
static wired_span sched_quic_label(
    u8 buf[VERSION_LABEL_MAX], u32 version, const char* sfx, usz sfx_len) {
  return wired_span_of(buf, version_quic_label(buf, version, sfx, sfx_len));
}

/* Expand the QUIC key/iv/hp triple from a traffic secret, with `version`'s
 * label prefix (RFC 9369 3.3.1; 0 = v1). */
static void protection_keys(
    const u8 ts[HKDF_PRK], u32 version, initial_keys* out) {
  u8 lb[VERSION_LABEL_MAX];
  hs_field(
      ts, sched_quic_label(lb, version, "key", 3),
      wired_mspan_of(out->key, INITIAL_KEY));
  hs_field(
      ts, sched_quic_label(lb, version, "iv", 2),
      wired_mspan_of(out->iv, INITIAL_IV));
  hs_field(
      ts, sched_quic_label(lb, version, "hp", 2),
      wired_mspan_of(out->hp, INITIAL_HP));
  protection_keys_zero_tail(out, INITIAL_KEY, INITIAL_HP);
}

void tls_handshake_keys(const handshake_keys_in* in, initial_keys* out) {
  const char*      label = in->is_server ? "s hs traffic" : "c hs traffic";
  u8               ts[HKDF_PRK];
  derive_secret_in dsi =
      derive_in(in->hs_secret, (ascii_label){label, 12}, in->transcript);
  tls_derive_secret(&dsi, ts);
  protection_keys(ts, in->version, out);
}

/* Expand the QUIC key/iv/hp triple from a traffic secret, sized for suite
 * (RFC 8446 B.4; AES_128_GCM_SHA256 key=16/hp=16, CHACHA20_POLY1305_SHA256
 * key=32/hp=32 -- RFC 9001 5.1/5.4.3), with `version`'s label prefix
 * (RFC 9369 3.3.1; 0 = v1). */
static void protection_keys_suite(
    const u8 ts[HKDF_PRK], u16 suite, u32 version, initial_keys* out) {
  usz key_len = resolved_key_len(suite), hp_len = resolved_hp_len(suite);
  u8  lb[VERSION_LABEL_MAX];
  hs_field(
      ts, sched_quic_label(lb, version, "key", 3),
      wired_mspan_of(out->key, key_len));
  hs_field(
      ts, sched_quic_label(lb, version, "iv", 2),
      wired_mspan_of(out->iv, INITIAL_IV));
  hs_field(
      ts, sched_quic_label(lb, version, "hp", 2),
      wired_mspan_of(out->hp, hp_len));
  protection_keys_zero_tail(out, key_len, hp_len);
}

void tls_handshake_keys_suite(
    const handshake_keys_in* in, u16 suite, initial_keys* out) {
  const char*      label = in->is_server ? "s hs traffic" : "c hs traffic";
  u8               ts[HKDF_PRK];
  derive_secret_in dsi =
      derive_in(in->hs_secret, (ascii_label){label, 12}, in->transcript);
  tls_derive_secret(&dsi, ts);
  protection_keys_suite(ts, suite, in->version, out);
}

void tls_early_keys(
    const u8      psk[HKDF_PRK],
    const u8*     client_hello,
    usz           client_hello_len,
    initial_keys* out) {
  u8 zero[HKDF_PRK] = {0};
  u8 early[HKDF_PRK];
  u8 ts[HKDF_PRK];
  /* Early Secret = HKDF-Extract(0, PSK). */
  hkdf_extract(
      wired_span_of(zero, HKDF_PRK), wired_span_of(psk, HKDF_PRK), early);
  /* client_early_traffic_secret over the ClientHello. */
  {
    derive_secret_in in = derive_in(
        early, (ascii_label){"c e traffic", 11},
        wired_span_of(client_hello, client_hello_len));
    tls_derive_secret(&in, ts);
  }
  /* RFC 9368 2.3: 0-RTT is only ever sent under the client's original
   * version, before any compatible switch -- always the v1 labels here. */
  protection_keys(ts, VERSION_1, out);
}
