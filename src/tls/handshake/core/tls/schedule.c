#include "tls/handshake/core/tls/schedule.h"

#include "common/bytes/util/bytes.h"
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

int tls_derive_secret(const derive_secret_in* in, u8* out) {
  const tls_hash* h = tls_hash_of(in->suite);
  u8              thash[TLS_HASH_MAX];
  h->digest(in->messages.p, in->messages.n, thash);
  hkdf_label l = {(const char*)in->label.p, in->label.n, {thash, h->len}};
  if (h->expand_label(in->secret, &l, wired_mspan_of(out, h->len))) return 1;
  bytes_memset(out, 0, h->len); /* fail closed: never an uninitialized key */
  return 0;
}

/* A literal ASCII label plus its length, before folding into a span. */
typedef struct {
  const char* s;
  usz         len;
} ascii_label;

/* Build the derive-secret input for a literal ASCII label. */
static derive_secret_in derive_in(
    u16 suite, const u8* secret, ascii_label label, wired_span messages) {
  derive_secret_in in;
  in.secret   = secret;
  in.label    = wired_span_of((const u8*)label.s, label.len);
  in.messages = messages;
  in.suite    = suite;
  return in;
}

/* RFC 8446 7.1: Handshake Secret = HKDF-Extract(Derive-Secret(early,
 * "derived", ""), ECDHE), given an already-computed Early Secret. Shared by
 * the no-PSK (Early = HKDF-Extract(0,0)) and PSK-resumption (Early =
 * HKDF-Extract(0, PSK)) branches below -- only the Early Secret input
 * differs between them. */
static void handshake_secret_from_early(
    u16 suite, const u8* early, const u8 ecdhe[32], u8* out) {
  const tls_hash* h = tls_hash_of(suite);
  u8              derived[TLS_HASH_MAX];
  /* derived = Derive-Secret(Early, "derived", "") -- empty transcript. */
  derive_secret_in in = derive_in(
      suite, early, (ascii_label){"derived", 7}, wired_span_of(early, 0));
  tls_derive_secret(&in, derived);
  /* Handshake Secret = HKDF-Extract(derived, ECDHE). */
  h->extract(wired_span_of(derived, h->len), wired_span_of(ecdhe, 32), out);
}

/* RFC 8446 7.1: Early Secret = HKDF-Extract(0, ikm), ikm being the PSK or
 * Hash.length zero bytes. */
static void sched_early_secret(u16 suite, const u8* ikm, u8* early) {
  const tls_hash* h                  = tls_hash_of(suite);
  u8              zero[TLS_HASH_MAX] = {0};
  h->extract(
      wired_span_of(zero, h->len), wired_span_of(ikm ? ikm : zero, h->len),
      early);
}

void tls_handshake_secret_psk_suite(
    u16 suite, const u8* psk, const u8 ecdhe[32], u8* out) {
  u8 early[TLS_HASH_MAX];
  sched_early_secret(suite, psk, early);
  handshake_secret_from_early(suite, early, ecdhe, out);
}

void tls_handshake_secret_suite(u16 suite, const u8 ecdhe[32], u8* out) {
  tls_handshake_secret_psk_suite(suite, 0, ecdhe, out);
}

void tls_handshake_secret(const u8 ecdhe[32], u8* out) {
  tls_handshake_secret_suite(TLS_AES_128_GCM_SHA256, ecdhe, out);
}

void tls_handshake_secret_psk(const u8* psk, const u8 ecdhe[32], u8* out) {
  tls_handshake_secret_psk_suite(TLS_AES_128_GCM_SHA256, psk, ecdhe, out);
}

/* Expand one packet-protection field (RFC 9001 5.1 labels) from a secret. */
static void hs_field(
    u16 suite, const u8* secret, wired_span label, wired_mspan out) {
  hkdf_label l = {(const char*)label.p, label.n, {0, 0}};
  tls_hash_of(suite)->expand_label(secret, &l, out);
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

void tls_handshake_keys(const handshake_keys_in* in, initial_keys* out) {
  tls_handshake_keys_suite(in, TLS_AES_128_GCM_SHA256, out);
}

/* Expand the QUIC key/iv/hp triple from a traffic secret, sized for suite
 * (RFC 8446 B.4; AES_128_GCM_SHA256 key=16/hp=16, CHACHA20_POLY1305_SHA256
 * key=32/hp=32 -- RFC 9001 5.1/5.4.3), with `version`'s label prefix
 * (RFC 9369 3.3.1; 0 = v1). */
static void protection_keys_suite(
    const u8* ts, u16 suite, u32 version, initial_keys* out) {
  usz key_len = resolved_key_len(suite), hp_len = resolved_hp_len(suite);
  u8  lb[VERSION_LABEL_MAX];
  hs_field(
      suite, ts, sched_quic_label(lb, version, "key", 3),
      wired_mspan_of(out->key, key_len));
  hs_field(
      suite, ts, sched_quic_label(lb, version, "iv", 2),
      wired_mspan_of(out->iv, INITIAL_IV));
  hs_field(
      suite, ts, sched_quic_label(lb, version, "hp", 2),
      wired_mspan_of(out->hp, hp_len));
  protection_keys_zero_tail(out, key_len, hp_len);
}

void tls_handshake_keys_suite(
    const handshake_keys_in* in, u16 suite, initial_keys* out) {
  const char*      label = in->is_server ? "s hs traffic" : "c hs traffic";
  u8               ts[TLS_HASH_MAX];
  derive_secret_in dsi =
      derive_in(suite, in->hs_secret, (ascii_label){label, 12}, in->transcript);
  tls_derive_secret(&dsi, ts);
  protection_keys_suite(ts, suite, in->version, out);
}

void tls_early_traffic_secret_suite(
    u16 suite, const u8* psk, wired_span client_hello, u8* out) {
  u8 early[TLS_HASH_MAX];
  sched_early_secret(suite, psk, early);
  /* client_early_traffic_secret over the ClientHello. */
  derive_secret_in in =
      derive_in(suite, early, (ascii_label){"c e traffic", 11}, client_hello);
  tls_derive_secret(&in, out);
}

void tls_early_traffic_secret(
    const u8* psk, const u8* client_hello, usz client_hello_len, u8* out) {
  tls_early_traffic_secret_suite(
      TLS_AES_128_GCM_SHA256, psk,
      wired_span_of(client_hello, client_hello_len), out);
}

void tls_early_keys_suite(
    u16           suite,
    const u8*     psk,
    const u8*     client_hello,
    usz           client_hello_len,
    initial_keys* out) {
  u8 ts[TLS_HASH_MAX];
  tls_early_traffic_secret_suite(
      suite, psk, wired_span_of(client_hello, client_hello_len), ts);
  /* RFC 9368 2.3: 0-RTT is only ever sent under the client's original
   * version, before any compatible switch -- always the v1 labels here. */
  protection_keys_suite(ts, suite, VERSION_1, out);
}

void tls_early_keys(
    const u8*     psk,
    const u8*     client_hello,
    usz           client_hello_len,
    initial_keys* out) {
  tls_early_keys_suite(
      TLS_AES_128_GCM_SHA256, psk, client_hello, client_hello_len, out);
}
