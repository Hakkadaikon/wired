#include "tls/handshake/core/tls/appkeys.h"

#include "tls/handshake/core/tls/aead_params.h"
#include "tls/handshake/core/tls/hp_select.h"
#include "tls/handshake/core/tls/schedule.h"

/* RFC 9001 5.1/5.4.3: AEAD key / header-protection key length for suite,
 * falling back to the AES-128 length on an unrecognized suite. */
static usz appkeys_key_len(u16 suite) {
  usz n = quic_aead_key_len(suite);
  return n ? n : QUIC_INITIAL_KEY;
}
static usz appkeys_hp_len(u16 suite) {
  usz n = quic_hp_key_len(suite);
  return n ? n : QUIC_INITIAL_HP;
}

/* out->key/out->hp are sized QUIC_AEAD_KEY_MAX to hold either suite (see
 * initial.h); a suite shorter than that (AES_128_GCM_SHA256) leaves a tail
 * the HKDF expand never touches. Zero it so out is always a fully
 * deterministic value, not partly whatever the caller's buffer held before
 * (e.g. two independent derivations of the same AES keys must compare equal
 * byte-for-byte, not just in the bytes AES actually uses). */
static void appkeys_zero_tail(quic_initial_keys* out, usz key_len, usz hp_len) {
  for (usz i = key_len; i < QUIC_AEAD_KEY_MAX; i++) out->key[i] = 0;
  for (usz i = hp_len; i < QUIC_AEAD_KEY_MAX; i++) out->hp[i] = 0;
}

void quic_tls_app_keys(const quic_app_keys_in* in, quic_initial_keys* out) {
  const char* label = in->is_server ? "s ap traffic" : "c ap traffic";
  u8          ts[QUIC_HKDF_PRK];
  /* RFC 8446 7.1: application_traffic_secret_0. */
  quic_derive_secret_in dsi = {
      in->master, quic_span_of((const u8*)label, 12), in->transcript};
  quic_tls_derive_secret(&dsi, ts);
  /* RFC 9001 5.1: expand the QUIC packet-protection triple. */
  quic_hkdf_label lk = {"quic key", 8, {0, 0}};
  quic_hkdf_label li = {"quic iv", 7, {0, 0}};
  quic_hkdf_label lh = {"quic hp", 7, {0, 0}};
  quic_hkdf_expand_label(ts, &lk, quic_mspan_of(out->key, QUIC_INITIAL_KEY));
  quic_hkdf_expand_label(ts, &li, quic_mspan_of(out->iv, QUIC_INITIAL_IV));
  quic_hkdf_expand_label(ts, &lh, quic_mspan_of(out->hp, QUIC_INITIAL_HP));
  appkeys_zero_tail(out, QUIC_INITIAL_KEY, QUIC_INITIAL_HP);
}

void quic_tls_app_keys_suite(
    const quic_app_keys_in* in, u16 suite, quic_initial_keys* out) {
  const char* label = in->is_server ? "s ap traffic" : "c ap traffic";
  u8          ts[QUIC_HKDF_PRK];
  usz         key_len = appkeys_key_len(suite), hp_len = appkeys_hp_len(suite);
  quic_derive_secret_in dsi = {
      in->master, quic_span_of((const u8*)label, 12), in->transcript};
  quic_tls_derive_secret(&dsi, ts);
  /* RFC 9001 5.1: expand the QUIC packet-protection triple, sized for the
   * negotiated suite (RFC 8446 B.4). */
  quic_hkdf_label lk = {"quic key", 8, {0, 0}};
  quic_hkdf_label li = {"quic iv", 7, {0, 0}};
  quic_hkdf_label lh = {"quic hp", 7, {0, 0}};
  quic_hkdf_expand_label(ts, &lk, quic_mspan_of(out->key, key_len));
  quic_hkdf_expand_label(ts, &li, quic_mspan_of(out->iv, QUIC_INITIAL_IV));
  quic_hkdf_expand_label(ts, &lh, quic_mspan_of(out->hp, hp_len));
  appkeys_zero_tail(out, key_len, hp_len);
}
