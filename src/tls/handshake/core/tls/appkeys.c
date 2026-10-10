#include "tls/handshake/core/tls/appkeys.h"

#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/aead_params.h"
#include "tls/handshake/core/tls/cipher.h"
#include "tls/handshake/core/tls/hp_select.h"
#include "tls/handshake/core/tls/schedule.h"
#include "transport/version/version/v2keys.h"

/* RFC 9001 5.1/5.4.3: AEAD key / header-protection key length for suite,
 * falling back to the AES-128 length on an unrecognized suite. */
static usz appkeys_key_len(u16 suite) {
  usz n = aead_key_len(suite);
  return n ? n : INITIAL_KEY;
}
static usz appkeys_hp_len(u16 suite) {
  usz n = hp_key_len(suite);
  return n ? n : INITIAL_HP;
}

/* out->key/out->hp are sized AEAD_KEY_MAX to hold either suite (see
 * initial.h); a suite shorter than that (AES_128_GCM_SHA256) leaves a tail
 * the HKDF expand never touches. Zero it so out is always a fully
 * deterministic value, not partly whatever the caller's buffer held before
 * (e.g. two independent derivations of the same AES keys must compare equal
 * byte-for-byte, not just in the bytes AES actually uses). */
static void appkeys_zero_tail(initial_keys* out, usz key_len, usz hp_len) {
  for (usz i = key_len; i < AEAD_KEY_MAX; i++) out->key[i] = 0;
  for (usz i = hp_len; i < AEAD_KEY_MAX; i++) out->hp[i] = 0;
}

/* Expand one packet-protection field under the "<quic |quicv2 ><suffix>"
 * label for `version` (RFC 9001 5.1 / RFC 9369 3.3.1; 0 = v1), over
 * suite's hash. */
static void appkeys_field(
    u16 suite, const u8* ts, u32 version, const char* sfx, wired_mspan out) {
  u8         lb[VERSION_LABEL_MAX];
  usz        n = version_quic_label(lb, version, sfx, wired_cstr_len(sfx));
  hkdf_label l = {(const char*)lb, n, {0, 0}};
  tls_hash_of(suite)->expand_label(ts, &l, out);
}

void tls_app_keys(const app_keys_in* in, initial_keys* out) {
  tls_app_keys_suite(in, TLS_AES_128_GCM_SHA256, out);
}

void tls_app_keys_suite(const app_keys_in* in, u16 suite, initial_keys* out) {
  const char* label = in->is_server ? "s ap traffic" : "c ap traffic";
  u8          ts[TLS_HASH_MAX];
  usz         key_len = appkeys_key_len(suite), hp_len = appkeys_hp_len(suite);
  derive_secret_in dsi = {
      in->master, wired_span_of((const u8*)label, 12), in->transcript, suite};
  /* RFC 8446 7.1: application_traffic_secret_0. */
  tls_derive_secret(&dsi, ts);
  /* RFC 9001 5.1: expand the QUIC packet-protection triple, sized for the
   * negotiated suite (RFC 8446 B.4). */
  appkeys_field(
      suite, ts, in->version, "key", wired_mspan_of(out->key, key_len));
  appkeys_field(
      suite, ts, in->version, "iv", wired_mspan_of(out->iv, INITIAL_IV));
  appkeys_field(suite, ts, in->version, "hp", wired_mspan_of(out->hp, hp_len));
  appkeys_zero_tail(out, key_len, hp_len);
}
