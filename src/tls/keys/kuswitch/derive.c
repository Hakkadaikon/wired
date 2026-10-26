#include "tls/keys/kuswitch/derive.h"

#include "common/bytes/util/bytes.h"
#include "tls/handshake/core/tls/aead_params.h"
#include "tls/handshake/core/tls/suitehash.h"
#include "tls/keys/keyupdate/kuderive.h"
#include "transport/version/version/v2keys.h"

/* Expand one field from secret under the "<quic |quicv2 ><sfx>" label for
 * `version` (RFC 9001 6.1 / RFC 9369 3.3.2; 0/unknown = v1), over suite's
 * hash. */
static void kuswitch_expand(
    u16         suite,
    u32         version,
    const u8*   secret,
    const char* sfx,
    wired_mspan out) {
  u8         lb[VERSION_LABEL_MAX];
  usz        n = version_quic_label(lb, version, sfx, wired_cstr_len(sfx));
  hkdf_label l = {(const char*)lb, n, {0, 0}};
  tls_hash_of(suite)->expand_label(secret, &l, out);
}

/* RFC 9001 6.1: key and iv re-derived from next_secret at key_len bytes; hp
 * stays as-is across a key update (shared by both entry points below). */
static void kuswitch_derive_key_iv(
    u16           suite,
    u32           version,
    const u8*     next_secret,
    initial_keys* next_keys,
    usz           key_len) {
  kuswitch_expand(
      suite, version, next_secret, "key",
      wired_mspan_of(next_keys->key, key_len));
  kuswitch_expand(
      suite, version, next_secret, "iv",
      wired_mspan_of(next_keys->iv, INITIAL_IV));
}

void kuswitch_next_keys(
    const u8      current_secret[HKDF_PRK],
    initial_keys* next_keys,
    u8            next_secret[HKDF_PRK]) {
  /* RFC 9001 6.1: secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku"). */
  ku_next_secret(current_secret, next_secret);
  kuswitch_derive_key_iv(0, VERSION_1, next_secret, next_keys, INITIAL_KEY);
}

void kuswitch_next_keys_suite(
    u16           suite,
    u32           version,
    const u8*     current_secret,
    initial_keys* next_keys,
    u8*           next_secret) {
  /* RFC 9001 6.1 / RFC 9369 3.3.2: HKDF-Expand-Label(secret_<n>, "quic ku"
   * or "quicv2 ku", "", Hash.length) over the suite's own hash. */
  kuswitch_expand(
      suite, version, current_secret, "ku",
      wired_mspan_of(next_secret, tls_hash_of(suite)->len));
  kuswitch_derive_key_iv(
      suite, version, next_secret, next_keys, aead_key_len(suite));
}
