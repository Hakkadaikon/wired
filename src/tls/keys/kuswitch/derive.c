#include "tls/keys/kuswitch/derive.h"

#include "tls/handshake/core/tls/aead_params.h"
#include "tls/handshake/core/tls/suitehash.h"
#include "tls/keys/keyupdate/kuderive.h"

/* RFC 9001 6.1: key and iv re-derived from next_secret at key_len bytes; hp
 * stays as-is across a key update (shared by both entry points below). */
static void kuswitch_derive_key_iv(
    u16 suite, const u8* next_secret, initial_keys* next_keys, usz key_len) {
  const tls_hash* h  = tls_hash_of(suite);
  hkdf_label      lk = {"quic key", 8, {0, 0}};
  hkdf_label      li = {"quic iv", 7, {0, 0}};
  h->expand_label(next_secret, &lk, wired_mspan_of(next_keys->key, key_len));
  h->expand_label(next_secret, &li, wired_mspan_of(next_keys->iv, INITIAL_IV));
}

void kuswitch_next_keys(
    const u8      current_secret[HKDF_PRK],
    initial_keys* next_keys,
    u8            next_secret[HKDF_PRK]) {
  /* RFC 9001 6.1: secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku"). */
  ku_next_secret(current_secret, next_secret);
  kuswitch_derive_key_iv(0, next_secret, next_keys, INITIAL_KEY);
}

void kuswitch_next_keys_v(
    u32           version,
    const u8      current_secret[HKDF_PRK],
    initial_keys* next_keys,
    u8            next_secret[HKDF_PRK]) {
  /* RFC 9369 3.3.2: secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quicv2 ku")
   * for v2, "quic ku" for v1 (RFC 9001 6.1). */
  ku_next_secret_v(version, current_secret, next_secret);
  kuswitch_derive_key_iv(0, next_secret, next_keys, INITIAL_KEY);
}

void kuswitch_next_keys_suite(
    u16           suite,
    const u8*     current_secret,
    initial_keys* next_keys,
    u8*           next_secret) {
  /* RFC 9001 6.1: HKDF-Expand-Label(secret_<n>, "quic ku", "",
   * Hash.length) over the suite's own hash. */
  const tls_hash* h = tls_hash_of(suite);
  hkdf_label      l = {"quic ku", 7, {0, 0}};
  h->expand_label(current_secret, &l, wired_mspan_of(next_secret, h->len));
  kuswitch_derive_key_iv(suite, next_secret, next_keys, aead_key_len(suite));
}
