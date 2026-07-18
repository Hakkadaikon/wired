#include "tls/keys/kuswitch/derive.h"

#include "tls/handshake/core/tls/aead_params.h"
#include "tls/keys/keyupdate/kuderive.h"

/* RFC 9001 6.1: key and iv re-derived from next_secret at key_len bytes; hp
 * stays as-is across a key update (shared by both entry points below). */
static void kuswitch_derive_key_iv(
    const u8 next_secret[QUIC_HKDF_PRK],
    quic_initial_keys* next_keys,
    usz                key_len) {
  quic_hkdf_label lk = {"quic key", 8, {0, 0}};
  quic_hkdf_label li = {"quic iv", 7, {0, 0}};
  quic_hkdf_expand_label(
      next_secret, &lk, quic_mspan_of(next_keys->key, key_len));
  quic_hkdf_expand_label(
      next_secret, &li, quic_mspan_of(next_keys->iv, QUIC_INITIAL_IV));
}

void quic_kuswitch_next_keys(
    const u8           current_secret[QUIC_HKDF_PRK],
    quic_initial_keys* next_keys,
    u8                 next_secret[QUIC_HKDF_PRK]) {
  /* RFC 9001 6.1: secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku"). */
  quic_ku_next_secret(current_secret, next_secret);
  kuswitch_derive_key_iv(next_secret, next_keys, QUIC_INITIAL_KEY);
}

void quic_kuswitch_next_keys_suite(
    u16                suite,
    const u8           current_secret[QUIC_HKDF_PRK],
    quic_initial_keys* next_keys,
    u8                 next_secret[QUIC_HKDF_PRK]) {
  quic_ku_next_secret(current_secret, next_secret);
  kuswitch_derive_key_iv(next_secret, next_keys, quic_aead_key_len(suite));
}
