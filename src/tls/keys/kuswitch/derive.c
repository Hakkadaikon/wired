#include "tls/keys/kuswitch/derive.h"

#include "tls/keys/keyupdate/kuderive.h"

void quic_kuswitch_next_keys(const u8 current_secret[QUIC_HKDF_PRK],
                             quic_initial_keys *next_keys,
                             u8 next_secret[QUIC_HKDF_PRK])
{
    /* RFC 9001 6.1: secret_<n+1> = HKDF-Expand-Label(secret_<n>, "quic ku"). */
    quic_ku_next_secret(current_secret, next_secret);
    /* RFC 9001 5.1: key and iv from the new secret; hp stays as RFC 9001 6.1. */
    quic_hkdf_expand_label(next_secret, "quic key", 8, 0, 0,
                           next_keys->key, QUIC_INITIAL_KEY);
    quic_hkdf_expand_label(next_secret, "quic iv", 7, 0, 0,
                           next_keys->iv, QUIC_INITIAL_IV);
}
