#ifndef QUIC_KUSWITCH_DERIVE_H
#define QUIC_KUSWITCH_DERIVE_H

#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 6.1: derive the next generation's 1-RTT keys. The next application
 * traffic secret comes from the current one via HKDF-Expand-Label("quic ku"),
 * then key and iv are re-derived from it; the header-protection key is
 * unchanged across a key update, so next_keys->hp is left untouched.
 * AES-128-GCM only (key length fixed at QUIC_INITIAL_KEY) -- see
 * quic_kuswitch_next_keys_suite for a negotiated-suite connection. */
void quic_kuswitch_next_keys(
    const u8           current_secret[QUIC_HKDF_PRK],
    quic_initial_keys* next_keys,
    u8                 next_secret[QUIC_HKDF_PRK]);

/* Same as quic_kuswitch_next_keys, but derives next_keys->key at the given
 * suite's own AEAD key length (RFC 8446 5.3: 16 for AES-128-GCM, 32 for
 * ChaCha20-Poly1305) instead of the fixed AES-only QUIC_INITIAL_KEY --
 * without this, a ChaCha20-negotiated connection's Key Update only fills
 * the first 16 of the 32 key bytes it actually needs, leaving the tail
 * stale and every post-update packet fails to open. */
void quic_kuswitch_next_keys_suite(
    u16                suite,
    const u8           current_secret[QUIC_HKDF_PRK],
    quic_initial_keys* next_keys,
    u8                 next_secret[QUIC_HKDF_PRK]);

#endif
