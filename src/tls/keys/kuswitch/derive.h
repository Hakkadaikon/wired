#ifndef QUIC_KUSWITCH_DERIVE_H
#define QUIC_KUSWITCH_DERIVE_H

#include "tls/handshake/core/tls/initial.h"

/* RFC 9001 6.1: derive the next generation's 1-RTT keys. The next application
 * traffic secret comes from the current one via HKDF-Expand-Label("quic ku"),
 * then key and iv are re-derived from it; the header-protection key is
 * unchanged across a key update, so next_keys->hp is left untouched. */
void quic_kuswitch_next_keys(const u8 current_secret[QUIC_HKDF_PRK],
                             quic_initial_keys *next_keys,
                             u8 next_secret[QUIC_HKDF_PRK]);

#endif
