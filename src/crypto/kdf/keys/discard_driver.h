#ifndef QUIC_KEYS_DISCARD_DRIVER_H
#define QUIC_KEYS_DISCARD_DRIVER_H

#include "crypto/kdf/keys/keyset.h"

/* RFC 9001 4.9.1: Initial keys are discarded once Handshake keys are
 * installed; Handshake keys are discarded once the handshake is confirmed. */

/* 1 if Initial keys should be discarded, else 0. */
int quic_key_should_discard_initial(int handshake_keys_installed);

/* 1 if Handshake keys should be discarded, else 0. */
int quic_key_should_discard_handshake(int handshake_confirmed);

/* Drop the key set at level (0/1/2). Returns 1 ok, 0 if level out of range.
 * After discard, quic_keyset_for_level reports the level not installed. */
int quic_keyset_discard(quic_keyset* state, int level);

#endif
