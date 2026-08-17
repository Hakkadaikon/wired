#ifndef QUIC_KEYS_PROMOTE_H
#define QUIC_KEYS_PROMOTE_H

#include "crypto/kdf/keys/keyset.h"

/* RFC 9001 4.1.4: protection keys are taken into use in strictly increasing
 * order (Initial -> Handshake -> 1-RTT); no level may be skipped. */

/* 1 if new_level is exactly one above current_max_level, else 0. */
int key_promote_ok(int current_max_level, int new_level);

/* RFC 9001 4.9: the highest protection level used to send. Once the TLS
 * handshake is complete, 1-RTT keys are used; until then, Handshake. */
int key_send_level(int handshake_complete, int handshake_confirmed);

#endif
