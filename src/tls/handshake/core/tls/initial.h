#ifndef QUIC_TLS_INITIAL_H
#define QUIC_TLS_INITIAL_H

#include "crypto/kdf/hkdf/hkdf.h"

/* RFC 9001 5.2: Initial packet protection keys derived from the client's
 * Destination Connection ID. AES-128-GCM, so key=16, iv=12, hp=16. */

#define QUIC_INITIAL_KEY 16
#define QUIC_INITIAL_IV  12
#define QUIC_INITIAL_HP  16

typedef struct {
    u8 key[QUIC_INITIAL_KEY];
    u8 iv[QUIC_INITIAL_IV];
    u8 hp[QUIC_INITIAL_HP];
} quic_initial_keys;

/* Derive the client (is_server=0) or server (is_server=1) Initial keys from
 * the Destination Connection ID of the client's first Initial packet. */
void quic_initial_derive(const u8 *dcid, usz dcid_len, int is_server,
                         quic_initial_keys *out);

#endif
