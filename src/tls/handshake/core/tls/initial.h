#ifndef QUIC_TLS_INITIAL_H
#define QUIC_TLS_INITIAL_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"

/** @file
 * RFC 9001 5.2: Initial packet protection keys derived from the client's
 * Destination Connection ID. AES-128-GCM, so key=16, iv=12, hp=16. */

/** AES-128-GCM packet protection key length in bytes. */
#define QUIC_INITIAL_KEY 16
/** AEAD IV length in bytes. */
#define QUIC_INITIAL_IV 12
/** Header protection key length in bytes. */
#define QUIC_INITIAL_HP 16

/** One direction's Initial packet protection keys (RFC 9001 5.2). */
typedef struct {
  u8 key[QUIC_INITIAL_KEY]; /**< AEAD packet protection key */
  u8 iv[QUIC_INITIAL_IV];   /**< AEAD IV */
  u8 hp[QUIC_INITIAL_HP];   /**< header protection key */
} quic_initial_keys;

/** Derive the client (is_server=0) or server (is_server=1) Initial keys from
 * the Destination Connection ID of the client's first Initial packet.
 * @param dcid the Destination Connection ID of the client's first Initial
 * @param is_server 1 for the server keys, 0 for the client keys
 * @param out receives the derived keys */
void quic_initial_derive(quic_span dcid, int is_server, quic_initial_keys* out);

#endif
