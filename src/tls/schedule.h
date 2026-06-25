#ifndef QUIC_TLS_SCHEDULE_H
#define QUIC_TLS_SCHEDULE_H

#include "hkdf/hkdf.h"
#include "tls/initial.h"

/* RFC 8446 7.1 key schedule (the handshake portion QUIC needs) plus the
 * QUIC packet-protection keys (RFC 9001 5.1) for the handshake level. */

/* Derive-Secret(secret, label, messages) = HKDF-Expand-Label(secret, label,
 * Hash(messages), Hash.length). Writes a 32-byte secret. */
void quic_tls_derive_secret(const u8 secret[QUIC_HKDF_PRK],
                            const char *label, usz label_len,
                            const u8 *messages, usz messages_len,
                            u8 out[QUIC_HKDF_PRK]);

/* Handshake Secret = HKDF-Extract(derived-from-early, ECDHE shared secret). */
void quic_tls_handshake_secret(const u8 ecdhe[32],
                               u8 out[QUIC_HKDF_PRK]);

/* From the handshake secret and the handshake transcript, derive one side's
 * (is_server) handshake-level QUIC packet protection keys. */
void quic_tls_handshake_keys(const u8 hs_secret[QUIC_HKDF_PRK],
                             const u8 *transcript, usz transcript_len,
                             int is_server, quic_initial_keys *out);

#endif
