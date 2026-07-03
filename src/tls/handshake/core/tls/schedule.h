#ifndef QUIC_TLS_SCHEDULE_H
#define QUIC_TLS_SCHEDULE_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "tls/handshake/core/tls/initial.h"

/* RFC 8446 7.1 key schedule (the handshake portion QUIC needs) plus the
 * QUIC packet-protection keys (RFC 9001 5.1) for the handshake level. */

/* Derive-Secret(secret, label, messages) inputs: label is the ASCII label
 * bytes (no "tls13 " prefix, that is added by hkdf), messages the transcript
 * bytes to hash. */
typedef struct {
  const u8 *secret; /* QUIC_HKDF_PRK bytes */
  quic_span label;
  quic_span messages;
} quic_derive_secret_in;

/* Derive-Secret(secret, label, messages) = HKDF-Expand-Label(secret, label,
 * Hash(messages), Hash.length). Writes a 32-byte secret. */
void quic_tls_derive_secret(const quic_derive_secret_in *in, u8 out[QUIC_HKDF_PRK]);

/* Handshake Secret = HKDF-Extract(derived-from-early, ECDHE shared secret). */
void quic_tls_handshake_secret(const u8 ecdhe[32], u8 out[QUIC_HKDF_PRK]);

/* quic_tls_handshake_keys inputs: hs_secret is the Handshake Secret,
 * transcript the handshake bytes hashed for the traffic secret, is_server
 * selects the "s hs traffic"/"c hs traffic" label. */
typedef struct {
  const u8 *hs_secret; /* QUIC_HKDF_PRK bytes */
  quic_span transcript;
  int       is_server;
} quic_handshake_keys_in;

/* From the handshake secret and the handshake transcript, derive one side's
 * (is_server) handshake-level QUIC packet protection keys. */
void quic_tls_handshake_keys(
    const quic_handshake_keys_in *in, quic_initial_keys *out);

/* RFC 9001 4.6 / RFC 8446 7.1: 0-RTT (early data) packet protection keys.
 * From a pre-shared key, derive client_early_traffic_secret over the
 * ClientHello transcript and expand the QUIC key/iv/hp. Only the client
 * direction exists for 0-RTT. */
void quic_tls_early_keys(
    const u8           psk[QUIC_HKDF_PRK],
    const u8          *client_hello,
    usz                client_hello_len,
    quic_initial_keys *out);

#endif
