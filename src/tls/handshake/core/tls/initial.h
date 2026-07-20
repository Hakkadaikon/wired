#ifndef QUIC_TLS_INITIAL_H
#define QUIC_TLS_INITIAL_H

#include "common/bytes/span/span.h"
#include "crypto/kdf/hkdf/hkdf.h"
#include "transport/version/version/version.h"

/** @file
 * RFC 9001 5.2: Initial packet protection keys derived from the client's
 * Destination Connection ID. Initial is always AES-128-GCM, so key=16,
 * iv=12, hp=16. Handshake/1-RTT levels reuse this same struct (RFC 9001 5.1)
 * and may instead be negotiated to ChaCha20-Poly1305 (RFC 8446 B.4 0x1303),
 * whose key is 32 bytes -- key[] is sized QUIC_AEAD_KEY_MAX to hold either. */

/** AES-128-GCM packet protection key length in bytes (Initial, always). */
#define QUIC_INITIAL_KEY 16
/** Largest AEAD key this SDK derives (ChaCha20-Poly1305, RFC 8446 5.3). */
#define QUIC_AEAD_KEY_MAX 32
/** AEAD IV length in bytes. */
#define QUIC_INITIAL_IV 12
/** Header protection key length in bytes for AES; ChaCha20 HP also uses a
 * 32-byte key (RFC 9001 5.4.3), so hp[] is sized QUIC_AEAD_KEY_MAX too. */
#define QUIC_INITIAL_HP 16

/** One direction's packet protection keys (RFC 9001 5.1/5.2). key/hp are
 * sized for the largest supported AEAD (ChaCha20-Poly1305); a suite that
 * uses fewer bytes (AES-128-GCM) simply leaves the tail unused. */
typedef struct {
  u8 key[QUIC_AEAD_KEY_MAX]; /**< AEAD packet protection key */
  u8 iv[QUIC_INITIAL_IV];    /**< AEAD IV */
  u8 hp[QUIC_AEAD_KEY_MAX];  /**< header protection key */
} quic_initial_keys;

/** Derive the client (is_server=0) or server (is_server=1) Initial keys from
 * the Destination Connection ID of the client's first Initial packet, using
 * the Initial salt and HKDF-Expand-Label prefix for `version` (RFC 9001 5.2
 * for v1, RFC 9369 3.3.1 for v2). An unknown version falls back to the v1
 * salt/prefix (RFC 9000 17.2 invariants still apply before a version is
 * negotiated).
 * @param dcid the Destination Connection ID of the client's first Initial
 * @param is_server 1 for the server keys, 0 for the client keys
 * @param version the QUIC version whose salt/label prefix to use
 * @param out receives the derived keys */
void quic_initial_derive(
    quic_span dcid, int is_server, u32 version, quic_initial_keys* out);

#endif
