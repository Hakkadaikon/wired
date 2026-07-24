#ifndef QUIC_TICKET_TICKET_H
#define QUIC_TICKET_TICKET_H

#include "common/bytes/span/span.h"

/* TLS 1.3 NewSessionTicket payload (RFC 8446 4.6.1), the part this SDK
 * persists for session resumption: the resumption secret plus the fields
 * needed to judge whether the ticket is still usable. Sealed opaque to the
 * client; only the server ever parses this struct. */

#define QUIC_TICKET_SECRET_LEN 32
#define QUIC_TICKET_KEY_LEN 32 /* ChaCha20-Poly1305 key (RFC 8439 2.8) */

/* Sealed-ticket framing: nonce || ciphertext || tag. */
#define QUIC_TICKET_NONCE_LEN 12
#define QUIC_TICKET_TAG_LEN 16
#define QUIC_TICKET_PLAIN_LEN (QUIC_TICKET_SECRET_LEN + 8 + 4 + 4)
#define QUIC_TICKET_SEALED_LEN \
  (QUIC_TICKET_NONCE_LEN + QUIC_TICKET_PLAIN_LEN + QUIC_TICKET_TAG_LEN)

/** One resumption ticket's plaintext contents (RFC 8446 4.6.1). */
typedef struct {
  u8  secret[QUIC_TICKET_SECRET_LEN]; /**< resumption master secret */
  u64 issued_at;                      /**< server clock at issuance */
  u32 lifetime_secs;                  /**< ticket_lifetime (RFC 8446 4.6.1) */
  u32 age_add; /**< ticket_age_add (RFC 8446 4.6.1), random per ticket */
} quic_ticket;

/* Seal a ticket under the server's fixed key: out receives
 * QUIC_TICKET_SEALED_LEN bytes (a fresh random nonce, then the encrypted
 * ticket, then the auth tag). The nonce is drawn fresh per call so the same
 * key never reuses a nonce. */
void quic_ticket_seal(
    const quic_ticket* t, const u8 key[QUIC_TICKET_KEY_LEN], u8* out);

/* Open a sealed ticket produced by quic_ticket_seal. in must span exactly
 * QUIC_TICKET_SEALED_LEN bytes. Returns 1 and fills *out on success; returns
 * 0 (leaving *out untouched) if the key is wrong or the bytes were altered. */
int quic_ticket_open(
    quic_span in, const u8 key[QUIC_TICKET_KEY_LEN], quic_ticket* out);

#endif
