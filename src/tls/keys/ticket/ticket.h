#ifndef TICKET_TICKET_H
#define TICKET_TICKET_H

#include "common/bytes/span/span.h"

/* TLS 1.3 NewSessionTicket payload (RFC 8446 4.6.1), the part this SDK
 * persists for session resumption: the resumption secret plus the fields
 * needed to judge whether the ticket is still usable. Sealed opaque to the
 * client; only the server ever parses this struct. */

#define TICKET_SECRET_LEN 32
#define TICKET_KEY_LEN 32 /* ChaCha20-Poly1305 key (RFC 8439 2.8) */

/* Sealed-ticket framing: nonce || ciphertext || tag. */
#define TICKET_NONCE_LEN 12
#define TICKET_TAG_LEN 16
#define TICKET_PLAIN_LEN (TICKET_SECRET_LEN + 8 + 4 + 4)
#define TICKET_SEALED_LEN (TICKET_NONCE_LEN + TICKET_PLAIN_LEN + TICKET_TAG_LEN)

/** One resumption ticket's plaintext contents (RFC 8446 4.6.1). */
typedef struct {
  u8  secret[TICKET_SECRET_LEN]; /**< resumption master secret */
  u64 issued_at;                 /**< server clock at issuance */
  u32 lifetime_secs;             /**< ticket_lifetime (RFC 8446 4.6.1) */
  u32 age_add; /**< ticket_age_add (RFC 8446 4.6.1), random per ticket */
} ticket;

/* Seal a ticket under the server's fixed key: out receives
 * TICKET_SEALED_LEN bytes (a fresh random nonce, then the encrypted
 * ticket, then the auth tag). The nonce is drawn fresh per call so the same
 * key never reuses a nonce. */
void ticket_seal(const ticket* t, const u8 key[TICKET_KEY_LEN], u8* out);

/* Open a sealed ticket produced by ticket_seal. in must span exactly
 * TICKET_SEALED_LEN bytes. Returns 1 and fills *out on success; returns
 * 0 (leaving *out untouched) if the key is wrong or the bytes were altered. */
int ticket_open(wired_span in, const u8 key[TICKET_KEY_LEN], ticket* out);

#endif
