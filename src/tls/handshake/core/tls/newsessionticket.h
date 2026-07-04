#ifndef QUIC_TLS_NEWSESSIONTICKET_H
#define QUIC_TLS_NEWSESSIONTICKET_H

#include "common/bytes/span/span.h"
#include "tls/keys/ticket/ticket.h"

/* RFC 8446 4.6.1: NewSessionTicket handshake message, minimal server-issued
 * form. This SDK does not yet implement client-side resumption, so only the
 * fields this codebase itself round-trips are real:
 *   ticket_lifetime(4) ticket_age_add(4)=0 ticket_nonce_len(1)=0
 *   ticket(2-byte length prefixed, the sealed quic_ticket) extensions_len(2)=0
 * ponytail: ticket_age_add fixed at 0 and no extensions/nonce — a real client
 * needs a random age_add and a per-ticket nonce for multi-ticket PSK
 * selection; add both when client-side resumption is implemented. */

#define QUIC_HS_NEW_SESSION_TICKET 4

/* Seal `t` under `key` and encode the NewSessionTicket message into out.
 * Returns total message length, or 0 if cap is too small. */
usz quic_tls_new_session_ticket_encode(
    u8 *out, usz cap, const quic_ticket *t, const u8 key[QUIC_TICKET_KEY_LEN]);

/* Parse a NewSessionTicket message (msg.p[0..msg.n)) and return the sealed
 * ticket bytes as a view into msg (still opaque; call quic_ticket_open with
 * the server's key to recover the quic_ticket). Returns 1 on success, 0 if
 * msg is truncated or inconsistent. */
int quic_tls_new_session_ticket_parse(quic_span msg, quic_span *sealed);

#endif
