#ifndef QUIC_TLS_NEWSESSIONTICKET_H
#define QUIC_TLS_NEWSESSIONTICKET_H

#include "common/bytes/span/span.h"
#include "tls/keys/ticket/ticket.h"

/* RFC 8446 4.6.1: NewSessionTicket handshake message, minimal server-issued
 * form. This SDK does not yet implement client-side resumption, so only the
 * fields this codebase itself round-trips are real:
 *   ticket_lifetime(4) ticket_age_add(4) ticket_nonce_len(1)=0
 *   ticket(2-byte length prefixed, the sealed quic_ticket) extensions_len(2)
 * followed by the early_data extension (RFC 8446 4.2.10, 0x002a) when
 * max_early_data_size is nonzero. ticket_age_add is drawn fresh per ticket
 * (RFC 8446 4.6.1) and also sealed inside the ticket itself so the server can
 * recover it later to check 0-RTT freshness (RFC 8446 4.2.11.1).
 * ponytail: no ticket_nonce — a real client needs a per-ticket nonce for
 * multi-ticket PSK selection; add it when client-side resumption is
 * implemented. */

#define QUIC_HS_NEW_SESSION_TICKET 4

/* Seal `t` under `key` and encode the NewSessionTicket message into out.
 * max_early_data_size 0 omits the early_data extension entirely (matching
 * the pre-existing wire format); nonzero appends it (RFC 9001 4.6.1: QUIC
 * servers that accept 0-RTT always advertise 0xffffffff here -- QUIC bounds
 * 0-RTT via transport parameters, not this TLS field).
 * Returns total message length, or 0 if cap is too small. */
usz quic_tls_new_session_ticket_encode(
    u8*                out,
    usz                cap,
    const quic_ticket* t,
    const u8           key[QUIC_TICKET_KEY_LEN],
    u32                max_early_data_size);

/* Parse a NewSessionTicket message (msg.p[0..msg.n)) and return the sealed
 * ticket bytes as a view into msg (still opaque; call quic_ticket_open with
 * the server's key to recover the quic_ticket). Returns 1 on success, 0 if
 * msg is truncated or inconsistent. */
int quic_tls_new_session_ticket_parse(quic_span msg, quic_span* sealed);

#endif
