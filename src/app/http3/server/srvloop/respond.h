#ifndef WIRED_SRVLOOP_RESPOND_H
#define WIRED_SRVLOOP_RESPOND_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"
#include "tls/keys/ticket/ticket.h"

/** RFC 8446 4.6.1: this process's fixed session-ticket encryption key (the
 * same key append_ticket_frame seals NewSessionTickets under) -- exposed so
 * the caller can also thread it to wired_srvboot_id.ticket_key for OPENING a
 * presented ticket (RFC 8446 4.2.11 resumption is symmetric: one key seals
 * and opens). QUIC_TICKET_KEY_LEN bytes, valid for the process lifetime.
 * @return a pointer to the fixed ticket key. */
const u8* wired_srvloop_ticket_key(void);

/* RFC 9000 12.2 / 13.2.1 / RFC 9114 6.2.1: pick the outbound datagram for one
 * step. The first reply emits the confirmation (SETTINGS + HANDSHAKE_DONE),
 * coalescing the 200 into its 1-RTT payload when the confirming datagram also
 * carried a GET; later replies are a 200 or a bare 1-RTT ACK, the confirmation
 * never repeated. Returns 1 and sets out->len when a packet was written, else
 * 0.
 */
int wired_srvloop_produce(
    const wired_srvloop_conn* conn, int got_request, quic_obuf* out);

/* RFC 9000 19.20: replay the confirmation (SETTINGS + session ticket +
 * HANDSHAKE_DONE) captured at its one-time emit, re-sealed under a fresh pn
 * -- the recovery when the single confirmation datagram was lost and the
 * client keeps probing its Finished. Returns 1 and sets out->len, or 0 when
 * no confirmation was emitted (or cached) yet. */
int wired_srvloop_reconfirm(const wired_srvloop_conn* conn, quic_obuf* out);

#endif
