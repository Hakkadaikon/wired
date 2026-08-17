#ifndef WIRED_SRVLOOP_RESPOND_H
#define WIRED_SRVLOOP_RESPOND_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"
#include "tls/keys/ticket/ticket.h"

/** RFC 8446 4.6.1: this process's fixed session-ticket encryption key (the
 * same key append_ticket_frame seals NewSessionTickets under) -- exposed so
 * the caller can also thread it to wired_srvboot_id.ticket_key for OPENING a
 * presented ticket (RFC 8446 4.2.11 resumption is symmetric: one key seals
 * and opens). TICKET_KEY_LEN bytes, valid for the process lifetime.
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
    const wired_srvloop_conn* conn, int got_request, wired_obuf* out);

/* RFC 9000 13.2.1: encode the App space's pending multi-range ACK into buf
 * WITHOUT clearing the pending state -- the deferred-ACK piggyback seam for
 * a driving loop (srvrun.c) that decides fit-or-not after seeing the
 * encoded length. Returns the encoded length, 0 when nothing is pending (or
 * encoding fails). Pair with wired_srvloop_ack_mark_sent once the carrying
 * packet is actually sent. */
usz wired_srvloop_ack_peek(wired_srvloop* l, u8* buf, usz cap);

/* Clear the pending-ACK state after a wired_srvloop_ack_peek result went
 * out on the wire, so the next step's due-check starts fresh. */
void wired_srvloop_ack_mark_sent(wired_srvloop* l);

/* RFC 9000 19.20: replay the confirmation (SETTINGS + session ticket +
 * HANDSHAKE_DONE) captured at its one-time emit, re-sealed under a fresh pn
 * -- the recovery when the single confirmation datagram was lost and the
 * client keeps probing its Finished. Returns 1 and sets out->len, or 0 when
 * no confirmation was emitted (or cached) yet. */
int wired_srvloop_reconfirm(const wired_srvloop_conn* conn, wired_obuf* out);

#endif
