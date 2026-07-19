#ifndef WIRED_SRVLOOP_RESPOND_H
#define WIRED_SRVLOOP_RESPOND_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"
#include "tls/keys/ticket/ticket.h"

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
