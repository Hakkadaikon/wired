#ifndef QUIC_SRVLOOP_RESPOND_H
#define QUIC_SRVLOOP_RESPOND_H

#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"

/* RFC 9000 12.2 / 13.2.1 / RFC 9114 6.2.1: pick the outbound datagram for one
 * step. The first reply emits the confirmation (SETTINGS + HANDSHAKE_DONE),
 * coalescing the 200 into its 1-RTT payload when the confirming datagram also
 * carried a GET; later replies are a 200 or a bare 1-RTT ACK, the confirmation
 * never repeated. Returns 1 and sets out->len when a packet was written, else
 * 0.
 */
int quic_srvloop_produce(
    const quic_srvloop_conn *conn, int got_request, quic_obuf *out);

#endif
