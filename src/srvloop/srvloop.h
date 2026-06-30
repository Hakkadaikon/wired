#ifndef QUIC_SRVLOOP_SRVLOOP_H
#define QUIC_SRVLOOP_SRVLOOP_H

#include "h3srv/state.h"
#include "server/server.h"

/* RFC 9001 4 / 5 / RFC 9000 17.2: the socket-free core of the server wire loop.
 * One step opens an inbound datagram with the peer-direction key, dispatches its
 * frames to the handshake or HTTP/3 layer, and seals the resulting outbound
 * packet with the server's own-direction key for the level the conversation has
 * reached. An example program wraps this in a UDP recv/send. */

typedef struct {
    quic_h3srv_state h3;
    u8 cli_scid[20]; /* the client's source id; DCID the server writes */
    u8 cli_scid_len;
    u64 tx_pn;    /* monotone packet number for sealed 1-RTT output */
    u64 hs_tx_pn; /* monotone packet number for sealed Handshake output */
    u64 app_rx_pn;  /* last received 1-RTT (application) packet number to ACK */
    int app_rx_seen;/* 1 once a 1-RTT packet has been received (app_rx_pn valid) */
    int hs_done_sent;/* 1 once the confirmation (HANDSHAKE_DONE) has been emitted */
} quic_srvloop;

/* Record the client's source connection id (the DCID for server-sent packets)
 * and reset the HTTP/3 state. Returns 1, or 0 if cli_scid_len exceeds 20. */
int quic_srvloop_init(quic_srvloop *l, const u8 *cli_scid, u8 cli_scid_len);

/* Drive one wire iteration: open `dgram`, dispatch it, and if the step produced
 * a server-direction packet (HANDSHAKE_DONE once confirmed, or a 200 response
 * to a decoded GET) seal it into out (cap) and set *out_len. Returns 1 if an
 * outbound packet was written, 0 if the step produced none (or the input was
 * dropped). */
int quic_srvloop_step(quic_srvloop *l, quic_server *s, u8 *dgram, usz len,
                      u8 *out, usz cap, usz *out_len);

#endif
