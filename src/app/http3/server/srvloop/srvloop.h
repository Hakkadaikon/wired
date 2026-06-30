#ifndef QUIC_SRVLOOP_SRVLOOP_H
#define QUIC_SRVLOOP_SRVLOOP_H

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/state.h"
#include "tls/handshake/roles/server/server.h"

/* Build the response body for a decoded request. Copy from `req` (its body is a
 * view into per-step scratch, not valid past the call) into body_out (cap),
 * setting *body_len. Returns 1 to send the body, 0 for a body-less 200. */
typedef int (*quic_srvloop_handler)(
    void                      *ctx,
    const quic_h3reqdrive_req *req,
    u8                        *body_out,
    usz                        cap,
    usz                       *body_len);

/* RFC 9001 4 / 5 / RFC 9000 17.2: the socket-free core of the server wire loop.
 * One step opens an inbound datagram with the peer-direction key, dispatches
 * its frames to the handshake or HTTP/3 layer, and seals the resulting outbound
 * packet with the server's own-direction key for the level the conversation has
 * reached. An example program wraps this in a UDP recv/send. */

typedef struct {
  quic_h3srv_state h3;
  u8  cli_scid[20]; /* the client's source id; DCID the server writes */
  u8  cli_scid_len;
  u64 tx_pn;        /* monotone packet number for sealed 1-RTT output */
  u64 hs_tx_pn;     /* monotone packet number for sealed Handshake output */
  u64 app_rx_pn;    /* last received 1-RTT (application) packet number to ACK */
  int app_rx_seen;  /* 1 once a 1-RTT packet has been received (app_rx_pn valid)
                     */
  u64 hs_rx_pn;     /* last received Handshake packet number to ACK (the client
                     * Finished's actual PN, which is not always 0) */
  int hs_rx_seen;   /* 1 once a Handshake packet has been received */
  int hs_done_sent; /* 1 once the confirmation (HANDSHAKE_DONE) has been emitted
                     */
  quic_srvloop_handler on_request;  /* app response-body builder, 0 if unset */
  void                *req_ctx;     /* opaque ctx passed to on_request */
  int                  got_request; /* 1 when this step decoded a request */
  quic_h3reqdrive_req  req; /* the decoded request (valid when got_request) */
  u8 req_scratch[512];      /* backing store for req's path/body views */
  /* RFC 9000 2.2: the request stream (id 0) reassembled across datagrams. curl
   * splits one request's HEADERS and DATA into separate STREAM frames in
   * separate 1-RTT packets; each frame's data is written at its offset here and
   * the request is decoded only once FIN arrives.
   * ponytail: a single request stream (id 0) only; one request per connection,
   * re-armed by quic_srvloop_init. Overflow past req_buf is truncated. */
  u8  req_buf[2048]; /* offset-indexed request stream bytes */
  usz req_len;       /* highest offset+len written into req_buf */
  u8  req_fin;       /* 1 once a request-stream FIN was seen */
  int req_done;      /* 1 once this request was decoded/answered */
} quic_srvloop;

/* Register the app response-body builder; pass 0 to clear (body-less 200). */
void quic_srvloop_set_handler(
    quic_srvloop *l, quic_srvloop_handler cb, void *ctx);

/* Record the client's source connection id (the DCID for server-sent packets)
 * and reset the HTTP/3 state. Returns 1, or 0 if cli_scid_len exceeds 20. */
int quic_srvloop_init(quic_srvloop *l, const u8 *cli_scid, u8 cli_scid_len);

/* Drive one wire iteration: open `dgram`, dispatch it, and if the step produced
 * a server-direction packet (HANDSHAKE_DONE once confirmed, or a 200 response
 * to a decoded GET) seal it into out (cap) and set *out_len. Returns 1 if an
 * outbound packet was written, 0 if the step produced none (or the input was
 * dropped). */
int quic_srvloop_step(
    quic_srvloop *l,
    quic_server  *s,
    u8           *dgram,
    usz           len,
    u8           *out,
    usz           cap,
    usz          *out_len);

#endif
