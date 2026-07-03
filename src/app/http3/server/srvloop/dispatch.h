#ifndef QUIC_SRVLOOP_DISPATCH_H
#define QUIC_SRVLOOP_DISPATCH_H

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/state.h"
#include "common/bytes/span/span.h"
#include "tls/handshake/roles/server/server.h"

/* RFC 9000 2.2: the request stream (id 0) reassembled across datagrams. Each
 * received request STREAM frame's data is written at its offset into buf (cap);
 * len tracks the high-water mark, fin latches the stream FIN, done latches that
 * the completed request was already decoded so it is answered only once. */
typedef struct {
  u8  *buf;
  usz  cap;
  usz *len;
  u8  *fin;
  int *done;
} quic_srvloop_reqacc;

/* Remaining arguments of quic_srvloop_dispatch beyond s/h3/acc: the opened
 * payload, the request-decode scratch buffer, and the completed-request
 * outputs. */
typedef struct {
  quic_span            payload;
  quic_mspan           scratch;
  int                 *got_request;
  quic_h3reqdrive_req *req;
} quic_srvloop_dispatch_in;

/* The server orchestrator, its HTTP/3 state and the cross-datagram request
 * accumulator dispatch reads/writes together. Folded into one parameter so
 * quic_srvloop_dispatch stays <=3 args. */
typedef struct {
  quic_server         *s;
  quic_h3srv_state    *h3;
  quic_srvloop_reqacc *acc;
} quic_srvloop_dispatch_ctx;

/* RFC 9000 12.4: route an opened payload's frames. CRYPTO frames (handshake)
 * drive the server orchestrator (quic_server_feed); a request STREAM frame
 * (1-RTT app data) is accumulated into ctx->acc at its offset and, once FIN
 * closes the stream, decoded as an HTTP/3 request. The two paths are kept
 * separate: a Handshake payload never reaches HTTP/3, a 1-RTT request never
 * re-enters the handshake. Returns 1 if a frame was handled, 0 otherwise. On
 * a completed request *in->got_request is set and *in->req filled. */
int quic_srvloop_dispatch(
    const quic_srvloop_dispatch_ctx *ctx, const quic_srvloop_dispatch_in *in);

#endif
