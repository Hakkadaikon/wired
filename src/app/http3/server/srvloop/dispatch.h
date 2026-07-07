#ifndef WIRED_SRVLOOP_DISPATCH_H
#define WIRED_SRVLOOP_DISPATCH_H

#include "app/http3/request/h3reqdrive/request_drive.h"
#include "app/http3/server/h3srv/state.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "common/bytes/span/span.h"
#include "tls/handshake/roles/server/server.h"

/* RFC 9000 2.2: the request stream (id 0) reassembled across datagrams. Each
 * received request STREAM frame's data is written at its offset into buf (cap);
 * len tracks the high-water mark, fin latches the stream FIN, done latches that
 * the completed request was already decoded so it is answered only once. */
typedef struct {
  u8*  buf;
  usz  cap;
  usz* len;
  u8*  fin;
  int* done;
} wired_srvloop_reqacc;

/* Remaining arguments of wired_srvloop_dispatch beyond s/h3/acc: the opened
 * payload, the request-decode scratch buffer, the re-wrap buffer req's
 * path/body views end up pointing into (must outlive the dispatch call, so
 * it is caller-owned rather than a dispatch-local), and the completed-request
 * outputs. */
typedef struct {
  quic_span             payload;
  quic_mspan            scratch;
  quic_mspan            wrap;
  int*                  got_request;
  wired_h3reqdrive_req* req;
} wired_srvloop_dispatch_in;

/* The server orchestrator, its HTTP/3 state and the cross-datagram request
 * accumulator dispatch reads/writes together. Folded into one parameter so
 * wired_srvloop_dispatch stays <=3 args. l is the owning loop, whose
 * wt_streams[] table draft-ietf-webtrans-http3-15 4.3 WT bidi traffic and
 * whose rx_datagrams[] queue RFC 9221 5 DATAGRAM frames are each gathered into
 * independent of the request path above; 0 in a test that exercises only the
 * request path directly (WT/DATAGRAM gathering are then both skipped). */
typedef struct {
  wired_server*         s;
  wired_h3srv_state*    h3;
  wired_srvloop_reqacc* acc;
  wired_srvloop*        l;
} wired_srvloop_dispatch_ctx;

/* RFC 9000 12.4: route an opened payload's frames. CRYPTO frames (handshake)
 * drive the server orchestrator (wired_server_feed); a request STREAM frame
 * (1-RTT app data) is accumulated into ctx->acc at its offset and, once FIN
 * closes the stream, decoded as an HTTP/3 request. A WT bidi STREAM frame
 * (draft-ietf-webtrans-http3-15 4.3, ctx->l != 0) is gathered into ctx->l's
 * wt_streams[] table, and a DATAGRAM frame (RFC 9221 5, ctx->l != 0) into
 * ctx->l's rx_datagrams[] queue, independent of whether a request frame is
 * ALSO present in the same payload. The two request/handshake paths are kept
 * separate: a Handshake payload never reaches HTTP/3, a 1-RTT request never
 * re-enters the handshake. Returns 1 if a frame was handled, 0 otherwise. On
 * a completed request *in->got_request is set and *in->req filled. */
int wired_srvloop_dispatch(
    const wired_srvloop_dispatch_ctx* ctx, const wired_srvloop_dispatch_in* in);

/* RFC 9000 2.1/2.2: find the stream id of this payload's first client bidi
 * request STREAM frame (low two bits 0), so the caller can route the payload
 * to that stream's own reassembly slot before dispatching it. A payload with
 * no request-stream frame (handshake CRYPTO, curl's unidirectional control/
 * QPACK streams, or a WebTransport bidi stream's signal/continuation frame —
 * draft-ietf-webtrans-http3-15 4.3, l's wt_streams[] table excludes it at ANY
 * offset, not just its leading signal) is not this connection's request
 * traffic. l may be 0 to check only the offset-0 signal (a caller with no
 * loop to consult, matching wired_srvloop_dispatch_ctx's own l==0 allowance).
 * @return 1 with *stream_id_out set, or 0 if no request-stream frame is
 *   present. */
int wired_srvloop_payload_stream_id(
    const wired_srvloop* l, quic_span payload, u64* stream_id_out);

#endif
