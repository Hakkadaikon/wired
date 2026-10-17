#include "app/http3/server/srvloop/dispatch_impl.h"

static int has_frame(const u8* payload, usz len);
static int dispatch_gather_wt(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
static int dispatch_gather_uni(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
static int dispatch_gather_ctrl_priupdate(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
static int dispatch_gather_req_priupdate(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
static int qdec_slot_is(const wired_srvloop_stream_slot* slot, u64 id);

/* 1 if the payload carries a STREAM frame of any kind (request or uni). Such a
 * 1-RTT payload belongs to the HTTP/3 path and must never re-enter the
 * handshake via wired_server_feed (RFC 9000 12.4). */
int srvloop_has_stream(const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  framewalk_init(&it, payload, len);
  while (framewalk_next(&it, &fr)) {
    if (srvloop_is_stream(fr.type)) {
      return 1;
    }
  }
  return 0;
}

/* 1 if the payload carries at least one walkable frame (non-empty, decodes).
 * An empty/undecodable payload drives nothing. */
static int has_frame(const u8* payload, usz len) {
  framewalk      it;
  framewalk_item fr;
  framewalk_init(&it, payload, len);
  return framewalk_next(&it, &fr);
}

/* No request stream found. A payload carrying only unidirectional STREAM frames
 * (curl's control / QPACK, RFC 9114 6.2) is accepted but drives no request; a
 * CRYPTO/handshake payload is handed to wired_server_feed. */
int srvloop_feed_or_accept(wired_server* s, const u8* payload, usz len) {
  if (srvloop_has_stream(payload, len)) {
    return 1;
  }
  return wired_server_feed(s, payload, len);
}

int dispatch_non_request(wired_server* s, const u8* payload, usz len) {
  if (!has_frame(payload, len)) {
    return 0;
  }
  return srvloop_feed_or_accept(s, payload, len);
}

/* 1 if ctx has a loop to gather WT bidi traffic into (ctx->l != 0) and this
 * payload carried any (draft-ietf-webtrans-http3-15 4.3). A dispatch caller
 * exercising only the request path directly (l == 0) skips WT gathering
 * entirely rather than dereferencing a null loop. */
static int dispatch_gather_wt(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) {
    return 0;
  }
  return srvloop_gather_wt_stream(ctx->l, payload.p, payload.n);
}

/* 1 if ctx has a loop to queue DATAGRAM frames into (ctx->l != 0) and this
 * payload carried any (RFC 9221 5). A dispatch caller exercising only the
 * request path directly (l == 0) skips DATAGRAM gathering entirely rather
 * than dereferencing a null loop. */
int dispatch_gather_datagrams(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) {
    return 0;
  }
  return srvloop_gather_rx_datagrams(ctx->l, payload.p, payload.n);
}

/* 1 if ctx has a loop to gather uni stream traffic into (ctx->l != 0) and this
 * payload carried any client uni STREAM frame (draft-ietf-webtrans-http3-15
 * 4.3 / RFC 9114 6.2), mirroring dispatch_gather_wt for the uni table. */
static int dispatch_gather_uni(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) {
    return 0;
  }
  return srvloop_gather_uni_stream(ctx->l, payload.p, payload.n);
}

/* 1 if ctx has a loop to latch a closed stream id into (ctx->l != 0) and this
 * payload carried a RESET_STREAM/STOP_SENDING/FIN-bearing STREAM frame
 * (RFC 9000 19.4/19.5/19.8), mirroring dispatch_gather_wt for
 * srvloop_gather_stream_closes. A payload carrying only
 * RESET_STREAM/STOP_SENDING (neither of which srvloop_has_stream's STREAM-only
 * check recognizes) would otherwise fall through to dispatch_non_request's
 * handshake-feed fallback (RFC 9000 12.4: a 1-RTT payload must never re-enter
 * the handshake). */
int dispatch_gather_closes(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) {
    return 0;
  }
  return srvloop_gather_stream_closes(ctx->l, payload.p, payload.n);
}

/* RFC 9000 19.9/19.10: 1 if ctx has a loop to latch a flow-control update
 * into and this payload carried a MAX_DATA or MAX_STREAM_DATA frame,
 * mirroring dispatch_gather_closes for the flow-control frame kinds. */
int dispatch_gather_flowctl(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  int got_max_data, got_max_stream_data, got_max_streams, got_streams_blocked,
      got_path_resp, got_path_chal, got_ncid;
  if (!ctx->l) {
    return 0;
  }
  got_max_data = srvloop_gather_max_data(ctx->l, payload.p, payload.n);
  got_max_stream_data =
      srvloop_gather_max_stream_data(ctx->l, payload.p, payload.n);
  got_max_streams =
      srvloop_gather_max_streams_uni(ctx->l, payload.p, payload.n);
  got_streams_blocked =
      srvloop_gather_streams_blocked(ctx->l, payload.p, payload.n);
  got_path_resp = srvloop_gather_path_response(ctx->l, payload.p, payload.n);
  got_path_chal = srvloop_gather_path_challenge(ctx->l, payload.p, payload.n);
  got_ncid      = srvloop_gather_ncid(ctx->l, payload.p, payload.n);
  return got_max_data | got_max_stream_data | got_max_streams |
         got_streams_blocked | got_path_resp | got_path_chal | got_ncid;
}

/* RFC 9218 7.1 / 10: 1 if ctx has a loop to reassemble the peer's control
 * stream into (ctx->l != 0) and this payload carried any of its frames,
 * mirroring dispatch_gather_uni for the PRIORITY_UPDATE-applying walk. */
static int dispatch_gather_ctrl_priupdate(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) {
    return 0;
  }
  return srvloop_gather_ctrl_priupdate(ctx->l, payload.p, payload.n);
}

/* RFC 9218 7.1 / 9218-013: 1 if ctx has a loop to latch a PRIORITY_UPDATE
 * violation into (ctx->l != 0) and this payload carried a request-stream
 * frame, mirroring dispatch_gather_ctrl_priupdate for the request-side scan.
 */
static int dispatch_gather_req_priupdate(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (!ctx->l) {
    return 0;
  }
  return srvloop_gather_req_priupdate(ctx->l, payload.p, payload.n);
}

/* RFC 9000 12.4 / 2.1, RFC 9114 6.2: a payload may lead with PADDING/ACK before
 * its CRYPTO or STREAM frame (curl/quiche do this). A client bidi STREAM drives
 * HTTP/3; unidirectional STREAMs are accepted but ignored; anything else is
 * handed whole to wired_server_feed, whose crecv reassembles a split
 * ClientHello/Finished. A STREAM payload never re-enters the handshake, and
 * neither does a WT bidi stream (draft-ietf-webtrans-http3-15 4.3), a client
 * uni stream (control/QPACK/WebTransport, same draft/RFC 9114 6.2), or a
 * DATAGRAM frame (RFC 9221 5) — all three are gathered independently before
 * either path below, since a coalesced payload may carry any combination. */
/* Gather this payload's WT bidi, uni, DATAGRAM, stream-close, and
 * PRIORITY_UPDATE-relevant frames (each independent of the others, see
 * wired_srvloop_dispatch's doc); 1 if any kind was present. */
int dispatch_gather_side_channels(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  int got_wt       = dispatch_gather_wt(ctx, payload);
  int got_uni      = dispatch_gather_uni(ctx, payload);
  int got_dg       = dispatch_gather_datagrams(ctx, payload);
  int got_closes   = dispatch_gather_closes(ctx, payload);
  int got_flowctl  = dispatch_gather_flowctl(ctx, payload);
  int got_ctrl_pri = dispatch_gather_ctrl_priupdate(ctx, payload);
  int got_req_pri  = dispatch_gather_req_priupdate(ctx, payload);
  return got_wt | got_uni | got_dg | got_closes | got_flowctl | got_ctrl_pri |
         got_req_pri;
}

/* 1 if slot is the live request slot of stream id. */
static int qdec_slot_is(const wired_srvloop_stream_slot* slot, u64 id) {
  return slot->in_use && slot->stream_id == id;
}

/* The request slot of stream id, -1 if it has none (never claims one). */
int srvloop_qdec_slot_find(const wired_srvloop* l, u64 id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++) {
    if (qdec_slot_is(&l->streams[i], id)) {
      return (int)i;
    }
  }
  return -1;
}

/* A request stream (a WebTransport stream carries no field sections) not
 * already answered and released -- an answered one was acknowledged. */
int srvloop_qdec_stream_open(const wired_srvloop* l, u64 id) {
  return srvloop_is_request_stream(id) &&
         wired_srvloop_wt_slot_find(l, id) < 0 &&
         !wired_srvloop_closed_has(&l->req_closed, id);
}

/* RFC 9204 4.4.2 / 2.2.2.2: a reset request stream with a slot owes a
 * Stream Cancellation (srvloop_qdec_cancel_slot, sent once the peer inserted
 * anything its sections could reference). Still receiving (RFC 9000 3.2), it is
 * noted in reset_slots -- read before the step end re-arms a completed slot's
 * req_done. */
void srvloop_reset_cancel_slot(wired_srvloop* l, int i, u64 code) {
  l->streams[i].abort_code = code; /* reported if its body is cut short */
  srvloop_qdec_cancel_slot(l, i);
  if (!l->streams[i].req_done) {
    l->reset_slots |= (u64)1 << i;
  }
}
