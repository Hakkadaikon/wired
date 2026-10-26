#include "app/http3/server/srvloop/dispatch_impl.h"

static void route_unreset(wired_srvloop* l, int i);
static int  route_headers_whole(const wired_srvloop_stream_slot* slot);
static void route_note_incomplete_append(wired_srvloop* l, int i);
static void route_note_incomplete(wired_srvloop* l, int i);
static void route_note_rejected(wired_srvloop* l, int i);
static u16  route_too_large_status(const wired_srvloop_stream_slot* slot);
static int  route_window_stuck(const wired_srvloop_stream_slot* slot);
static int  route_is_over(const wired_srvloop_dispatch_ctx* ctx, int i);

/* Append slot i to this step's completion list and mirror its request into
 * l->req/req_stream_id (the pre-existing single-request API surface; the
 * mirror carries the LAST completion when more than one lands this step). */
/* RFC 9000 3.2: slot i reached an outcome this step; a RESET_STREAM seen
 * earlier in the same datagram (another packet) no longer leaves it
 * marked as reset mid-request, so the server layer handles it once. */
static void route_unreset(wired_srvloop* l, int i) {
  l->reset_slots &= ~((u64)1 << i);
}

void srvloop_route_note_done(wired_srvloop* l, int i) {
  route_unreset(l, i);
  l->req           = l->streams[i].req;
  l->req_stream_id = l->streams[i].stream_id;
  srvloop_route_qpack_ack(l, i);
  if (l->done_n < WIRED_SRVLOOP_MAX_STREAMS) {
    l->done_slots[l->done_n++] = (u8)i;
  }
}

/* RFC 9114 4.1 / 7.2 (9114-007/067/073): a frame a request stream must not
 * carry is a connection error of type H3_FRAME_UNEXPECTED -- latched for
 * srvrun to close over. Also append slot i to frame_unexpected_slots -- split
 * out of route_note_incomplete so its own reject-vs- incomplete branch stays a
 * single extra check there. */
void srvloop_route_note_frame_unexpected(wired_srvloop* l, int i) {
  route_unreset(l, i);
  srvloop_h3_fail(l, H3_FRAME_UNEXPECTED); /* RFC 9114 4.1 / 7.2: connection */
  if (l->frame_unexpected_n < WIRED_SRVLOOP_MAX_STREAMS) {
    l->frame_unexpected_slots[l->frame_unexpected_n++] = (u8)i;
  }
}

/* RFC 9114 4.1.2: slot holds a whole HEADERS frame -- a rejected request
 * with one was malformed, not cut short. */
static int route_headers_whole(const wired_srvloop_stream_slot* slot) {
  return wired_h3reqdrive_headers_end(
             wired_span_of(slot->req_buf, slot->req_len)) != 0;
}

/* Mark slot i incomplete and append it to incomplete_slots -- the actual
 * H3_REQUEST_INCOMPLETE (or, malformed, H3_MESSAGE_ERROR) bookkeeping, split
 * out of route_note_incomplete so its own reject-vs-incomplete branch stays a
 * single extra check there. */
static void route_note_incomplete_append(wired_srvloop* l, int i) {
  route_unreset(l, i);
  l->streams[i].req_incomplete = 1;
  if (route_headers_whole(&l->streams[i])) {
    l->malformed_slots |= (u64)1 << i;
  }
  if (l->incomplete_n < WIRED_SRVLOOP_MAX_STREAMS) {
    l->incomplete_slots[l->incomplete_n++] = (u8)i;
  }
}

/* RFC 9114 4.1: slot i's request stream completed (FIN, or a HEADERS frame
 * with no FIN to wait for, see srvloop_connect_headers_complete) without
 * decoding into a request -- append it to incomplete_slots (the
 * H3_REQUEST_INCOMPLETE counterpart of srvloop_route_note_done) for whichever
 * layer aborts it, UNLESS the decode failed because the stream carried a frame
 * this endpoint must reject outright (req.frame_unexpected,
 * 9114-067/9114-073), which takes the H3_FRAME_UNEXPECTED list instead. */
static void route_note_incomplete(wired_srvloop* l, int i) {
  wired_srvloop_stream_slot* slot = &l->streams[i];
  if (slot->req.frame_unexpected) {
    srvloop_route_note_frame_unexpected(l, i);
  } else {
    route_note_incomplete_append(l, i);
  }
}

/* RFC 9114 4.1 vs hq-interop (see hq09.h): dispatch slot i's just-completed
 * request through whichever decoder this connection negotiated -- QPACK/
 * HEADERS for h3, a bare "GET <path>\r\n" line for hq-interop. Split out so
 * srvloop_route_complete_slot's own CCN stays at the gate. */
void srvloop_route_dispatch_complete(
    const wired_srvloop_dispatch_ctx* ctx,
    wired_srvloop_reqacc*             acc,
    const wired_srvloop_dispatch_in*  sin) {
  if (ctx->s->sdrv.alpn == SALPN_HQ) {
    srvloop_drive_complete_hq09(acc, sin);
  } else {
    srvloop_drive_complete(ctx->h3, acc, sin);
  }
}

/* RFC 9204 4.5.1 / 2.1.2: a section prefix that failed to decode is a
 * connection error, not just an aborted request. */
void srvloop_route_note_qpack(wired_srvloop* l, int i) {
  if (l->streams[i].req.qpack_failed) {
    l->qpack_stream_violation = QPACK_DECOMPRESSION_FAILED;
  }
}

/* A completed stream that yielded no request: reading stops, so a Stream
 * Cancellation releases every reference its sections hold, a trailer never
 * decoded included (RFC 9204 2.2.2.2; the Insert Count Increment advances
 * the Known Received Count an acknowledgment would have), then the stream
 * is aborted. */
static void route_note_rejected(wired_srvloop* l, int i) {
  srvloop_qdec_cancel_slot(l, i);
  route_note_incomplete(l, i);
}

/* Record slot i's decode outcome: a request to answer, or an incomplete /
 * rejected stream to abort. */
void srvloop_route_note_result(wired_srvloop* l, int i, int got) {
  srvloop_route_note_qpack(l, i);
  if (got) {
    srvloop_route_note_done(l, i);
  } else {
    route_note_rejected(l, i);
  }
}

/* RFC 6585 5 / RFC 9110 15.5.14: 431 when the leading HEADERS frame itself
 * does not fit req_buf, 413 when it does (the body overflowed). The one
 * place a streaming-body consumer would accept the overflow instead. */
static u16 route_too_large_status(const wired_srvloop_stream_slot* slot) {
  h3_frame f = {0};
  usz      n = h3_frame_get(wired_span_of(slot->req_buf, slot->req_len), &f);
  return n && f.type == H3_FRAME_HEADERS ? 413 : 431;
}

/* RFC 9000 4.1: a window full of contiguous bytes with no FIN -- a client
 * that honors the request-stream credit can send no more, so the request
 * can never complete in it. ponytail: a request of exactly one window whose
 * FIN comes in a later, separate empty frame is answered here too. */
static int route_window_stuck(const wired_srvloop_stream_slot* slot) {
  return bodywin_frontier(&slot->body) == BODYWIN_CAP && !slot->req_fin;
}

/* 1 if slot i overflowed req_buf before its request was answered, on an h3
 * connection (an hq-interop request line has no status to answer with). */
static int route_is_over(const wired_srvloop_dispatch_ctx* ctx, int i) {
  const wired_srvloop_stream_slot* slot = &ctx->l->streams[i];
  return route_window_stuck(slot) && !slot->req_done &&
         ctx->s->sdrv.alpn != SALPN_HQ;
}

/* An overflowed request is answered as soon as the overflow lands, not at
 * FIN: a client stalled on stream flow control might never send one. The
 * request is handed up empty except for too_large_status. Returns 1 if
 * slot i was handled this way. */
int srvloop_route_complete_over(const wired_srvloop_dispatch_ctx* ctx, int i) {
  wired_srvloop_stream_slot* slot = &ctx->l->streams[i];
  if (!route_is_over(ctx, i)) {
    return 0;
  }
  slot->req_done             = 1;
  slot->req                  = (wired_h3reqdrive_req){0};
  slot->req.too_large_status = route_too_large_status(slot);
  srvloop_qdec_cancel_slot(ctx->l, i); /* RFC 9204 2.2.2.2: reading abandoned */
  srvloop_route_note_done(ctx->l, i);
  return 1;
}

/* ---- Streaming request body (wired_srvloop_on_body) ---- */

/* The app streams request bodies, and this is an h3 connection (an
 * hq-interop request line has no body framing). */
int srvloop_route_body_on(const wired_srvloop_dispatch_ctx* ctx) {
  return ctx->l->on_body && ctx->s->sdrv.alpn != SALPN_HQ;
}

/* Bytes up to the end of the leading HEADERS frame (past any GREASE ahead of
 * it, RFC 9114 7.2.8) whole inside slot's contiguous window prefix, 0 when
 * there is none yet -- or the slot was already answered on the buffered
 * path. */
usz srvloop_route_body_head_len(const wired_srvloop_stream_slot* slot) {
  if (slot->req_done) {
    return 0;
  }
  return wired_h3reqdrive_headers_end(
      wired_span_of(slot->req_buf, bodywin_frontier(&slot->body)));
}

/* RFC 9114 4.1: decode slot's leading n-byte HEADERS frame alone into
 * slot->req (views into req_wrap/req_scratch, which the window never
 * touches). 1 for a decoded non-CONNECT request. */
int srvloop_route_body_decode(
    const wired_srvloop_dispatch_ctx* ctx,
    wired_srvloop_stream_slot*        slot,
    usz                               n) {
  stream_frame       f  = {0, 0, n, slot->req_buf, 0};
  wired_obuf         ob = obuf_of(slot->req_wrap, sizeof slot->req_wrap);
  wired_h3srv_req_in rin;
  if (!appdata_stream_frame(&f, &ob)) {
    return 0;
  }
  rin = (wired_h3srv_req_in){
      wired_span_of(slot->req_wrap, ob.len),
      wired_mspan_of(slot->req_scratch, sizeof slot->req_scratch)};
  return wired_h3srv_on_request(ctx->h3, &rin, &slot->req) &&
         !srvloop_req_method_is_connect(&slot->req);
}
