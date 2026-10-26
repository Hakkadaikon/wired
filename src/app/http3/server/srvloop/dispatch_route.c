#include "app/http3/server/srvloop/dispatch_impl.h"

static void route_land_bytes(
    wired_srvloop_stream_slot* slot, const stream_frame* sf);
static void route_watch(wired_srvloop* l, const stream_frame* sf);
static void route_land(wired_srvloop* l, const stream_frame* sf, u64* touched);
static int  qdec_table_used(const wired_srvloop* l);
static int  qdec_settle(wired_srvloop* l, int i);

/* RFC 9114 4.1: re-wrap the reassembled stream bytes as a single STREAM frame
 * (offset 0) into in->wrap and drive the HTTP/3 request decoder once. req's
 * path/body views end up pointing into in->wrap, so it must be caller-owned
 * storage that outlives this call (a stack local here would dangle by the
 * time the handler reads req). */
void srvloop_drive_complete(
    wired_h3srv_state*               h3,
    wired_srvloop_reqacc*            acc,
    const wired_srvloop_dispatch_in* in) {
  stream_frame f  = {0, 0, *acc->len, acc->buf, 1};
  wired_obuf   ob = obuf_of(in->wrap.p, in->wrap.n);
  *acc->done      = 1;
  if (appdata_stream_frame(&f, &ob)) {
    dispatch_stream(h3, wired_span_of(in->wrap.p, ob.len), in);
  }
}

/* quic-interop-runner's hq-interop (HTTP/0.9 over QUIC, see hq09.h):
 * parse acc's reassembled bytes as a single "GET <path>\r\n" request line
 * (no QPACK/HEADERS framing at all -- the accumulated bytes ARE the
 * request line). On a valid line, sets *in->req's path (a view into acc's
 * own storage, which outlives this call the same way in->wrap does for the
 * H3 path) and marks the request complete; an invalid line marks acc done
 * without producing a request (the stream is spent either way, matching
 * srvloop_drive_complete's "decode at most once" contract). */
void srvloop_drive_complete_hq09(
    wired_srvloop_reqacc* acc, const wired_srvloop_dispatch_in* in) {
  wired_span path;
  *acc->done = 1;
  if (!wired_hq09_parse_get(wired_span_of(acc->buf, *acc->len), &path)) {
    return;
  }
  *in->req            = (wired_h3reqdrive_req){0};
  in->req->method     = (const u8*)"GET";
  in->req->method_len = 3;
  in->req->path       = path.p;
  in->req->path_len   = path.n;
  *in->got_request    = 1;
}

/* RFC 9000 2.2: view one stream slot's cross-datagram request accumulator
 * (the routed path's per-slot counterpart of the caller-built ctx->acc). */
wired_srvloop_reqacc srvloop_route_slot_acc(wired_srvloop_stream_slot* slot) {
  wired_srvloop_reqacc acc;
  acc.buf  = slot->req_buf;
  acc.cap  = sizeof slot->req_buf;
  acc.len  = &slot->req_len;
  acc.fin  = &slot->req_fin;
  acc.done = &slot->req_done;
  return acc;
}

/* Land one request STREAM frame in its own stream's slot (claiming one on
 * first sight) and mark that slot touched. A full table drops the frame --
 * same policy as the old single fixed slot. */
/* RFC 9000 2.2: write sf into slot's window (only its in-window part,
 * relative to the window base), raise the high-water mark, latch FIN, and
 * flag data the window could not take. */
static void route_land_bytes(
    wired_srvloop_stream_slot* slot, const stream_frame* sf) {
  wired_srvloop_reqacc acc = srvloop_route_slot_acc(slot);
  bodywin_land(
      &slot->body, slot->req_buf, sf->offset,
      wired_span_of(sf->data, (usz)sf->length), sf->fin);
  srvloop_bump_len(&acc, (usz)sf->offset + (usz)sf->length);
  slot->req_fin |= sf->fin;
  slot->req_over |= sf->offset + sf->length > slot->body.base + acc.cap;
}

/* draft-ietf-webtrans-http3-16 6: a frame of the released CONNECT stream
 * watched after the peer's WT_CLOSE_SESSION -- bytes past the capsule are
 * "additional stream data" (hit), a retransmission is not. */
static void route_watch(wired_srvloop* l, const stream_frame* sf) {
  wired_srvloop_wt_watch* w = &l->wt_watch;
  if (w->id != sf->stream_id + 1) {
    return;
  }
  w->hit = (u8)(w->hit | (sf->offset + sf->length > w->end));
  w->fin = (u8)(w->fin | sf->fin);
}

static void route_land(wired_srvloop* l, const stream_frame* sf, u64* touched) {
  int i = wired_srvloop_slot_for(l, sf->stream_id);
  /* RFC 9000 3.2: a late duplicate of an answered-and-released stream is
   * discarded outright -- it must not consume a slot or count as new. */
  if (i == -2) {
    route_watch(l, sf);
    return;
  }
  if (i < 0) {
    return;
  }
  route_land_bytes(&l->streams[i], sf);
  l->flow_control_violation |= l->streams[i].req_over; /* RFC 9000 4.1 */
  /* u64: the table holds up to WIRED_SRVLOOP_MAX_STREAMS (40) slots, so a
   * 32-bit mask loses (as undefined-behavior shifts) slots 32..39. */
  *touched |= (u64)1 << i;
}

/* RFC 9000 2.2 / 12.4: route every request STREAM frame in this payload to
 * its own stream's slot (a payload may coalesce frames of several request
 * streams -- quic-go packs parallel GETs' HEADERS into one packet). Returns
 * 1 if any request-stream frame was seen, with *touched marking the slots
 * written. */
int srvloop_route_request_frames(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload, u64* touched) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  stream_frame   sf;
  framewalk_init(&it, payload.p, payload.n);
  while (framewalk_next(&it, &fr)) {
    if (srvloop_request_stream_of(
            ctx->l, fr.type, wired_span_of(fr.start, fr.remaining), &sf)) {
      route_land(ctx->l, &sf, touched);
      seen = 1;
    }
  }
  return seen;
}

/* RFC 9204 4.4.2: references are only possible once the peer inserted. */
static int qdec_table_used(const wired_srvloop* l) {
  return l->h3.qdyn.dropped + l->h3.qdyn.count != 0;
}

/* RFC 9204 4.4.1 / 4.4.2: 1 the first time the decoder speaks for slot i's
 * stream. It sends an acknowledgment or a cancellation, never both: once
 * cancelled the peer's encoder forgets the stream and treats a later
 * acknowledgment as QPACK_DECODER_STREAM_ERROR, and an acknowledged stream
 * holds no reference left to cancel. */
static int qdec_settle(wired_srvloop* l, int i) {
  int first                   = !l->streams[i].qpack_settled;
  l->streams[i].qpack_settled = 1;
  return first;
}

void srvloop_qdec_cancel_id(wired_srvloop* l, u64 id) {
  if (qdec_table_used(l)) {
    qdyn_dec_stream_cancel(&l->h3.qdec, id);
  }
}

/* RFC 9204 2.2.2.2: "When a stream is reset or reading is abandoned, the
 * decoder emits a Stream Cancellation instruction" -- releasing the
 * references the encoder still holds for slot i's stream, unless the stream
 * was already settled (qdec_settle). */
void srvloop_qdec_cancel_slot(wired_srvloop* l, int i) {
  if (qdec_settle(l, i)) {
    srvloop_qdec_cancel_id(l, l->streams[i].stream_id);
  }
}

/* RFC 9204 2.2.2.1 / 4.4.1: acknowledge slot i's decoded field sections
 * (leading, then trailer) on the decoder stream when their Required Insert
 * Count is non-zero; a section that failed to decode is a connection error
 * instead. */
void srvloop_route_qpack_ack(wired_srvloop* l, int i) {
  const wired_h3reqdrive_req* r  = &l->streams[i].req;
  u64                         id = l->streams[i].stream_id;
  if (r->qpack_failed || !qdec_settle(l, i)) {
    return;
  }
  qdyn_dec_section_ack(&l->h3.qdec, id, r->qpack_ric);
  qdyn_dec_section_ack(&l->h3.qdec, id, r->qpack_trailer_ric);
}
