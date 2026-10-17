#include "app/http3/server/srvloop/dispatch_impl.h"

static void reset_request_stream(wired_srvloop* l, u64 id, u64 code);
static void reset_request_streams(wired_srvloop* l, wired_span payload);
static void dispatch_request_resets(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
static int dispatch_h3(
    const wired_srvloop_dispatch_ctx* ctx, const wired_srvloop_dispatch_in* in);
static int  dispatch_is_raw(const wired_srvloop_dispatch_ctx* ctx);
static void raw_land_bidi(wired_srvloop* l, const stream_frame* sf);
static int  raw_uni_slot(wired_srvloop* l, u64 stream_id);
static void raw_land_uni(wired_srvloop* l, const stream_frame* sf);
static void raw_land_none(wired_srvloop* l, const stream_frame* sf);
static int  raw_client_stream_of(u64 type, wired_span frame, stream_frame* sf);
static int  gather_raw_frame(wired_srvloop* l, u64 type, wired_span frame);
static int  gather_raw_streams(wired_srvloop* l, wired_span payload);
static int  dispatch_raw_side(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload);
static int dispatch_raw(
    const wired_srvloop_dispatch_ctx* ctx, const wired_srvloop_dispatch_in* in);

/* RFC 9000 3.2: a RESET_STREAM ends an open request stream's receive side.
 * With a slot, its references are cancelled (srvloop_reset_cancel_slot); with
 * none yet, the stream is cancelled if anything could be referenced and marked
 * closed either way, so its late data never opens a request, and its stream
 * credit is owed back (4.6) -- once, since a closed stream returns above. */
static void reset_request_stream(wired_srvloop* l, u64 id, u64 code) {
  int i;
  if (!srvloop_qdec_stream_open(l, id)) return;
  i = srvloop_qdec_slot_find(l, id);
  if (i >= 0) {
    srvloop_reset_cancel_slot(l, i, code);
    return;
  }
  srvloop_qdec_cancel_id(l, id);
  wired_srvloop_slot_release(l, id);
  l->reset_slotless_n++;
}

/* Every RESET_STREAM in this payload -- run after request reassembly, so a
 * section completed in the same packet is acknowledged and not cancelled. */
static void reset_request_streams(wired_srvloop* l, wired_span payload) {
  framewalk          it;
  framewalk_item     fr;
  reset_stream_frame rs;
  framewalk_init(&it, payload.p, payload.n);
  while (framewalk_next(&it, &fr))
    if (srvloop_wt_reset_frame(
            fr.type, wired_span_of(fr.start, fr.remaining), &rs))
      reset_request_stream(l, rs.stream_id, rs.error_code);
}

static void dispatch_request_resets(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  if (ctx->l) reset_request_streams(ctx->l, payload);
}

/* The HTTP/3 (and hq-interop) payload path: side channels, then request
 * reassembly, then the handshake-feed fallback. */
static int dispatch_h3(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  int handled_side = dispatch_gather_side_channels(ctx, in->payload);
  int handled_req  = srvloop_reassemble_and_drive(ctx, in);
  dispatch_request_resets(ctx, in->payload);
  if (handled_req || handled_side) return 1;
  return dispatch_non_request(ctx->s, in->payload.p, in->payload.n);
}

/* 1 if ctx is a loop-backed connection whose negotiated ALPN is a raw-QUIC
 * application protocol (RFC 7301 3.2, e.g. moqt-19 per
 * draft-ietf-moq-transport-19 3.1) rather than h3/hq-interop. */
static int dispatch_is_raw(const wired_srvloop_dispatch_ctx* ctx) {
  return ctx->l && ctx->s && ctx->s->sdrv.alpn == SALPN_RAW;
}

/* Raw QUIC bidi (RFC 9000 2.1): find-or-claim the stream's wt_streams[] slot
 * with no signal (sig_len stays 0 from the claim), so every byte from offset
 * 0 is session data; a full table refuses the stream like a WT one. */
static void raw_land_bidi(wired_srvloop* l, const stream_frame* sf) {
  int i = wired_srvloop_wt_slot_claim_local(l, sf->stream_id);
  if (i < 0) {
    wired_srvloop_wt_refuse(l, sf->stream_id);
    return;
  }
  srvloop_gather_wt_one(sf, &l->wt_streams[i]);
}

/* Find-or-claim a raw uni stream's wt_uni_streams[] slot (type_len 0). */
static int raw_uni_slot(wired_srvloop* l, u64 stream_id) {
  int i = wired_srvloop_wt_uni_slot_find(l, stream_id);
  return i >= 0 ? i : wired_srvloop_wt_uni_slot_claim(l, stream_id);
}

/* Raw QUIC uni (draft-ietf-moq-transport-19 3.3: the leading type is the
 * MoQT header itself, never stripped): land every byte from offset 0. */
static void raw_land_uni(wired_srvloop* l, const stream_frame* sf) {
  int i = raw_uni_slot(l, sf->stream_id);
  if (i >= 0) srvloop_gather_wt_uni_one(sf, &l->wt_uni_streams[i]);
  dispatch_qlog_stream_received(l, sf);
}

/* A route rawq_route never yields on raw QUIC. */
static void raw_land_none(wired_srvloop* l, const stream_frame* sf) {
  (void)l;
  (void)sf;
}

static const raw_land_fn raw_land_by_route[] = {
    [RAWQ_ROUTE_REQUEST_H3] = raw_land_none,
    [RAWQ_ROUTE_WT_BIDI]    = raw_land_none,
    [RAWQ_ROUTE_WT_UNI]     = raw_land_none,
    [RAWQ_ROUTE_RAW_BIDI]   = raw_land_bidi,
    [RAWQ_ROUTE_RAW_UNI]    = raw_land_uni,
    [RAWQ_ROUTE_H3_UNI]     = raw_land_none,
};

/* 1 if the walked frame is a client-initiated STREAM frame (RFC 9000 2.1 id
 * bit 0x1 clear), decoded into sf. */
static int raw_client_stream_of(u64 type, wired_span frame, stream_frame* sf) {
  return srvloop_is_stream(type) && frame_get_stream(frame.p, frame.n, sf) &&
         !(sf->stream_id & 1);
}

/* Route one client STREAM frame on a raw-QUIC connection via rawq_route. */
static int gather_raw_frame(wired_srvloop* l, u64 type, wired_span frame) {
  stream_frame sf;
  if (!raw_client_stream_of(type, frame, &sf)) return 0;
  raw_land_by_route[rawq_route(
      1, sf.stream_id, wired_span_of(sf.data, (usz)sf.length))](l, &sf);
  return 1;
}

/* Raw QUIC: every client bidi/uni STREAM frame goes to the implicit
 * session's slot tables, a server bidi reply to its pre-claimed slot; no
 * frame reaches the H3 request, control, or QPACK paths. */
static int gather_raw_streams(wired_srvloop* l, wired_span payload) {
  framewalk      it;
  framewalk_item fr;
  int            seen = 0;
  framewalk_init(&it, payload.p, payload.n);
  while (framewalk_next(&it, &fr)) {
    seen |= srvloop_gather_server_bidi_frame(
        l, fr.type, wired_span_of(fr.start, fr.remaining));
    seen |= gather_raw_frame(l, fr.type, wired_span_of(fr.start, fr.remaining));
  }
  return seen;
}

/* The raw-QUIC subset of dispatch_gather_side_channels: streams, DATAGRAM
 * (RFC 9221 5), stream closes and flow control; no H3 PRIORITY_UPDATE. */
static int dispatch_raw_side(
    const wired_srvloop_dispatch_ctx* ctx, wired_span payload) {
  int got_st = gather_raw_streams(ctx->l, payload);
  int got_dg = dispatch_gather_datagrams(ctx, payload);
  int got_cl = dispatch_gather_closes(ctx, payload);
  int got_fc = dispatch_gather_flowctl(ctx, payload);
  return got_st | got_dg | got_cl | got_fc;
}

static int dispatch_raw(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  if (dispatch_raw_side(ctx, in->payload)) return 1;
  return dispatch_non_request(ctx->s, in->payload.p, in->payload.n);
}

int wired_srvloop_dispatch(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  return dispatch_is_raw(ctx) ? dispatch_raw(ctx, in) : dispatch_h3(ctx, in);
}
