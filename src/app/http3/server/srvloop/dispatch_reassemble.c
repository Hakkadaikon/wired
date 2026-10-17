#include "app/http3/server/srvloop/dispatch_impl.h"

static int route_body_start(
    const wired_srvloop_dispatch_ctx* ctx, wired_srvloop_stream_slot* slot);
static int  route_body_sink(void* ctx, wired_span chunk, int fin);
static void route_body_open(wired_srvloop* l, int i);
static void route_body_done(wired_srvloop* l, int i);
static void route_body_reject(wired_srvloop* l, int i);
static void route_body_frame_error(wired_srvloop* l, int i);
static void route_body_frame_unexpected(wired_srvloop* l, int i);
static void route_body_pump(wired_srvloop* l, int i);
static int  route_body_ready(
    const wired_srvloop_dispatch_ctx* ctx, wired_srvloop_stream_slot* slot);
static int  route_body(const wired_srvloop_dispatch_ctx* ctx, int i);
static int  route_answered_early(const wired_srvloop_dispatch_ctx* ctx, int i);
static void route_complete_touched(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in,
    u64                               touched);
static int reassemble_routed(
    const wired_srvloop_dispatch_ctx* ctx, const wired_srvloop_dispatch_in* in);
static int reassemble_single(
    const wired_srvloop_dispatch_ctx* ctx, const wired_srvloop_dispatch_in* in);

/* Start streaming slot's body once its HEADERS frame is whole: decode it
 * and slide it out of the window. 0 leaves the slot on the buffered path
 * (no whole HEADERS yet, undecodable, or a CONNECT). */
static int route_body_start(
    const wired_srvloop_dispatch_ctx* ctx, wired_srvloop_stream_slot* slot) {
  usz n = srvloop_route_body_head_len(slot);
  if (!n || !srvloop_route_body_decode(ctx, slot, n)) {
    return 0;
  }
  bodywin_consume(&slot->body, slot->req_buf, n);
  slot->body.on = 1;
  return 1;
}

static int route_body_sink(void* ctx, wired_span chunk, int fin) {
  route_body_call* c = ctx;
  return c->l->on_body(
      c->l->req_ctx, &c->slot->req, c->slot->stream_id, chunk, fin);
}

static void route_body_open(wired_srvloop* l, int i) {
  (void)l;
  (void)i;
}

/* fin delivered: the request is complete; the handler answers it. */
static void route_body_done(wired_srvloop* l, int i) {
  l->streams[i].req_done = 1;
  srvloop_route_note_done(l, i);
}

/* on_body declined: answer 413 (RFC 9110 15.5.14), like an overflow. */
static void route_body_reject(wired_srvloop* l, int i) {
  l->streams[i].req.too_large_status = 413;
  route_body_done(l, i);
}

/* RFC 9114 7.1: the stream ended inside a frame -- H3_FRAME_ERROR. */
static void route_body_frame_error(wired_srvloop* l, int i) {
  l->streams[i].req_done = 1;
  l->req_frame_error     = 1;
  srvloop_qdec_cancel_slot(l, i); /* RFC 9204 2.2.2.2: reading abandoned */
}

/* RFC 9114 7.2: a frame a request stream must not carry -- rejected the
 * same way the buffered path rejects it (H3_FRAME_UNEXPECTED). */
static void route_body_frame_unexpected(wired_srvloop* l, int i) {
  l->streams[i].req_done = 1;
  srvloop_route_note_frame_unexpected(l, i);
  srvloop_qdec_cancel_slot(l, i); /* RFC 9204 2.2.2.2: reading abandoned */
}

/* Parse what the window holds and settle the outcome (once: a finished
 * body is never pumped again, so a re-armed slot cannot re-settle). */
static void route_body_pump(wired_srvloop* l, int i) {
  static void (*const settle[])(wired_srvloop*, int) = {
      route_body_open, route_body_done, route_body_reject,
      route_body_frame_error, route_body_frame_unexpected};
  wired_srvloop_stream_slot* slot = &l->streams[i];
  route_body_call            c    = {l, slot};
  if (slot->body.state != BODYWIN_OPEN) {
    return;
  }
  settle[bodywin_pump(&slot->body, slot->req_buf, route_body_sink, &c)](l, i);
}

/* slot streams its body: already started, or starts now. */
static int route_body_ready(
    const wired_srvloop_dispatch_ctx* ctx, wired_srvloop_stream_slot* slot) {
  return slot->body.on || route_body_start(ctx, slot);
}

/* RFC 9114 4.1: stream slot i's body to on_body. 1 if the slot is on the
 * streaming path (the buffered completion below then stays out of it). */
static int route_body(const wired_srvloop_dispatch_ctx* ctx, int i) {
  if (!srvloop_route_body_on(ctx)) {
    return 0;
  }
  if (!route_body_ready(ctx, &ctx->l->streams[i])) {
    return 0;
  }
  route_body_pump(ctx->l, i);
  return 1;
}

/* Slot i is on the streaming-body path, or was answered for overflowing. */
static int route_answered_early(const wired_srvloop_dispatch_ctx* ctx, int i) {
  return route_body(ctx, i) || srvloop_route_complete_over(ctx, i);
}

/* Decode slot i's request if it just completed, using the slot's OWN
 * scratch/wrap/req storage (each stream's decoded views must stay alive
 * independently of the others'). */
void srvloop_route_complete_slot(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in,
    int                               i) {
  wired_srvloop_stream_slot* slot = &ctx->l->streams[i];
  wired_srvloop_reqacc       acc  = srvloop_route_slot_acc(slot);
  int                        got  = 0;
  wired_srvloop_dispatch_in  sin  = {
      in->payload, wired_mspan_of(slot->req_scratch, sizeof slot->req_scratch),
      wired_mspan_of(slot->req_wrap, sizeof slot->req_wrap), &got, &slot->req};
  if (route_answered_early(ctx, i)) {
    return;
  }
  if (!srvloop_request_complete(ctx->h3, &acc, &sin)) {
    srvloop_route_note_qpack(
        ctx->l, i); /* RFC 9204 2.2.3: no FIN may ever come */
    return;
  }
  srvloop_route_dispatch_complete(ctx, &acc, &sin);
  srvloop_route_note_result(ctx->l, i, got);
}

/* Run completion over every slot this payload touched. */
static void route_complete_touched(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in,
    u64                               touched) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++) {
    if ((touched >> i) & (u64)1) {
      srvloop_route_complete_slot(ctx, in, (int)i);
    }
  }
}

/* The routed (ctx->l != 0) reassembly path: per-frame slot routing, then
 * per-touched-slot completion. */
static int reassemble_routed(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  u64 touched = 0;
  if (!srvloop_route_request_frames(ctx, in->payload, &touched)) {
    return 0;
  }
  route_complete_touched(ctx, in, touched);
  return 1;
}

/* The single-accumulator (ctx->l == 0) path: the caller owns the acc and the
 * scratch/wrap/req in `in` -- the direct-dispatch test surface. */
static int reassemble_single(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  if (!srvloop_gather_request(ctx->l, in->payload.p, in->payload.n, ctx->acc)) {
    return 0;
  }
  if (srvloop_request_complete(ctx->h3, ctx->acc, in)) {
    srvloop_drive_complete(ctx->h3, ctx->acc, in);
  }
  return 1;
}

/* RFC 9000 2.2 / RFC 9114 4.1: accumulate this payload's request-stream frames;
 * once FIN closes the stream, decode the reassembled request exactly once.
 * Returns 1 if a request-stream frame was present (handled), 0 otherwise. */
int srvloop_reassemble_and_drive(
    const wired_srvloop_dispatch_ctx* ctx,
    const wired_srvloop_dispatch_in*  in) {
  return ctx->l ? reassemble_routed(ctx, in) : reassemble_single(ctx, in);
}
