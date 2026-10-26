#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_copy_stream_req(
    srvrun_resp* r, const wired_h3reqdrive_req* req);
static void srvrun_prime_streaming(
    srvrun_resp*                r,
    const wired_h3reqdrive_req* req,
    int                         more,
    usz                         round_len,
    u64                         base_shift);
static u64  srvrun_round0_total_len(int more, u64 total_size, usz body_len);
static int  srvrun_continue_due(const wired_srvloop_stream_slot* s);
static void srvrun_continue_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_stream_slot* s);

/* Copy req into r->stream_req with every view re-pointed at r's own scratch
 * (see stream_req's doc): later rounds must call the handler with THIS copy,
 * never c->l.req directly, since c->l.req is a per-connection mirror any
 * sibling stream's completion overwrites between rounds -- and its views
 * point into a decode scratch the next request reuses. :path goes first so
 * it is the last to be truncated. wt_avail/cookie are inline arrays the
 * struct copy already owns. */
static void srvrun_copy_stream_req(
    srvrun_resp* r, const wired_h3reqdrive_req* req) {
  wired_h3reqdrive_req* q   = &r->stream_req;
  usz                   off = 0;
  *q                        = *req;
  srvrun_scratch_view(r, &off, &q->path, &q->path_len);
  srvrun_scratch_view(r, &off, &q->method, &q->method_len);
  srvrun_scratch_view(r, &off, &q->authority, &q->authority_len);
  srvrun_scratch_view(r, &off, &q->scheme, &q->scheme_len);
  srvrun_scratch_view(r, &off, &q->protocol, &q->protocol_len);
  srvrun_scratch_view(r, &off, &q->origin, &q->origin_len);
  srvrun_copy_stream_hdrs(r, off);
  q->body     = 0; /* not valid past round 0, streaming is GET */
  q->body_len = 0;
}

/* Prime r's streaming state after round 0: stays 0 for an
 * ordinary single-round response. base_shift is round 0's own base offset
 * (0, or a preceding 100-continue HEADERS frame's byte length, RFC 9110
 * 10.1.1) that round 1's own offset must keep counting up from. */
static void srvrun_prime_streaming(
    srvrun_resp*                r,
    const wired_h3reqdrive_req* req,
    int                         more,
    usz                         round_len,
    u64                         base_shift) {
  r->streaming = more != 0;
  if (!more) {
    return;
  }
  wired_sendsess_set_base_offset(&r->sess, base_shift);
  r->stream_off = base_shift + round_len;
  srvrun_copy_stream_req(r, req);
}

/* Arm r's round-0 body over st, hq-interop-raw or H3-framed depending on
 * what this connection negotiated, and prime the streaming state when the
 * handler asked for another round. base_shift shifts round 0's own STREAM
 * frame offset past a preceding 100-continue interim response (0 for the
 * ordinary case, see srvrun_send_continue). */
/* round 0's DATA frame length: the streaming total when the handler asked
 * for more rounds, else just this (only) round's own body. Split out so
 * srvrun_arm_round0's own branch count stays at the CCN gate. */
static u64 srvrun_round0_total_len(int more, u64 total_size, usz body_len) {
  if (more) {
    return total_size;
  }
  return body_len;
}

/* Turn a freshly-armed streaming response's queue into a ring over the
 * remainder of its storage row -- from wherever round 0's arm placed q.p
 * (the H3 prefix start, or st + HDR_ROOM for hq-interop) to the row's end.
 * The refill loop (srvrun_resp_refill) then cycles through it for the whole
 * response instead of draining and re-arming per round. */
void srvrun_resp_ring_init(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  u8* base    = srvrun_resp_storage_ro(ctx, slot, c, r);
  r->ring_cap = srvrun_resp_row_size(r) - (usz)(r->sess.q.p - base);
  wired_sendq_set_ring(&r->sess.q, r->ring_cap);
}

void srvrun_arm_round0(
    const srvrun_step_ctx*     ctx,
    srvrun_conn*               c,
    int                        slot,
    srvrun_resp*               r,
    u8*                        st,
    const wired_http_exchange* x,
    u64                        base_shift) {
  const wired_obuf* body = x->body;
  u64 total_len = srvrun_round0_total_len(x->more, x->total_size, body->len);
  if (c->s.sdrv.alpn == SALPN_HQ) {
    srvrun_arm_hq09_resp(c, r, st, body);
  } else {
    srvrun_arm_h3_resp(ctx, c, slot, r, st, x, total_len);
  }
  wired_sendsess_set_base_offset(&r->sess, base_shift);
  srvrun_prime_streaming(r, &c->l.req, x->more, body->len, base_shift);
  if (r->streaming) {
    srvrun_resp_ring_init(ctx, c, slot, r);
  }
}

/* Run the app handler's round 0 into x, settling a wired_http_handler's
 * status/fields (srvrun_http_settle; a 7-argument handler is always 200
 * and is left untouched). */
void srvrun_call_round0(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_http_exchange* x) {
  x->req = &c->l.req;
  srvrun_call_handler(ctx, x);
  if (ctx->cfg->http) {
    srvrun_http_settle(x);
  }
}

/* 1 iff request slot s asked for 100-continue and has not had it yet. */
static int srvrun_continue_due(const wired_srvloop_stream_slot* s) {
  return s->in_use && s->req.expect_continue && !s->continue_len;
}

/* RFC 9110 10.1.1: "The origin server MUST NOT wait for the content
 * before sending the 100 (Continue) response." Slot s's HEADERS frame was
 * decoded the moment it was whole (srvloop's CONNECT peek on the buffered
 * path, route_body_start when bodies stream), so the 100 goes out on that
 * same step; continue_len records where the final response's stream
 * offset starts (0 when no 1-RTT key could seal it yet). Tried once. */
static void srvrun_continue_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_stream_slot* s) {
  if (!srvrun_continue_due(s)) {
    return;
  }
  s->continue_len = (u16)(SRVLOOP_CONTINUE_TRIED |
                          srvrun_send_continue(cfg, c, s->stream_id));
}

/* Send every 100 (Continue) this step's HEADERS frames asked for, ahead of
 * the final responses srvrun_start_done_resps starts next. */
void srvrun_send_continues(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++) {
    srvrun_continue_slot(ctx->cfg, c, &c->l.streams[i]);
  }
}

/* The stream bytes stream_id's 100 (Continue) already took: the base
 * offset its final response starts at (0 if none was sent). */
u64 srvrun_continue_shift(const srvrun_conn* c, u64 stream_id) {
  const wired_srvloop_stream_slot* s = srvrun_req_slot_of(c, stream_id);
  return s ? s->continue_len & ~SRVLOOP_CONTINUE_TRIED : 0;
}

/* RFC 9110 10.1.1: the base offset shift srvrun_arm_round0 must apply so
 * the final response continues the stream right after its 100-continue
 * interim: the one srvrun_send_continues already sent, else -- a request
 * that never went through it (no request slot) -- sent now. 0 when the
 * request did not ask, or no confirmed 1-RTT key could seal one. */
u64 srvrun_maybe_send_continue(const srvrun_cfg* cfg, srvrun_conn* c) {
  const wired_srvloop_stream_slot* s =
      srvrun_req_slot_of(c, c->l.req_stream_id);
  if (s) {
    return s->continue_len & ~SRVLOOP_CONTINUE_TRIED;
  }
  if (!c->l.req.expect_continue) {
    return 0;
  }
  return srvrun_send_continue(cfg, c, c->l.req_stream_id);
}
