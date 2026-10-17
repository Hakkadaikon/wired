#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_copy_stream_req(
    srvrun_resp* r, const wired_h3reqdrive_req* req);
static void srvrun_prime_streaming(
    srvrun_resp*                r,
    const wired_h3reqdrive_req* req,
    int                         more,
    usz                         round_len,
    u64                         base_shift);
static u64 srvrun_round0_total_len(int more, u64 total_size, usz body_len);

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

/* RFC 9110 10.1.1: send the 100-continue interim ahead of round 0 when the
 * request asked for it (c->l.req.expect_continue), returning the base offset
 * shift srvrun_arm_round0 must apply so the final response's STREAM frame
 * continues the same QUIC stream right after it. 0 (no interim, no shift)
 * when the request did not ask, or c has no confirmed 1-RTT key yet to seal
 * one with (srvrun_send_continue's underlying seal simply fails and this
 * still returns 0 -- the final response then starts at offset 0 as usual). */
u64 srvrun_maybe_send_continue(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!c->l.req.expect_continue) {
    return 0;
  }
  return srvrun_send_continue(cfg, c, c->l.req_stream_id);
}
