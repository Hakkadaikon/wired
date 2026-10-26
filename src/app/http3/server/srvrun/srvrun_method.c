#include "app/http3/server/srvrun/srvrun_impl.h"
#include "app/http3/server/srvrun/srvrun_origin.h"

static void srvrun_start_method_status(
    wired_srvrun_env* env,
    int               slot,
    srvrun_conn*      c,
    srvrun_resp*      r,
    u16               status);
static int          srvrun_req_answered(srvrun_conn* c, u64 id);
static srvrun_resp* srvrun_start_resp_claim(srvrun_conn* c);
static u16          srvrun_non_wt_status(const wired_h3reqdrive_req* r);
static void         srvrun_stop_unread(const srvrun_cfg* cfg, srvrun_conn* c);
static void         srvrun_dispatch_resp(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r);
static int  srvrun_past_goaway(const srvrun_conn* c, u64 id);
static void srvrun_reject_past_goaway(const srvrun_cfg* cfg, srvrun_conn* c);

/* srvrun_dispatch_wt gated on the client's own SETTINGS having arrived first
 * (WTH3-009/042: held until they do) and its transport parameters carrying
 * every value WebTransport requires (WTH3-007) -- split out so
 * srvrun_dispatch_resp's own dispatch decision stays a single branch (CCN).
 * A CONNECT failing the transport-parameter gate is rejected the same way a
 * malformed Origin is (403), since draft-ietf-webtrans-http3-15 does not
 * name a specific status for it. */
void srvrun_dispatch_wt_gated(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (!srvrun_wt_settings_ready(c)) {
    srvrun_wt_hold(c, r);
    return;
  }
  if (!srvrun_wt_tp_ok(c)) {
    srvrun_reject_wt(cfg->env, slot, c, r);
    return;
  }
  srvrun_dispatch_wt_resource(cfg, c, slot, r);
}

/* RFC 9110 9.1 (9110-017/9110-018): the status this request's method earns
 * before it ever reaches the application handler -- 0 once it passes both
 * gates, 501 for a method this server does not even recognize, 405 for one
 * it recognizes but does not allow through (see method.h's doc for the
 * allow set). Checked ahead of the WT Extended CONNECT dispatch in
 * srvrun_start_resp so a malformed/unsupported method never reaches either
 * path. */
u16 srvrun_method_status(const wired_h3reqdrive_req* r) {
  wired_span method = wired_span_of(r->method, r->method_len);
  if (!h3_method_is_known(method)) {
    return 501;
  }
  if (!h3_method_is_allowed(method)) {
    return 405;
  }
  return 0;
}

/* Seal the bare status-only response srvrun_method_status asked for into r's
 * own storage row, reusing srvrun_start_wt_status's low-level prefix+arm
 * primitive (it is protocol-level response building, not WT-specific despite
 * the name). */
static void srvrun_start_method_status(
    wired_srvrun_env* env,
    int               slot,
    srvrun_conn*      c,
    srvrun_resp*      r,
    u16               status) {
  srvrun_start_wt_status(env, slot, c, r, status, 0);
}

/* Build the decoded request's response into a freshly claimed resp[] slot
 * and arm its session over the whole stream. A request stream that already
 * has an in-flight response is dropped rather than claiming a second slot
 * for it (its existing response keeps flowing); a request with no free slot
 * anywhere is also dropped (bounded, same policy as the old single-response-
 * per-connection table). An Extended CONNECT for WebTransport (RFC 9220 3,
 * draft-ietf-webtrans-http3-15 SS3) establishes a WT session or is rejected
 * with 403, and never reaches the app handler. */
/* 1 iff stream id was already answered and its answer still stands: a
 * response in flight, or an established WT session on it (one response
 * per request -- a CONNECT stream outlives its reaped 200). */
static int srvrun_req_answered(srvrun_conn* c, u64 id) {
  return srvrun_resp_find(c, id) || srvrun_wt_slot_by_connect_id(c, id) >= 0;
}

/* Claim a fresh resp[] slot for c->l.req_stream_id, or 0 when the stream
 * was already answered (srvrun_req_answered) or every slot is busy. */
static srvrun_resp* srvrun_start_resp_claim(srvrun_conn* c) {
  if (srvrun_req_answered(c, c->l.req_stream_id)) {
    return 0;
  }
  return srvrun_resp_claim(c, c->l.req_stream_id);
}

/* RFC 9110 9.1 / RFC 9220 3: the status a non-WT request earns before it
 * reaches the app handler -- srvrun_method_status's own 501/405, or 501 for
 * an Extended CONNECT naming an unsupported :protocol
 * (srvrun_is_wt_connect_unsupported_protocol, checked first since that
 * predicate only matches a shape srvrun_method_status would otherwise wave
 * through as a plain CONNECT). 0 once neither applies. Split out of
 * srvrun_dispatch_resp so its own branch count stays at the CCN gate. */
static u16 srvrun_non_wt_status(const wired_h3reqdrive_req* r) {
  if (r->too_large_status) {
    return r->too_large_status;
  }
  if (srvrun_is_wt_connect_unsupported_protocol(r)) {
    return 501;
  }
  return srvrun_method_status(r);
}

/* A 413/431 answers a request the server stopped reading (an overflow, or
 * on_body declining): ask the client to stop sending the rest. */
static void srvrun_stop_unread(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (c->l.req.too_large_status) {
    srvrun_send_stop_sending(cfg, c, c->l.req_stream_id);
  }
}

/* Route a claimed slot to WT dispatch, a method/protocol-status response
 * (501/405), or the application handler -- split out of srvrun_start_resp so
 * its own `!r` guard stays a single branch at the CCN gate. */
static void srvrun_dispatch_resp(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  u16 status;
  if (srvrun_is_wt_connect(&c->l.req)) {
    srvrun_dispatch_wt_gated(ctx->cfg, c, slot, r);
    return;
  }
  status = srvrun_origin_status(c, srvrun_non_wt_status(&c->l.req));
  if (status) {
    srvrun_start_method_status(ctx->cfg->env, slot, c, r, status);
    srvrun_stop_unread(ctx->cfg, c);
    return;
  }
  srvrun_start_app_resp(ctx, c, slot, r);
}

/* RFC 9114 5.2: 1 if stream id is at or past the GOAWAY c already sent --
 * a request the server announced it will not process. */
static int srvrun_past_goaway(const srvrun_conn* c, u64 id) {
  return c->goaway_sent && id >= c->goaway_id;
}

/* RFC 9114 5.2 / 8.1: refuse a request opened past the GOAWAY with
 * H3_REQUEST_REJECTED (RESET_STREAM + STOP_SENDING) and free its slot,
 * never dispatching it. */
static void srvrun_reject_past_goaway(const srvrun_cfg* cfg, srvrun_conn* c) {
  srvrun_send_wt_busy_reset(cfg, c, c->l.req_stream_id, H3_REQUEST_REJECTED);
  wired_srvloop_slot_release(&c->l, c->l.req_stream_id);
}

void srvrun_start_resp(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_resp* r;
  if (srvrun_past_goaway(c, c->l.req_stream_id)) {
    srvrun_reject_past_goaway(ctx->cfg, c);
    return;
  }
  r = srvrun_start_resp_claim(c);
  if (!r) {
    return;
  }
  srvrun_dispatch_resp(ctx, c, slot, r);
}

/* The wire FIN belongs on exactly the slice that ends the whole response:
 * computed fresh at send time as "ends at the queue's current logical end,
 * with no more refills coming" -- never from sl->fin, which is frozen at
 * take time and goes stale the moment a later refill extends the queue (a
 * requeued end-of-buffer slice would otherwise retransmit with FIN at a
 * mid-stream offset, RFC 9000 4.5 FINAL_SIZE_ERROR). The Extended CONNECT
 * stream never gets FIN at all: it IS the WebTransport session
 * (draft-ietf-webtrans-http3 4) -- a FIN on the session-accept 200 reads
 * as "session over" and Chrome closes with code 0 the moment it arrives.
 * Scoped to r's own stream_id: sibling normal responses still get theirs.
 */
u8 srvrun_slice_fin(
    const srvrun_conn* c, const srvrun_resp* r, const wired_sendq_slice* sl) {
  if (srvrun_wt_slot_by_connect_id(c, r->stream_id) >= 0) {
    return 0;
  }
  if (r->streaming) {
    return 0; /* the handler still owes bytes */
  }
  return (u8)(sl->offset + sl->len == r->sess.q.len);
}
