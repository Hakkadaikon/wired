#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_capsule_flow_or_skip(
    srvrun_wt_caprx* x, u64 type, wired_span value);
static int srvrun_wt_capsule_flow(
    srvrun_wt_caprx* x, u64 type, wired_span value);
static void srvrun_wt_drain_notify(const srvrun_wt_caprx* x);
static int  srvrun_wt_capsule_drain(const srvrun_wt_caprx* x, wired_span value);
static int  srvrun_wt_capsule_ignored(const srvrun_wt_caprx* x, u64 type);
static int  srvrun_wt_capsule_apply(void* ctx, u64 type, wired_span value);
static int  srvrun_wt_rx_ok(int st);

/* The non-CLOSE half of srvrun_wt_capsule_flow: a flow-control setter type,
 * a WT_STREAMS_BLOCKED ceiling check, or skip (RFC 9297 SS3.2). */
static int srvrun_wt_capsule_flow_or_skip(
    srvrun_wt_caprx* x, u64 type, wired_span value) {
  if (srvrun_wt_capsule_streams_blocked_type(type)) {
    return srvrun_wt_capsule_streams_blocked(x, value);
  }
  if (!srvrun_wt_capsule_flow_type(type)) {
    return 1;
  }
  return srvrun_wt_capsule_flow_raise(x, type, value);
}

/* One received capsule. draft-ietf-webtrans-http3-16 SS6: a
 * WT_CLOSE_SESSION ends the session on the spot (srvrun_wt_capsule_close),
 * so a peer withholding the CONNECT stream's FIN cannot keep it alive. */
static int srvrun_wt_capsule_flow(
    srvrun_wt_caprx* x, u64 type, wired_span value) {
  if (type == WTCAPSULE_TYPE_CLOSE) {
    return srvrun_wt_capsule_close(x, value);
  }
  return srvrun_wt_capsule_flow_or_skip(x, type, value);
}

static void srvrun_wt_drain_notify(const srvrun_wt_caprx* x) {
  if (x->env->wt_on_session_draining) {
    x->env->wt_on_session_draining(x->env->wt_session_draining_ctx, x->s);
  }
}

/* draft-ietf-webtrans-http3-15 4.7 Figure 5: WT_DRAIN_SESSION's Length is 0,
 * so one carrying a value is malformed (0, the caller closes the session).
 * Otherwise tell the app, once per session; the session stays as it is. */
static int srvrun_wt_capsule_drain(const srvrun_wt_caprx* x, wired_span value) {
  if (value.n) {
    return 0;
  }
  if (*x->drain_rcvd) {
    return 1;
  }
  *x->drain_rcvd = 1;
  srvrun_wt_drain_notify(x);
  return 1;
}

/* draft-ietf-webtrans-http3-16 SS5.1 (MUST): "if flow control is not
 * enabled, an endpoint MUST ignore receipt of any flow control capsules" --
 * the peer might not have received our SETTINGS yet, or packets might have
 * been reordered. 1 iff type is exactly such a capsule on a session that
 * never negotiated flow control (session.c's own flow_control, set from the
 * peer's SETTINGS_WT_INITIAL_* at session creation, srvrun_wt_seed_limits) --
 * the caller then drops it unapplied, same as an unknown type (RFC 9297
 * SS3.2's "skip"). */
static int srvrun_wt_capsule_ignored(const srvrun_wt_caprx* x, u64 type) {
  return !x->s->flow_control && srvrun_wt_capsule_is_flow_control(type);
}

static int srvrun_wt_capsule_apply(void* ctx, u64 type, wired_span value) {
  srvrun_wt_caprx* x = ctx;
  if (srvrun_wt_capsule_ignored(x, type)) {
    return 1;
  }
  if (type == WTCAPSULE_TYPE_DRAIN) {
    return srvrun_wt_capsule_drain(x, value);
  }
  return srvrun_wt_capsule_flow(x, type, value);
}

/* A capsule pass leaves the session healthy only while the stream is still
 * open or ended cleanly; every other state is a malformed capsule. */
static int srvrun_wt_rx_ok(int st) {
  return st == BODYWIN_OPEN || st == BODYWIN_DONE;
}

/* One session slot's receive pass over its CONNECT stream window: slide out
 * the request HEADERS still in front (wt_capsule_rx_at), then apply every
 * whole capsule (bodywin_capsules). Returns 1 while the session stays
 * healthy, 0 on a malformed capsule (bad body, or the stream FINing
 * mid-capsule, RFC 9297 SS3.3), a flow-control violation, or a
 * WT_CLOSE_SESSION -- out->violation_code then says which code to use. */
int srvrun_wt_rx_walk(
    const srvrun_cfg*          cfg,
    srvrun_conn*               c,
    int                        sidx,
    wired_srvloop_stream_slot* slot,
    srvrun_wt_caprx*           out) {
  if (c->wt_capsule_rx_at[sidx]) {
    bodywin_consume(&slot->body, slot->req_buf, c->wt_capsule_rx_at[sidx]);
  }
  c->wt_capsule_rx_at[sidx] = 0;
  out->env                  = cfg->env;
  out->s                    = srvrun_wt_slot(c, sidx);
  out->drain_rcvd           = &c->wt_drain_rcvd[sidx];
  /* A clean FIN (BODYWIN_DONE) is left to srvrun_close_wt_on_stream_close. */
  return srvrun_wt_rx_ok(bodywin_capsules(
      &slot->body, slot->req_buf, &c->wt_capq[sidx], srvrun_wt_capsule_apply,
      out));
}

/* RESET_STREAM + STOP_SENDING carrying code on session slot sidx's own
 * CONNECT stream, final size every byte already sent on it (RFC 9000 4.5:
 * wt_connect_sent_len), kept until ACKed. The session itself is untouched. */
void srvrun_reset_connect_stream_code(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 code) {
  u8                 pl[48];
  wired_obuf         plb = obuf_of(pl, sizeof pl);
  u64                id  = srvrun_wt_slot(c, sidx)->connect_stream_id;
  reset_stream_frame rs  = {id, code, c->wt_connect_sent_len[sidx]};
  usz                rn  = reset_stream_encode(pl, sizeof pl, &rs);
  usz                sn  = srvrun_wt_abort_stop(id, code, &plb, rn);
  srvrun_send_kept(cfg, c, pl, rn + sn, "WT CONNECT stream reset\n");
}

/* draft-ietf-webtrans-http3-16 SS6: a rejected capsule pass ends the
 * session. An invalid WT_CLOSE_SESSION body also resets the CONNECT stream
 * with H3_MESSAGE_ERROR, and the session's other streams get WT_SESSION_GONE;
 * every other end (the peer's WT_CLOSE_SESSION, a flow-control violation, a
 * malformed capsule) resets the owned streams with its own code and closes
 * this server's side of the CONNECT stream with a FIN (srvrun_wt_connect_fin:
 * the recipient MUST close or reset it in response). */
void srvrun_wt_rx_fail(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 code) {
  if (code == H3_MESSAGE_ERROR) {
    srvrun_reset_connect_stream_code(cfg, c, sidx, code);
    code = WTERR_SESSION_GONE;
  } else {
    srvrun_wt_connect_fin(c, sidx);
  }
  srvrun_close_wt_session_slot(cfg, c, sidx, code);
}
