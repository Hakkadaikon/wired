#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_resp_matches(const srvrun_resp* r, u64 stream_id);

/* 1 if r is claimed and answering stream_id. */
static int srvrun_resp_matches(const srvrun_resp* r, u64 stream_id) {
  return r->in_use && r->stream_id == stream_id;
}

/* The in-use resp[] slot answering stream_id, or 0 if none (RFC 9000 2.2:
 * at most one response per request stream at a time). */
srvrun_resp* srvrun_resp_find(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (srvrun_resp_matches(&c->resp[i], stream_id)) {
      return &c->resp[i];
    }
  }
  return 0;
}

/* Claim and reset a free resp[] slot for stream_id (caller has already
 * confirmed via srvrun_resp_find that stream_id has none). 0 if every slot
 * is busy -- the request is dropped, same bound as the old single-response-
 * per-connection behavior but per stream instead of per connection. */
srvrun_resp* srvrun_resp_claim(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (c->resp[i].in_use) {
      continue;
    }
    c->resp[i].in_use    = 1;
    c->resp[i].stream_id = stream_id;
    /* Start from no send state: a slot freed mid-send (srvrun_resp_stop)
     * keeps its old sess, and an arm that never happens (a header section
     * too large to frame) would otherwise send it under this stream id. */
    c->resp[i].sess       = (wired_sendsess){0};
    c->resp[i].bigbuf_row = -1;
    c->resp[i].streaming  = 0;
    c->resp[i].ring_cap   = 0;
    c->resp[i].arm_failed = 0;
    c->resp[i].sdb        = (srvrun_blocked_mark){0, 0};
    /* RFC 9000 18.2/19.10: seed this stream's send credit from the peer's
     * ClientHello TP (initial_max_stream_data_bidi_local, RFC 9000 18.2:
     * the TP sender's own locally-initiated streams' credit -- this
     * client-initiated request stream). MAX_STREAM_DATA naming stream_id
     * only ever raises it (srvrun_sess_on_step applies those each step). */
    c->resp[i].stream_credit =
        c->s.sdrv.peer_initial_max_stream_data_bidi_local;
    return &c->resp[i];
  }
  return 0;
}

/* r's index within c->resp[], for locating its respstore row
 * (env->respstore[slot][index]). */
usz srvrun_resp_index(const srvrun_conn* c, const srvrun_resp* r) {
  return (usz)(r - c->resp);
}

/* Seal an SDK-built status response (srvrun_status_build: one optional
 * extra field line, the SDK's own fields, and a short explanation for a
 * 4xx/5xx) into r's own storage row and arm r's session
 * over it — the same low-level prefix+arm mechanism srvrun_start_app_resp
 * uses for a normal 200, minus the app handler: this is protocol-level
 * WebTransport response building (draft-ietf-webtrans-http3-15 SS3.2), not
 * an application response. Used for both the 2xx that establishes a session
 * (extra = the wt-protocol header when a subprotocol was negotiated, SS3.4)
 * and the 403 that rejects one (extra = 0), and for the SDK's own
 * 405/413/431/501 (srvrun_start_method_status). The response is built
 * whole, so it is written at the row's start rather than
 * right-aligned into the body path's SRVRUN_RESP_HDR_ROOM prefix area. */
void srvrun_start_wt_status(
    wired_srvrun_env*  env,
    int                slot,
    srvrun_conn*       c,
    srvrun_resp*       r,
    u16                status,
    const qpack_field* extra) {
  u8*        st  = env->respstore[slot][srvrun_resp_index(c, r)];
  wired_obuf pob = obuf_of(st, WIRED_SRVRUN_RESP_MAX);
  if (!srvrun_status_build(&c->l.req, status, extra, &pob)) {
    r->arm_failed = 1; /* e.g. an app redirect's Location too long */
    return;
  }
  wired_sendsess_arm(&r->sess, st, pob.len, srvrun_mps(c));
  /* RFC 9110 10.1.1: after an early 100 (Continue), if one went out */
  wired_sendsess_set_base_offset(
      &r->sess, srvrun_continue_shift(c, r->stream_id));
}

/* draft-ietf-webtrans-http3-15 SS3.2 (WTH3-018): "The server may reply with
 * a 3xx response, indicating a redirection (Section 15.4 of [HTTP])." RFC
 * 9110 15.4 ties every 3xx redirect status to a Location response header
 * field naming the target; encoded here as one Literal Field Line With
 * Literal Name (RFC 9204 4.5.6), the same mechanism srvrun_start_wt's own
 * wt-protocol header already uses via srvrun_start_wt_status's extra param. */
void srvrun_reject_wt_redirect(
    wired_srvrun_env* env,
    int               slot,
    srvrun_conn*      c,
    srvrun_resp*      r,
    u16               status,
    wired_span        location) {
  static const u8 name[] = {'l', 'o', 'c', 'a', 't', 'i', 'o', 'n'};
  qpack_field     f      = {wired_span_of(name, sizeof name), location};
  srvrun_start_wt_status(env, slot, c, r, status, &f);
}

/* draft-ietf-webtrans-http3-15 SS3.2: run the app's registered resource
 * check (if any) for this Extended CONNECT's :authority/:path, filling
 * *out. A callback that leaves *out's status at 0 (its caller-zeroed
 * default) accepts the resource -- same as no callback registered at all
 * (cfg->wt_resource_check == 0), which never runs the callback and leaves
 * *out zeroed by this function's own memset-equivalent init. */
void srvrun_wt_resource_decide(
    const srvrun_cfg*           cfg,
    const srvrun_conn*          c,
    wired_wt_resource_decision* out) {
  *out = (wired_wt_resource_decision){0, 0, 0};
  if (!cfg->wt_resource_check) {
    return;
  }
  cfg->wt_resource_check(
      cfg->wt_resource_ctx,
      wired_span_of(c->l.req.authority, c->l.req.authority_len),
      wired_span_of(c->l.req.path, c->l.req.path_len), out);
}
