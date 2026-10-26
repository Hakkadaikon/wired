#include "app/http3/server/srvrun/srvrun_impl.h"

static int  srvrun_stream_id_is_client_bidi(u64 stream_id);
static void srvrun_reject_wt_bad_id(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r);

/* Body of srvrun_start_resp for a normal (non-WT) request: run the app
 * handler's first round, then frame+arm the response -- H3-framed or
 * hq-interop-raw depending on what this connection negotiated. Split out so
 * srvrun_start_resp itself stays at its gate/dispatch decision (CCN). */
void srvrun_start_app_resp(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  u8*        st = srvrun_resp_storage(ctx, slot, c, r);
  wired_obuf body =
      obuf_of(st + SRVRUN_RESP_HDR_ROOM, srvrun_resp_storage_cap(r));
  wired_http_exchange x          = {0};
  u64                 base_shift = srvrun_maybe_send_continue(ctx->cfg, c);
  r->stream_h3_framed            = 0;
  x.body                         = &body;
  srvrun_call_round0(ctx, c, &x);
  srvrun_arm_round0(ctx, c, slot, r, st, &x, base_shift);
}

/* Reject this Extended CONNECT with 429 (a new Extended CONNECT arriving
 * while every session slot is already occupied, SRVRUN_MAX_WT_SESSIONS
 * reached) without disturbing any existing session -- srvrun_start_wt
 * only ever claims a FREE slot (srvrun_wt_free_slot), so an existing
 * ESTABLISHED session's own slot is never re-initialized by this path. Also
 * aborts the rejected stream with H3_REQUEST_REJECTED (RFC 9114 4.1.1/8.1),
 * independent of and in addition to the 429 above. */
void srvrun_reject_wt_busy(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  srvrun_start_wt_status(cfg->env, slot, c, r, 429, 0);
  srvrun_send_wt_busy_reset(cfg, c, c->l.req_stream_id, H3_REQUEST_REJECTED);
}

/* RFC 9000 2.1: bit 0x01 of a stream id is the initiator role (0 = client),
 * bit 0x02 is the directionality (0 = bidi) -- so a client-initiated bidi
 * stream id is exactly the ones with both low bits clear. Same check as
 * srvloop/dispatch.c's is_request_stream, duplicated here because that one is
 * file-static and srvrun.c has no visibility into it. */
static int srvrun_stream_id_is_client_bidi(u64 stream_id) {
  return (stream_id & 0x03) == 0;
}

/* draft-ietf-webtrans-http3-15 SS3.2/SS4: the WT session id is the CONNECT
 * stream's own id, so it must be a client-initiated bidi stream
 * id (RFC 9000 2.1) or the session would be keyed by an id that cannot
 * possibly be the client's request stream. RFC 9114 8.1 lists H3_ID_ERROR for
 * exactly this "stream id used incorrectly" case; it is a stream-level abort
 * reason, so this mirrors srvrun_reject_wt_busy's RESET_STREAM+STOP_SENDING
 * shape rather than a CONNECTION_CLOSE. */
static void srvrun_reject_wt_bad_id(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  srvrun_start_wt_status(cfg->env, slot, c, r, 403, 0);
  srvrun_send_wt_busy_reset(cfg, c, c->l.req_stream_id, H3_ID_ERROR);
}

/* Body of srvrun_dispatch_wt once Origin has passed and no session is
 * already active: reject a non-client-bidi session id or establish the
 * session. Split out so srvrun_dispatch_wt itself stays at one
 * gate (CCN). */
void srvrun_dispatch_wt_free_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (!srvrun_stream_id_is_client_bidi(c->l.req_stream_id)) {
    srvrun_reject_wt_bad_id(cfg, c, slot, r);
    return;
  }
  srvrun_start_wt(cfg, slot, c, r);
}

/* A well-formed Extended CONNECT for WebTransport either establishes a
 * session (Origin absent, or present and well-formed, and no session
 * already active on this connection), or is rejected: 403 for a malformed
 * or app-refused Origin, 429 if no session slot is free (per connection or
 * server-wide, srvrun_wt_no_room), or H3_ID_ERROR if the CONNECT stream's own
 * id is not a client-initiated bidi stream id. */
void srvrun_dispatch_wt(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (!srvrun_wt_origin_ok(cfg, &c->l.req)) {
    srvrun_reject_wt(cfg->env, slot, c, r);
    return;
  }
  if (srvrun_wt_no_room(cfg, c)) {
    srvrun_reject_wt_busy(cfg, c, slot, r);
    return;
  }
  srvrun_dispatch_wt_free_slot(cfg, c, slot, r);
}

/* draft-ietf-webtrans-http3-15 SS3.2 (WTH3-016/WTH3-018): the app's resource
 * check runs before Origin verification (the RFC lists it first: "the HTTP/3
 * server can check if it has a WebTransport server associated with the
 * specified :authority and :path values ... When the request contains the
 * Origin header, the WebTransport server MUST verify" second) -- a status of
 * 0 (accept, including the no-callback-registered default) falls through to
 * srvrun_dispatch_wt unchanged; any other status seals and sends the app's
 * verdict verbatim instead. Split out of srvrun_dispatch_wt_gated so its own
 * branch count stays at the CCN gate. */
void srvrun_dispatch_wt_resource(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  wired_wt_resource_decision d;
  srvrun_wt_resource_decide(cfg, c, &d);
  if (d.status) {
    srvrun_start_wt_resource_status(cfg->env, slot, c, r, &d);
    return;
  }
  srvrun_dispatch_wt(cfg, c, slot, r);
}

/* draft-ietf-webtrans-http3-15 SS3.1 (WTH3-009/042): "for draft versions of
 * WebTransport, the server shall not process any incoming WebTransport
 * requests until the client's SETTINGS have been received." c->l.h3peer.ctrl
 * (priority_ctrl.c's ctrl_note_generic) latches settings_seen the moment the
 * client's control-stream SETTINGS frame is actually walked -- 0 here means
 * either no control stream has been reassembled yet, or one has but its
 * SETTINGS has not yet arrived. */
int srvrun_wt_settings_ready(const srvrun_conn* c) {
  return c->l.h3peer.ctrl.settings_seen != 0;
}

/* draft-ietf-webtrans-http3-15 SS3.1 (WTH3-007): "If the server receives ...
 * transport parameters that do not have correct values for every required
 * WebTransport ... parameter, then the server shall treat ... newly incoming
 * WebTransport sessions as malformed." RFC 9297 2.1.1 requires a peer that
 * wants HTTP Datagrams (which every WebTransport session rides on, SS4.5) to
 * advertise a non-zero max_datagram_frame_size transport parameter (0 is
 * this repo's existing "not advertised" sentinel, c->s.sdrv's own doc) -- a
 * WT CONNECT from a peer that never advertised it is exactly this "incorrect
 * value for a required parameter" case, so newly incoming sessions are
 * rejected rather than established malformed. */
int srvrun_wt_tp_ok(const srvrun_conn* c) {
  return c->s.sdrv.peer_max_datagram_frame_size != 0;
}

/* WTH3-009/042: hold this CONNECT until the client's SETTINGS arrive --
 * no response yet (r is handed back unused), only its request slot's bit
 * in wt_held_mask; srvrun_start_held_resps processes it then. */
void srvrun_wt_hold(srvrun_conn* c, srvrun_resp* r) {
  const wired_srvloop_stream_slot* s =
      srvrun_req_slot_of(c, c->l.req_stream_id);
  r->in_use = 0;
  if (!s) {
    return;
  }
  c->wt_held_mask |= (u64)1 << (s - c->l.streams);
  c->wt_held_id[s - c->l.streams] = s->stream_id;
}
