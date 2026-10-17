#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_req_slot_matches(const wired_srvloop_stream_slot* s, u64 id);
static int srvrun_req_slot_idx(const srvrun_conn* c, u64 id);
static wired_srvloop_stream_slot* srvrun_req_slot_mut(srvrun_conn* c, u64 id);
static int srvrun_wt_capsule_raise(wired_wt_session* s, u64 type, u64 v);
static int srvrun_wt_close_body_ok(wired_span value);

/* Common body of "close WT session slot sidx, resetting every stream it owns
 * with err_code and freeing the slot" -- shared by srvrun_close_wt_on_stream_
 * close (WT_SESSION_GONE, triggered by the CONNECT stream itself closing),
 * srvrun_wt_rx_capsules_one (WT_SESSION_GONE, triggered by a malformed
 * capsule on the CONNECT stream), and srvrun_send_wt_close (WT_CLOSE_SESSION,
 * WTH3-067). Split out so no caller repeats the free-slot bookkeeping. */
/* App-facing session-ended delivery (wired_wt_on_session_close): every path
 * that ends a WT session server-side funnels through here, BEFORE the
 * session's storage can be reused by a later connection -- an app keying
 * per-session state on the session pointer frees it in this callback. */
void srvrun_notify_wt_close(const srvrun_cfg* cfg, wired_wt_session* s) {
  if (cfg->wt_on_session_close == 0) return;
  cfg->wt_on_session_close(cfg->wt_session_close_ctx, s);
}

void srvrun_close_wt_session_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 err_code) {
  srvrun_notify_wt_close(cfg, srvrun_wt_slot(c, sidx));
  wired_wt_session_close(srvrun_wt_slot(c, sidx));
  srvrun_reset_wt_streams_for_session(cfg, c, sidx, err_code);
  srvrun_wt_connect_sender_drop(c, sidx);
  /* The CONNECT stream's reassembly slot was kept past its 2xx's resp reap
   * (srvrun_resp_release_stream) so the peer's session flow-control
   * capsules kept landing there (srvrun_wt_rx_capsules) -- with the session
   * gone, nothing reads it anymore; release it (idempotent when the reap
   * already did). */
  wired_srvloop_slot_release(&c->l, srvrun_wt_slot(c, sidx)->connect_stream_id);
  /* Closing frees the slot -- a later Extended CONNECT may reuse it
   * (srvrun_wt_free_slot's own check is the active flag, not session state,
   * since WIRED_WT_UNESTABLISHED's enum value 0 is indistinguishable from
   * "never initialized" by state alone). */
  *srvrun_wt_active_slot(c, sidx) = 0;
}

/* draft-ietf-webtrans-http3-15 SS5.6 / RFC 9297 SS3.2: the CONNECT stream's
 * reassembly slot (l.streams[], claimed for the Extended CONNECT request and
 * kept alive for the session's lifetime), or 0 when session slot sidx is
 * inactive or its stream has no reassembly slot -- the receive-side source
 * srvrun_wt_rx_capsules decodes the peer's session flow-control capsules
 * from. */
/* 1 iff this request reassembly slot is claimed for stream id -- the same
 * check srvloop.c's own (file-static) slot_matches makes, re-stated here
 * because that one is not visible across the module boundary. */
static int srvrun_req_slot_matches(const wired_srvloop_stream_slot* s, u64 id) {
  return s->in_use && s->stream_id == id;
}

/* Index of the request reassembly slot claimed for stream id, -1 if none. */
static int srvrun_req_slot_idx(const srvrun_conn* c, u64 id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    if (srvrun_req_slot_matches(&c->l.streams[i], id)) return (int)i;
  return -1;
}

/* The request reassembly slot claimed for stream id, or 0 if none. */
const wired_srvloop_stream_slot* srvrun_req_slot_of(
    const srvrun_conn* c, u64 id) {
  int i = srvrun_req_slot_idx(c, id);
  return i < 0 ? 0 : &c->l.streams[i];
}

/* srvrun_req_slot_of for a slot the caller writes. */
static wired_srvloop_stream_slot* srvrun_req_slot_mut(srvrun_conn* c, u64 id) {
  int i = srvrun_req_slot_idx(c, id);
  return i < 0 ? 0 : &c->l.streams[i];
}

wired_srvloop_stream_slot* srvrun_wt_rx_slot(srvrun_conn* c, int sidx) {
  if (!srvrun_wt_is_active(c, sidx)) return 0;
  return srvrun_req_slot_mut(c, srvrun_wt_slot_c(c, sidx)->connect_stream_id);
}

/* RFC 9297 SS3.2 / RFC 9220 3: on the CONNECT stream, everything after the
 * request's own single HEADERS frame is capsule bytes -- the byte length of
 * that frame (type + length varints + payload, h3_frame_get) within the
 * just-established request's reassembly slot is where the capsule cursor
 * starts. 0 when the slot is gone or the frame does not parse (nothing is
 * consumed until real capsule bytes decode there anyway). */
usz srvrun_wt_capsule_start(const srvrun_conn* c) {
  const wired_srvloop_stream_slot* slot =
      srvrun_req_slot_of(c, c->l.req_stream_id);
  h3_frame f;
  if (!slot) return 0;
  return h3_frame_get(wired_span_of(slot->req_buf, slot->req_len), &f);
}

/* 1 iff type is a session flow-control capsule this server applies on
 * receive (SS5.6.2/SS5.6.4): WT_MAX_DATA and the two WT_MAX_STREAMS
 * directions. Every unknown type is skipped by the caller instead (RFC 9297
 * SS3.2: "receivers MUST skip over an unknown capsule"); the blocked-hint
 * capsules are handled separately by srvrun_wt_capsule_streams_blocked_type
 * (draft-ietf-webtrans-http3-16 SS5.6.3 gives WT_STREAMS_BLOCKED a ceiling
 * check despite applying no state). */
int srvrun_wt_capsule_flow_type(u64 type) {
  return type == WTCAPSULE_TYPE_MAX_DATA ||
         type == WTCAPSULE_TYPE_MAX_STREAMS_BIDI ||
         type == WTCAPSULE_TYPE_MAX_STREAMS_UNI;
}

/* 1 iff type is either direction of WT_STREAMS_BLOCKED
 * (draft-ietf-webtrans-http3-16 SS5.6.3). */
int srvrun_wt_capsule_streams_blocked_type(u64 type) {
  return type == WTCAPSULE_TYPE_STREAMS_BLOCKED_BIDI ||
         type == WTCAPSULE_TYPE_STREAMS_BLOCKED_UNI;
}

/* 1 iff type is governed by session-level flow control at all (SS5.6): the
 * two WT_MAX_STREAMS/WT_STREAMS_BLOCKED directions, or WT_MAX_DATA. */
int srvrun_wt_capsule_is_flow_control(u64 type) {
  return srvrun_wt_capsule_flow_type(type) ||
         srvrun_wt_capsule_streams_blocked_type(type);
}

/* Apply one decoded flow-control value to the session, 1 if the setter
 * accepted it. A non-increasing value or one exceeding 2^60 (session.c) is
 * a protocol violation the caller closes the session over with
 * WT_FLOW_CONTROL_ERROR (draft-ietf-webtrans-http3-16 SS5.6.2/SS5.6.4). */
static int srvrun_wt_capsule_raise(wired_wt_session* s, u64 type, u64 v) {
  if (type == WTCAPSULE_TYPE_MAX_DATA)
    return wired_wt_session_set_max_data(s, v);
  return wired_wt_session_set_max_streams(
      s, type == WTCAPSULE_TYPE_MAX_STREAMS_BIDI, v);
}

/* 1 iff value is a WT_CLOSE_SESSION body whose message both fits the
 * WTCAPSULE_CLOSE_MESSAGE_MAX cap and is valid UTF-8 (draft-ietf-webtrans-
 * http3-16 SS6). value.n < WTCAPSULE_CLOSE_CODE_LEN (too short for even the
 * fixed 4-byte code) covers bodywin's own "oversized capsule, handed over
 * empty" case too (body_window.h's bodywin_capq_oversized): a well-formed
 * CLOSE body is never shorter than its code, so either way this is the
 * same length violation. */
static int srvrun_wt_close_body_ok(wired_span value) {
  usz msg_n;
  if (value.n < WTCAPSULE_CLOSE_CODE_LEN) return 0;
  msg_n = value.n - WTCAPSULE_CLOSE_CODE_LEN;
  if (msg_n > WTCAPSULE_CLOSE_MESSAGE_MAX) return 0;
  return wtcapsule_utf8_valid(
      wired_span_of(value.p + WTCAPSULE_CLOSE_CODE_LEN, msg_n));
}

/* draft-ietf-webtrans-http3-16 SS6: a WT_CLOSE_SESSION always ends the
 * session (0); an invalid body (too long or not UTF-8) additionally latches
 * H3_MESSAGE_ERROR so the caller resets the CONNECT stream with it. */
int srvrun_wt_capsule_close(srvrun_wt_caprx* x, wired_span value) {
  if (!srvrun_wt_close_body_ok(value)) x->violation_code = H3_MESSAGE_ERROR;
  return 0;
}

/* WT_STREAMS_BLOCKED: 1 if value is a well-formed varint within the 2^60
 * ceiling, else 0 with x->violation_code set to WT_FLOW_CONTROL_ERROR
 * (draft-ietf-webtrans-http3-16 SS5.6.3). A malformed body (not one whole
 * varint) is the pre-existing "malformed capsule" case and keeps the
 * caller's WT_SESSION_GONE default instead. */
int srvrun_wt_capsule_streams_blocked(srvrun_wt_caprx* x, wired_span value) {
  u64 v;
  if (!wtcapsule_value_varint(value, &v)) return 0;
  if (wtsession_streams_blocked_ok(v)) return 1;
  x->violation_code = WTERR_FLOW_CONTROL_ERROR;
  return 0;
}

/* WT_MAX_DATA/WT_MAX_STREAMS: 1 if value is a well-formed varint the setter
 * accepted, else 0. x->violation_code is set to WT_FLOW_CONTROL_ERROR only
 * when the body parsed but the setter rejected the value (non-increasing,
 * or -- WT_MAX_STREAMS only -- over the 2^60 ceiling, session.c) -- a
 * malformed body keeps the caller's WT_SESSION_GONE default, matching the
 * pre-existing malformed-capsule case. */
int srvrun_wt_capsule_flow_raise(
    srvrun_wt_caprx* x, u64 type, wired_span value) {
  u64 v;
  if (!wtcapsule_value_varint(value, &v)) return 0;
  if (srvrun_wt_capsule_raise(x->s, type, v)) return 1;
  x->violation_code = WTERR_FLOW_CONTROL_ERROR;
  return 0;
}
