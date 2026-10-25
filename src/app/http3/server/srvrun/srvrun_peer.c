#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_send_wt_stream_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, usz i);
static int wt_reset_uni_matches(
    const wired_srvloop_wt_uni_stream_slot* slot, u64 reset_stream_id);
static int  wt_reset_bidi_session(srvrun_conn* c, u64 stream_id);
static int  wt_reset_uni_session(srvrun_conn* c, u64 stream_id);
static int  wt_reset_session_slot(srvrun_conn* c, u64 stream_id);
static void srvrun_note_peer_reset(
    srvrun_conn* c, const wired_srvloop_reset* e);
static void srvrun_deliver_one_wt_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, const wired_srvloop_reset* e);

/* Seal and send latch entry i's RESET_STREAM as its own 1-RTT packet. */
static void srvrun_send_wt_stream_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, usz i) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_wt_stream_reset(c, i, &ob)) {
    return;
  }
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "WT stream RESET sent\n");
}

/* Drain the wired_server_wt_stream_reset latch (the wt_stream_reset_*
 * fields' own doc): every entry gets its own RESET_STREAM packet. The send
 * slots were already freed at latch time (wired_server_wt_stream_reset),
 * so only the wire bytes remain to send. */
void srvrun_drain_wt_stream_reset(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < c->wt_stream_reset_n; i++) {
    srvrun_send_wt_stream_reset(cfg, c, i);
  }
  c->wt_stream_reset_n = 0;
}

/* 1 if slot is in-use and its stream id is this step's latched
 * reset entry's stream id -- the same "is this the reset target" test
 * wt_reset_bidi_session/wt_reset_uni_session each apply to their own table,
 * pulled into one predicate so neither loop's own `if` carries the `||`
 * (CCN). */
int srvrun_wt_reset_bidi_matches(
    const wired_srvloop_wt_stream_slot* slot, u64 reset_stream_id) {
  return slot->in_use && slot->stream_id == reset_stream_id;
}

/* Same as srvrun_wt_reset_bidi_matches, for one WT uni stream slot. */
static int wt_reset_uni_matches(
    const wired_srvloop_wt_uni_stream_slot* slot, u64 reset_stream_id) {
  return slot->in_use && slot->stream_id == reset_stream_id;
}

/* A queued peer reset (gather_one_wt_reset, dispatch.c) on stream_id
 * belongs to session slot sidx's own WT bidi stream: free that ONE stream
 * slot (WTH3-036: a reset ends the stream, not its session) and return the
 * session slot it belonged to, or -1 if it names no in-use bidi slot at all
 * -- split out of wt_reset_session_slot so its own branch count stays at
 * the CCN gate. */
static int wt_reset_bidi_session(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    wired_srvloop_wt_stream_slot* slot = &c->l.wt_streams[i];
    if (!srvrun_wt_reset_bidi_matches(slot, stream_id)) {
      continue;
    }
    srvrun_wt_bidi_slot_free(c, slot);
    return slot->wt_session_slot;
  }
  return -1;
}

/* Same as wt_reset_bidi_session, over the uni table. */
static int wt_reset_uni_session(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    wired_srvloop_wt_uni_stream_slot* slot = &c->l.wt_uni_streams[i];
    if (!wt_reset_uni_matches(slot, stream_id)) {
      continue;
    }
    srvrun_wt_uni_slot_free(c, slot);
    return slot->wt_session_slot;
  }
  return -1;
}

/* draft-ietf-webtrans-http3-15 4.4 (WTH3-039/WTH3-040): the session slot
 * this step's latched RESET_STREAM/STOP_SENDING belongs to -- the bidi
 * table first, then the uni table (the two id spaces are disjoint, RFC
 * 9000 2.1, so at most one ever matches), or -1 if the stream id names
 * neither a live WT bidi nor uni slot on this connection at all (e.g. a
 * plain HTTP/3 request stream's own reset, out of WebTransport's scope). */
static int wt_reset_session_slot(srvrun_conn* c, u64 stream_id) {
  int sidx = wt_reset_bidi_session(c, stream_id);
  if (sidx >= 0) {
    return sidx;
  }
  return wt_reset_uni_session(c, stream_id);
}

/* draft-ietf-webtrans-http3-15 4.4 (WTH3-040): "If a RESET_STREAM or
 * STOP_SENDING frame is received with an error code outside the
 * WT_APPLICATION_ERROR range, then the implementation should deliver this
 * to the application as a stream reset with no application error code."
 * wired_wterrmap_from_http3 (errmap.h) recovers the WebTransport application
 * error code when the wire code falls inside that range; mapped is left 0
 * (app_error_code meaningless) otherwise -- this is the SDK-side half of
 * WTH3-040, deciding what to hand the app; wired_wt_on_stream_reset's own
 * doc covers the same split from the app's point of view. */
void srvrun_deliver_wt_reset(
    const srvrun_cfg*          cfg,
    srvrun_conn*               c,
    int                        sidx,
    const wired_srvloop_reset* e) {
  u32 app_code = 0;
  int mapped =
      rawq_reset_code_in(srvrun_conn_is_raw(c), e->error_code, &app_code);
  if (!cfg->wt_on_stream_reset) {
    return;
  }
  cfg->wt_on_stream_reset(
      cfg->wt_stream_reset_ctx, srvrun_wt_slot(c, sidx), e->stream_id, mapped,
      app_code);
}

/* draft-ietf-webtrans-http3-15 4.4 (WTH3-039/WTH3-040): once a step's
 * gather_one_wt_reset (dispatch.c) latched a RESET_STREAM/STOP_SENDING on a
 * stream id that resolves to one of THIS connection's own live WT bidi/uni
 * slots, deliver it to the app (srvrun_deliver_wt_reset) and free that one
 * stream's slot -- narrower than srvrun_close_wt_session_slot, which tears
 * down a whole SESSION; this tears down only the ONE stream the peer reset,
 * leaving the rest of its session untouched (WTH3-036: a reset is a per-
 * stream event, not a session-ending one). Every queued entry
 * (c->l.peer_resets) is walked; srvrun_clear_peer_resets empties the queue
 * at the next step's start (srvrun_on_step_live). */
static void srvrun_deliver_one_wt_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, const wired_srvloop_reset* e) {
  int sidx = wt_reset_session_slot(c, e->stream_id);
  if (sidx >= 0) {
    srvrun_deliver_wt_reset(cfg, c, sidx, e);
  }
}

/* Entries actually stored this step (peer_reset_n counts past the queue). */
usz srvrun_peer_resets_stored(const srvrun_conn* c) {
  usz n = c->l.peer_reset_n;
  return n < WIRED_SRVLOOP_RESET_Q ? n : WIRED_SRVLOOP_RESET_Q;
}

/* RFC 9000 3.5: record a peer RESET_STREAM (peer_reset_seen's doc). */
static void srvrun_note_peer_reset(
    srvrun_conn* c, const wired_srvloop_reset* e) {
  if (!e->is_stop) {
    wired_srvloop_closed_mark(
        &c->peer_reset_seen[e->stream_id & 3], e->stream_id);
  }
}

int srvrun_peer_reset_seen(const srvrun_conn* c, u64 stream_id) {
  return wired_srvloop_closed_has(
      &c->peer_reset_seen[stream_id & 3], stream_id);
}

void srvrun_deliver_wt_reset_if_owned(const srvrun_cfg* cfg, srvrun_conn* c) {
  usz n = srvrun_peer_resets_stored(c);
  for (usz i = 0; i < n; i++) {
    srvrun_note_peer_reset(c, &c->l.peer_resets[i]);
    srvrun_deliver_one_wt_reset(cfg, c, &c->l.peer_resets[i]);
  }
}

/* RFC 9221 3: this step's DATAGRAM gathering (dispatch.c) latched a violation
 * -- close the connection with a transport-level PROTOCOL_VIOLATION. Split out
 * of srvrun_on_step to keep its own branch count at the CCN gate. */
void srvrun_close_on_datagram_violation(const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "DATAGRAM exceeds advertised limit";
  srvrun_send_transport_close(
      cfg, c, ERR_PROTOCOL_VIOLATION, wired_span_of(reason, sizeof reason - 1));
}

/* draft-ietf-webtrans-http3-15 4.3: this step's WT bidi gathering
 * (dispatch.c's gather_one_wt_signal_violation) latched the WT_STREAM signal
 * (0x41) arriving as a STREAM frame's own leading bytes at a non-zero stream
 * offset -- "Receiving this frame type in any other circumstances MUST be
 * treated as a connection error of type H3_FRAME_ERROR." An H3-level error
 * on an HTTP/3 connection is an application-level CONNECTION_CLOSE (RFC 9114
 * 8.1), the same shape srvrun_close_on_bad_qsid already uses for a different
 * H3-level violation -- NOT srvrun_close_on_datagram_violation's transport-
 * level PROTOCOL_VIOLATION, which is RFC 9221's own (different-layer) rule. */
void srvrun_close_on_wt_signal_violation(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "WT_STREAM signal outside stream's leading bytes";
  srvrun_send_app_close(
      cfg, c, H3_FRAME_ERROR, wired_span_of(reason, sizeof reason - 1));
}
