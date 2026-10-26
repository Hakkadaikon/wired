#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_wt_preclaim_bidi_recv(
    srvrun_conn* c, wired_wt_session* s, int sidx, u64 id);
static i64 srvrun_wt_open_bidi_common(
    wired_wt_session* s, wired_span payload, int keep_open);

/* Shared body of the one-shot and keep-open uni opens: flow gates, slot
 * claim, id allocation. keep_open sets append_open (srvrun_wtsend's own
 * doc), the only difference between the two entry points. */
/* WT-session flow gates plus the peer's QUIC uni-stream limit (RFC 9000
 * 4.6) -- an open past the latter is refused HERE, because the peer may
 * answer it with a connection-fatal STREAM_LIMIT_ERROR or silently discard
 * the stream and everything sent on it. */
int srvrun_wt_uni_open_ok(
    srvrun_conn* c, int sidx, wired_wt_session* s, wired_span payload) {
  if (!srvrun_wt_open_flow_ok(sidx, s, 0, payload)) {
    return 0;
  }
  return srvrun_wt_uni_grant_ok(c);
}

i64 srvrun_wt_open_uni_common(
    wired_wt_session* s, wired_span payload, int keep_open) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = srvrun_wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  if (!srvrun_wt_uni_open_ok(c, sidx, s, payload)) {
    srvrun_wt_notify_streams_blocked(c, sidx, s, 0);
    srvrun_wt_notify_data_blocked(c, sidx, s, payload.n);
    return -1;
  }
  w = srvrun_wtsend_claim(c, c->s.sdrv.peer_initial_max_stream_data_uni);
  if (!w) {
    return -1;
  }
  w->append_open     = keep_open;
  w->wt_session_slot = sidx;
  wired_wt_session_note_stream_opened(s, 0);
  wired_wt_session_note_data_sent(s, payload.n);
  return srvrun_wtsend_arm_id(c, w, srvrun_next_uni_id(c), payload);
}

i64 wired_server_wt_open_uni(wired_wt_session* s, wired_span payload) {
  return srvrun_wt_open_uni_common(s, payload, 0);
}

i64 wired_server_wt_open_uni_stream(wired_wt_session* s, wired_span payload) {
  return srvrun_wt_open_uni_common(s, payload, 1);
}

/* RFC 9000 2.1 / draft-ietf-webtrans-http3-15 4.3: pre-register id's receive
 * side as a WT bidi slot with no signal prefix (server-initiated bidi carries
 * none, unlike a client-signalled stream) and associate it with s directly --
 * this endpoint already knows which session owns id (it just opened it), so
 * there is no offer/accept race to resolve the way an incoming client-
 * signalled stream has (srvrun_offer_wt_slot's own srvrun_wt_slot_for_new_
 * stream lookup). A full wt_streams[] table silently leaves the reply
 * unreceivable, same fixed-capacity drop policy as every other WT slot table
 * here. */
static void srvrun_wt_preclaim_bidi_recv(
    srvrun_conn* c, wired_wt_session* s, int sidx, u64 id) {
  int i = wired_srvloop_wt_slot_claim_local(&c->l, id);
  if (i < 0) {
    return;
  }
  c->l.wt_streams[i].offered         = 1;
  c->l.wt_streams[i].wt_session_slot = sidx; /* its owner, D1 */
  wired_wt_session_offer_stream(s, id);
}

/* Shared body of the one-shot and keep-open bidi opens -- the bidi twin of
 * srvrun_wt_open_uni_common, plus the receive-side preclaim. */
static i64 srvrun_wt_open_bidi_common(
    wired_wt_session* s, wired_span payload, int keep_open) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = srvrun_wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  u64            id;
  if (!srvrun_wt_open_flow_ok(sidx, s, 1, payload)) {
    srvrun_wt_notify_streams_blocked(c, sidx, s, 1);
    srvrun_wt_notify_data_blocked(c, sidx, s, payload.n);
    return -1;
  }
  w = srvrun_wtsend_claim(
      c, c->s.sdrv.peer_initial_max_stream_data_bidi_remote);
  if (!w) {
    return -1;
  }
  w->append_open     = keep_open;
  w->wt_session_slot = sidx;
  wired_wt_session_note_stream_opened(s, 1);
  wired_wt_session_note_data_sent(s, payload.n);
  id = srvrun_next_bidi_id(c);
  srvrun_wt_preclaim_bidi_recv(c, s, sidx, id);
  return srvrun_wtsend_arm_id(c, w, id, payload);
}

i64 wired_server_wt_open_bidi(wired_wt_session* s, wired_span payload) {
  return srvrun_wt_open_bidi_common(s, payload, 0);
}

i64 wired_server_wt_open_bidi_stream(wired_wt_session* s, wired_span payload) {
  return srvrun_wt_open_bidi_common(s, payload, 1);
}

/* draft-ietf-webtrans-http3-15 SS5.4 (WTH3-061): same WT_MAX_DATA gate as
 * srvrun_wt_open_flow_ok, minus the stream-count half -- a reply on an
 * already-open client-initiated stream opens no new stream, so only
 * wired_wt_session_data_ send_allowed applies. An over-limit send is refused
 * the same way srvrun_wt_open_flow_ok refuses: the session stays established
 * and the same round is accepted once a WT_MAX_DATA capsule raises the limit.
 */
int srvrun_wt_reply_flow_ok(int sidx, wired_wt_session* s, usz len) {
  return sidx >= 0 && wired_wt_session_data_send_allowed(s, len);
}

/* The owner recorded on stream_id's receive slot, SRVRUN_WT_UNTRACKED for
 * none. */
int srvrun_wt_rx_owner(const srvrun_conn* c, u64 stream_id) {
  int i = wired_srvloop_wt_slot_find(&c->l, stream_id);
  if (i >= 0) {
    return c->l.wt_streams[i].wt_session_slot;
  }
  i = wired_srvloop_wt_uni_slot_find(&c->l, stream_id);
  return i >= 0 ? c->l.wt_uni_streams[i].wt_session_slot : SRVRUN_WT_UNTRACKED;
}
