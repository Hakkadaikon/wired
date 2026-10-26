#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_owner(srvrun_conn* c, u64 stream_id);
static int srvrun_wt_owner_other(int owner, int sidx);
static int srvrun_wt_h3_internal(const srvrun_conn* c, u64 stream_id);
static int srvrun_wt_reply_refused(srvrun_conn* c, int sidx, u64 stream_id);
static int srvrun_wt_reply_allowed(
    srvrun_conn* c, int sidx, wired_wt_session* s, u64 stream_id, usz len);
static int srvrun_wt_stream_reply_common(
    wired_wt_session* s, u64 stream_id, wired_span payload, int keep_open);
static int srvrun_wtsend_blocked_by_view(const srvrun_wtsend* w);
static int srvrun_wtsend_accepting(const srvrun_wtsend* w);

/* The owner recorded on stream_id: its send slot's, else its receive
 * slot's, else SRVRUN_WT_UNTRACKED. */
static int srvrun_wt_owner(srvrun_conn* c, u64 stream_id) {
  const srvrun_wtsend* w = srvrun_wtsend_find(c, stream_id);
  return w ? w->wt_session_slot : srvrun_wt_rx_owner(c, stream_id);
}

/* 1 iff the owner recorded for stream_id (owner_of) is not sidx. */
static int srvrun_wt_owner_other(int owner, int sidx) {
  return owner != SRVRUN_WT_UNTRACKED && owner != sidx;
}

/* 1 iff stream_id is an HTTP/3 stream no session may touch: a session's
 * CONNECT stream, or a request stream. */
static int srvrun_wt_h3_internal(const srvrun_conn* c, u64 stream_id) {
  return srvrun_wt_slot_by_connect_id(c, stream_id) >= 0 ||
         srvrun_req_slot_of(c, stream_id) != 0;
}

/* 1 iff stream_id belongs to something other than session slot sidx. */
int srvrun_wt_foreign(srvrun_conn* c, int sidx, u64 stream_id) {
  return srvrun_wt_owner_other(srvrun_wt_owner(c, stream_id), sidx) ||
         srvrun_wt_h3_internal(c, stream_id);
}

/* 1 iff session slot sidx owns stream_id's receive slot. */
int srvrun_wt_rx_owns(const srvrun_conn* c, int sidx, u64 stream_id) {
  return sidx >= 0 && srvrun_wt_rx_owner(c, stream_id) == sidx;
}

/* Session slot sidx's own send slot on stream_id, 0 if none or another
 * owner's (plumbing included). */
srvrun_wtsend* srvrun_wtsend_owned(srvrun_conn* c, int sidx, u64 stream_id) {
  srvrun_wtsend* w = srvrun_wtsend_find(c, stream_id);
  return w && w->wt_session_slot == sidx ? w : 0;
}

/* 1 iff stream_id can never carry a WT reply: not a client-initiated bidi
 * stream (RFC 9000 2.1), or already spoken for -- a send slot is open on
 * it, or it is foreign to sidx (srvrun_wt_foreign). A client bidi whose
 * receive slot was reaped at FIN is untracked: the reply-after-FIN echo
 * case stays allowed. */
static int srvrun_wt_reply_refused(srvrun_conn* c, int sidx, u64 stream_id) {
  return (stream_id & 3) != 0 || srvrun_wtsend_find(c, stream_id) ||
         srvrun_wt_foreign(c, sidx, stream_id);
}

/* A reply of len bytes on stream_id fits session slot sidx's flow limits
 * and names a stream only that session may answer. */
static int srvrun_wt_reply_allowed(
    srvrun_conn* c, int sidx, wired_wt_session* s, u64 stream_id, usz len) {
  return srvrun_wt_reply_flow_ok(sidx, s, len) &&
         !srvrun_wt_reply_refused(c, sidx, stream_id);
}

/* Shared body of the one-shot and keep-open replies on a client-initiated
 * bidi stream. */
static int srvrun_wt_stream_reply_common(
    wired_wt_session* s, u64 stream_id, wired_span payload, int keep_open) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = srvrun_wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  if (!srvrun_wt_reply_allowed(c, sidx, s, stream_id, payload.n)) {
    srvrun_wt_notify_data_blocked(c, sidx, s, payload.n);
    return 0;
  }
  /* RFC 9000 18.2: the peer's bidi_local TP governs what we may send on a
   * stream the peer itself initiated -- same seed resp[] claiming uses. */
  w = srvrun_wtsend_claim(c, c->s.sdrv.peer_initial_max_stream_data_bidi_local);
  if (!w) {
    return 0;
  }
  w->append_open     = keep_open;
  w->wt_session_slot = sidx;
  wired_wt_session_note_data_sent(s, payload.n);
  srvrun_wtsend_arm_id(c, w, stream_id, payload);
  return 1;
}

int wired_server_wt_stream_reply(
    wired_wt_session* s, u64 stream_id, wired_span payload) {
  return srvrun_wt_stream_reply_common(s, stream_id, payload, 0);
}

int wired_server_wt_stream_reply_open(
    wired_wt_session* s, u64 stream_id, wired_span payload) {
  return srvrun_wt_stream_reply_common(s, stream_id, payload, 1);
}

/* 1 iff w names a claimed slot still open for appending. */
int srvrun_wtsend_open_slot(const srvrun_wtsend* w) {
  return w && w->append_open;
}

/* 1 iff every byte staged in w's sendsess has been sent and ACKed -- the
 * idempotent twin of wired_sendsess_done (which consumes the session's
 * active flag), so the append path can test-and-recycle the epoch buffer
 * without stealing the reap's own done() edge. */
int srvrun_wtsend_epoch_acked(const srvrun_wtsend* w) {
  return wired_sendq_all_sent(&w->sess.q) && w->sess.requeue_n == 0 &&
         wired_sendsess_inflight(&w->sess) == 0;
}

/* 1 iff w's stream is already closing: a bare FIN was requested or armed,
 * so no further data round may be staged behind it. */
int srvrun_wtsend_closing(const srvrun_wtsend* w) {
  return w->fin_requested || w->fin_only_pending;
}

/* 1 while an oversized view round is still in flight -- its bytes live in
 * the APP's storage (srvrun.h's keep-alive contract), so nothing can be
 * staged behind them in roundbuf until they fully ACK. */
static int srvrun_wtsend_blocked_by_view(const srvrun_wtsend* w) {
  return w->view_round && !srvrun_wtsend_epoch_acked(w);
}

static int srvrun_wtsend_accepting(const srvrun_wtsend* w) {
  return !srvrun_wtsend_closing(w) && !srvrun_wtsend_blocked_by_view(w);
}

/* 1 iff a new round may be staged on w at all: the slot is open for
 * appending, the round is non-empty (a FIN needs a final slice to ride on
 * -- wired_sendq_next never yields an empty slice), and nothing blocks
 * acceptance (srvrun_wtsend_accepting). Room in the epoch buffer is the
 * one remaining condition, checked by srvrun_wtsend_stage_round itself. */
int srvrun_wtsend_appendable(const srvrun_wtsend* w, usz len) {
  return srvrun_wtsend_open_slot(w) && len != 0 && srvrun_wtsend_accepting(w);
}

/* Recycle w's fully-ACKed staging: fresh arm over roundbuf at the
 * cumulative stream offset. Safe exactly because everything staged so far
 * is ACKed (srvrun_wtsend_epoch_acked) -- no logged or requeued slice
 * still resolves into the old bytes. */
void srvrun_wtsend_epoch_reset(const srvrun_conn* c, srvrun_wtsend* w) {
  wired_sendsess_arm(&w->sess, w->roundbuf, 0, srvrun_mps(c));
  wired_sendsess_set_base_offset(&w->sess, w->stream_off);
  wired_sendq_set_ring(&w->sess.q, SRVRUN_WTSEND_BUF);
  w->view_round = 0;
}
