#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_rx_hold_bidi(wired_srvloop* l, u64 stream_id, int hold);
static int srvrun_wt_rx_hold_uni(wired_srvloop* l, u64 stream_id, int hold);
static u64 srvrun_server_opened(const srvrun_conn* c, u64 stream_id);
static int srvrun_wt_send_over(srvrun_conn* c, u64 stream_id);
static int srvrun_wt_reset_refused(srvrun_conn* c, int sidx, u64 stream_id);

/* Set the bidi receive slot reassembling stream_id to hold (or resume) its
 * credit raises, -1 when no wt_streams slot holds the id -- the bidi half
 * of wired_server_wt_stream_hold's lookup, split out with its uni mirror
 * below to keep the entry point at the CCN gate. */
static int srvrun_wt_rx_hold_bidi(wired_srvloop* l, u64 stream_id, int hold) {
  int i = wired_srvloop_wt_slot_find(l, stream_id);
  if (i < 0) return -1;
  l->wt_streams[i].credit_hold = hold;
  return 1;
}

static int srvrun_wt_rx_hold_uni(wired_srvloop* l, u64 stream_id, int hold) {
  int i = wired_srvloop_wt_uni_slot_find(l, stream_id);
  if (i < 0) return -1;
  l->wt_uni_streams[i].credit_hold = hold;
  return 1;
}

int wired_server_wt_stream_hold(wired_wt_session* s, u64 stream_id, int hold) {
  srvrun_conn* c    = srvrun_session_conn(s);
  int          sidx = srvrun_wt_session_slot_or_absent(c, s);
  if (!srvrun_wt_rx_owns(c, sidx, stream_id)) return -1;
  if (srvrun_wt_rx_hold_bidi(&c->l, stream_id, hold) == 1) return 1;
  return srvrun_wt_rx_hold_uni(&c->l, stream_id, hold);
}

/* Free the WT send slot armed on stream_id, if any: abandoning delivery
 * (RFC 9000 19.4 RESET_STREAM) releases the app's payload view and stops
 * the pump from sending further slices. The id is recorded as send-done so
 * no later reset can claim a smaller Final Size (RFC 9000 4.5). */
void srvrun_wtsend_release(srvrun_conn* c, u64 stream_id) {
  srvrun_wtsend* w = srvrun_wtsend_find(c, stream_id);
  if (!w) return;
  w->in_use = 0;
  srvrun_wt_send_done_mark(c, stream_id);
}

/* Bytes already sent on stream_id's send slot (the round's base offset plus
 * its send cursor; lost slices are requeued, never rewind it), 0 when no
 * slot holds the id. RFC 9000 4.5: a RESET_STREAM's Final Size is exactly
 * the bytes sent -- armed-but-unsent bytes would charge the peer's flow
 * control for data that never comes. */
u64 srvrun_wtsend_final_size(srvrun_conn* c, u64 stream_id) {
  const srvrun_wtsend* w = srvrun_wtsend_find(c, stream_id);
  return w ? w->sess.stream_base_offset + w->sess.q.cur : 0;
}

/* Server-initiated streams of stream_id's direction this server opened so
 * far, counted in id / 4 units (RFC 9000 2.1): uni counts the plumbing
 * streams (HTTP/3 ids 3 and 7, none on raw QUIC) ahead of wt_uni_opened,
 * srvrun_next_uni_id. */
static u64 srvrun_server_opened(const srvrun_conn* c, u64 stream_id) {
  return (stream_id & 2) ? c->wt_uni_opened + srvrun_uni_plumbing(c)
                         : c->wt_bidi_opened;
}

/* 1 iff stream_id's send part ran to its end once its (live) send slot is
 * discounted: a server-initiated id (RFC 9000 2.1 low bit set) this server
 * already opened -- its send slot is claimed at open, so a missing slot
 * means reaped -- or a client bidi recorded in wt_send_done (its doc). */
static int srvrun_wt_send_over(srvrun_conn* c, u64 stream_id) {
  if (stream_id & 1) return stream_id / 4 < srvrun_server_opened(c, stream_id);
  return wired_srvloop_closed_has(&c->wt_send_done, stream_id);
}

/* 1 iff stream_id's send part already ended: its send slot is gone (reaped
 * after the FIN was ACKed -- RFC 9000 3.1 "Data Recvd" -- or freed by an
 * earlier reset that already carried the Final Size). */
int srvrun_wt_send_ended(srvrun_conn* c, u64 stream_id) {
  return !srvrun_wtsend_find(c, stream_id) && srvrun_wt_send_over(c, stream_id);
}

/* Record a client-bidi reply's send part as over (wt_send_done's doc).
 * Server-initiated ids are covered by the opened counters instead, and
 * would alias client ids in the /4-indexed window. */
void srvrun_wt_send_done_mark(srvrun_conn* c, u64 stream_id) {
  if (!(stream_id & 1)) wired_srvloop_closed_mark(&c->wt_send_done, stream_id);
}

int wired_server_wt_stream_inflight(wired_wt_session* s, u64 stream_id) {
  return srvrun_wtsend_of(s, stream_id) != 0;
}

/* 1 iff wired_server_wt_stream_reset latches nothing for stream_id: its
 * send part already ended, the latch is full, or it is foreign to session
 * slot sidx. */
static int srvrun_wt_reset_refused(srvrun_conn* c, int sidx, u64 stream_id) {
  return srvrun_wt_send_ended(c, stream_id) ||
         c->wt_stream_reset_n >= SRVRUN_WT_RESET_LATCH ||
         srvrun_wt_foreign(c, sidx, stream_id);
}

/* 1 iff wired_server_wt_stream_stop latches nothing: no live connection,
 * the latch is full, or stream_id is foreign to session slot sidx. */
int srvrun_wt_stop_refused(srvrun_conn* c, int sidx, u64 stream_id) {
  return !c || c->wt_stream_reset_n >= SRVRUN_WT_RESET_LATCH ||
         srvrun_wt_foreign(c, sidx, stream_id);
}

int wired_server_wt_stream_reset(
    wired_wt_session* s, u64 stream_id, u32 error_code) {
  srvrun_conn* c    = srvrun_session_conn(s);
  int          sidx = srvrun_wt_session_slot_or_absent(c, s);
  usz          i;
  if (!c) return 0;
  /* Latch full: refuse WITHOUT touching the send slot. Freeing it here
   * would abandon delivery with no wire notification ever queued -- the
   * peer would wait on the stream forever. A send part already ended has
   * nothing left to reset (srvrun_wt_abort_reset): done, nothing latched. */
  if (srvrun_wt_reset_refused(c, sidx, stream_id))
    return srvrun_wt_send_ended(c, stream_id);
  i                              = c->wt_stream_reset_n++;
  c->wt_stream_reset_id[i]       = stream_id;
  c->wt_stream_reset_app_code[i] = error_code;
  c->wt_stream_reset_final[i]    = srvrun_wtsend_final_size(c, stream_id);
  c->wt_stream_reset_stop[i]     = 0;
  srvrun_wtsend_release(c, stream_id);
  /* Recorded even with no send slot (a client bidi never replied on): this
   * RESET_STREAM ends the send part, so the session-close sweep and any
   * repeated reset must not send a second one with another code (RFC 9000
   * 19.4, 3.5; draft-ietf-webtrans-http3-16 6). */
  srvrun_wt_send_done_mark(c, stream_id);
  return 1;
}
