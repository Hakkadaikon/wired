#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_reset_noted(const srvrun_conn* c, usz i);
static usz srvrun_reset_free(srvrun_conn* c, usz i);
static int srvrun_held_is(const srvrun_conn* c, usz i, u64 id);
static int srvrun_held_slot_of(const srvrun_conn* c, u64 id);
static usz srvrun_drop_held(srvrun_conn* c, const wired_srvloop_reset* e);
static int srvrun_wtsend_capsule_open(const srvrun_conn* c, srvrun_wtsend* w);
static int srvrun_wtsend_reapable(const srvrun_conn* c, srvrun_wtsend* w);

/* RFC 9000 3.5: "An endpoint that receives a STOP_SENDING frame MUST send
 * a RESET_STREAM frame if the stream is in the Ready or Send state" -- every
 * STOP_SENDING queued this step (c->l.peer_resets) is answered. */
void srvrun_answer_peer_stops(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  usz n = srvrun_peer_resets_stored(c), freed = 0;
  for (usz i = 0; i < n; i++)
    if (c->l.peer_resets[i].is_stop)
      freed += srvrun_answer_peer_stop(ctx, c, &c->l.peer_resets[i]);
  srvrun_grant_streams(ctx, c, srvrun_stream_limit_base(ctx), freed);
}

/* 1 if srvloop noted slot i reset while still receiving (reset_slots) and
 * it is still live -- a STOP_SENDING answered this step may have freed it. */
static int srvrun_reset_noted(const srvrun_conn* c, usz i) {
  return ((c->l.reset_slots >> i) & 1) && c->l.streams[i].in_use;
}

/* RFC 9000 3.2: a RESET_STREAM ends a request still being received -- it
 * can never complete, so its slot is freed. A response still in flight
 * owns the slot instead (3.1: a reset in Data Sent); its reap frees it.
 * 1 when a slot was freed. */
static usz srvrun_reset_free(srvrun_conn* c, usz i) {
  u64 id = c->l.streams[i].stream_id;
  if (!srvrun_reset_noted(c, i) || srvrun_resp_find(c, id)) return 0;
  wired_srvloop_slot_release(&c->l, id);
  return 1;
}

/* 1 iff slot i holds a CONNECT waiting for SETTINGS on stream id. */
static int srvrun_held_is(const srvrun_conn* c, usz i, u64 id) {
  return ((c->wt_held_mask >> i) & 1) && c->l.streams[i].stream_id == id;
}

static int srvrun_held_slot_of(const srvrun_conn* c, u64 id) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    if (srvrun_held_is(c, i, id)) return (int)i;
  return -1;
}

/* RFC 9000 3.2: a RESET_STREAM on a CONNECT still held for SETTINGS ends
 * it -- it must not be started once SETTINGS arrive. Its slot is freed
 * (1 when freed). */
static usz srvrun_drop_held(srvrun_conn* c, const wired_srvloop_reset* e) {
  int i = e->is_stop ? -1 : srvrun_held_slot_of(c, e->stream_id);
  if (i < 0) return 0;
  c->wt_held_mask &= ~((u64)1 << i);
  wired_srvloop_slot_release(&c->l, e->stream_id);
  return 1;
}

/* Every held CONNECT reset this step is dropped and its credit returned. */
void srvrun_drop_held_resets(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  usz n = srvrun_peer_resets_stored(c), freed = 0;
  for (usz i = 0; i < n; i++)
    freed += srvrun_drop_held(c, &c->l.peer_resets[i]);
  srvrun_grant_streams(ctx, c, srvrun_stream_limit_base(ctx), freed);
}

/* Every slot reset this step (c->l.reset_slots) is freed and its bidi
 * credit returned (RFC 9000 4.6), with that of each slot-less reset
 * request stream (reset_slotless_n). */
void srvrun_free_reset_reqs(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  usz freed = c->l.reset_slotless_n;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_STREAMS; i++)
    freed += srvrun_reset_free(c, i);
  srvrun_grant_streams(ctx, c, srvrun_stream_limit_base(ctx), freed);
}

/* w has delivered every byte (sent and acknowledged) AND the app has
 * written the stream's end -- the same fully-drained guard srvrun_resp_reap
 * applies, minus the response-only streaming/bigbuf concerns a WT send
 * never has. An append-open slot is never finished: its fully-ACKed round
 * is just the pause before the app's next wired_server_wt_stream_send
 * (whose busy check consumes wired_sendsess_done instead), the same way a
 * streaming resp[] slot survives its round boundary. */
int srvrun_wtsend_finished(srvrun_wtsend* w) {
  return w->in_use && !w->append_open && wired_sendsess_done(&w->sess);
}

/* Free every fully-ACKed WT send slot; the app's payload view is released
 * (nothing SDK-side to return -- the sendsess only ever borrowed it). */
/* 1 iff w is a live session's CONNECT-stream capsule slot still open for
 * more capsules (srvrun_wt_connect_sender). */
static int srvrun_wtsend_capsule_open(const srvrun_conn* c, srvrun_wtsend* w) {
  return w->append_open && srvrun_wt_slot_by_connect_id(c, w->stream_id) >= 0;
}

/* 1 iff w may be freed now: fully done, or an open capsule slot whose
 * bytes are all ACKed -- a WT_DRAIN_SESSION must not pin a send slot for
 * the session's life; a later capsule claims a fresh slot at
 * wt_connect_sent_len. */
static int srvrun_wtsend_reapable(const srvrun_conn* c, srvrun_wtsend* w) {
  return srvrun_wtsend_finished(w) ||
         (srvrun_wtsend_capsule_open(c, w) && srvrun_wtsend_epoch_acked(w));
}

/* Reap w if it may be freed. A FINISHED slot (FIN sent and ACKed, "Data
 * Recvd") records its id as send-done, so no later reset can shrink the
 * final size (RFC 9000 4.5); a recycled open capsule slot does not -- its
 * CONNECT stream is still live and may yet be reset. finished is checked
 * exactly once per slot: wired_sendsess_done latches (its true also clears
 * active), so a second call would read 0 and lose the mark. */
void srvrun_reap_one_wtsend(srvrun_conn* c, srvrun_wtsend* w) {
  if (srvrun_wtsend_finished(w)) {
    srvrun_wt_send_done_mark(c, w->stream_id);
    w->in_use = 0;
    return;
  }
  if (srvrun_wtsend_reapable(c, w)) w->in_use = 0;
}
