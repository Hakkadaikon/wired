#include "app/http3/server/srvrun/srvrun_impl.h"

static u64 wt_frontier_abs(const wired_srvloop_wt_window* win);
static int wt_stream_fin_only(
    u8 fin, u64 fin_off, u64 frontier_abs, int fin_delivered);
static int wt_stream_delta_pending(
    u64 frontier_abs,
    u8  fin,
    u64 fin_off,
    u64 delivered_len,
    int fin_delivered);
static int wt_stream_delta_ready(
    const srvrun_cfg* cfg,
    int               sidx,
    u64               frontier_abs,
    u8                fin,
    u64               fin_off,
    u64               delivered_len,
    int               fin_delivered);
static int wt_delivered_fin(u8 fin, u64 frontier_abs, u64 fin_off);

/* srvrun_wt_bidi_slot_free's uni twin: free an ended client WT uni stream's
 * slot and owe the peer one stream of uni credit back (RFC 9000 4.6). */
void srvrun_wt_uni_slot_free(
    srvrun_conn* c, wired_srvloop_wt_uni_stream_slot* slot) {
  c->wt_uni_credit_owed++;
  wired_srvloop_wt_uni_slot_release(&c->l, slot->stream_id);
}

/* The code a refused client stream is reset with: the HTTP/3 code h3 on
 * WebTransport; on raw QUIC there is no HTTP/3 error space, so the MoQT
 * code goes on the wire verbatim (rawq_reset_code_out). */
u64 srvrun_refuse_code(const srvrun_conn* c, u64 h3) {
  return srvrun_conn_is_raw(c) ? rawq_reset_code_out(1, SRVRUN_RAW_REFUSE_CODE)
                               : h3;
}

/* draft-ietf-webtrans-http3-16 9.5: a buffered-stream-capacity rejection
 * (wired_wt_session_offer_stream returned 0, i.e. WIRED_WT_MAX_BUFFERED_
 * STREAMS is full on an unestablished session) is the caller's own contract
 * to enforce (session.h's offer_stream doc): reset the stream with
 * WT_BUFFERED_STREAM_REJECTED, sent as its own raw HTTP/3 error code (IANA
 * "HTTP/3 Error Code" registration) -- NOT mapped through
 * wired_wterrmap_to_http3, which packs an application error code into the
 * WT_APPLICATION_ERROR range; this code is protocol-level, not app-level. */
void srvrun_reject_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id) {
  srvrun_send_wt_busy_reset(
      cfg, c, stream_id, srvrun_refuse_code(c, WTERR_BUFFERED_STREAM_REJECTED));
}

/* draft-ietf-webtrans-http3-15 4.3: associate one newly-reassembled WT bidi
 * stream slot with c's WebTransport session, exactly once (slot->offered
 * latches it) — the session only needs to know the stream id, not its bytes
 * (wired_wt_session_offer_stream's own signature, session.h). A stray WT bidi
 * stream on a connection with no active session (srvrun_wt_slot_for_new_
 * stream returns -1) is a protocol-level mismatch this slice leaves as
 * accepted-and-ignored, matching
 * the pre-Slice-3 fallback: routing to a session that does not exist is not
 * meaningful, so nothing is offered and the slot is simply left reassembled
 * but unclaimed by any session. A 0 return (buffer full) is rejected on the
 * wire and the slot freed so a retry does not loop forever re-offering the
 * same doomed stream id. */
void srvrun_offer_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  int sidx = srvrun_wt_slot_for_signal(c, slot->sig, slot->sig_have);
  if (sidx < 0) return;
  cfg->env->wt_usage.streams++;
  if (!wired_wt_session_offer_stream(
          srvrun_wt_slot(c, sidx), slot->stream_id)) {
    srvrun_reject_wt_slot(cfg, c, slot->stream_id);
    srvrun_wt_bidi_slot_free(c, slot);
    return;
  }
  slot->offered         = 1;
  slot->wt_session_slot = sidx;
}

/* A reassembled-but-not-yet-associated slot: in_use (claimed by a WT-bidi
 * stream) and not already offered to the session this connection owns. */
int srvrun_wt_slot_needs_offer(const wired_srvloop_wt_stream_slot* slot) {
  return slot->in_use && !slot->offered;
}

/* The absolute stream offset the slot's receive window has contiguously
 * reassembled up to so far (RFC 9000 2.2) -- the caller may only deliver up
 * to here, never past a gap, however far an out-of-order frame's own
 * high-water mark reaches (wired_srvloop_wt_window's own frontier doc). */
static u64 wt_frontier_abs(const wired_srvloop_wt_window* win) {
  return win->base + win->frontier;
}

/* A fresh, not-yet-delivered FIN — the one case wt_stream_delta_pending's
 * plain frontier > delivered_len check misses (a stream whose closing frame,
 * or whose only frame, carries no new bytes past the frontier already
 * delivered). fin_delivered (not delivered_len) is the guard: delivered_len
 * alone cannot tell "FIN already delivered" apart from "nothing delivered
 * yet" when both are 0. A FIN is deliverable only once the frontier has
 * actually reached the offset it was seen at (fin_off) -- FIN itself can
 * arrive out of order, same as any other STREAM frame (RFC 9000 19.8). */
static int wt_stream_fin_only(
    u8 fin, u64 fin_off, u64 frontier_abs, int fin_delivered) {
  return fin && !fin_delivered && frontier_abs >= fin_off;
}

/* Whether this step has anything new worth delivering for one WT stream slot:
 * either fresh bytes past the last delivery, or a fresh FIN (see
 * wt_stream_fin_only). */
static int wt_stream_delta_pending(
    u64 frontier_abs,
    u8  fin,
    u64 fin_off,
    u64 delivered_len,
    int fin_delivered) {
  if (frontier_abs > delivered_len) return 1;
  return wt_stream_fin_only(fin, fin_off, frontier_abs, fin_delivered);
}

/* Whether srvrun_deliver_wt_stream_delta has anything to do at all: an active
 * session slot (sidx >= 0, from srvrun_wt_slot_for_new_stream), a registered
 * callback, and a pending delta (wt_stream_delta_pending) — folded into one
 * predicate so the caller is a single guarded early return. */
static int wt_stream_delta_ready(
    const srvrun_cfg* cfg,
    int               sidx,
    u64               frontier_abs,
    u8                fin,
    u64               fin_off,
    u64               delivered_len,
    int               fin_delivered) {
  if (sidx < 0 || !cfg->wt_on_stream_data) return 0;
  return wt_stream_delta_pending(
      frontier_abs, fin, fin_off, delivered_len, fin_delivered);
}

/* draft-ietf-webtrans-http3-15 4.3 (Phase 7b Slice 4): deliver the bytes a WT
 * bidi/uni slot has reassembled contiguously (up to its window's frontier)
 * since the last delivery to the app callback. buf is window-relative (buf[0]
 * is win->base's own first byte), so "new data this step" is buf[delivered_
 * len - win->base .. frontier - win->base) — the caller passes pointers to
 * the slot's own delivered_len/fin_delivered so this can advance them in
 * place. sidx is the session slot this stream was offered to
 * (srvrun_offer_wt_slot's own resolution), so the callback's session pointer
 * always matches the slot the stream is actually associated with. Called
 * every step for every in_use slot regardless of offered, so bytes that
 * arrive before the stream's session association still reach the app once
 * one exists, mirroring srvrun_offer_wt_slot's own no-active-session fallback
 * (silently skip rather than buffer growing unboundedly). */
/* 1 if this delivery includes the stream's FIN -- a FIN was seen AND the
 * frontier has reached the offset it was seen at (RFC 9000 19.8: FIN can
 * itself arrive out of order, so "seen" alone is not "deliverable yet").
 * Shared by both call sites in srvrun_deliver_wt_stream_delta that need this
 * exact condition, keeping its own branch count at the gate. */
static int wt_delivered_fin(u8 fin, u64 frontier_abs, u64 fin_off) {
  return fin && frontier_abs >= fin_off;
}

void srvrun_deliver_wt_stream_delta(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, const srvrun_wt_rx* rx) {
  u64 frontier_abs = wt_frontier_abs(rx->win);
  u64 done         = *rx->delivered_len;
  int fin_now      = wt_delivered_fin(rx->fin, frontier_abs, rx->fin_off);
  if (!wt_stream_delta_ready(
          cfg, sidx, frontier_abs, rx->fin, rx->fin_off, done,
          *rx->fin_delivered))
    return;
  cfg->wt_on_stream_data(
      cfg->wt_stream_data_ctx, srvrun_wt_slot(c, sidx), rx->stream_id,
      wired_span_of(
          rx->buf + (done - rx->win->base), (usz)(frontier_abs - done)),
      fin_now);
  *rx->delivered_len = frontier_abs;
  if (fin_now) *rx->fin_delivered = 1;
}

/* RFC 9000 2.2 / 19.8: once a WT bidi slot's FIN has been delivered to the
 * app, its stream is fully spent -- free the slot (raising the table's
 * released-id watermark, wired_srvloop_wt_slot_release) so a later Extended
 * CONNECT's worth of new streams is not permanently blocked by
 * WIRED_SRVLOOP_MAX_WT_STREAMS exhausting after that many sequential
 * streams, mirroring srvrun_resp_reap's own release of streams[]. */
void srvrun_reap_wt_slot(srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  if (!slot->in_use || !slot->fin_delivered) return;
  c->wt_rx_reaped_total += slot->delivered_len;
  wired_srvloop_wt_slot_release(&c->l, slot->stream_id);
  c->wt_bidi_credit_owed += !(slot->stream_id & 1);
}
