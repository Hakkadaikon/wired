#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_bodywin_any(const bodywin* w);
static int srvrun_wt_after_close(
    const srvrun_conn* c, int sidx, const wired_srvloop_stream_slot* slot);
static int  srvrun_wt_fin_at_end(const bodywin* w);
static void srvrun_wt_watch_arm(srvrun_conn* c, int sidx, const bodywin* w);
static int  srvrun_wt_watch_done(const wired_srvloop_wt_watch* w);

/* draft-ietf-webtrans-http3-16 6: "If any additional stream data is
 * received on the CONNECT stream after receiving a WT_CLOSE_SESSION
 * capsule, the stream MUST be reset with code H3_MESSAGE_ERROR." Bytes
 * already here when the capsule is applied reset the stream at once; a
 * stream not yet FINed is released with the session and watched
 * (c->l.wt_watch) for later frames. */

/* 1 iff any byte is held in w's window past its base. */
static int srvrun_bodywin_any(const bodywin* w) {
  u8 any = 0;
  for (usz i = 0; i < sizeof w->have; i++) {
    any = (u8)(any | w->have[i]);
  }
  return any != 0;
}

/* Bytes past the capsule already arrived: held in the capsule queue, owed
 * by the DATA frame the capsule rode in, or landed in the window. */
static int srvrun_wt_after_close(
    const srvrun_conn* c, int sidx, const wired_srvloop_stream_slot* slot) {
  return c->wt_capq[sidx].n || slot->body.left ||
         srvrun_bodywin_any(&slot->body);
}

static int srvrun_wt_fin_at_end(const bodywin* w) {
  return w->fin && w->fin_off == w->base;
}

/* Watch session slot sidx's CONNECT stream past the capsule's end unless
 * its FIN is already here. shortcut: one watch per connection -- a second
 * session closing while the first is watched replaces it; make it per
 * session if a client ever overlaps two closes. */
static void srvrun_wt_watch_arm(srvrun_conn* c, int sidx, const bodywin* w) {
  if (srvrun_wt_fin_at_end(w)) {
    return;
  }
  c->l.wt_watch = (wired_srvloop_wt_watch){
      srvrun_wt_slot(c, sidx)->connect_stream_id + 1, w->base,
      c->wt_connect_sent_len[sidx], 0, 0};
}

/* The code a rejected capsule pass closes session sidx with: x's own,
 * except that a peer WT_CLOSE_SESSION followed by more bytes is
 * H3_MESSAGE_ERROR (srvrun_wt_rx_fail then resets the CONNECT stream). */
u64 srvrun_wt_rx_fail_code(
    srvrun_conn*                     c,
    int                              sidx,
    const wired_srvloop_stream_slot* slot,
    const srvrun_wt_caprx*           x) {
  if (!x->peer_closed) {
    return x->violation_code;
  }
  if (srvrun_wt_after_close(c, sidx, slot)) {
    return H3_MESSAGE_ERROR;
  }
  srvrun_wt_watch_arm(c, sidx, &slot->body);
  return x->violation_code;
}

static int srvrun_wt_watch_done(const wired_srvloop_wt_watch* w) {
  return w->hit || w->fin;
}

/* Per step: a watched stream that carried more bytes is reset (RESET_STREAM
 * + STOP_SENDING, H3_MESSAGE_ERROR); either that or the peer's FIN ends the
 * watch. */
void srvrun_wt_watch_drain(const srvrun_cfg* cfg, srvrun_conn* c) {
  wired_srvloop_wt_watch* w = &c->l.wt_watch;
  if (w->hit) {
    srvrun_reset_stream_final(cfg, c, w->id - 1, w->final, H3_MESSAGE_ERROR);
  }
  if (srvrun_wt_watch_done(w)) {
    *w = (wired_srvloop_wt_watch){0};
  }
}
