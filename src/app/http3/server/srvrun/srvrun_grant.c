#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_grant_stream_credit(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    u64               stream_id,
    u64               delivered_len,
    u64*              credit_advertised);
static int srvrun_wt_bidi_held(const wired_srvloop_wt_stream_slot* slot);

/* RFC 9000 4.6/19.11: one MAX_STREAMS(uni) raise for every client WT uni
 * stream ended since the last one (wt_uni_credit_owed). */
void srvrun_grant_wt_uni(const srvrun_cfg* cfg, srvrun_conn* c) {
  srvrun_grant_uni_streams(cfg, c, c->wt_uni_credit_owed);
  c->wt_uni_credit_owed = 0;
}

/* draft-ietf-webtrans-http3-15 4.3: after a step has reassembled this
 * datagram's frames into c->l.wt_uni_streams[], run srvrun_offer_and_deliver_
 * wt_uni_slot over every slot, mirroring srvrun_offer_wt_streams for the
 * separate uni table -- then raise the uni stream limit for the streams that
 * ended (srvrun_grant_wt_uni). */
void srvrun_offer_wt_uni_streams(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    srvrun_offer_and_deliver_wt_uni_slot(cfg, c, &c->l.wt_uni_streams[i]);
  }
  srvrun_grant_wt_uni(cfg, c);
}

/* RFC 9000 4.1: the most a WT slot's receive window can currently absorb --
 * bytes already delivered (and reclaimed, wired_srvloop_wt_window_slide) plus
 * one full buffer's worth ahead of them, i.e. the credit that keeps the
 * peer's send window always fully covered by buffer capacity (this SDK's own
 * invariant: never advertise more than buf can actually hold). */
u64 srvrun_wt_slot_credit_ceiling(u64 delivered_len) {
  return delivered_len + WIRED_SRVLOOP_WT_BUF_CAP;
}

/* RFC 9000 4.1/19.10: whether stream_id's MAX_STREAM_DATA is worth
 * re-announcing right now -- the window has advanced enough that the new
 * ceiling exceeds what was last advertised. An advertisement MUST NOT
 * decrease, so a ceiling at or below credit_advertised is never sent. */
int srvrun_wt_credit_stream_due(u64 ceiling, u64 credit_advertised) {
  return ceiling > credit_advertised;
}

/* Seal one MAX_STREAM_DATA frame (RFC 9000 19.10) naming stream_id/value as
 * its own 1-RTT packet and send it, mirroring srvrun_rst_send's
 * shape for a different frame. */
int srvrun_seal_max_stream_data(
    srvrun_conn* c, u64 stream_id, u64 value, wired_obuf* out) {
  u8                    pl[32];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  stream_data_frame     f   = {stream_id, value};
  wired_srvloop_send_in sin;
  usz                   pln = max_stream_data_encode(plb.p, plb.cap, &f);
  if (!pln) {
    return 0;
  }
  plb.len = pln;
  sin     = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      wired_span_of(pl, pln),
      0,
      0,
      0,
      0};
  return srvloop_send_onertt_rec(&c->l, &c->s, &sin, out);
}

void srvrun_send_max_stream_data(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 value) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  /* RFC 9000 13.3: none once the receive part is in Size Known/Reset Recvd */
  if (wired_srvloop_rx_final_known(&c->l, stream_id) ||
      !srvrun_seal_max_stream_data(c, stream_id, value, &ob)) {
    return;
  }
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "WT MAX_STREAM_DATA sent\n");
}

/* RFC 9000 4.1/19.10: re-grant stream_id's receive credit if the window has
 * advanced enough to be worth it (srvrun_wt_credit_stream_due), recording the
 * new ceiling so a later step's absence of further progress does not re-send
 * the same value. Shared body for both the bidi (wt_streams) and uni
 * (wt_uni_streams) tables -- each caller passes its own slot's stream_id/
 * delivered_len/credit_advertised. */
static void srvrun_grant_stream_credit(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    u64               stream_id,
    u64               delivered_len,
    u64*              credit_advertised) {
  u64 ceiling = srvrun_wt_slot_credit_ceiling(delivered_len);
  if (!srvrun_wt_credit_stream_due(ceiling, *credit_advertised)) {
    return;
  }
  srvrun_send_max_stream_data(cfg, c, stream_id, ceiling);
  *credit_advertised = ceiling;
}

/* A held bidi slot stops raising only past its first grant: the stream
 * started at the request window's credit (initial_max_stream_data_bidi_
 * remote), and the first grant is what lifts it to the WT buffer. */
static int srvrun_wt_bidi_held(const wired_srvloop_wt_stream_slot* slot) {
  return slot->credit_hold && slot->credit_advertised;
}

/* One in-use wt_streams slot's own credit re-grant, split out so the driving
 * loop stays at the CCN gate. A held slot (credit_hold, the app's
 * backpressure request via wired_server_wt_stream_hold) is skipped once
 * granted (srvrun_wt_bidi_held): its advertisement stays frozen at the last
 * value sent, never lowered. */
void srvrun_grant_wt_slot_credit(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  if (!slot->in_use || srvrun_wt_bidi_held(slot)) {
    return;
  }
  srvrun_grant_stream_credit(
      cfg, c, slot->stream_id, slot->delivered_len, &slot->credit_advertised);
}

void srvrun_grant_wt_uni_slot_credit(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot) {
  if (!slot->in_use || slot->credit_hold) {
    return;
  }
  srvrun_grant_stream_credit(
      cfg, c, slot->stream_id, slot->delivered_len, &slot->credit_advertised);
}
