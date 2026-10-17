#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_deliver_raw_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, const wired_srvloop_rx_datagram* dg);
static void srvrun_offer_wt_uni_slot(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot);
static int wt_uni_slot_needs_offer(
    const wired_srvloop_wt_uni_stream_slot* slot);
static void srvrun_reap_wt_uni_slot(
    srvrun_conn* c, wired_srvloop_wt_uni_stream_slot* slot);

/* RFC 9297 2.1: the payload is prefixed with varint(quarter stream id) --
 * decode that prefix, rejecting a short/oversized field with
 * H3_DATAGRAM_ERROR (srvrun_close_on_bad_qsid, same failure signal
 * wired_wtwire_qsid_take gives both cases), then hand the derived stream id
 * and the remaining bytes to srvrun_route_rx_datagram. */
void srvrun_deliver_rx_datagram(
    const srvrun_cfg*                cfg,
    srvrun_conn*                     c,
    const wired_srvloop_rx_datagram* dg) {
  wired_span raw = wired_span_of(dg->buf, dg->len);
  u64        connect_id;
  usz        prefix = wired_wtwire_qsid_take(raw, &connect_id);
  if (!prefix) {
    srvrun_close_on_bad_qsid(cfg, c);
    return;
  }
  srvrun_route_rx_datagram(
      cfg, c, connect_id, wired_span_of(dg->buf + prefix, dg->len - prefix));
}

/* draft-ietf-moq-transport-19 11.3 / -22 11.2: on raw QUIC the whole
 * DATAGRAM payload is one MoQT Object for the connection's one session --
 * no RFC 9297 quarter-stream-id to parse (rawq_dgram_prefix_len 0). */
static void srvrun_deliver_raw_datagram(
    const srvrun_cfg*                cfg,
    srvrun_conn*                     c,
    const wired_srvloop_rx_datagram* dg) {
  if (c->wt_active) {
    srvrun_deliver_to_known_session(
        cfg, &c->wt, wired_span_of(dg->buf, dg->len));
  }
}

/* Indexed by srvrun_conn_is_raw: WebTransport (qsid-prefixed), raw. */
static const srvrun_rx_dg_fn srvrun_rx_dg_by_raw[2] = {
    srvrun_deliver_rx_datagram, srvrun_deliver_raw_datagram};

/* RFC 9221 5 (Phase 7b Slice 2): drain every DATAGRAM this step's
 * gather_rx_datagrams (dispatch.c) queued into c->l.rx_datagrams, delivering
 * each to the app callback (srvrun_deliver_rx_datagram) in arrival order, then
 * empty the queue -- rx_datagram_n persists across steps until drained (only
 * wired_srvloop_init resets it), so this must run every step regardless of
 * whether this step itself added anything. */
void srvrun_drain_rx_datagrams(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < c->l.rx_datagram_n; i++) {
    srvrun_rx_dg_by_raw[srvrun_conn_is_raw(c)](cfg, c, &c->l.rx_datagrams[i]);
  }
  c->l.rx_datagram_n = 0;
}

/* draft-ietf-webtrans-http3-15 4.3: associate one newly-reassembled WT uni
 * stream slot with c's WebTransport session, mirroring srvrun_offer_wt_slot's
 * bidi counterpart exactly (same offer_stream contract, same no-active-
 * session fallback of leaving the slot reassembled but unclaimed, same
 * reject-and-free-the-slot handling of a buffer-full 0 return). */
static void srvrun_offer_wt_uni_slot(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot) {
  int sidx = srvrun_wt_slot_for_signal(c, slot->sig, slot->sig_have);
  if (sidx < 0) {
    return;
  }
  cfg->env->wt_usage.streams++;
  if (!wired_wt_session_offer_stream(
          srvrun_wt_slot(c, sidx), slot->stream_id)) {
    srvrun_reject_wt_slot(cfg, c, slot->stream_id);
    srvrun_wt_uni_slot_free(c, slot);
    return;
  }
  slot->offered         = 1;
  slot->wt_session_slot = sidx;
}

/* A reassembled-but-not-yet-associated uni slot, mirroring
 * srvrun_wt_slot_needs_offer for the separate uni table. */
static int wt_uni_slot_needs_offer(
    const wired_srvloop_wt_uni_stream_slot* slot) {
  return slot->in_use && !slot->offered;
}

/* RFC 9000 2.2 / 19.8: same reap-once-FIN-delivered policy as
 * srvrun_reap_wt_slot, for the separate uni table; the released slot's uni
 * stream-limit grant is owed (wt_uni_credit_owed). */
static void srvrun_reap_wt_uni_slot(
    srvrun_conn* c, wired_srvloop_wt_uni_stream_slot* slot) {
  if (!slot->in_use || !slot->fin_delivered) {
    return;
  }
  c->wt_rx_reaped_total += slot->delivered_len;
  wired_srvloop_wt_uni_slot_release(&c->l, slot->stream_id);
  c->wt_uni_credit_owed++;
}

/* One wt_uni_streams slot's per-step work, mirroring
 * srvrun_offer_and_deliver_wt_slot for the separate uni table. */
void srvrun_offer_and_deliver_wt_uni_slot(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot) {
  int sidx;
  if (wt_uni_slot_needs_offer(slot)) {
    srvrun_offer_wt_uni_slot(cfg, c, slot);
  }
  if (!slot->in_use) {
    return;
  }
  sidx = srvrun_wt_stream_owner(c, slot->offered, slot->wt_session_slot);
  srvrun_wt_rx rx = {slot->stream_id,     slot->buf,     &slot->win,
                     slot->fin,           slot->fin_off, &slot->delivered_len,
                     &slot->fin_delivered};
  srvrun_deliver_wt_stream_delta(cfg, c, sidx, &rx);
  wired_srvloop_wt_window_slide(
      &slot->win, slot->buf, sizeof slot->buf, slot->delivered_len);
  srvrun_reap_wt_uni_slot(c, slot);
}
