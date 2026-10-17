#include "app/http3/server/srvrun/srvrun_impl.h"

/* Seal one slice of sess as its own 1-RTT packet (a STREAM frame on
 * stream_id, RFC 9000 19.8) and send it -- the shared body under both a
 * resp[] slot's send (srvrun_send_slice) and a WT send slot's
 * (srvrun_pump_one_wt). Returns 1 once logged in flight. */
/* RFC 9000 13.2.1: piggyback the step's deferred pending ACK ahead of a
 * slice when the combined plaintext still fits this connection's validated
 * packet size. The ACK length is fixed by encoding it BEFORE committing
 * (wired_srvloop_ack_peek leaves the pending state untouched), so an ACK
 * that does not fit simply stays pending and the slice goes out bare -- no
 * take-then-fail hole: the policy is only cleared (mark_sent) after the
 * carrying packet went out. Returns the ACK bytes written at pl[0]. */
usz srvrun_slice_ack_peek(srvrun_conn* c, const wired_sendq_slice* sl, u8* pl) {
  usz al;
  if (!c->l.ack_defer) {
    return 0;
  }
  al = wired_srvloop_ack_peek(&c->l, pl, SRVRUN_ACK_ROOM);
  return sl->len + al <= srvrun_mps(c) ? al : 0;
}

/* Seal pl as one 1-RTT packet under pn, send it, and -- once it is on the
 * wire -- consume the piggybacked pending ACK when the payload carried one
 * (al != 0). Returns 1 on success, 0 if sealing failed (nothing sent, the
 * pending ACK untouched). */
int srvrun_seal_send_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_span pl, u64 pn, usz al) {
  u8                    out[1500];
  wired_obuf            ob  = obuf_of(out, sizeof out);
  wired_srvloop_send_in sin = {
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), pn, -1, pl, 0, 0, 0, 0};
  if (!wired_srvloop_send_onertt(&c->s, &sin, &ob)) {
    return 0;
  }
  srvrun_send_staged(
      ctx->cfg, c, wired_span_of(out, ob.len), "1-RTT payload sent\n");
  if (al) {
    wired_srvloop_ack_mark_sent(&c->l);
  }
  return 1;
}

int srvrun_send_stream_slice(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    wired_sendsess*          sess,
    u64                      stream_id,
    const wired_sendq_slice* sl,
    u8                       fin) {
  u8           pl[SRVRUN_ACK_ROOM + SRVRUN_SLICE_PL];
  usz          al  = srvrun_slice_ack_peek(c, sl, pl);
  wired_obuf   plb = obuf_of(pl + al, sizeof pl - al);
  stream_frame f   = {
      stream_id, wired_sendsess_stream_offset(sess, sl), sl->len,
      wired_sendq_slice_data(&sess->q, sl), fin};
  u64 pn;
  if (!appdata_stream_frame(&f, &plb)) {
    return 0;
  }
  pn = c->l.tx_pn++;
  srvrun_qlog_stream_sent(ctx->cfg, c, ctx->now_ms, pn, &f);
  if (!srvrun_seal_send_slice(
          ctx, c, wired_span_of(pl, al + plb.len), pn, al)) {
    return 0;
  }
  return wired_sendsess_sent(sess, sl, pn, ctx->now_ms);
}

/* Send a just-taken slice; on failure return it to sess via
 * wired_sendsess_untake so the next take offers it again. The take already
 * advanced the sendq cursor (the slice's bytes count as consumed for flow
 * control), so a slice dropped here would be a permanent hole -- in no log
 * or requeue, invisible to loss detection, never resent. */
int srvrun_send_taken(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    wired_sendsess*          sess,
    u64                      stream_id,
    const wired_sendq_slice* sl,
    u8                       fin) {
  if (srvrun_send_stream_slice(ctx, c, sess, stream_id, sl, fin)) {
    return 1;
  }
  wired_sendsess_untake(sess, sl);
  return 0;
}

/* One resp[] slot's slice, with the response path's own FIN suppression
 * (WT CONNECT stream / streaming rounds, srvrun_slice_fin above). */
int srvrun_send_slice(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    srvrun_resp*             r,
    const wired_sendq_slice* sl) {
  return srvrun_send_taken(
      ctx, c, &r->sess, r->stream_id, sl, srvrun_slice_fin(c, r, sl));
}

/* Sum of in-flight stream bytes across every WT send slot -- the wtsend
 * side of srvrun_inflight_bytes_all's fan-out (its own function so both
 * loops stay at the CCN gate). */
usz srvrun_wtsend_inflight_bytes(const srvrun_conn* c) {
  usz total = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (c->wtsend[i].in_use) {
      total += wired_sendsess_inflight_bytes(&c->wtsend[i].sess);
    }
  }
  return total;
}
