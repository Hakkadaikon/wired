#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_rst_any(const srvrun_conn* c);
static int srvrun_wt_close_or_drain_pending(const srvrun_conn* c, int i);
static int srvrun_wt_close_drain_any(const srvrun_conn* c);
static int srvrun_rst_due(const srvrun_rst* e, u64 now_ms);
static int srvrun_rst_retry_one(
    const srvrun_cfg* cfg, srvrun_conn* c, srvrun_rst* e, u64 now);
static int srvrun_close_allowed(const srvrun_conn* c, usz pln);

/* 1 iff any packet on c still awaits its ACK -- keeps the poll tick armed
 * (srvrun_slot_waiting) so the resend deadline is honored. */
static int srvrun_rst_any(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RST_RETX; i++) {
    if (c->rst[i].pln) {
      return 1;
    }
  }
  return 0;
}

int srvrun_rst_pending(const srvrun_conn* c) {
  return c->up && srvrun_rst_any(c);
}

/* 1 iff slot i's close or drain is latched from an app callback. */
static int srvrun_wt_close_or_drain_pending(const srvrun_conn* c, int i) {
  return c->wt_close_pending[i] || c->wt_drain_pending[i];
}

/* 1 iff any WT session slot has a close or drain latched. */
static int srvrun_wt_close_drain_any(const srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    if (srvrun_wt_close_or_drain_pending(c, i)) {
      return 1;
    }
  }
  return 0;
}

/* 1 iff any WT session slot has a close, drain or stream-reset latched
 * from an app callback (wt_close_pending/wt_drain_pending/wt_stream_
 * reset_n's own docs: all three are drained only at srvrun_on_step, which
 * a receive-only peer -- one that calls wired_server_wt_close_session from
 * a tick/on_step hook rather than from handling that peer's own packet --
 * may never trigger on its own. Without this, srvrun_may_block_unbounded
 * blocks in recvmmsg forever and the latch never leaves: the same class of
 * bug srvrun_has_outbound's dg_pending check already closed for broadcast
 * DATAGRAMs. */
int srvrun_wt_app_pending(const srvrun_conn* c) {
  return c->wt_stream_reset_n != 0 || srvrun_wt_close_drain_any(c);
}

/* 1 iff e awaits an ACK and its resend deadline has passed. */
static int srvrun_rst_due(const srvrun_rst* e, u64 now_ms) {
  return e->pln && now_ms >= e->due_ms;
}

/* Resend e if its deadline passed. 0 once its resend budget is spent with
 * the packet still unACKed (the caller tears the connection down). */
static int srvrun_rst_retry_one(
    const srvrun_cfg* cfg, srvrun_conn* c, srvrun_rst* e, u64 now) {
  if (!srvrun_rst_due(e, now)) {
    return 1;
  }
  if (!e->tries) {
    return 0;
  }
  e->tries--;
  srvrun_rst_send(cfg, c, e, now);
  return 1;
}

/* Resend every kept packet on c whose deadline passed without an ACK.
 * 0 when one has exhausted SRVRUN_PTO_MAX resends. */
int srvrun_rst_retry(const srvrun_cfg* cfg, srvrun_conn* c, u64 now) {
  for (usz i = 0; i < SRVRUN_RST_RETX; i++) {
    if (!srvrun_rst_retry_one(cfg, c, &c->rst[i], now)) {
      return 0;
    }
  }
  return 1;
}

/* RFC 9000 10.2.3: an application-level CONNECTION_CLOSE (type 0x1d,
 * is_app=1) carrying an HTTP/3 or WebTransport-level error code and reason.
 * Mirrors wired_srvboot_refusal's is_app=0 handshake-rejection pattern
 * (srvboot.c) but for use OUTSIDE handshake rejection -- an established
 * connection closing itself for an application-level protocol violation. */
usz srvrun_app_close_payload(
    u64 error_code, wired_span reason, wired_obuf* plb) {
  conn_close_frame cc = {1, error_code, 0, reason.n, reason.p};
  return frame_put_conn_close(plb->p, plb->cap, &cc);
}

/* Seal the CONNECTION_CLOSE frame pl into out as its own 1-RTT packet under
 * the next packet number. Returns 1 with out->len set, 0 if the seal
 * failed. */
int srvrun_seal_close_pl(srvrun_conn* c, wired_span pl, wired_obuf* out) {
  wired_srvloop_send_in sin = {
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len),
      c->l.tx_pn++,
      -1,
      pl,
      0,
      0,
      0,
      0};
  return srvloop_send_onertt_rec(&c->l, &c->s, &sin, out);
}

/* RFC 9000 10.2.1: send the kept close frame (close_pl) again as a fresh
 * 1-RTT packet (plus Handshake/Initial copies while unconfirmed) -- the one
 * send the closing state still allows, so it goes around srvrun_send's closing
 * gate. */
void srvrun_close_resend(const srvrun_cfg* cfg, srvrun_conn* c) {
  u8         out[MIN_INITIAL_DATAGRAM];
  wired_obuf ob = obuf_of(out, sizeof out);
  srvrun_close_send_long(cfg, c); /* RFC 9000 10.2.3, before confirmation */
  if (!srvrun_seal_close_pl(c, wired_span_of(c->close_pl, c->close_pln), &ob)) {
    return;
  }
  srvrun_send_now(
      cfg, c, wired_span_of(out, ob.len), "CONNECTION_CLOSE sent\n");
}

/* 1 iff a close frame of pln bytes may go out: it was built, and none went
 * out before (one CONNECTION_CLOSE per connection -- a later violation or
 * shutdown must not put a second, different code on the wire). */
static int srvrun_close_allowed(const srvrun_conn* c, usz pln) {
  return !c->closing && pln != 0;
}

/* RFC 9000 10.2 / 10.2.1: send the CONNECTION_CLOSE frame pl and enter the
 * closing state in the same step -- every WT session ends now
 * (srvrun_close_all_wt: wt_on_session_close once, then inactive), no
 * further app delivery or send happens, and the slot is reaped three PTOs
 * later (srvrun_close_reap_due). Returns 0, sending nothing, when the
 * connection is already closing or pl is empty. */
int srvrun_close_send(const srvrun_cfg* cfg, srvrun_conn* c, wired_span pl) {
  if (!srvrun_close_allowed(c, pl.n)) {
    return 0;
  }
  bytes_memcpy(c->close_pl, pl.p, pl.n);
  c->close_pln = pl.n;
  srvrun_close_resend(cfg, c);
  c->closing          = 1;
  c->closing_until_ms = c->l.now_ms + 3 * srvrun_pto_deadline_ms(c, 0);
  srvrun_close_all_wt(cfg, c);
  return 1;
}
