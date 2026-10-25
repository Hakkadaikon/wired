#include "app/http3/server/srvrun/srvrun_impl.h"

static srvrun_rst* srvrun_rst_free(srvrun_conn* c);
static int         srvrun_rst_fits(usz pln);
static int         srvrun_pn_in(u64 pn, u64 lo, u64 hi);
static int         srvrun_rst_acked(const srvrun_rst* e, u64 lo, u64 hi);

/* srvrun_seal_kept, then send it with log line msg. */
void srvrun_send_kept(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    const u8*         pl,
    usz               pln,
    const char*       msg) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_kept(c, pl, pln, &ob)) {
    return;
  }
  srvrun_send(cfg, c, wired_span_of(out, ob.len), msg);
}

/* RFC 9114 4.1.2: a server answering before it read the whole request
 * "SHOULD" ask with H3_NO_ERROR that the client stop sending the rest. */
void srvrun_send_stop_sending(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id) {
  u8         pl[32];
  wired_obuf plb = obuf_of(pl, sizeof pl);
  srvrun_send_kept(
      cfg, c, pl, srvrun_wt_abort_stop(c, stream_id, H3_NO_ERROR, &plb, 0),
      "STOP_SENDING sent\n");
}

/* Seal e's frames as their own 1-RTT packet and send it, recording the
 * packet number its ACK will name and the deadline for the next resend
 * (backing off like a PTO, RFC 9002 6.2.1). */
void srvrun_rst_send(
    const srvrun_cfg* cfg, srvrun_conn* c, srvrun_rst* e, u64 now_ms) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  e->pn         = c->l.tx_pn;
  e->due_ms =
      now_ms + srvrun_pto_deadline_ms(c, SRVRUN_PTO_MAX - (int)e->tries);
  if (!srvrun_seal_ctl(c, e->pl, e->pln, &ob)) {
    return;
  }
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "control frame resent\n");
}

/* A free entry on c, or 0 when all are awaiting ACKs. */
static srvrun_rst* srvrun_rst_free(srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RST_RETX; i++) {
    if (!c->rst[i].pln) {
      return &c->rst[i];
    }
  }
  return 0;
}

/* 1 iff a payload of pln bytes can be kept (nonempty, fits pl[]). */
static int srvrun_rst_fits(usz pln) {
  return pln && pln <= sizeof(((srvrun_rst*)0)->pl);
}

void srvrun_rst_keep(srvrun_conn* c, const u8* pl, usz pln) {
  srvrun_rst* e = srvrun_rst_free(c);
  /* ponytail: the table holds every trackable stream's abort at once
   * (SRVRUN_RST_RETX), and every caller's payload fits pl[]; only more than
   * that many aborts unACKed within one RTT would find it full and go out
   * once. Raise SRVRUN_RST_RETX if that is ever seen. */
  if (!e || !srvrun_rst_fits(pln)) {
    return;
  }
  bytes_memcpy(e->pl, pl, pln);
  e->pln    = (u8)pln;
  e->tries  = SRVRUN_PTO_MAX;
  e->pn     = c->l.tx_pn;
  e->due_ms = c->l.now_ms + srvrun_pto_deadline_ms(c, 0);
}

/* Send the type-appropriate abort frames carrying err_code as their own
 * 1-RTT packet, kept for resending until ACKed (RFC 9000 13.3: RESET_STREAM
 * and STOP_SENDING are retransmitted until acknowledged; draft-ietf-
 * webtrans-http3-15 5.3 needs resets delivered so both ends agree on which
 * streams are open). With the table full the abort still goes out once. */
void srvrun_send_wt_busy_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 err_code) {
  u8         pl[48];
  wired_obuf plb = obuf_of(pl, sizeof pl);
  srvrun_send_kept(
      cfg, c, pl, srvrun_wt_busy_reset_payload(c, stream_id, err_code, &plb),
      "WT stream abort sent\n");
  /* RFC 9000 3.1: no STREAM frame follows a RESET_STREAM -- an unsent tail
   * past its Final Size would be a FINAL_SIZE_ERROR at the peer. */
  srvrun_wtsend_release(c, stream_id);
}

/* 1 iff pn lies in [lo, hi]. */
static int srvrun_pn_in(u64 pn, u64 lo, u64 hi) { return lo <= pn && pn <= hi; }

/* 1 iff e awaits an ACK that the range [lo, hi] carries. */
static int srvrun_rst_acked(const srvrun_rst* e, u64 lo, u64 hi) {
  return e->pln && srvrun_pn_in(e->pn, lo, hi);
}

/* RFC 9000 13.3: an ACK naming a kept packet ends its resends. */
void srvrun_rst_ack(srvrun_conn* c, u64 lo, u64 hi) {
  for (usz i = 0; i < SRVRUN_RST_RETX; i++) {
    if (srvrun_rst_acked(&c->rst[i], lo, hi)) {
      c->rst[i].pln = 0;
    }
  }
}
