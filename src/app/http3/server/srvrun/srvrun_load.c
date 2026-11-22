#include "app/http3/server/srvrun/srvrun_impl.h"

/* Per-connection load limits on what a peer can make the server spend
 * (srvrun_conn.load, srvrun_impl_load.h): the RFC 9114 10.5 rapid-reset
 * count and the RFC 9000 21.9 count of packets that make no progress,
 * over one shared fixed window.
 * shortcut: a raw-QUIC (MoQT) connection is closed with the HTTP/3 code
 * H3_EXCESSIVE_LOAD as well; use the MoQT session error once one is
 * chosen for it. */

static u32 srvrun_reset_limit(const srvrun_cfg* cfg);
static int srvrun_reset_flooded(const srvrun_cfg* cfg, const srvrun_conn* c);
static int srvrun_pn_acked(const srvrun_conn* c, u64 pn);
static int srvrun_ack_hits_sent(const srvrun_conn* c);
static int srvrun_sess_hit(int in_use, const wired_sendsess* s, u64 lo, u64 hi);
static int srvrun_sess_acked(const srvrun_conn* c, u64 lo, u64 hi);
static int srvrun_ack_progress(const srvrun_conn* c);
static int srvrun_dg_progress(const srvrun_rxmark* m, const srvrun_conn* c);
static int srvrun_rx_progress(const srvrun_rxmark* m, const srvrun_conn* c);
static int srvrun_noprog_counts(const srvrun_rxmark* m, const srvrun_conn* c);
static int srvrun_load_exceeded(const srvrun_cfg* cfg, const srvrun_conn* c);

/* RFC 9114 10.5 rapid reset: start a new fixed window (clearing the
 * srvloop reset counter) once SRVRUN_RESET_WINDOW_MS has elapsed since the
 * current one began. Runs before the step's gathering so this step's own
 * resets land in the window they belong to. */
void srvrun_roll_reset_window(srvrun_conn* c, u64 now_ms) {
  if (now_ms - c->load.window_start_ms < SRVRUN_RESET_WINDOW_MS) {
    return;
  }
  c->load = (srvrun_load){now_ms, 0}; /* RFC 9000 21.9 count too */
  c->l.peer_reset_count   = 0;
  c->wt_sess_window_count = 0; /* same window, SS5.2 session churn */
}

static u32 srvrun_reset_limit(const srvrun_cfg* cfg) {
  u32 v = cfg->env->max_resets_per_window;
  return v ? v : SRVRUN_MAX_RESETS_PER_WINDOW;
}

/* RFC 9114 10.5: 1 iff this window's RESET_STREAM/STOP_SENDING
 * count passed the limit, or this step carried more than
 * WIRED_SRVLOOP_RESET_Q (two per tracked stream, its doc). */
static int srvrun_reset_flooded(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return c->l.peer_reset_count > srvrun_reset_limit(cfg) ||
         c->l.peer_reset_n > WIRED_SRVLOOP_RESET_Q;
}

/* 1 if one of this step's ACK ranges covers pn. */
static int srvrun_pn_acked(const srvrun_conn* c, u64 pn) {
  int hit = 0;
  for (usz r = 0; r < c->l.ack_n; r++) {
    hit |= u64_pn1_in(pn + 1, c->l.ack_lo[r], c->l.ack_hi[r]);
  }
  return hit;
}

/* 1 if this step's ACK covers a sent-record slot still live that carried
 * application data, i.e. a newly acknowledged STREAM or DATAGRAM packet:
 * srvrun_rec_on_acks (RFC 9002 A.7) reclaims acknowledged slots later in
 * the step, from srvrun_feed_acks in srvrun_sess_on_step. */
static int srvrun_ack_hits_sent(const srvrun_conn* c) {
  const sentmeta* m   = &c->l.ackst.sent;
  int             hit = 0;
  if (!c->l.ack_n) {
    return 0;
  }
  for (usz i = sentmeta_next(m, 0); i < SENTMETA_CAP;
       i     = sentmeta_next(m, i + 1)) {
    hit |= m->pkts[i].app & srvrun_pn_acked(c, m->pkts[i].pn);
  }
  return hit;
}

static int srvrun_sess_hit(
    int in_use, const wired_sendsess* s, u64 lo, u64 hi) {
  return in_use && srvrun_range_hits(s, lo, hi) != 0;
}

/* 1 if [lo, hi] covers a STREAM slice a send session still has in flight
 * -- exact past the sent record's SENTMETA_CAP, which a large window
 * overruns. */
static int srvrun_sess_acked(const srvrun_conn* c, u64 lo, u64 hi) {
  int hit = 0;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    hit |= srvrun_sess_hit(c->resp[i].in_use, &c->resp[i].sess, lo, hi);
  }
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    hit |= srvrun_sess_hit(c->wtsend[i].in_use, &c->wtsend[i].sess, lo, hi);
  }
  return hit;
}

/* RFC 9000 21.9: an ACK is progress only when it newly acknowledges a
 * packet of ours that carried application data -- acknowledging the
 * ACK-only and control packets a peer's own frames drew is not.
 * shortcut: a DATAGRAM packet the full sent record could not keep is not
 * seen (it is not counted in cwnd either). Key DATAGRAM sends by pn once
 * cwnd can exceed SENTMETA_CAP packets: DATAGRAM-only delivery at about
 * 100 Mbps x 100 ms could close in about 0.2 s, about 20 Mbps does not. */
static int srvrun_ack_progress(const srvrun_conn* c) {
  int hit = srvrun_ack_hits_sent(c);
  for (usz r = 0; r < c->l.ack_n; r++) {
    hit |= srvrun_sess_acked(c, c->l.ack_lo[r], c->l.ack_hi[r]);
  }
  return hit;
}

/* A DATAGRAM with a payload queued this step (RFC 9221 5). */
static int srvrun_dg_progress(const srvrun_rxmark* m, const srvrun_conn* c) {
  /* Early return, not an |= reduction: the vectorized reduction's trip
   * count under -fsanitize=bounds,pointer-overflow needs __udivti3, which
   * a -nostdlib link does not have. */
  for (usz i = m->rx_dg; i < c->l.rx_datagram_n; i++) {
    if (c->l.rx_datagrams[i].len) {
      return 1;
    }
  }
  return 0;
}

/* RFC 9000 21.9: the step delivered stream bytes never received before
 * (past a stream's highest offset or into a gap below it), a DATAGRAM with
 * a payload, or an ACK of our application data. */
static int srvrun_rx_progress(const srvrun_rxmark* m, const srvrun_conn* c) {
  return c->l.ackst.rx_fresh != m->rx_fresh || srvrun_dg_progress(m, c) ||
         srvrun_ack_progress(c);
}

/* The step admitted a 1-RTT packet on a confirmed connection -- a booting
 * one has its own bounds (SRVRUN_BOOT_DEADLINE_MS). */
static int srvrun_noprog_counts(const srvrun_rxmark* m, const srvrun_conn* c) {
  return c->l.rx_admitted[LEVEL_ONERTT] != m->app_adm &&
         wired_server_is_confirmed(&c->s);
}

/* RFC 9000 21.9: "track cost of processing relative to progress" -- charge
 * a packet that made none, credit one back for a packet that did. Design
 * bound: +1 and -1 cancel, so a peer with one cheap source of progress may
 * keep up to half of its packets unproductive; the limit stops the rest. */
void srvrun_noprog_note(srvrun_conn* c, const srvrun_rxmark* m) {
  if (!srvrun_noprog_counts(m, c)) {
    return;
  }
  if (srvrun_rx_progress(m, c)) {
    c->load.noprog -= c->load.noprog != 0;
    return;
  }
  c->load.noprog++;
}

static int srvrun_load_exceeded(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return srvrun_reset_flooded(cfg, c) ||
         c->load.noprog > SRVRUN_MAX_NOPROG_PER_WINDOW;
}

/* RFC 9114 10.5 / RFC 9000 21.9 "excessive load": past either limit, close
 * with the RFC 9114 8.1 H3_EXCESSIVE_LOAD application CONNECTION_CLOSE (the
 * frame sent stays in c->close_pl for a test to decode). */
int srvrun_close_on_load(const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 resets[] = "stream reset rate exceeded";
  static const u8 noprog[] = "excessive load";
  wired_span      reason   = wired_span_of(noprog, sizeof noprog - 1);
  if (!srvrun_load_exceeded(cfg, c)) {
    return 0;
  }
  if (srvrun_reset_flooded(cfg, c)) {
    reason = wired_span_of(resets, sizeof resets - 1);
  }
  srvrun_send_app_close(cfg, c, H3_EXCESSIVE_LOAD, reason);
  return 1;
}
