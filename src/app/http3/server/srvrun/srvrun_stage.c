#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_stage_reset(wired_srvrun_env* e);
static void srvrun_stage_tx_multi(const srvrun_cfg* cfg);
static int  srvrun_stage_room(const wired_srvrun_env* e, usz n);
static int  srvrun_stage_same_peer(
    const wired_srvrun_env* e, const sockaddr* sa);
static int srvrun_stage_extends(
    const wired_srvrun_env* e, const sockaddr* sa, usz n);
static int srvrun_conn_unstaged(const srvrun_cfg* cfg, const srvrun_conn* c);
static int srvrun_stage_bypass(
    const srvrun_cfg* cfg, const srvrun_conn* c, wired_span pkt);

/* --- GSO staging: sealed datagrams batched into one sendmsg ------------- */

static void srvrun_stage_reset(wired_srvrun_env* e) {
  e->gso_count    = 0;
  e->gso_len      = 0;
  e->gso_seg_size = 0;
}

/* Multi-segment wire-out: one UDP GSO sendmsg for the whole batch, or --
 * when the kernel lacks UDP_SEGMENT (negative return) -- a sendto per
 * segment. Either way it is one flush. */
static void srvrun_stage_tx_multi(const srvrun_cfg* cfg) {
  wired_srvrun_env* e   = cfg->env;
  wired_span        all = wired_span_of(e->gso_stage, e->gso_len);
  i64               fd  = srvrun_stage_fd(cfg, e);
  e->tx_flush_count++;
  if (wired_udp_send_gso(fd, &e->gso_peer, all, (u16)e->gso_seg_size) >= 0)
    return;
  wired_udp_send_batch(fd, &e->gso_peer, all, (u16)e->gso_seg_size);
}

/* Flush the staged batch to the wire: a single staged datagram goes out the
 * ordinary srvrun_tx path, several leave as one GSO sendmsg. No-op when the
 * stage is empty. Per-datagram bookkeeping (qlog, send_count) already
 * happened at staging time (srvrun_send_staged). */
void srvrun_stage_flush(const srvrun_cfg* cfg) {
  wired_srvrun_env* e = cfg->env;
  if (e->gso_count == 0) return;
  if (e->gso_count == 1)
    srvrun_tx(
        cfg, srvrun_stage_fd(cfg, e), &e->gso_peer,
        wired_span_of(e->gso_stage, e->gso_len));
  else
    srvrun_stage_tx_multi(cfg);
  srvrun_stage_reset(e);
}

/* 1 if a pkt.n-byte datagram still has stage room: batch open, not full,
 * and no larger than the batch's segment size (a smaller one is GSO's one
 * legal short tail -- srvrun_stage_put closes the batch right after it). */
static int srvrun_stage_room(const wired_srvrun_env* e, usz n) {
  return e->gso_count != 0 && e->gso_count < SRVRUN_GSO_SEGS &&
         n <= e->gso_seg_size;
}

/* 1 if sa is the same address:port the open batch is headed to. */
static int srvrun_stage_same_peer(
    const wired_srvrun_env* e, const sockaddr* sa) {
  return sa->port_be == e->gso_peer.port_be &&
         ct_diffn(sa->addr, e->gso_peer.addr, 16) == 0;
}

static int srvrun_stage_extends(
    const wired_srvrun_env* e, const sockaddr* sa, usz n) {
  return srvrun_stage_room(e, n) && srvrun_stage_same_peer(e, sa);
}

/* Stage one sealed datagram for c's peer. A datagram that cannot extend the
 * open batch (different peer, larger than the segment size, or the batch is
 * full) flushes it first and opens a new one; a shorter-than-segment
 * datagram joins as the batch's legal short tail and closes it. */
void srvrun_stage_put(
    const srvrun_cfg* cfg, const srvrun_conn* c, wired_span pkt) {
  wired_srvrun_env* e = cfg->env;
  if (!srvrun_stage_extends(e, &c->peer, pkt.n)) {
    srvrun_stage_flush(cfg);
    e->gso_seg_size = pkt.n;
    e->gso_peer     = c->peer;
    e->gso_fd       = c->tx_fd;
  }
  bytes_memcpy(e->gso_stage + e->gso_len, pkt.p, pkt.n);
  e->gso_len += pkt.n;
  e->gso_count++;
  if (pkt.n < e->gso_seg_size) srvrun_stage_flush(cfg);
}

/* srvrun_send, except the wire syscall is deferred into the env's GSO stage
 * (srvrun_stage_flush sends it); the per-datagram bookkeeping happens now.
 * AF_XDP has its own TX path with no GSO, so it sends immediately. Staged
 * packets can leave the wire AFTER a direct srvrun_send issued later in the
 * same pump pass (e.g. DATA_BLOCKED) -- plain datagram reordering, which
 * any QUIC peer already tolerates (RFC 9000 12.3). */
/* 1 iff pkt skips the GSO stage for srvrun_send: AF_XDP, an empty packet,
 * a closing connection (srvrun_send's own gate drops it), or an unmarked
 * one (srvrun_ecn_unmarked: its per-send TOS cmsg is not staged).
 * ponytail: an unmarked connection loses GSO batching; carry the TOS in
 * the stage if ECN-failed paths ever matter for throughput. */
static int srvrun_conn_unstaged(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return c->closing || srvrun_ecn_unmarked(cfg, c);
}

static int srvrun_stage_bypass(
    const srvrun_cfg* cfg, const srvrun_conn* c, wired_span pkt) {
  return cfg->xdp || pkt.n == 0 || srvrun_conn_unstaged(cfg, c);
}

void srvrun_send_staged(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    wired_span         pkt,
    const char*        what) {
  (void)what;
  if (srvrun_stage_bypass(cfg, c, pkt)) {
    srvrun_send(cfg, c, pkt, what);
    return;
  }
  srvrun_stage_put(cfg, c, pkt);
  srvrun_qlog_sent(cfg, c, pkt.n);
  WIRED_LOG(what);
  g_srvrun_send_count++;
  g_srvrun_tx_max_len = (usz)u64_max(g_srvrun_tx_max_len, pkt.n);
}
