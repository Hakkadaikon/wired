#include "app/http3/server/srvrun/srvrun_impl.h"

__attribute__((unused)) static usz srvrun_test_send_count(void);
__attribute__((unused)) static usz srvrun_test_flush_count(
    const srvrun_cfg* cfg);
static void srvrun_tx_conn(
    const srvrun_cfg* cfg, const srvrun_conn* c, wired_span pkt);

/* Send a sealed buffer to c's recorded peer, with a trace line (skip an empty
 * buffer). Always targets the slot's own peer (RFC 9000 5.1), not whichever
 * datagram was received most recently. */
/* Test-only send counter: how many times srvrun_send has fired since the
 * last srvrun_test_reset_send_count, so a test can assert an exact number of
 * UDP sends happened (e.g. proving a boot retransmit resent a flight)
 * without needing a real socket to observe bytes on. Not signal-safe/thread-
 * safe -- fine, each env's own send_count is only touched by that env's own
 * loop, and tests are the only other caller. */
__attribute__((unused)) static void srvrun_test_reset_send_count(void) {
  g_srvrun_send_count = 0;
}

__attribute__((unused)) static usz srvrun_test_send_count(void) {
  return g_srvrun_send_count;
}

/* Test-only wire-flush counter (env.tx_flush_count's doc): syscall batches,
 * where one whole GSO sendmsg counts 1 -- so a test can pin how many
 * syscalls a burst of datagrams costs, independent of the per-datagram
 * send_count above. */
__attribute__((unused)) static void srvrun_test_reset_flush_count(
    const srvrun_cfg* cfg) {
  cfg->env->tx_flush_count = 0;
}

__attribute__((unused)) static usz srvrun_test_flush_count(
    const srvrun_cfg* cfg) {
  return cfg->env->tx_flush_count;
}

/* The one TX seam: AF_XDP when cfg->xdp is set, the UDP socket otherwise.
 * Both srvrun_send and the direct Version Negotiation send route through
 * this. */
/* The arrival fd of the datagram being served, for stateless replies that
 * must return the way they came (0 while not inside a batch = primary). */
i64 srvrun_rx_fd(const srvrun_cfg* cfg) {
  return cfg->env->rx_fd ? cfg->env->rx_fd : cfg->fd;
}

/* The socket c's replies leave through (see srvrun_conn.tx_fd). */
i64 srvrun_conn_fd(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return c->tx_fd ? c->tx_fd : cfg->fd;
}

/* The fd a staged GSO batch flushes through (see wired_srvrun_env.gso_fd). */
i64 srvrun_stage_fd(const srvrun_cfg* cfg, const wired_srvrun_env* e) {
  return e->gso_fd ? e->gso_fd : cfg->fd;
}

/* Both wired_srvxdp_send and wired_udp_send's return value are ignored on
 * purpose: a dropped/short send here (e.g. AF_XDP's TX pool momentarily
 * exhausted) is not retried at this layer. It does not need to be --
 * srvrun_step calls srvrun_fire_ptos every iteration (RFC 9002 6.2 PTO),
 * which re-sends any unacked bytes once its deadline fires, so a locally
 * dropped packet is recovered by the existing QUIC loss-detection timer
 * rather than by an app-level retry loop here. */
void srvrun_tx(
    const srvrun_cfg* cfg, i64 fd, const sockaddr* sa, wired_span pkt) {
  cfg->env->tx_flush_count++;
  if (cfg->xdp) {
    wired_srvxdp_send(cfg->xdp, sa, pkt);
  } else {
    wired_udp_send(fd, sa, pkt);
  }
}

/* RFC 9000 13.4.2.2: c's ECN validation failed (ecn_track_fail counted
 * it), so c stops marking -- on the UDP socket path, whose ECT(0) is
 * socket-wide (AF_XDP never marks). */
int srvrun_ecn_unmarked(const srvrun_cfg* cfg, const srvrun_conn* c) {
  return !cfg->xdp && c->ecn.fail_count != 0;
}

/* srvrun_tx for c's own packet: an unmarked connection's datagram carries a
 * Not-ECT TOS cmsg overriding the socket's ECT(0) (wired_udp_send_tos). */
static void srvrun_tx_conn(
    const srvrun_cfg* cfg, const srvrun_conn* c, wired_span pkt) {
  i64 fd = srvrun_conn_fd(cfg, c);
  if (!srvrun_ecn_unmarked(cfg, c)) {
    srvrun_tx(cfg, fd, &c->peer, pkt);
    return;
  }
  cfg->env->tx_flush_count++;
  wired_udp_send_tos(fd, &c->peer, pkt, 0);
}

void srvrun_send_now(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span pkt, const char* what) {
  (void)what; /* WIRED_LOG compiles out without -DWIRED_DEBUG */
  if (pkt.n && srvrun_send_spend(cfg, c, pkt.n)) { /* RFC 9000 8 */
    srvrun_tx_conn(cfg, c, pkt);
    srvrun_qlog_sent(cfg, c, pkt.n);
    WIRED_LOG(what);
    g_srvrun_send_count++;
    g_srvrun_tx_max_len = (usz)u64_max(g_srvrun_tx_max_len, pkt.n);
  }
}

/* srvrun_send_now, except on a closing connection: RFC 9000 10.2.1 lets it
 * send nothing but its CONNECTION_CLOSE again (srvrun_close_resend). */
void srvrun_send(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span pkt, const char* what) {
  if (!c->closing) {
    srvrun_send_now(cfg, c, pkt, what);
  }
}

/* One unconditional line per connection-ending event (the "conn refused:
 * table full" precedent below), so a deployment's plain logs say WHY a
 * peer went away: a WebTransport session dropping mid-transfer looked like
 * "the attachment never arrived" until the cause was visible here. what
 * is a NUL-terminated prefix, reason the (possibly empty) detail. */
void srvrun_log_close(const char* what, wired_span reason) {
  char line[160];
  usz  n = wired_cstr_len(what);
  usz  r = reason.n > 96 ? 96 : reason.n;
  bytes_memcpy(line, what, n);
  bytes_memcpy(line + n, reason.p, r);
  n += r;
  line[n++] = '\n';
  line[n]   = 0;
  wired_log_str(line);
}

/* RFC 8446 6.2: implementations "SHOULD provide a way to facilitate logging
 * the sending and receiving of alerts". A close whose error code is a
 * CRYPTO_ERROR (0x0100 | alert, RFC 9001 4.8) logs what followed by the
 * alert number; any other code logs what alone (srvrun_log_close's line). */
void srvrun_log_close_alert(const char* what, u64 code) {
  static const char tag[] = " (TLS alert ";
  char              line[160];
  usz               n = wired_cstr_len(what);
  bytes_memcpy(line, what, n);
  if (err_is_crypto(code)) {
    bytes_memcpy(line + n, tag, sizeof tag - 1);
    n += sizeof tag - 1;
    wired_fmt_u64(line, &n, &(wired_fmt_u64_in){err_alert(code), 1});
    line[n++] = ')';
  }
  line[n++] = '\n';
  line[n]   = 0;
  wired_log_str(line);
}
