#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_recv_serve_one(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, usz nbufs, i64 fd);
static void srvrun_recv_serve(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, usz nbufs);
static void srvrun_app_step(const srvrun_cfg* cfg);
static int  srvrun_drain_tick(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, int tick);
static void srvrun_rx_init(wired_srvrun_env* env, mmsg_buf* bufs);
static u64  srvrun_close_grease_id(void);
static void srvrun_close_drained(const srvrun_cfg* cfg, srvrun_state* st);
static int  srvrun_wt_close_tick(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, int tick);
static void srvrun_wt_close_and_wait(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs);

/* RFC 9000 9.6.2 two-socket receive: with a preferred-address socket bound,
 * the wait covers both fds, so neither may block the other -- drain each
 * with a non-blocking batch, marking env->rx_fd so slot claims, stateless
 * replies and rebind detection know which path a datagram arrived on. */
static void srvrun_recv_serve_one(
    const srvrun_cfg* cfg,
    srvrun_state*     st,
    mmsg_buf*         bufs,
    usz               nbufs,
    i64               fd) {
  i64 r           = wired_udp_recvmmsg_nowait(fd, bufs, nbufs);
  cfg->env->rx_fd = fd;
  if (r > 0) {
    srvrun_serve_batch(cfg, st, bufs, r);
  }
  cfg->env->rx_fd = 0;
}

static void srvrun_recv_serve(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, usz nbufs) {
  i64 r;
  if (cfg->env->pref_fd) {
    srvrun_recv_serve_one(cfg, st, bufs, nbufs, cfg->fd);
    srvrun_recv_serve_one(cfg, st, bufs, nbufs, cfg->env->pref_fd);
    return;
  }
  r = srvrun_recv(cfg, bufs, nbufs);
  if (r > 0) {
    srvrun_serve_batch(cfg, st, bufs, r);
  }
}

/* wired_srvrun_opt.on_step: the app's own per-step work (e.g. a clock-
 * paced publisher), given the same monotonic clock the loop's timers use. */
static void srvrun_app_step(const srvrun_cfg* cfg) {
  if (cfg->on_step) {
    cfg->on_step(cfg->on_step_ctx, clock_mono_ms());
  }
}

void srvrun_step(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, usz nbufs) {
  srvrun_reload_if_requested(cfg, cfg->env);
  srvrun_bcast_drain_self(st); /* other workers' broadcasts */
  srvrun_polling_ptos(cfg, st);
  if (srvrun_wait_input(cfg, st)) {
    srvrun_recv_serve(cfg, st, bufs, nbufs);
  }
  srvrun_app_step(cfg);
  /* RFC 9002 6.2: evaluate every slot's PTO deadlines on EVERY iteration,
   * not only on a poll timeout -- a steady inbound stream (e.g. the peer's
   * own Handshake PTO probes under the interop amplificationlimit case)
   * kept wait_input returning 1 forever, so the timeout-only fire path
   * never ran: the boot flight's withheld tail was never resent even as
   * the arriving probes kept raising the anti-amplification budget, and
   * the client idled out after 30s. The due checks are cheap integer
   * compares per slot; deadlines re-arm on any real send, so firing here
   * cannot double-probe a round. */
  srvrun_fire_ptos(cfg, st);
  /* Session-addressed datagrams queued by this step's callbacks (or left
   * from an interrupted prior step) go out before the loop waits again. */
  srvrun_dgring_drain(cfg, st, clock_mono_ms());
}

/* Drain phase (RFC 9114 5.2): GOAWAY already sent to every live connection:
 * poll with a timeout instead of blocking forever, so the loop keeps making
 * progress toward the tick budget even if the peer sends nothing more.
 * Returns 1 once every connection has drained or the tick budget is spent
 * (the caller should stop), 0 to keep draining. */
static int srvrun_drain_tick(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, int tick) {
  if (poll_wait_readable(cfg->fd, SRVRUN_DRAIN_TICK_MS) > 0) {
    srvrun_step(cfg, st, bufs, SRVRUN_RX_BATCH);
  }
  return srvrun_all_drained(st) || tick >= SRVRUN_DRAIN_TICKS;
}

/* draft-ietf-webtrans-http3-16 6 (WTH3-081): after WT_CLOSE_SESSION went
 * out, keep serving (receive, or tick the slots so the capsules and their
 * resends go out) until the peer closed every CONNECT stream, bounded by
 * SRVRUN_WT_CLOSE_TICKS. Returns 1 when the wait is over. */
static int srvrun_wt_close_tick(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs, int tick) {
  if (poll_wait_readable(cfg->fd, SRVRUN_DRAIN_TICK_MS) > 0) {
    srvrun_step(cfg, st, bufs, SRVRUN_RX_BATCH);
  } else {
    srvrun_fire_ptos(cfg, st);
  }
  return !srvrun_wt_close_waiting(st) || tick >= SRVRUN_WT_CLOSE_TICKS;
}

/* WT_CLOSE_SESSION on every live session, pushed out now, then the
 * bounded wait for the peers' CONNECT-stream closes (srvrun_wt_close_tick). */
static void srvrun_wt_close_and_wait(
    const srvrun_cfg* cfg, srvrun_state* st, mmsg_buf* bufs) {
  int tick = 0;
  srvrun_wt_close_all_live(cfg, st);
  srvrun_fire_ptos(cfg, st);
  while (!srvrun_wt_close_tick(cfg, st, bufs, tick)) {
    tick++;
  }
}

/* Point each batch slot at env's own storage. */
static void srvrun_rx_init(wired_srvrun_env* env, mmsg_buf* bufs) {
  for (usz i = 0; i < SRVRUN_RX_BATCH; i++) {
    bufs[i].buf = wired_mspan_of(env->rxstorage[i], sizeof env->rxstorage[i]);
  }
}

/* RFC 9114 8.1 / 9114-077: when about to close with H3_NO_ERROR, occasionally
 * substitute a reserved (grease) error code instead, so a peer's handling of
 * an unrecognized-but-valid code (9114-075: treated as equivalent to
 * H3_NO_ERROR) gets exercised on the wire -- same one-random-byte shape as
 * control_settings_grease_id (control_settings.c), applied to the error-code
 * space instead of the SETTINGS-identifier space. A failed RNG read skips
 * greasing, same fallback. */
static u64 srvrun_close_grease_id(void) {
  u8 b;
  if (!rng_bytes(&b, 1)) {
    return 0;
  }
  if (b & 1) {
    return 0;
  }
  return h3_grease_value(b);
}

/* RFC 9114 5.2: once the drain grace period ends, any connection still up
 * (the peer never finished on its own) is closed by the server with an
 * application-level CONNECTION_CLOSE carrying H3_NO_ERROR -- the graceful
 * shutdown's own completion, distinct from GOAWAY (which merely announces
 * the intent to stop accepting new requests on it). h3_error_send_value
 * substitutes an occasional grease code per connection (9114-077, above). */
static void srvrun_close_drained(const srvrun_cfg* cfg, srvrun_state* st) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    if (st->conns[i].up) {
      srvrun_send_app_close(
          cfg, &st->conns[i],
          h3_error_send_value(H3_NO_ERROR, srvrun_close_grease_id()),
          wired_span_of(0, 0));
    }
  }
}

/* Receive datagrams until told to stop: normal service while no shutdown has
 * been requested; once requested, send GOAWAY to every live connection once
 * and drain for a bounded grace period (RFC 9114 5.2) before returning. */
void srvrun_loop(const srvrun_cfg* cfg) {
  srvrun_state st = {cfg->env->table, cfg->env->conns};
  mmsg_buf     bufs[SRVRUN_RX_BATCH];
  int          tick = 0;
  conntable_init(st.table, WIRED_CONNTABLE_CAP);
  srvrun_rx_init(cfg->env, bufs);
  while (!srvrun_shutdown_requested()) {
    srvrun_step(cfg, &st, bufs, SRVRUN_RX_BATCH);
  }
  srvrun_goaway_all(cfg, &st);
  while (!srvrun_drain_tick(cfg, &st, bufs, tick)) {
    tick++;
  }
  srvrun_wt_close_and_wait(cfg, &st, bufs);
  srvrun_close_drained(cfg, &st);
}

/* Arm SIGHUP only when a cert path was given (cfg.cert_path unset means
 * reload is disabled, so there is nothing to reload into). */
void srvrun_install_sighup(const srvrun_cfg* cfg) {
  if (!cfg->cert_path) {
    return;
  }
  if (!wired_sighup_install(srvrun_sighup_handler)) {
    WIRED_LOG("SIGHUP install failed, no cert reload\n");
  }
}
