#include "app/http3/server/srvrun/srvrun_impl.h"

static int srvrun_wt_waiting(const srvrun_conn* c);
static int srvrun_path_waiting(const srvrun_conn* c);
static int srvrun_timer_waiting(const srvrun_conn* c);
static int srvrun_latch_waiting(const srvrun_conn* c);
static int srvrun_recovery_waiting(const srvrun_conn* c);
static int srvrun_polling(const srvrun_cfg* cfg);
static int srvrun_bounded_wait_forced(const srvrun_cfg* cfg);
static int srvrun_poll_sockets(const srvrun_cfg* cfg);
static i64 srvrun_recv_xdp(const srvrun_cfg* cfg, mmsg_buf* bufs, usz nbufs);

/* Serve a recvmmsg batch message by message, in arrival order. One idle
 * sweep and one clock read cover the whole batch; each message's own source
 * address is the peer a fresh slot records (RFC 9000 5.1). */
void srvrun_serve_batch(
    const srvrun_cfg* cfg, srvrun_state* st, const mmsg_buf* bufs, i64 n) {
  u64 now = clock_mono_ms();
  srvrun_sweep_idle(cfg, st, now); /* lazy: swept on each arrival */
  for (i64 i = 0; i < n; i++) {
    srvrun_step_ctx ctx = {cfg, &bufs[i].src, st, now, bufs[i].ecn};
    srvrun_serve(&ctx, wired_mspan_of(bufs[i].buf.p, bufs[i].len));
  }
}

/* One receive+serve step: drain up to a batch of waiting datagrams in one
 * recvmmsg (it blocks for the first only, then returns what else is queued)
 * and serve each. Pending SIGHUP is consumed once per step (same granularity
 * as SIGTERM's shutdown flag): a reload lands before the batch is served, so
 * a fresh Initial arriving right after a reload already sees the new
 * identity. */
/* 1 if c needs the poll-timeout tick to keep making progress: a response
 * awaiting ACKs/a queued DATAGRAM (srvrun_has_outbound), or a boot flight
 * awaiting confirm (srvrun_has_boot_outbound). */
/* 1 iff c is up and has a WT app-callback latch pending (srvrun_wt_app_
 * pending's own doc): split out so srvrun_slot_waiting's own branch count
 * stays flat. */
static int srvrun_wt_waiting(const srvrun_conn* c) {
  return c->up && srvrun_wt_app_pending(c);
}

/* RFC 9000 8.2.4/9.4: an outstanding PATH_CHALLENGE needs the tick for its
 * resend and abandon timers. */
static int srvrun_path_waiting(const srvrun_conn* c) {
  return c->path.slot[0].in_use || c->path.slot[1].in_use;
}

/* A WT latch, a closing connection waiting for its reap
 * (srvrun_closing_tick), or an outstanding path challenge. */
static int srvrun_timer_waiting(const srvrun_conn* c) {
  return srvrun_wt_waiting(c) || c->closing || srvrun_path_waiting(c);
}

/* srvrun_rst_pending, srvrun_timer_waiting or an armed loss timer (RFC
 * 9002 6.1.2, srvrun_loss_timer_slot): the latch-style waits,
 * grouped so srvrun_slot_waiting's own || count stays flat. */
static int srvrun_latch_waiting(const srvrun_conn* c) {
  return srvrun_rst_pending(c) || srvrun_timer_waiting(c) ||
         srvrun_recovery_waiting(c);
}

/* An armed loss timer (RFC 9002 6.1.2) or an ACK still owed (RFC 9000
 * 13.2.1): both fire from the poll tick. */
static int srvrun_recovery_waiting(const srvrun_conn* c) {
  return c->loss_time_us || (c->up && c->l.app_ack_policy.pending);
}

int srvrun_slot_waiting(const srvrun_conn* c) {
  return srvrun_has_outbound(c) || srvrun_has_boot_outbound(c) ||
         srvrun_latch_waiting(c);
}

/* Wait for input: block in recvmmsg unless some slot needs the poll-timeout
 * tick (srvrun_slot_waiting), in which case poll with the probe tick so
 * silence still makes progress.
 * @return 1 to receive, 0 when the tick expired instead. */
int srvrun_any_waiting(const srvrun_state* st) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    if (srvrun_slot_waiting(&st->conns[i])) {
      return 1;
    }
  }
  return 0;
}

/* Non-blocking receive path: the busy_poll spin loop and the AF_XDP driver
 * both drain without ever waiting in poll(2). */
static int srvrun_polling(const srvrun_cfg* cfg) {
  return cfg->busy_poll || cfg->xdp != 0;
}

/* env->pto_next_ms/pto_spin: the PTO probe deadline for every driver. The
 * polling drivers never sleep in poll(2), so the poll-timeout probe pass in
 * srvrun_step is unreachable for them -- and the blocking driver's timeout
 * branch is just as unreachable for as long as continuous inbound traffic
 * keeps the socket readable within every 25ms window (a live relay under
 * steady voice uploads starved it for 30+ seconds, RFC 9002 6.2's probe
 * never firing). So the clocked pass runs for all drivers; pto_spin paces
 * the clock read below (1 on every 1024th call) for the spin drivers only,
 * since a blocking step already pays at least one syscall per iteration. */
int srvrun_pto_due(const srvrun_cfg* cfg, wired_srvrun_env* env) {
  if (!srvrun_polling(cfg)) {
    return 1;
  }
  env->pto_spin++;
  return (env->pto_spin & 1023u) == 0;
}

/* The clocked probe pass: fire the PTOs on the SRVRUN_PTO_MS cadence
 * regardless of whether poll(2) ever times out (srvrun_pto_due's doc). */
void srvrun_polling_ptos(const srvrun_cfg* cfg, srvrun_state* st) {
  u64 now;
  if (!srvrun_pto_due(cfg, cfg->env)) {
    return;
  }
  now = clock_mono_ms();
  if (now < cfg->env->pto_next_ms) {
    return;
  }
  cfg->env->pto_next_ms = now + SRVRUN_PTO_MS;
  srvrun_fire_ptos(cfg, st);
}

/* busy_poll=1 or xdp!=0: the blocking poll(2) itself is replaced by a non-
 * blocking return (the srvrun_any_waiting branch above is kept as-is; only
 * this leaf call changes). The actual non-blocking receive happens at the
 * recv step (srvrun_recv), so there is nothing left to wait for here. */
/* 1 if nothing requires a bounded wait: no response is awaiting ACKs, and
 * this instance owns SIGTERM/SIGHUP so an unbounded blocking recv can still
 * be interrupted. A srvthreads worker keeps SIGTERM/SIGHUP blocked for its
 * whole lifetime (no_signal_handlers), so only a timeout -- never a signal
 * -- can break it out of the loop to observe shutdown; it always takes the
 * bounded path below even with nothing in flight. */
/* A srvthreads worker cannot be signal-interrupted (no_signal_handlers's
 * doc), and a registered per-step hook (on_step) is time-driven: either way
 * the loop must keep its bounded SRVRUN_PTO_MS poll cadence instead of
 * blocking on input, or an idle socket would stall the hook until the next
 * inbound packet. */
static int srvrun_bounded_wait_forced(const srvrun_cfg* cfg) {
  return cfg->no_signal_handlers || cfg->on_step != 0;
}

int srvrun_may_block_unbounded(const srvrun_cfg* cfg, srvrun_state* st) {
  if (srvrun_bounded_wait_forced(cfg)) {
    return 0;
  }
  /* Undrained ring entries need further steps to go out (the per-step drain
   * cap holds the rest back); an unbounded block here would strand them. */
  if (cfg->env->dgring_n) {
    return 0;
  }
  return !srvrun_any_waiting(st);
}

/* The bounded readable-wait over the primary socket, or over both when the
 * preferred-address socket exists (one poll syscall either way). */
static int srvrun_poll_sockets(const srvrun_cfg* cfg) {
  if (cfg->env->pref_fd) {
    return poll_wait_readable2(cfg->fd, cfg->env->pref_fd, SRVRUN_PTO_MS) > 0;
  }
  return poll_wait_readable(cfg->fd, SRVRUN_PTO_MS) > 0;
}

int srvrun_wait_input(const srvrun_cfg* cfg, srvrun_state* st) {
  if (srvrun_polling(cfg)) {
    return 1;
  }
  if (srvrun_may_block_unbounded(cfg, st)) {
    return 1;
  }
  return srvrun_poll_sockets(cfg);
}

/* AF_XDP rx_burst step: pause once on an empty burst, same spin-step shape
 * as wired_srvpoll_spin_step (srvrun_recv below). */
static i64 srvrun_recv_xdp(const srvrun_cfg* cfg, mmsg_buf* bufs, usz nbufs) {
  i64 n = wired_srvxdp_rx_burst(cfg->xdp, bufs, nbufs);
  if (!n) {
    wired_arch_pause();
  }
  return n;
}

/* The batch receive call itself: AF_XDP when cfg->xdp is set, MSG_DONTWAIT
 * spin-step in busy_poll mode, the existing blocking recvmmsg otherwise
 * (byte-identical default path). */
i64 srvrun_recv(const srvrun_cfg* cfg, mmsg_buf* bufs, usz nbufs) {
  if (cfg->xdp) {
    return srvrun_recv_xdp(cfg, bufs, nbufs);
  }
  if (cfg->busy_poll) {
    return wired_srvpoll_spin_step(cfg->fd, bufs, nbufs);
  }
  return wired_udp_recvmmsg(cfg->fd, bufs, nbufs);
}
