#include "app/http3/server/srvrun/srvrun_impl.h"

static void srvrun_ghost_add(const srvrun_step_ctx* ctx, const u8* cid, u8 len);
static void srvrun_refuse_unroutable(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg);
static void srvrun_route_and_serve(
    const srvrun_step_ctx* ctx,
    wired_span             dcid,
    wired_mspan            dg,
    wired_span             odcid);
static int  srvrun_size_violation(wired_mspan dg);
static void srvrun_serve_sized(const srvrun_step_ctx* ctx, wired_mspan dg);
static void srvrun_maybe_busy_poll(i64 fd, int so_busy_poll_us);
static int  srvrun_prefer_busy_poll_wanted(const wired_srvrun_opt* opt);
static void srvrun_maybe_prefer_busy_poll(i64 fd, const wired_srvrun_opt* opt);
static void srvrun_maybe_busy_poll_budget(i64 fd, const wired_srvrun_opt* opt);
static void srvrun_maybe_incoming_cpu(i64 fd, const wired_srvrun_opt* opt);

/* Remember one cid of len bytes as freshly closed in the next ring entry. */
static void srvrun_ghost_add(
    const srvrun_step_ctx* ctx, const u8* cid, u8 len) {
  wired_srvrun_env* env = ctx->cfg->env;
  srvrun_ghost*     g   = &env->ghosts[env->ghost_at++ % SRVRUN_GHOST_SLOTS];
  bytes_memcpy(g->scid, cid, len);
  g->len      = len;
  g->until_ms = ctx->now_ms + SRVRUN_GHOST_MS;
}

/* Remember every connection ID c answers to -- its scid and, once issued,
 * its spare CID (the one a migrated peer addresses, RFC 9000 5.1.1) -- as
 * freshly closed (srvrun_ghost) before its slot is reclaimed, so the
 * peer's closing-period stragglers go unanswered instead of drawing a
 * stateless reset. */
void srvrun_note_ghost(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (!ctx->cfg->id) {
    return; /* no identity, no scid to remember */
  }
  srvrun_ghost_add(ctx, c->scid, ctx->cfg->id->scid_len);
  if (c->l.spare_cid_len) {
    srvrun_ghost_add(ctx, c->l.spare_cid, c->l.spare_cid_len);
  }
}

/* RFC 9000 10.3 for a datagram no slot claims: refuse and reset -- unless
 * it names a freshly closed connection (RFC 9000 10.2.2: its peer's own
 * CONNECTION_CLOSE retransmit or final ack is expected traffic during the
 * closing period, and a reset here read to the peer as a transport error
 * on a cleanly closed connection), or is itself the peer's Stateless Reset
 * of a live one (10.3.1). */
static void srvrun_refuse_unroutable(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  if (srvrun_ghost_match(ctx, dcid) || srvrun_peer_reset_any(ctx, dg)) {
    return;
  }
  srvrun_send_new_conn_refusal(ctx, dcid, dg);
  srvrun_send_stateless_reset(ctx, dcid, dg);
}

/* Route dg to its slot and serve it there, threading a retry-recovered
 * ODCID (if any) onto the freshly claimed slot before the accept path
 * reads it (srvrun_slot_id -> srvboot_tp_odcid). */
static void srvrun_route_and_serve(
    const srvrun_step_ctx* ctx,
    wired_span             dcid,
    wired_mspan            dg,
    wired_span             odcid) {
  int slot = srvrun_route_or_evict(ctx, dcid, dg);
  if (slot < 0) {
    srvrun_refuse_unroutable(ctx, dcid, dg);
    return;
  }
  if (odcid.n) {
    srvrun_note_retry_odcid(&ctx->st->conns[slot], odcid);
  }
  srvrun_serve_slot(ctx, slot, dg);
}

/* RFC 9000 14.1/14: a datagram carrying an Initial packet below the
 * 1200-byte floor violates the size constraint and is discarded outright --
 * never treated as a connection error, since a malicious or misbehaving
 * middlebox (not the peer) is the more likely cause (RFC 9000 14). */
static int srvrun_size_violation(wired_mspan dg) {
  return wired_srvboot_is_initial(dg.p, dg.n) && !middlebox_initial_ok(dg.n);
}

/* dg past the size-violation gate: version-negotiate, consume a retry, or
 * route it to its slot. Split from srvrun_serve so neither carries more than
 * one guard beyond its own entry check (CCN). */
static void srvrun_serve_sized(const srvrun_step_ctx* ctx, wired_mspan dg) {
  wired_span dcid  = srvrun_dcid(dg, ctx->cfg->id->scid_len);
  wired_span odcid = {0, 0};
  if (srvrun_vneg(ctx, dg)) {
    return;
  }
  if (srvrun_retry_consumed(ctx, dcid, dg, &odcid)) {
    return;
  }
  srvrun_route_and_serve(ctx, dcid, dg, odcid);
}

void srvrun_serve(const srvrun_step_ctx* ctx, wired_mspan dg) {
  if (srvrun_size_violation(dg)) {
    return;
  }
  srvrun_serve_sized(ctx, dg);
}

/* so_busy_poll_us > 0 enables SO_BUSY_POLL on fd; best-effort like
 * SO_REUSEPORT, a no-op when <= 0 or unsupported by the kernel/driver. */
static void srvrun_maybe_busy_poll(i64 fd, int so_busy_poll_us) {
  if (so_busy_poll_us > 0) {
    wired_udp_busy_poll_enable(fd, so_busy_poll_us);
  }
}

/* SO_PREFER_BUSY_POLL only has kernel effect when SO_BUSY_POLL is also
 * enabled; hoisted so the caller's `if` stays a single condition (CCN). */
static int srvrun_prefer_busy_poll_wanted(const wired_srvrun_opt* opt) {
  return opt->so_busy_poll_us > 0 && opt->so_prefer_busy_poll;
}

/* so_prefer_busy_poll/so_busy_poll_budget: best-effort like SO_REUSEPORT and
 * srvrun_maybe_busy_poll above, each independently opt-in. */
static void srvrun_maybe_prefer_busy_poll(i64 fd, const wired_srvrun_opt* opt) {
  if (srvrun_prefer_busy_poll_wanted(opt)) {
    wired_udp_prefer_busy_poll_enable(fd, 1);
  }
}

static void srvrun_maybe_busy_poll_budget(i64 fd, const wired_srvrun_opt* opt) {
  if (opt->so_busy_poll_budget > 0) {
    wired_udp_busy_poll_budget_set(fd, opt->so_busy_poll_budget);
  }
}

/* -1 = disabled (wired_srvrun_opt's own sentinel; see srvrun.h). */
static void srvrun_maybe_incoming_cpu(i64 fd, const wired_srvrun_opt* opt) {
  if (opt->incoming_cpu >= 0) {
    wired_udp_incoming_cpu_set(fd, opt->incoming_cpu);
  }
}

/* Bind a UDP socket on port. Returns the fd, or <0 on failure. */
i64 srvrun_listen(u16 port, const wired_srvrun_opt* opt) {
  sockaddr sa;
  i64      fd = wired_udp_socket();
  if (fd < 0) {
    return fd;
  }
  /* Best-effort: lets multiple srvworkers children share one port. A
   * single-worker run does not need it, so a failure here is not fatal --
   * fall through to bind unconditionally. */
  wired_udp_reuseport_enable(fd);
  /* RFC 9000 13.4 / RFC 9002 19.3.2: best-effort like reuseport above -- ECT(0)
   * marking on send and IP_TOS cmsg on receive are an optimization an ECN-
   * unaware kernel/NIC simply won't provide, never a bind blocker. */
  wired_udp_ect0_enable(fd);
  wired_udp_recvtos_enable(fd);
  /* RFC 8899 4.5: this connection runs its own DPLPMTUD search (pmtu via
   * connrunner's probe drive), so the kernel's own PMTU enforcement/caching
   * must be suspended for this socket's flows -- best-effort like the ECN
   * options above, never a bind blocker. */
  wired_udp_pmtu_probe_enable(fd);
  srvrun_maybe_busy_poll(fd, opt->so_busy_poll_us);
  srvrun_maybe_prefer_busy_poll(fd, opt);
  srvrun_maybe_busy_poll_budget(fd, opt);
  srvrun_maybe_incoming_cpu(fd, opt);
  wired_udp_addr(&sa, port, (const u8[4]){0, 0, 0, 0});
  if (wired_udp_bind(fd, &sa) < 0) {
    return -1;
  }
  return fd;
}
