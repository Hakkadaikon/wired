#include "app/http3/server/srvrun/srvrun_impl.h"

static usz  srvrun_dgring_slice(const wired_srvrun_env* env, u64 now_ms);
static void srvrun_goaway_one(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* ob);
static int srvrun_reload_requested(const wired_srvrun_env* env);
__attribute__((unused)) static void srvrun_test_set_reload(int v);
static void                         srvrun_reload_cert(
    const srvrun_cfg* cfg, wired_certreload_store* store);
static int srvrun_reinit_ok(const srvrun_conn* c);

/* Entries this drain may send now: 0 while the pacing interval since the
 * last slice has not yet elapsed; otherwise capped by both the per-slice
 * entry count and byte budget above. */
static usz srvrun_dgring_slice(const wired_srvrun_env* env, u64 now_ms) {
  usz max = (usz)u64_min(env->dgring_n, SRVRUN_DGRING_DRAIN_MAX);
  if (now_ms < env->dgring_next_drain_ms) {
    return 0;
  }
  return srvrun_dgring_budget_count(env, max);
}

/* Drain up to one paced slice of ring entries, oldest first -- run once per
 * loop step (srvrun_step); what this slice cannot send stays queued for a
 * later step, never dropped. */
void srvrun_dgring_drain(const srvrun_cfg* cfg, srvrun_state* st, u64 now_ms) {
  wired_srvrun_env* env = cfg->env;
  usz               n   = srvrun_dgring_slice(env, now_ms);
  if (n) {
    env->dgring_next_drain_ms = now_ms + SRVRUN_DGRING_DRAIN_MS;
  }
  while (n--) {
    srvrun_dgring_send_one(cfg, st, &env->dgring[env->dgring_head]);
    env->dgring_head = (env->dgring_head + 1) % SRVRUN_DGRING_CAP;
    env->dgring_n--;
  }
}

/* Send GOAWAY to every live connection that still owes one (RFC 9114 5.2), the
 * first step of graceful shutdown. Connections not yet confirmed simply have
 * no 1-RTT key to receive it and are left to time out normally. */
/* GOAWAY plus this connection's own WT_DRAIN_SESSION fan-out
 * (srvrun_send_wt_drain_all, WTH3-048) -- split out of srvrun_goaway_all so
 * its own loop stays at the CCN gate. */
static void srvrun_goaway_one(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* ob) {
  if (!srvrun_send_goaway(cfg, c, ob)) {
    return;
  }
  srvrun_send_wt_drain_all(c);
}

void srvrun_goaway_all(const srvrun_cfg* cfg, srvrun_state* st) {
  u8         out[256];
  wired_obuf ob = obuf_of(out, sizeof out);
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    if (srvrun_owes_goaway(&st->conns[i])) {
      srvrun_goaway_one(cfg, &st->conns[i], &ob);
    }
  }
}

/* 1 once every slot has drained (gone down) or never came up — the condition
 * that lets the shutdown grace period end early instead of waiting out the
 * whole budget. */
int srvrun_all_drained(const srvrun_state* st) {
  for (usz i = 0; i < WIRED_CONNTABLE_CAP; i++) {
    if (st->conns[i].up) {
      return 0;
    }
  }
  return 1;
}

/* Graceful shutdown: set by srvrun_sigterm_handler (async-signal-safe: it
 * only stores to this word), read by the main loop to stop accepting new
 * connections and start winding down live ones. A process-wide word, not an
 * env member: SIGTERM is process-wide, so every srvrun loop in the process
 * shares one shutdown state, whether serving through the single g_srvrun_env
 * or a caller-supplied one via wired_srvrun_serve_env. 0->1 monotonic only
 * (never reset back to 0 outside test teardown) so a concurrent reader never
 * observes it going backward; __atomic_store_n/__atomic_load_n (same
 * idiom as xskring.c) make the cross-thread handoff well-defined without a
 * lock. */
static int g_srvrun_shutdown;

/* SIGTERM handler: the ONLY thing safe to do here is set a flag (async-signal-
 * safe rule) — no syscalls, no allocation, nothing the interrupted code might
 * itself have been mid-way through. Registration (wired_sigterm_install) uses
 * the real rt_sigaction(2) syscall and is not exercised by unit tests; the
 * behavior driven off the flag below is. */
void srvrun_sigterm_handler(int sig) {
  (void)sig;
  __atomic_store_n(&g_srvrun_shutdown, 1, __ATOMIC_RELEASE);
}

/* 1 once a graceful shutdown has been requested (SIGTERM, or a test forcing
 * the flag directly). */
int srvrun_shutdown_requested(void) {
  return __atomic_load_n(&g_srvrun_shutdown, __ATOMIC_RELAXED);
}

/* Test-only hook: force the shutdown flag without going through a real
 * SIGTERM delivery (rt_sigaction registration is not unit-testable — see
 * sigterm.c — so tests drive the flag directly and assert on the behavior
 * that follows: new-Initial rejection, GOAWAY fan-out, drain). Also resets
 * it, so tests do not leak shutdown state into one another.
 * ponytail: unused in the freestanding build (only tests/run.c calls this),
 * so it needs the attribute to avoid -Wunused-function under -Werror there. */
__attribute__((unused)) static void srvrun_test_set_shutdown(int v) {
  __atomic_store_n(&g_srvrun_shutdown, v, __ATOMIC_RELEASE);
}

int* wired_srvrun_shutdown_word(void) { return &g_srvrun_shutdown; }

/* Certificate hot reload: a monotonically increasing generation counter, bumped
 * by srvrun_sighup_handler (async-signal-safe: __atomic_fetch_add is a single
 * lock xadd on x86, nothing else). Process-wide like g_srvrun_shutdown above
 * (SIGHUP is process-wide too) -- each env tracks its own reload_seen_gen so
 * "was this generation already applied by THIS env" is answered per-instance
 * even though the generation itself is shared. */
static u32 g_srvrun_reload_gen;

/* SIGHUP handler: same async-signal-safety rule as srvrun_sigterm_handler —
 * bump the generation and nothing else. Registration (wired_sighup_install)
 * is not exercised by unit tests; the behavior driven off the counter below
 * is. */
void srvrun_sighup_handler(int sig) {
  (void)sig;
  __atomic_fetch_add(&g_srvrun_reload_gen, 1, __ATOMIC_RELEASE);
}

/* 1 once a certificate reload is pending for env: its own reload_seen_gen has
 * not caught up to the current generation yet (SIGHUP, or a test forcing the
 * generation directly). */
static int srvrun_reload_requested(const wired_srvrun_env* env) {
  u32 gen = __atomic_load_n(&g_srvrun_reload_gen, __ATOMIC_ACQUIRE);
  return gen != env->reload_seen_gen;
}

/* Test-only hook: force a reload to be (or not be) pending for g_srvrun_env
 * without a real SIGHUP delivery (same rationale as srvrun_test_set_shutdown).
 * v=1 makes one generation pending; v=0 marks the current generation already
 * seen, so tests do not leak reload state into one another.
 * ponytail: unused in the freestanding build, needs the attribute to avoid
 * -Wunused-function under -Werror there. */
__attribute__((unused)) static void srvrun_test_set_reload(int v) {
  if (v) {
    __atomic_fetch_add(&g_srvrun_reload_gen, 1, __ATOMIC_RELEASE);
    return;
  }
  g_srvrun_env.reload_seen_gen =
      __atomic_load_n(&g_srvrun_reload_gen, __ATOMIC_ACQUIRE);
}

/* Re-decode cfg->cert_path/key_path into cfg->id in place (wired_certreload_
 * load overwrites only chain/chain_count/cert_seed, RFC 9114 5.2-adjacent
 * operational note: no live connection is affected, see the srvrun_cfg
 * comment above). A failed reload (bad path or malformed PEM/DER) leaves the
 * previous identity untouched — wired_certreload_load does not partially
 * mutate *id on failure. No-op when reload is disabled (cert_path unset). */
static void srvrun_reload_cert(
    const srvrun_cfg* cfg, wired_certreload_store* store) {
  if (!cfg->cert_path) {
    return;
  }
  if (!wired_certreload_load(cfg->cert_path, cfg->key_path, store, cfg->id)) {
    WIRED_LOG("cert reload failed, keeping previous identity\n");
  }
}

/* Consume a pending reload request once: mark this generation seen first so a
 * SIGHUP arriving mid-reload is not lost (it bumps the generation again),
 * then (re)load if one was pending. */
void srvrun_reload_if_requested(const srvrun_cfg* cfg, wired_srvrun_env* env) {
  if (!srvrun_reload_requested(env)) {
    return;
  }
  env->reload_seen_gen =
      __atomic_load_n(&g_srvrun_reload_gen, __ATOMIC_ACQUIRE);
  srvrun_reload_cert(cfg, &env->certstore);
}

/* RFC 9000 7: only a slot that is not up yet cold-starts on an Initial. An
 * unconfirmed slot treats it as a retransmit (srvrun_is_boot_retransmit); a
 * confirmed one has discarded its Initial keys (RFC 9001 4.9.1), so the
 * Initial falls through to the live loop and is dropped there -- rebuilding
 * in place would let anyone who reads the server CID off the wire tear a
 * live connection down without its close callback. */
static int srvrun_reinit_ok(const srvrun_conn* c) { return !c->up; }

/* Whether dg may (re)open c: a long-header Initial, not during graceful
 * shutdown (no new Initial is accepted, fresh slot or existing one alike),
 * and only on a slot eligible to (re)cold-start. */
int srvrun_is_new(const srvrun_conn* c, wired_mspan dg) {
  if (!wired_srvboot_is_initial(dg.p, dg.n)) {
    return 0;
  }
  if (srvrun_shutdown_requested()) {
    return 0;
  }
  return srvrun_reinit_ok(c);
}

/* c is up but its handshake is not confirmed yet -- still within the window
 * where an Initial retransmit means "resend the same flight", not "start a
 * fresh connection" (RFC 9000 13.3). */
int srvrun_awaiting_confirm(const srvrun_conn* c) {
  return c->up && !wired_server_is_confirmed(&c->s);
}
