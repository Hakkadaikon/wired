#include "app/http3/server/srvworkers/srvworkers.h"

#include "app/http3/server/sigterm/sigterm.h"
#include "app/http3/server/srvpin/srvpin.h"
#include "common/platform/sys/syscall.h"

/* fork(57) over clone (no trampoline asm needed, crash isolation, plain
 * wait4(61) reaping), exit_group(231) uniformly even though each worker is
 * single-threaded. */

/** worker_index -> pid table, 0 = slot unused (pid 0 cannot occur here: fork
 * never returns 0 to the parent). */
typedef struct {
  i64 pid[WIRED_SRVWORKERS_MAX];
  int n;
  int forwarded; /* SIGTERM already forwarded to the workers */
} srvworkers_table;

/* Set by the supervisor's SIGTERM handler, which does nothing else: the
 * forward to the workers happens in the supervise loop (after any fork in
 * flight), so a worker forked around the signal is never missed. */
static volatile int g_srvworkers_term;

static void srvworkers_on_term(int sig) {
  (void)sig;
  g_srvworkers_term = 1;
}

/* Find the slot whose recorded pid == pid. Pure lookup, no syscalls: kept
 * free of I/O so it is unit-testable without an actual fork.
 * @return slot index in [0,n), or -1 if not found. */
static int srvworkers_slot_for_pid(const i64* pids, int n, i64 pid) {
  for (int i = 0; i < n; i++)
    if (pids[i] == pid) return i;
  return -1;
}

/* The real child body always runs wired_server_run unmodified. Tests
 * substitute this with a trivial stand-in (immediate return) via
 * srvworkers_test_set_child_fn below, so a fork test never blocks on a real
 * socket bind/loop.
 * ponytail: unused in the freestanding build (only tests/run.c substitutes
 * it), so it needs the attribute to avoid -Wunused-function under -Werror
 * there. */
typedef void (*srvworkers_child_fn)(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  worker_index);

/* The base run options every child derives from -- written once by
 * srvworkers_fork_all (before any fork, so children inherit it through the
 * fork'd address space) from wired_srvworkers_opt.run. A process-global
 * rather than a child-fn parameter so the test-substitution seam
 * (srvworkers_child_fn) keeps its signature. */
static wired_srvrun_opt g_srvworkers_run_base;

/* This child's run options: the app-set base, with the per-worker fields the
 * fork model owns layered on top -- incoming_cpu hints the kernel to steer
 * this worker's packets toward the CPU it is pinned to (worker_index), and
 * core_id stays -1 (never AF_XDP in fork mode). */
static wired_srvrun_opt srvworkers_child_opt(int worker_index) {
  wired_srvrun_opt opt = g_srvworkers_run_base;
  opt.incoming_cpu     = worker_index;
  opt.xdp              = 0;
  opt.core_id          = -1;
  return opt;
}

static void srvworkers_run_real(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  worker_index) {
  wired_srvrun_opt opt = srvworkers_child_opt(worker_index);
  wired_server_run_opt(port, id, h, obs, &opt);
}

static srvworkers_child_fn g_srvworkers_child_fn = srvworkers_run_real;

/* Test-only hook: substitute what the child runs instead of the real
 * wired_server_run (which binds a socket and loops forever). Pass 0 to
 * restore the real one. */
__attribute__((unused)) static void srvworkers_test_set_child_fn(
    srvworkers_child_fn fn) {
  g_srvworkers_child_fn = fn ? fn : srvworkers_run_real;
}

/* Runs inside the child after fork() returns 0. SIGTERM first goes back to
 * the default action (the inherited handler would only set the supervisor's
 * flag in this copy, swallowing a forward that lands before the server loop
 * installs its own), then unblocks it (blocked across fork), and arms
 * PR_SET_PDEATHSIG(1) so the worker drains if the supervisor dies. A
 * supervisor that died before the arm is caught by getppid no longer being
 * the pid saved before fork. Then pins to CPU == worker_index if requested,
 * and runs the (real or test-substituted) server body.
 * That body does not return in normal operation; if it ever does, exit_group
 * cleanly rather than falling into the parent's supervisor code below this
 * call. Never returns. */
static void srvworkers_child_start(
    int                  worker_index,
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  pin_cores,
    i64                  parent) {
  wired_sigterm_install(0); /* SIG_DFL */
  wired_sigmask_unblock_shutdown();
  wired_arch_prctl(1 /* PR_SET_PDEATHSIG */, SIGTERM);
  if (wired_arch_getppid() != parent) wired_arch_exit_group(0);
  if (pin_cores) wired_srvpin_bind_self(worker_index);
  g_srvworkers_child_fn(port, id, h, obs, worker_index);
  wired_arch_exit_group(0);
}

/* Fork one worker. On the child side this never returns (see
 * srvworkers_child_start). On the parent side, records the new pid in slot
 * worker_index and returns 0; returns negative on fork() failure itself. */
static int srvworkers_fork_one(
    srvworkers_table*    t,
    int                  worker_index,
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  pin_cores) {
  i64 parent = wired_arch_getpid();
  i64 pid;
  wired_sigmask_block_shutdown();
  pid = wired_arch_fork();
  if (pid == 0)
    srvworkers_child_start(worker_index, port, id, h, obs, pin_cores, parent);
  wired_sigmask_unblock_shutdown();
  if (pid < 0) return (int)pid;
  t->pid[worker_index] = pid;
  return 0;
}

/* Fork opt->workers children, filling t. Stops and returns negative on the
 * first fork() failure (the "initial fork setup itself fails" contract
 * case); otherwise returns 0 once every worker has started. */
static int srvworkers_fork_all(
    srvworkers_table*           t,
    u16                         port,
    wired_srvboot_id*           id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvworkers_opt* opt) {
  g_srvworkers_run_base = opt->run; /* pre-fork: children inherit it */
  t->n                  = opt->workers;
  for (int i = 0; i < t->n; i++) {
    int r = srvworkers_fork_one(t, i, port, id, h, obs, opt->pin_cores);
    if (r < 0) return r;
  }
  return 0;
}

/* Respawn only a crash (killed by a signal, or a non-zero exit code; both
 * make the low 16 wait4 status bits non-zero) and only while not shutting
 * down. A clean exit 0 never respawns. */
static int srvworkers_should_respawn(i64 status, int terminating) {
  return (status & 0xffff) != 0 && !terminating;
}

static int srvworkers_should_forward(const srvworkers_table* t) {
  return g_srvworkers_term && !t->forwarded;
}

static void srvworkers_kill_all(const srvworkers_table* t) {
  for (int i = 0; i < t->n; i++)
    if (t->pid[i]) wired_arch_kill(t->pid[i], SIGTERM);
}

/* Once SIGTERM has arrived, send it to every still-live worker, once. */
static void srvworkers_forward(srvworkers_table* t) {
  if (!srvworkers_should_forward(t)) return;
  t->forwarded = 1;
  srvworkers_kill_all(t);
}

/* Reap one exited worker without blocking; nap when none has, so a SIGTERM
 * whose handler ran outside the wait (no EINTR to wake on) is still
 * forwarded within one nap.
 * ponytail: 100 ms idle wakeups and up to 100 ms forward latency; a
 * signalfd in the wait set if that ever matters.
 * @return the reaped pid, or -1 if none (never 0: a free slot holds 0). */
static i64 srvworkers_wait(i64* status) {
  i64 dead = wired_arch_wait4(-1, status, 1 /* WNOHANG */, 0);
  if (dead == 0) wired_arch_poll(0, 0, 100);
  return dead ? dead : -1;
}

/* Empty the slot of a reaped worker and respawn it if it crashed while not
 * shutting down. */
static void srvworkers_reap(
    srvworkers_table*           t,
    int                         slot,
    i64                         status,
    u16                         port,
    wired_srvboot_id*           id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvworkers_opt* opt) {
  t->pid[slot] = 0;
  if (srvworkers_should_respawn(status, g_srvworkers_term))
    srvworkers_fork_one(t, slot, port, id, h, obs, opt->pin_cores);
}

/* Reap at most one child that changed state, find which
 * worker slot it was, empty the slot, and re-fork a replacement with the
 * SAME worker index (so pinning stays consistent) if it crashed while not
 * shutting down. Then forward a pending SIGTERM -- after the fork, so a
 * worker forked as the signal landed gets it too. A wait4 error or an exited
 * pid this table does not track only falls through to the forward.
 * This is the unit test seam: one call = one detect-and-restart cycle, no
 * infinite loop. */
static void srvworkers_supervise_once(
    srvworkers_table*           t,
    u16                         port,
    wired_srvboot_id*           id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvworkers_opt* opt) {
  i64 status = 0;
  int slot   = srvworkers_slot_for_pid(t->pid, t->n, srvworkers_wait(&status));
  if (slot >= 0) srvworkers_reap(t, slot, status, port, id, h, obs, opt);
  srvworkers_forward(t);
}

/* Any worker slot still holding an unreaped pid? */
static int srvworkers_live(const srvworkers_table* t) {
  for (int i = 0; i < t->n; i++)
    if (t->pid[i]) return 1;
  return 0;
}

/* Resolve opt->workers into a concrete count: 0 means auto-detect via
 * srvpin's CPU count, and anything beyond the fixed table size is clamped to
 * it (the array behind srvworkers_table cannot hold more). */
static int srvworkers_resolve_count(int workers) {
  if (workers == 0) workers = wired_srvpin_cpu_count();
  if (workers > WIRED_SRVWORKERS_MAX) workers = WIRED_SRVWORKERS_MAX;
  return workers;
}

int wired_srvworkers_run(
    u16                         port,
    wired_srvboot_id*           id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvworkers_opt* opt) {
  srvworkers_table     t     = {0};
  wired_srvworkers_opt local = *opt;
  int                  r;
  local.workers = srvworkers_resolve_count(local.workers);
  wired_sigterm_install(srvworkers_on_term);
  r = srvworkers_fork_all(&t, port, id, h, obs, &local);
  if (r < 0) return r;
  while (srvworkers_live(&t))
    srvworkers_supervise_once(&t, port, id, h, obs, &local);
  return 0;
}
