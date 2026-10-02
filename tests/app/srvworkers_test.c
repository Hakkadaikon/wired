#include "app/http3/server/srvworkers/srvworkers.h"

#include "app/http3/server/sigterm/sigterm.h"
#include "common/platform/sys/syscall.h"
#include "test.h"

/* @file
 * srvworkers_slot_for_pid is a pure lookup, tested directly with no
 * syscalls. The fork/wait4 bookkeeping is
 * tested with REAL fork()/wait4() (confirmed available in this sandbox), but
 * the child body is substituted via srvworkers_test_set_child_fn so a test
 * child returns immediately instead of calling the real wired_server_run
 * (which binds a socket and loops forever) -- this keeps the test bounded
 * without needing an infinite-loop escape hatch. wired_srvworkers_run itself
 * runs in a forked stand-in supervisor process so a test can SIGTERM it and
 * bound the wait. */

/* TEST: slot_for_pid finds an exact match and reports -1 for a pid not in the
 * table (unit test of the pure bookkeeping helper, no fork involved). */
static void test_srvworkers_slot_for_pid_finds_match(void) {
  i64 pids[4] = {10, 20, 30, 40};
  CHECK(srvworkers_slot_for_pid(pids, 4, 30) == 2);
  CHECK(srvworkers_slot_for_pid(pids, 4, 999) == -1);
}

/* TEST: an empty table (n == 0) never matches anything. */
static void test_srvworkers_slot_for_pid_empty_table(void) {
  i64 pids[1] = {5};
  CHECK(srvworkers_slot_for_pid(pids, 0, 5) == -1);
}

/* Trivial test child body: returns immediately instead of running a real
 * server, so srvworkers_child_start's exit_group fires right away. */
static void sw_child_noop(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  worker_index) {
  (void)port;
  (void)id;
  (void)h;
  (void)obs;
  (void)worker_index;
}

/* TEST: fork_all(workers=2) starts two distinct live children and records
 * both pids in the table. */
static void test_srvworkers_fork_all_starts_two_children(void) {
  srvworkers_table     t   = {0};
  wired_srvworkers_opt opt = {2, 0, {0}};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  i64                  status;

  srvworkers_test_set_child_fn(sw_child_noop);
  CHECK(srvworkers_fork_all(&t, 0, &id, h, obs, &opt) == 0);
  CHECK(t.pid[0] > 0);
  CHECK(t.pid[1] > 0);
  CHECK(t.pid[0] != t.pid[1]);

  /* Reap both so no zombies leak into later tests. */
  syscall4(SYS_wait4, t.pid[0], &status, 0, 0);
  syscall4(SYS_wait4, t.pid[1], &status, 0, 0);
  srvworkers_test_set_child_fn(0);
}

/* Supervise steps (each reaps at most one child without blocking) until
 * slot 0 no longer holds pid, bounded at ~5 s. */
static void sw_supervise_until_reaped(
    srvworkers_table* t, i64 pid, const wired_srvworkers_opt* opt) {
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  for (int i = 0; i < 50 && t->pid[0] == pid; i++)
    srvworkers_supervise_once(t, 0, &id, h, obs, opt);
}

/* Test child body that crashes: a non-zero exit status. */
static void sw_child_crash(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  worker_index) {
  (void)port;
  (void)id;
  (void)h;
  (void)obs;
  (void)worker_index;
  wired_arch_exit_group(1);
}

/* TEST: after a worker crashes, one srvworkers_supervise_once call detects it
 * (via the real slot_for_pid lookup on a real wait4 result) and re-forks a
 * replacement in the SAME slot -- proving the restart-with-same-index
 * contract without an infinite supervisor loop. */
static void test_srvworkers_supervise_once_restarts_same_slot(void) {
  srvworkers_table     t   = {0};
  wired_srvworkers_opt opt = {1, 0, {0}};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  i64                  first_pid, status;

  srvworkers_test_set_child_fn(sw_child_crash);
  CHECK(srvworkers_fork_all(&t, 0, &id, h, obs, &opt) == 0);
  first_pid = t.pid[0];

  /* supervise_once never blocks, so step until the crashed child is
   * reaped and replaced. */
  sw_supervise_until_reaped(&t, first_pid, &opt);

  CHECK(t.pid[0] > 0);
  CHECK(t.pid[0] != first_pid); /* same slot, new pid: replacement worker */

  syscall4(SYS_wait4, t.pid[0], &status, 0, 0);
  srvworkers_test_set_child_fn(0);
}

/* TEST (boundary): opt->workers == 0 resolves to the auto-detected CPU count
 * (srvpin's cpu_count, already proven >= 1 by srvpin_test.c), not 0 itself. */
static void test_srvworkers_resolve_count_zero_is_auto(void) {
  CHECK(srvworkers_resolve_count(0) >= 1);
}

/* TEST (boundary): a workers count beyond the fixed table size is clamped,
 * never left to overrun srvworkers_table.pid[]. */
static void test_srvworkers_resolve_count_clamps_to_max(void) {
  CHECK(
      srvworkers_resolve_count(WIRED_SRVWORKERS_MAX + 100) ==
      WIRED_SRVWORKERS_MAX);
}

/* TEST: a within-range count passes through unchanged. */
static void test_srvworkers_resolve_count_passthrough(void) {
  CHECK(srvworkers_resolve_count(3) == 3);
}

static i64 sw_now_ms(void) {
  i64 ts[2];
  wired_arch_clock_gettime(1 /* CLOCK_MONOTONIC */, ts);
  return ts[0] * 1000 + ts[1] / 1000000;
}

/* TEST: with no child left to wait for, wait4 fails with ECHILD; the
 * supervisor's wait must still nap rather than return at once, or the loop
 * around it spins a CPU. */
static void test_srvworkers_wait_naps_on_echild(void) {
  i64 status = 0;
  i64 t0;
  while (syscall4(SYS_wait4, -1, &status, 1 /* WNOHANG */, 0) > 0) {
  }
  t0 = sw_now_ms();
  CHECK(srvworkers_wait(&status) == -10 /* -ECHILD */);
  CHECK(sw_now_ms() - t0 >= 50);
}

/* Test child body that proves worker_index really reaches the child body
 * (srvworkers_child_start -> g_srvworkers_child_fn): exits with worker_index
 * as its exit status, which
 * the parent's wait4 status can decode without any new IPC machinery. */
static void sw_child_echo_index(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  worker_index) {
  (void)port;
  (void)id;
  (void)h;
  (void)obs;
  syscall1(SYS_exit_group, worker_index);
}

/* TEST: srvworkers_child_start passes its own worker_index through to the
 * child body unchanged (here worker_index=1, the second of two forked
 * workers) -- decoded from the exit status wait4 reports (WIFEXITED/
 * WEXITSTATUS: low byte of status, shifted right 8). */
static void test_srvworkers_child_start_passes_worker_index(void) {
  srvworkers_table     t   = {0};
  wired_srvworkers_opt opt = {2, 0, {0}};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  i64                  status;

  srvworkers_test_set_child_fn(sw_child_echo_index);
  CHECK(srvworkers_fork_all(&t, 0, &id, h, obs, &opt) == 0);

  syscall4(SYS_wait4, t.pid[0], &status, 0, 0);
  CHECK(((status >> 8) & 0xff) == 0);
  syscall4(SYS_wait4, t.pid[1], &status, 0, 0);
  CHECK(((status >> 8) & 0xff) == 1);
  srvworkers_test_set_child_fn(0);
}

/* App-facing run options handed to the driver (opt.run) must reach every
 * forked child's server loop. They did not: the child rebuilt its run from a
 * zeroed literal, so wt_on_datagram/busy_poll/force_retry set by the app
 * were silently dropped in --workers mode (same disease the --cores driver
 * had). fork_all must seed the pre-fork base every child derives from. */
static void sw_marker_dg_cb(void* ctx, wired_wt_session* s, wired_span d) {
  (void)ctx;
  (void)s;
  (void)d;
}

static void test_srvworkers_fork_all_seeds_child_run_base(void) {
  srvworkers_table     t   = {0};
  wired_srvworkers_opt opt = {1, 0, {0}};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  i64                  status;

  opt.run.wt_on_datagram = sw_marker_dg_cb;
  opt.run.busy_poll      = 1;
  g_srvworkers_run_base  = (wired_srvrun_opt){0};

  srvworkers_test_set_child_fn(sw_child_noop);
  CHECK(srvworkers_fork_all(&t, 0, &id, h, obs, &opt) == 0);
  CHECK(g_srvworkers_run_base.wt_on_datagram == sw_marker_dg_cb);
  CHECK(g_srvworkers_run_base.busy_poll == 1);
  syscall4(SYS_wait4, t.pid[0], &status, 0, 0);
  srvworkers_test_set_child_fn(0);
  g_srvworkers_run_base = (wired_srvrun_opt){0};
}

/* The child's own run = the base, with the per-worker fork-model fields
 * layered on top: incoming_cpu is the worker index, xdp/core_id stay off. */
static void test_srvworkers_child_opt_layers_worker_fields(void) {
  wired_srvrun_opt o;
  g_srvworkers_run_base                = (wired_srvrun_opt){0};
  g_srvworkers_run_base.wt_on_datagram = sw_marker_dg_cb;
  g_srvworkers_run_base.busy_poll      = 1;
  o                                    = srvworkers_child_opt(3);
  CHECK(o.wt_on_datagram == sw_marker_dg_cb);
  CHECK(o.busy_poll == 1);
  CHECK(o.incoming_cpu == 3);
  CHECK(o.xdp == 0);
  CHECK(o.core_id == -1);
  g_srvworkers_run_base = (wired_srvrun_opt){0};
}

/* TEST: exit status 0 never respawns, shutting down or not. */
static void test_srvworkers_should_respawn_exit0(void) {
  CHECK(srvworkers_should_respawn(0, 0) == 0);
  CHECK(srvworkers_should_respawn(0, 1) == 0);
}

/* TEST: a crash (killed by a signal, or a non-zero exit code) respawns only
 * while the supervisor is not shutting down. */
static void test_srvworkers_should_respawn_crash(void) {
  CHECK(srvworkers_should_respawn(9, 0) == 1);      /* SIGKILL */
  CHECK(srvworkers_should_respawn(1 << 8, 0) == 1); /* exit(1) */
  CHECK(srvworkers_should_respawn(9, 1) == 0);      /* during shutdown */
  CHECK(srvworkers_should_respawn(1 << 8, 1) == 0);
}

/* TEST: a worker that exits 0 is reaped and its slot stays empty. */
static void test_srvworkers_supervise_once_exit0_leaves_slot_empty(void) {
  srvworkers_table     t   = {0};
  wired_srvworkers_opt opt = {1, 0, {0}};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};

  srvworkers_test_set_child_fn(sw_child_noop);
  CHECK(srvworkers_fork_all(&t, 0, &id, h, obs, &opt) == 0);
  sw_supervise_until_reaped(&t, t.pid[0], &opt);
  CHECK(t.pid[0] == 0);
  srvworkers_test_set_child_fn(0);
}

/* Child body that marks that it ran with a distinctive exit code. */
static void sw_child_exit7(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  worker_index) {
  (void)port;
  (void)id;
  (void)h;
  (void)obs;
  (void)worker_index;
  wired_arch_exit_group(7);
}

/* Wait for pid for at most ~5 s; on timeout SIGKILL and reap it.
 * @return the wait4 status, or -1 on timeout. */
static i64 sw_wait_bounded(i64 pid) {
  i64 status = 0;
  for (int i = 0; i < 500; i++) {
    if (wired_arch_wait4(pid, &status, 1 /* WNOHANG */, 0) == pid)
      return status & 0xffff;
    wired_arch_poll(0, 0, 10);
  }
  wired_arch_kill(pid, 9);
  wired_arch_wait4(pid, &status, 0, 0);
  return -1;
}

/* TEST: a fresh worker whose parent is already gone (getppid differs from
 * the pid saved before fork) exits at once without running its body. */
static void test_srvworkers_child_start_exits_when_parent_gone(void) {
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  i64                  pid;

  srvworkers_test_set_child_fn(sw_child_exit7);
  pid = wired_arch_fork();
  if (pid == 0) srvworkers_child_start(0, 0, &id, h, obs, 0, -1);
  CHECK(sw_wait_bounded(pid) == 0);
  srvworkers_test_set_child_fn(0);
}

static volatile int sw_term_seen;

static void sw_on_term(int sig) {
  (void)sig;
  sw_term_seen = 1;
}

/* Child body that serves ~3 s without a SIGTERM handler of its own. */
static void sw_child_spin(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  worker_index) {
  (void)port;
  (void)id;
  (void)h;
  (void)obs;
  (void)worker_index;
  for (int i = 0; i < 300; i++) wired_arch_poll(0, 0, 10);
  wired_arch_exit_group(5);
}

/* TEST: a SIGTERM that reaches a worker before it installs its own handler
 * is not swallowed by the flag-only handler inherited from the supervisor:
 * the worker resets SIGTERM to the default action, so it dies. */
static void test_srvworkers_child_start_resets_sigterm(void) {
  srvworkers_table     t   = {0};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};

  t.n = 1;
  wired_sigterm_install(sw_on_term);
  srvworkers_test_set_child_fn(sw_child_spin);
  CHECK(srvworkers_fork_one(&t, 0, 0, &id, h, obs, 0) == 0);
  wired_arch_kill(t.pid[0], SIGTERM);
  CHECK(sw_wait_bounded(t.pid[0]) == SIGTERM);
  srvworkers_test_set_child_fn(0);
  wired_sigterm_install(0); /* SIG_DFL */
}

/* Fork a process that runs wired_srvworkers_run with 2 workers, send it
 * SIGTERM first if term, and return its bounded wait status. SIGTERM is
 * blocked across the fork so it stays pending until the supervisor's own
 * handler is in place. */
static i64 sw_run_supervisor(int term) {
  wired_srvworkers_opt opt = {2, 0, {0}};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  i64                  pid;

  wired_sigmask_block_shutdown();
  pid = wired_arch_fork();
  if (pid == 0)
    wired_arch_exit_group(wired_srvworkers_run(0, &id, h, obs, &opt) ? 3 : 0);
  if (term) wired_arch_kill(pid, SIGTERM);
  wired_sigmask_unblock_shutdown();
  return sw_wait_bounded(pid);
}

/* TEST: once every worker exited 0 and was reaped, the supervisor returns
 * instead of respawning or spinning on wait4. */
static void test_srvworkers_run_returns_when_all_exit(void) {
  srvworkers_test_set_child_fn(sw_child_noop);
  CHECK(sw_run_supervisor(0) == 0);
  srvworkers_test_set_child_fn(0);
}

/* Child body that drains on SIGTERM: installs its own handler, then serves
 * until told to stop (bounded at ~10 s, past the
 * supervisor wait bound so a missing forward fails the test) and returns (exit
 * 0). */
static void sw_child_wait_term(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs,
    int                  worker_index) {
  (void)port;
  (void)id;
  (void)h;
  (void)obs;
  (void)worker_index;
  wired_sigterm_install(sw_on_term);
  for (int i = 0; i < 1000 && !sw_term_seen; i++) wired_arch_poll(0, 0, 10);
}

/* TEST: SIGTERM to the supervisor does not kill it; it forwards SIGTERM to
 * every worker, reaps them all without respawning, then returns 0. */
static void test_srvworkers_run_sigterm_drains_and_exits(void) {
  srvworkers_test_set_child_fn(sw_child_wait_term);
  CHECK(sw_run_supervisor(1) == 0);
  srvworkers_test_set_child_fn(0);
}

void test_srvworkers(void) {
  test_srvworkers_slot_for_pid_finds_match();
  test_srvworkers_slot_for_pid_empty_table();
  test_srvworkers_fork_all_starts_two_children();
  test_srvworkers_supervise_once_restarts_same_slot();
  test_srvworkers_resolve_count_zero_is_auto();
  test_srvworkers_resolve_count_clamps_to_max();
  test_srvworkers_resolve_count_passthrough();
  test_srvworkers_wait_naps_on_echild();
  test_srvworkers_child_start_passes_worker_index();
  test_srvworkers_fork_all_seeds_child_run_base();
  test_srvworkers_child_opt_layers_worker_fields();
  test_srvworkers_should_respawn_exit0();
  test_srvworkers_should_respawn_crash();
  test_srvworkers_supervise_once_exit0_leaves_slot_empty();
  test_srvworkers_child_start_exits_when_parent_gone();
  test_srvworkers_child_start_resets_sigterm();
  test_srvworkers_run_returns_when_all_exit();
  test_srvworkers_run_sigterm_drains_and_exits();
}
