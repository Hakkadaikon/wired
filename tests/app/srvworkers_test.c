#include "app/http3/server/srvworkers/srvworkers.h"

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
 * is a thin `while (1) srvworkers_supervise_once(...)` wrapper and is
 * exercised only through that one-call seam, never invoked directly (it does
 * not return by contract). */

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
  wired_srvworkers_opt opt = {2, 0};
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

/* TEST: after a worker exits, one srvworkers_supervise_once call detects it
 * (via the real slot_for_pid lookup on a real wait4 result) and re-forks a
 * replacement in the SAME slot -- proving the restart-with-same-index
 * contract without an infinite supervisor loop. */
static void test_srvworkers_supervise_once_restarts_same_slot(void) {
  srvworkers_table     t   = {0};
  wired_srvworkers_opt opt = {1, 0};
  wired_srvboot_id     id  = {0};
  wired_srvrun_handler h   = {0};
  wired_srvrun_obs     obs = {0};
  i64                  first_pid, status;

  srvworkers_test_set_child_fn(sw_child_noop);
  CHECK(srvworkers_fork_all(&t, 0, &id, h, obs, &opt) == 0);
  first_pid = t.pid[0];

  /* The lone child already ran sw_child_noop and exit_group'd by the time
   * this parent gets here in the common case, but supervise_once's own
   * wait4 blocks until it has, so this is not a race. */
  srvworkers_supervise_once(&t, 0, &id, h, obs, &opt);

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
  wired_srvworkers_opt opt = {2, 0};
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

void test_srvworkers(void) {
  test_srvworkers_slot_for_pid_finds_match();
  test_srvworkers_slot_for_pid_empty_table();
  test_srvworkers_fork_all_starts_two_children();
  test_srvworkers_supervise_once_restarts_same_slot();
  test_srvworkers_resolve_count_zero_is_auto();
  test_srvworkers_resolve_count_clamps_to_max();
  test_srvworkers_resolve_count_passthrough();
  test_srvworkers_child_start_passes_worker_index();
}
