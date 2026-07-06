#include "app/http3/server/srvworkers/srvworkers.h"

#include "app/http3/server/srvpin/srvpin.h"
#include "common/platform/sys/syscall.h"

/* tasks/core-pinning-plan.md THR-004/005/008: fork(57) over clone (no
 * trampoline asm needed, crash isolation, plain wait4(61) reaping),
 * exit_group(231) uniformly even though each worker is single-threaded. */

/** worker_index -> pid table, 0 = slot unused (pid 0 cannot occur here: fork
 * never returns 0 to the parent). */
typedef struct {
  i64 pid[WIRED_SRVWORKERS_MAX];
  int n;
} srvworkers_table;

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
    u16 port, wired_srvboot_id* id, wired_srvrun_handler h,
    wired_srvrun_obs obs);

static void srvworkers_run_real(
    u16 port, wired_srvboot_id* id, wired_srvrun_handler h,
    wired_srvrun_obs obs) {
  wired_server_run(port, id, h, obs);
}

static srvworkers_child_fn g_srvworkers_child_fn = srvworkers_run_real;

/* Test-only hook: substitute what the child runs instead of the real
 * wired_server_run (which binds a socket and loops forever). Pass 0 to
 * restore the real one. */
__attribute__((unused)) static void srvworkers_test_set_child_fn(
    srvworkers_child_fn fn) {
  g_srvworkers_child_fn = fn ? fn : srvworkers_run_real;
}

/* Runs inside the child after fork() returns 0. Pins to CPU == worker_index
 * first if requested, then runs the (real or test-substituted) server body.
 * That body does not return in normal operation; if it ever does, exit_group
 * cleanly rather than falling into the parent's supervisor code below this
 * call. Never returns. */
static void srvworkers_child_start(
    int                      worker_index,
    u16                      port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    int                      pin_cores) {
  if (pin_cores) wired_srvpin_bind_self(worker_index);
  g_srvworkers_child_fn(port, id, h, obs);
  syscall1(SYS_exit_group, 0);
}

/* Fork one worker. On the child side this never returns (see
 * srvworkers_child_start). On the parent side, records the new pid in slot
 * worker_index and returns 0; returns negative on fork() failure itself. */
static int srvworkers_fork_one(
    srvworkers_table*       t,
    int                      worker_index,
    u16                      port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    int                      pin_cores) {
  i64 pid = syscall1(SYS_fork, 0);
  if (pid < 0) return (int)pid;
  if (pid == 0)
    srvworkers_child_start(worker_index, port, id, h, obs, pin_cores);
  t->pid[worker_index] = pid;
  return 0;
}

/* Fork opt->workers children, filling t. Stops and returns negative on the
 * first fork() failure (the "initial fork setup itself fails" contract
 * case); otherwise returns 0 once every worker has started. */
static int srvworkers_fork_all(
    srvworkers_table*             t,
    u16                            port,
    wired_srvboot_id*             id,
    wired_srvrun_handler          h,
    wired_srvrun_obs              obs,
    const wired_srvworkers_opt*   opt) {
  t->n = opt->workers;
  for (int i = 0; i < t->n; i++) {
    int r = srvworkers_fork_one(t, i, port, id, h, obs, opt->pin_cores);
    if (r < 0) return r;
  }
  return 0;
}

/* Block for any one child to change state, find which worker slot it was,
 * and re-fork a replacement with the SAME worker index (so pinning stays
 * consistent). A wait4 error (e.g. ECHILD, no children left to wait for) or
 * an exited pid this table does not track is silently ignored -- there is
 * nothing this supervisor step can do about it, and it simply loops again.
 * This is the unit test seam: one call = one detect-and-restart cycle, no
 * infinite loop. */
static void srvworkers_supervise_once(
    srvworkers_table*             t,
    u16                            port,
    wired_srvboot_id*             id,
    wired_srvrun_handler          h,
    wired_srvrun_obs              obs,
    const wired_srvworkers_opt*   opt) {
  i64 status;
  i64 dead = syscall4(SYS_wait4, -1, &status, 0, 0);
  int slot = srvworkers_slot_for_pid(t->pid, t->n, dead);
  if (slot >= 0)
    srvworkers_fork_one(t, slot, port, id, h, obs, opt->pin_cores);
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
    u16                          port,
    wired_srvboot_id*            id,
    wired_srvrun_handler         h,
    wired_srvrun_obs             obs,
    const wired_srvworkers_opt*  opt) {
  srvworkers_table     t     = {0};
  wired_srvworkers_opt local = *opt;
  int                  r;
  local.workers = srvworkers_resolve_count(local.workers);
  r             = srvworkers_fork_all(&t, port, id, h, obs, &local);
  if (r < 0) return r;
  while (1) srvworkers_supervise_once(&t, port, id, h, obs, &local);
}
