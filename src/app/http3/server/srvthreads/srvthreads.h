#ifndef WIRED_SRVTHREADS_SRVTHREADS_H
#define WIRED_SRVTHREADS_SRVTHREADS_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvrun/srvrun.h"
#include "app/http3/server/srvxdp/srvxdp.h"

/** @file
 * Thread-based worker fan-out over the single-process wired_srvrun_serve_env
 * (Phase D of tasks/core-pinning-plan.md): one control thread spawns N
 * worker threads sharing the process's address space (unlike srvworkers'
 * fork fan-out), each running its own wired_srvrun_env instance. The
 * control thread blocks on a timed futex wait for the shared shutdown word
 * (wired_srvrun_shutdown_word), then joins every worker before releasing
 * shared resources (the BPF objects, the mmap'd env storage).
 *
 * Lifecycle (modeled and checked in TLA+ before this was written): the
 * control thread blocks SIGTERM/SIGHUP, spawns all N workers (which inherit
 * the mask), unblocks and installs the handlers, waits for shutdown, then
 * joins every worker and cleans up. A signal arriving during the blocked
 * window is delivered, pending, once unblocked. */

/** Max worker threads this domain supports (fixed-size cores[] table). */
#define WIRED_SRVTHREADS_MAX 16u

/** Fan-out policy: per-worker CPU pinning, optional control-thread pinning,
 * the srvrun knobs copied to every worker, and an optional shared AF_XDP
 * config selecting multi-queue mode. */
typedef struct {
  int cores[WIRED_SRVTHREADS_MAX]; /**< CPU index for worker i */
  int n_cores;          /**< number of workers, <= WIRED_SRVTHREADS_MAX */
  int control_core;     /**< CPU to pin the control thread to; -1 = don't pin */
  wired_srvrun_opt run; /**< busy_poll etc., copied to every worker
                         * (no_signal_handlers is forced to 1 regardless of
                         * what is passed here: only the control thread
                         * installs signal handlers) */
  /** 0 = UDP + SO_REUSEPORT mode (every worker binds its own socket on
   * `port` via wired_srvrun_serve_env's existing listen path). Non-0 =
   * AF_XDP multi-queue mode: worker i opens queue i
   * (wired_srvxdp_open_shared) against one shared per-interface BPF object
   * the control thread owns (wired_srvxdpbpf_open/close). */
  const wired_srvxdp_cfg* xdp;
} wired_srvthreads_opt;

/** Run N worker threads serving `port`/`h` until a graceful shutdown is
 * requested (SIGTERM, or SIGHUP-driven cert reload paths configured via
 * `id`), matching wired_srvworkers_run's contract but over threads instead
 * of processes: shared address space, one shared AF_XDP BPF filter in XDP
 * mode instead of N independent ones.
 * @param port UDP port every worker serves
 * @param id the fixed server identity; each worker gets its own copy so a
 *   SIGHUP reload (handled by wired_srvrun_serve_env internally) never
 *   races across workers
 * @param h the application's request responder, passed through unchanged
 * @param obs optional qlog/keylog/cert-reload settings, passed through
 * @param opt worker CPU pinning, control pinning, srvrun knobs, and
 *   optional AF_XDP config
 * @return 1 once every worker has exited and cleanup is complete; 0 if
 *   opening the shared BPF filter or allocating per-worker env storage
 *   fails before any worker starts. */
int wired_srvthreads_run(
    u16                         port,
    wired_srvboot_id*           id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvthreads_opt* opt);

/** Parse a comma-separated core list ("2,3,4,5") into opt->cores[] and
 * opt->n_cores, e.g. for a --cores CLI flag (examples/webtransport_chat and
 * examples/word_list each reimplemented this parser separately; this is the
 * shared version).
 *
 * The empty string is rejected rather than accepted as "0 cores": an empty
 * --cores value is always a caller mistake (the thread-fan-out driver is
 * only selected when --cores is given at all), so treating it as malformed
 * surfaces the mistake instead of silently running zero workers. The same
 * reasoning rejects a leading/trailing/doubled comma: an empty field is not
 * a valid core number, so "2,3," and ",2,3" are malformed rather than
 * silently ignoring the empty field.
 *
 * @param s   NUL-terminated comma-separated list of non-negative base-10
 *            core numbers, e.g. "2,3,4,5"
 * @param opt destination; cores[]/n_cores are written on success, left
 *            untouched on failure
 * @return 1 on success, 0 if s is malformed (non-digit, empty field) or
 *         the parsed core count exceeds WIRED_SRVTHREADS_MAX
 */
int wired_srvthreads_parse_cores(const char* s, wired_srvthreads_opt* opt);

#endif
