#ifndef WIRED_SRVWORKERS_SRVWORKERS_H
#define WIRED_SRVWORKERS_SRVWORKERS_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvrun/srvrun.h"

/** @file
 * Multi-process worker fan-out over the single-process wired_server_run
 * (tasks/core-pinning-plan.md Phase 2 / THR-004..008): fork N shared-nothing
 * child processes, each optionally pinned to one CPU, each running its own
 * copy of the existing server loop unmodified. The parent becomes a
 * supervisor that restarts any worker that dies.
 *
 * ponytail: for N workers to actually share one UDP port, the socket
 * wired_server_run binds must have SO_REUSEPORT enabled before bind — that
 * wiring lives in srvrun.c's listen path (wired_udp_reuseport_enable, already
 * implemented in transport/io/socket/io/udp.h), not here. srvworkers only
 * forks/pins/supervises; verify separately that srvrun.c's bind path calls
 * wired_udp_reuseport_enable before relying on multiple workers sharing a
 * port. */

/** Worker fan-out policy. */
typedef struct {
  int workers;   /**< 0 = auto (wired_srvpin_cpu_count()) */
  int pin_cores; /**< 1 = pin worker i to CPU i, 0 = no pinning */
} wired_srvworkers_opt;

/** Upper bound on concurrent workers (matches the CPU pin range srvpin
 * supports: 64 bits in an 8-byte sched_setaffinity mask). */
#define WIRED_SRVWORKERS_MAX 64

/** Fork opt->workers (or CPU count if opt->workers == 0) child processes.
 * Each child, if opt->pin_cores, pins itself to CPU == its worker index via
 * wired_srvpin_bind_self before doing anything else, then calls
 * wired_server_run(port, id, h, obs) unmodified. wired_server_run does not
 * return under normal operation; if it ever does, the child exits cleanly
 * (exit_group) rather than falling into the parent's supervisor code.
 *
 * The parent enters a wait4 supervisor loop: block for any child to change
 * state, and re-fork a replacement with the SAME worker index (so pinning
 * stays consistent) whenever a worker exits. This does NOT return in normal
 * operation -- it is a supervisor loop, not a one-shot call.
 *
 * @param port UDP port passed through to each worker's wired_server_run
 * @param id the fixed server identity, passed through to every worker
 * @param h the application's request responder, passed through
 * @param obs optional qlog/keylog/cert-reload settings, passed through
 * @param opt worker count / pinning policy; 0 workers means auto-detect
 * @return negative only if the very first fork() itself fails before any
 *   worker starts; otherwise this does not return. */
int wired_srvworkers_run(
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvworkers_opt* opt);

#endif
