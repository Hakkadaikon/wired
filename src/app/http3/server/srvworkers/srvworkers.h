#ifndef WIRED_SRVWORKERS_SRVWORKERS_H
#define WIRED_SRVWORKERS_SRVWORKERS_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvrun/srvrun.h"

/** @file
 * Multi-process worker fan-out over the single-process wired_server_run:
 * fork N shared-nothing child processes, each optionally pinned to one CPU,
 * each running its own copy of the existing server loop unmodified. The
 * parent becomes a supervisor that restarts any worker that crashes.
 *
 * Packet routing (workers > 1, RFC 9000 5.2/9): before forking, the
 * supervisor binds one SO_REUSEPORT socket per worker in worker order and
 * attaches a classic-BPF selection program to the group (srvsteer /
 * rpsteer), the reuseport analogue of the AF_XDP driver's CID steering:
 * each worker embeds its index into every CID it issues
 * (srvrun_issue_cid), and the program decodes a datagram's DCID back to
 * that index, so a server-issued DCID keeps reaching the worker holding
 * its connection across NAT rebinding and migration. A DCID this server
 * did not issue -- notably a client's first Initial -- falls back to the
 * kernel's 4-tuple hash (or an in-range decode); both are deterministic
 * for retransmitted identical bytes, so a handshake stays on one worker.
 * Steering is best-effort: if the sockets or the attach fail (or scid_len
 * < NCID_ROUTE_MIN_LEN), workers fall back to each binding its own socket
 * and the kernel's hash alone, the historical behavior. A worker that
 * CRASHES keeps its socket (the supervisor holds every fd and the respawn
 * inherits it), so routing survives respawn; its in-flight connections die
 * with it either way. */

/** Worker fan-out policy. */
typedef struct {
  int workers;   /**< 0 = auto (wired_srvpin_cpu_count()) */
  int pin_cores; /**< 1 = pin worker i to CPU i, 0 = no pinning */
  /** Base run options every forked child serves with (app callbacks,
   * busy-poll knobs, force_retry ...). Per-worker fields the fork model owns
   * (incoming_cpu = the worker's index) are overridden per child; everything
   * else passes through unchanged. Zeroed = the historical defaults. */
  wired_srvrun_opt run;
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
 * The parent enters a wait4 supervisor loop: it re-forks a replacement with
 * the SAME worker index (so pinning stays consistent) whenever a worker
 * crashes (killed by a signal or a non-zero exit); a worker that exits 0 is
 * not replaced. On SIGTERM the parent forwards SIGTERM once to every live
 * worker, stops respawning, and keeps reaping. Each worker arms
 * PR_SET_PDEATHSIG(SIGTERM), so it drains if the parent dies. The parent
 * returns once every worker has been reaped.
 *
 * Call it at most once per process, from a single-threaded caller: the
 * SIGTERM handler and its flag are process-wide, and PR_SET_PDEATHSIG fires
 * on the death of the forking THREAD, not the process.
 *
 * @param port UDP port passed through to each worker's wired_server_run
 * @param id the fixed server identity, passed through to every worker
 * @param h the application's request responder, passed through
 * @param obs optional qlog/keylog/cert-reload settings, passed through
 * @param opt worker count / pinning policy; 0 workers means auto-detect
 * @return negative if the ticket/Retry seed draw or the initial fork()
 *   fails; 0 once every worker has been reaped (after SIGTERM, or when all
 *   exited 0). */
int wired_srvworkers_run(
    u16                         port,
    wired_srvboot_id*           id,
    wired_srvrun_handler        h,
    wired_srvrun_obs            obs,
    const wired_srvworkers_opt* opt);

#endif
