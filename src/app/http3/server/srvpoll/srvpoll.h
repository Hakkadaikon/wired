#ifndef WIRED_SRVPOLL_SRVPOLL_H
#define WIRED_SRVPOLL_SRVPOLL_H

#include "transport/io/socket/io/udp.h"

/** @file
 * Non-blocking receive-and-spin loop control (see
 * tasks/polling-driver-plan.md POLL-005). One step wraps
 * wired_udp_recvmmsg_nowait and adds exactly one behavior: issue a single
 * CPU PAUSE instruction when the underlying call reports no data ready, so
 * the caller's own loop can retry immediately without blocking. It does not
 * reinterpret the underlying result. */

/** One step of a non-blocking receive-and-spin loop. Calls
 * wired_udp_recvmmsg_nowait(fd, bufs, count); if that call reports no data
 * (return value <= 0 -- 0 datagrams or a negative errno such as -EAGAIN),
 * issues one PAUSE instruction before returning. Never blocks, never loops
 * internally: exactly one recvmmsg_nowait call per invocation.
 * @param fd the socket fd
 * @param bufs array of count receive slots (see quic_mmsg_buf)
 * @param count number of slots in bufs
 * @return whatever wired_udp_recvmmsg_nowait returned, unchanged (datagram
 *   count, 0, or a negative errno). */
i64 wired_srvpoll_spin_step(i64 fd, quic_mmsg_buf* bufs, usz count);

/** Cap on wired_srvpoll_backoff.empty_spins (and thus on PAUSE instructions
 * issued per empty step) -- bounds worst-case latency into a burst after a
 * long idle period. */
#define WIRED_SRVPOLL_BACKOFF_MAX 64

/** Per-poll-loop adaptive backoff state (tasks/polling-driver-plan.md
 * POLL-006). Not per-connection: the caller owns one instance for the
 * lifetime of its polling loop and threads it through each step call. */
typedef struct {
  u64 empty_spins; /**< consecutive empty steps so far, capped at
                     * WIRED_SRVPOLL_BACKOFF_MAX. */
} wired_srvpoll_backoff;

/** Like wired_srvpoll_spin_step, but scales the number of PAUSE
 * instructions with how long the loop has been idle: each empty result
 * increments bo->empty_spins (capped at WIRED_SRVPOLL_BACKOFF_MAX) and
 * issues that many PAUSE instructions; any result with data resets
 * bo->empty_spins to 0 immediately, so no backoff carries into a burst.
 * @param bo caller-owned backoff state, threaded across calls.
 * @return whatever wired_udp_recvmmsg_nowait returned, unchanged. */
i64 wired_srvpoll_spin_step_backoff(
    i64 fd, quic_mmsg_buf* bufs, usz count, wired_srvpoll_backoff* bo);

#endif
