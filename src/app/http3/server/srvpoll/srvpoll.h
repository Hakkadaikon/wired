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

#endif
