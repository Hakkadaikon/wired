#ifndef QUIC_CLOSELIFE_KEEPALIVE_H
#define QUIC_CLOSELIFE_KEEPALIVE_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 10.1.2: to keep a connection alive an endpoint sends a packet (e.g.
 * PING) before the idle timeout expires. We send once half the idle timeout
 * has elapsed since the last activity. Times share one unit (ms or ticks). */

/* Interval after which a keep-alive packet is due: half the idle timeout. */
u64 quic_keepalive_interval(u64 idle_timeout);

/* True if a keep-alive packet should be sent now. */
int quic_keepalive_due(u64 last_activity, u64 now, u64 idle_timeout);

#endif
