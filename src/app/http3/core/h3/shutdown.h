#ifndef QUIC_H3_SHUTDOWN_H
#define QUIC_H3_SHUTDOWN_H

#include "common/platform/sys/syscall.h"

/* RFC 9114 5.2: graceful shutdown via GOAWAY. A server sends GOAWAY with a
 * large request id, then retransmits a smaller id to narrow the shutdown.
 * A request is processed only when its id is below the GOAWAY limit, and
 * successive GOAWAY ids are monotonically non-increasing. */

/* Whether the request with `request_id` is processed under `goaway_limit`. */
int quic_h3_shutdown_processes(u64 request_id, u64 goaway_limit);

/* Whether a GOAWAY id update from `prev` to `next` is valid (non-increasing).
 */
int quic_h3_shutdown_id_monotone(u64 prev, u64 next);

#endif
