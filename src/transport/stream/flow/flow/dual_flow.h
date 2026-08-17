#ifndef QUIC_FLOW_DUAL_FLOW_H
#define QUIC_FLOW_DUAL_FLOW_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.1: each byte counts against both the stream limit and the
 * connection limit. Accepting data requires staying within both. */

/** Bytes consumed against one advertised limit. */
typedef struct {
  u64 used;
  u64 max;
} flow_usage;

/* Whether the stream and connection usages are each within their limits. */
int dual_flow_ok(const flow_usage* stream, const flow_usage* conn);

#endif
