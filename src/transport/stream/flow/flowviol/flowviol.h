#ifndef QUIC_FLOWVIOL_H
#define QUIC_FLOWVIOL_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.1/4.6: detect a flow-control violation and pick the transport
 * error code to close with. Connection-level or per-stream data over the
 * advertised limit is a FLOW_CONTROL_ERROR (0x03); opening more streams than
 * granted is a STREAM_LIMIT_ERROR (0x04). */

/* Returns 1 and writes the error code to *error_code on a violation, 0 if
 * within limits (*error_code left unchanged). Connection-level data is checked
 * before the stream count, so a data overrun reports FLOW_CONTROL_ERROR. */
int quic_flowviol_check(u64 received_total, u64 max_data,
                        u64 stream_count, u64 max_streams, u64 *error_code);

#endif
