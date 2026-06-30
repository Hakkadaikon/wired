#ifndef QUIC_FLOW_STREAM_FLOW_H
#define QUIC_FLOW_STREAM_FLOW_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.1: per-stream receive flow control. The receiver advertises a
 * MAX_STREAM_DATA limit and slides it forward as the application consumes. */

typedef struct {
    u64 consumed;        /* cumulative bytes delivered to the application */
    u64 max_stream_data; /* limit advertised to the peer */
    u64 window;          /* how far ahead of consumed to keep the limit */
} quic_stream_flow;

void quic_stream_flow_init(quic_stream_flow *s, u64 window);

/* Consume n delivered bytes and slide the limit forward. Returns the new
 * max_stream_data to advertise. */
u64 quic_stream_flow_consume(quic_stream_flow *s, u64 n);

/* Whether a received highest offset exceeds the advertised limit: a
 * FLOW_CONTROL_ERROR when received > max_stream_data. Returns 1 on violation. */
int quic_stream_flow_violation(u64 received, u64 max_stream_data);

#endif
