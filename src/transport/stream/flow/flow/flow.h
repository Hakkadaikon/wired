#ifndef FLOW_FLOW_H
#define FLOW_FLOW_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4: flow control accounting. A sender may send up to max_data
 * cumulative bytes; a receiver advertises a limit and advances it. */

typedef struct {
  u64 sent;     /* cumulative bytes sent */
  u64 max_data; /* peer-advertised send limit */
} flow_send;

typedef struct {
  u64 consumed; /* cumulative bytes delivered to the application */
  u64 max_data; /* limit advertised to the peer */
  u64 window;   /* how far ahead of consumed to keep the limit */
} flow_recv;

void flow_send_init(flow_send* f, u64 max_data);

/* Bytes the sender may still send right now. */
u64 flow_send_avail(const flow_send* f);

/* Account n newly sent bytes. Returns 1 if within the limit, 0 if it would
 * exceed max_data (in which case nothing is recorded). */
int flow_send_record(flow_send* f, u64 n);

/* Raise the send limit from a MAX_DATA frame (never lowers it). */
void flow_send_update_max(flow_send* f, u64 max_data);

/* Whether the sender is flow-control blocked trying to send `want` more
 * bytes: it wants to send but the limit leaves too little room. When blocked,
 * a DATA_BLOCKED frame reporting the current limit should be sent (RFC 9000
 * 4.1, 19.12). */
int flow_send_blocked(const flow_send* f, u64 want);

void flow_recv_init(flow_recv* f, u64 window);

/* Consume n delivered bytes and slide the advertised limit forward.
 * Returns the new max_data to advertise. */
u64 flow_recv_consume(flow_recv* f, u64 n);

#endif
