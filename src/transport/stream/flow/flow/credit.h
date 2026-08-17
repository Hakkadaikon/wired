#ifndef FLOW_CREDIT_H
#define FLOW_CREDIT_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 4.1: connection-level receive credit. The receiver advertises a
 * max_data limit covering all streams and advances it as data is consumed. A
 * peer sending more than max_data cumulative bytes is a FLOW_CONTROL_ERROR. */

typedef struct {
  u64 consumed; /* cumulative bytes consumed across all streams */
  u64 max_data; /* limit advertised to the peer */
  u64 window;   /* how far ahead of consumed to keep the limit */
} flow_credit;

void flow_credit_init(flow_credit* c, u64 initial_max);

/* Consume n bytes and slide the limit forward. Returns the new max_data. */
u64 flow_credit_consume(flow_credit* c, u64 n);

/* Whether the peer's cumulative received bytes exceed the advertised limit:
 * a FLOW_CONTROL_ERROR when received_total > max_data. Returns 1 on violation.
 */
int flow_credit_violation(const flow_credit* c, u64 received_total);

#endif
