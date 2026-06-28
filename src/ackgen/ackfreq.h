#ifndef QUIC_ACKGEN_ACKFREQ_H
#define QUIC_ACKGEN_ACKFREQ_H

#include "sys/syscall.h"

/* RFC 9000 13.2.1: rather than acking every ack-eliciting packet, an endpoint
 * may ack once two are outstanding, or once max_ack_delay has elapsed since the
 * oldest unacked one (elapsed and max_ack_delay share one monotonic unit). */

/* Whether an ACK is due now. unacked_eliciting: outstanding unacked
 * ack-eliciting packets. elapsed: ticks since the oldest. */
int quic_ackgen_due(u32 unacked_eliciting, u64 elapsed, u64 max_ack_delay);

#endif
