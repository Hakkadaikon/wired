#ifndef QUIC_RECOVERY_ACKPOLICY_H
#define QUIC_RECOVERY_ACKPOLICY_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 13.2.1 / 13.2.2: an endpoint sends an ACK on receiving an
 * ack-eliciting packet, within its advertised max_ack_delay. As a recommended
 * policy it acknowledges immediately after receiving two ack-eliciting packets
 * without yet acking; otherwise it may delay until max_ack_delay elapses since
 * the oldest unacked ack-eliciting packet. Time is abstracted as a monotonic
 * tick count; max_ack_delay is expressed in the same unit. */

typedef struct {
  u64 pending;    /* unacked ack-eliciting packets received */
  u64 since_tick; /* tick of the oldest currently-pending packet */
} quic_ackpolicy;

void quic_ackpolicy_init(quic_ackpolicy *p);

/* Record receipt of an ack-eliciting packet at the given tick. */
void quic_ackpolicy_on_eliciting(quic_ackpolicy *p, u64 tick);

/* Whether an ACK should be sent now: true once two or more ack-eliciting
 * packets are pending, or once max_ack_delay has elapsed since the oldest. */
int quic_ackpolicy_should_ack(
    const quic_ackpolicy *p, u64 now, u64 max_ack_delay);

/* Clear pending state after an ACK has been sent. */
void quic_ackpolicy_on_ack_sent(quic_ackpolicy *p);

#endif
