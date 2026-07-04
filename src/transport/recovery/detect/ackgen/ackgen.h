#ifndef QUIC_ACKGEN_ACKGEN_H
#define QUIC_ACKGEN_ACKGEN_H

#include "common/platform/sys/syscall.h"

/* RFC 9000 13.2.1 / 13.2.2: an endpoint sends an ACK on receiving an
 * ack-eliciting packet, within its advertised max_ack_delay. After a second
 * unacked ack-eliciting packet it acks immediately. Stateless predicate over
 * the caller's tracked counters (a monotonic tick unit shared with
 * max_ack_delay). */

/* ack_eliciting_received: the packet just received elicits an ack.
 * ack_already_pending: an earlier ack-eliciting packet is still unacked (a
 * second one forces immediate ack). since_last_ack: ticks elapsed since the
 * oldest unacked ack-eliciting packet. */
typedef struct {
  int ack_eliciting_received;
  int ack_already_pending;
  u64 since_last_ack;
} quic_ackgen_state;

/* Whether an ACK should be sent now. */
int quic_ackgen_should_ack(const quic_ackgen_state* s, u64 max_ack_delay);

#endif
