#include "transport/recovery/detect/ackgen/ackgen.h"

/* RFC 9000 13.2.1: max_ack_delay elapsed since the oldest unacked packet. */
static int delay_due(u64 since_last_ack, u64 max_ack_delay) {
  return since_last_ack >= max_ack_delay;
}

/* RFC 9000 13.2.2: a second unacked ack-eliciting packet forces an ack. */
static int second_eliciting(
    int ack_eliciting_received, int ack_already_pending) {
  return ack_eliciting_received && ack_already_pending;
}

/* Any ack-eliciting packet, received now or still pending, is outstanding. */
static int has_outstanding(
    int ack_eliciting_received, int ack_already_pending) {
  return ack_eliciting_received || ack_already_pending;
}

int quic_ackgen_should_ack(
    int ack_eliciting_received,
    int ack_already_pending,
    u64 since_last_ack,
    u64 max_ack_delay) {
  if (!has_outstanding(ack_eliciting_received, ack_already_pending)) return 0;
  if (second_eliciting(ack_eliciting_received, ack_already_pending)) return 1;
  return delay_due(since_last_ack, max_ack_delay);
}
