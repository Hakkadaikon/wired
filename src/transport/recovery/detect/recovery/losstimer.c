#include "transport/recovery/detect/recovery/losstimer.h"

/* RFC 9002 6.2 */
u64 quic_losstimer_next(u64 loss_time, u64 pto_time, int has_loss_time) {
  if (has_loss_time && loss_time < pto_time) return loss_time;
  return pto_time;
}

/* RFC 9002 6.2 */
int quic_losstimer_set(int ack_eliciting_in_flight) {
  return ack_eliciting_in_flight != 0;
}
