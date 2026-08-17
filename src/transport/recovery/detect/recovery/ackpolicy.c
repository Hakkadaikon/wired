#include "transport/recovery/detect/recovery/ackpolicy.h"

void ackpolicy_init(ackpolicy* p) {
  p->pending    = 0;
  p->since_tick = 0;
}

void ackpolicy_on_eliciting(ackpolicy* p, u64 tick) {
  if (p->pending == 0)
    p->since_tick = tick; /* start the delay from the oldest */
  p->pending++;
}

/* Whether max_ack_delay has elapsed since the oldest pending packet. */
static int delay_elapsed(const ackpolicy* p, u64 now, u64 max_ack_delay) {
  return now - p->since_tick >= max_ack_delay;
}

int ackpolicy_should_ack(const ackpolicy* p, u64 now, u64 max_ack_delay) {
  if (p->pending == 0) return 0;
  if (p->pending >= 2) return 1; /* two ack-eliciting packets: ack at once */
  return delay_elapsed(p, now, max_ack_delay);
}

void ackpolicy_on_ack_sent(ackpolicy* p) { p->pending = 0; }
