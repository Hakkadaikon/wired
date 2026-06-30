#include "transport/recovery/detect/recovery/ptoreset.h"

/* RFC 9002 6.2.1 */
int quic_pto_should_reset(int ack_received, u64 ack_eliciting_in_flight) {
  return ack_received && ack_eliciting_in_flight == 0;
}
