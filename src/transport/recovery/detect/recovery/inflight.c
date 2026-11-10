#include "transport/recovery/detect/recovery/inflight.h"

int pkt_in_flight(int ack_eliciting, int has_padding) {
  return (ack_eliciting || has_padding) ? 1 : 0;
}
