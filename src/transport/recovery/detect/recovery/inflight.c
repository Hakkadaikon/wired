#include "transport/recovery/detect/recovery/inflight.h"

int pkt_ack_eliciting(int has_non_ack_frame) {
  return has_non_ack_frame ? 1 : 0;
}

int pkt_in_flight(int ack_eliciting, int has_padding) {
  return (ack_eliciting || has_padding) ? 1 : 0;
}

u64 pkt_counts_bytes(int in_flight, u64 size) { return in_flight ? size : 0; }
