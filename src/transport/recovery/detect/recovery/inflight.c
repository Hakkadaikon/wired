#include "transport/recovery/detect/recovery/inflight.h"

int quic_pkt_ack_eliciting(int has_non_ack_frame) {
  return has_non_ack_frame ? 1 : 0;
}

int quic_pkt_in_flight(int ack_eliciting, int has_padding) {
  return (ack_eliciting || has_padding) ? 1 : 0;
}

u64 quic_pkt_counts_bytes(int in_flight, u64 size) {
  return in_flight ? size : 0;
}
