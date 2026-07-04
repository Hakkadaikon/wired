#ifndef QUIC_SENTMETA_ON_ACK_H
#define QUIC_SENTMETA_ON_ACK_H

#include "transport/recovery/rtx/sentmeta/record.h"

/* An acked packet's RTT-relevant fields. */
typedef struct {
  u64 rtt_sample_time_sent;
  int was_ack_eliciting;
} quic_sentmeta_acked;

/* RFC 9002 A.2.2 / 5.1: process one acked PN. Removes it from the ring,
 * subtracts its bytes from total_in_flight, and fills out with the packet's
 * time_sent (for an RTT sample) and whether it was ack-eliciting. Returns 1
 * when the PN was tracked, 0 otherwise (*out untouched). */
int quic_sentmeta_on_ack(
    quic_sentmeta* m, u64 acked_pn, quic_sentmeta_acked* out);

#endif
