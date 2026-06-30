#ifndef QUIC_SENTMETA_ON_ACK_H
#define QUIC_SENTMETA_ON_ACK_H

#include "transport/recovery/rtx/sentmeta/record.h"

/* RFC 9002 A.2.2 / 5.1: process one acked PN. Removes it from the ring,
 * subtracts its bytes from total_in_flight, and returns the packet's
 * time_sent (for an RTT sample) plus whether it was ack-eliciting.
 * Returns 1 when the PN was tracked, 0 otherwise (outputs untouched). */
int quic_sentmeta_on_ack(
    quic_sentmeta *m,
    u64            acked_pn,
    u64           *rtt_sample_time_sent,
    int           *was_ack_eliciting);

#endif
