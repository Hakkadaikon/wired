#ifndef QUIC_RECOVERY_RTTVALID_H
#define QUIC_RECOVERY_RTTVALID_H

#include "sys/syscall.h"

/* RFC 9002 5.1: conditions for generating an RTT sample. */

/* An RTT sample is taken only when the largest acked is newly acked and the
 * packet was ack-eliciting. */
int quic_rtt_sample_valid(int largest_newly_acked, int was_ack_eliciting);

/* latest_rtt = now - sent_time; clamps to 0 on underflow (now < sent_time). */
u64 quic_rtt_sample_time(u64 now, u64 sent_time);

#endif
