#include "recovery/rttvalid.h"

int quic_rtt_sample_valid(int largest_newly_acked, int was_ack_eliciting)
{
    return (largest_newly_acked && was_ack_eliciting) ? 1 : 0;
}

u64 quic_rtt_sample_time(u64 now, u64 sent_time)
{
    return now >= sent_time ? now - sent_time : 0;
}
