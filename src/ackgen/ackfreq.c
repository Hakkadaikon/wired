#include "ackgen/ackfreq.h"

int quic_ackgen_due(u32 unacked_eliciting, u64 elapsed, u64 max_ack_delay)
{
    if (unacked_eliciting == 0) return 0;
    if (unacked_eliciting >= 2) return 1; /* RFC 9000 13.2.1 */
    return elapsed >= max_ack_delay;
}
