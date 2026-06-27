#include "cc/ccphase.h"

int quic_cc_in_slow_start(u64 cwnd, u64 ssthresh)
{
    return cwnd < ssthresh;
}

u64 quic_cc_slow_start_inc(u64 acked)
{
    return acked;
}

u64 quic_cc_avoid_inc(u64 max_datagram, u64 acked, u64 cwnd)
{
    return max_datagram * acked / cwnd;
}
