#include "transport/packet/frame/frame/ack_range.h"

/* RFC 9000 19.3.1: First ACK Range counts back from Largest, so it must not
 * exceed it. */
int quic_ack_range_ok(u64 largest, u64 first_range)
{
    return first_range <= largest;
}

/* RFC 9000 19.3.1: the next range's high is smallest - gap - 2 and its low is
 * that minus range_len. Subtract stepwise so a large gap or length cannot
 * wrap u64 below zero. */
int quic_ack_gap_ok(u64 smallest, u64 gap, u64 range_len)
{
    if (smallest < gap + 2) return 0;
    return smallest - gap - 2 >= range_len;
}
