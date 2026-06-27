#include "packet/pnlen.h"

/* RFC 9000 Appendix A.2: num_unacked = pn - largest_acked; the smallest b in
 * 1..4 with 2*num_unacked < 2^(8b) (i.e. min_bits = floor(log2)+1, rounded up
 * to whole bytes). largest_acked ~0 (none acked) yields b=1. */
usz quic_pnlen_needed(u64 pn, u64 largest_acked)
{
    u64 num_unacked = pn - largest_acked;
    usz b = 1;
    while (b < 4 && (num_unacked >> (8 * b - 1)) != 0) b++;
    return b;
}
