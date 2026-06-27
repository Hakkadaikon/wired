#include "recovery/largestacked.h"
#include "util/num.h"

u64 quic_largest_acked_update(u64 current, u64 new_largest)
{
    return quic_u64_max(current, new_largest);
}

int quic_newly_acked(u64 prev_largest, u64 pn)
{
    return pn > prev_largest ? 1 : 0;
}
