#include "transport/io/socket/poll/deadline.h"

u64 quic_poll_timeout_until(u64 now, u64 deadline)
{
    return deadline > now ? deadline - now : 0;
}

static u64 min_u64(u64 a, u64 b) { return a < b ? a : b; }

u64 quic_poll_min_deadline(const u64 *deadlines, usz n)
{
    if (n == 0) return 0;
    u64 min = deadlines[0];
    for (usz i = 1; i < n; i++) min = min_u64(min, deadlines[i]);
    return min;
}
