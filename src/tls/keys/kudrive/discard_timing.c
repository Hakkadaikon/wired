#include "tls/keys/kudrive/discard_timing.h"

/* RFC 9001 6.5: the retention period is three PTOs measured from a reference
 * instant. true once now reaches mark + 3*PTO. */
static int retention_elapsed(u64 now, u64 mark, u64 pto)
{
    return now >= mark + 3 * pto;
}

int quic_kudrive_can_discard_old(u64 now, u64 update_completed_at, u64 pto)
{
    return retention_elapsed(now, update_completed_at, pto);
}

int quic_kudrive_can_initiate_again(u64 now, u64 last_update_at, u64 pto)
{
    return retention_elapsed(now, last_update_at, pto);
}
