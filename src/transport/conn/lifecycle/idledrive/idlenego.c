#include "transport/conn/lifecycle/idledrive/idlenego.h"

/* Treat 0 as "no limit" (largest possible) so it never wins the min. */
static u64 idlenego_as_limit(u64 v) { return v ? v : (u64)-1; }

/* RFC 9000 10.1 */
u64 quic_idledrive_effective(u64 local_timeout, u64 peer_timeout)
{
    u64 l = idlenego_as_limit(local_timeout), p = idlenego_as_limit(peer_timeout);
    u64 m = l < p ? l : p;
    return m == (u64)-1 ? 0 : m;
}
