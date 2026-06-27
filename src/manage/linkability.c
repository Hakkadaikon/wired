#include "manage/linkability.h"

/* RFC 9312 5.3 */
int quic_linkability_broken(u64 old_cid, u64 new_cid)
{
    return old_cid != new_cid;
}

/* RFC 9312 5.3 */
int quic_linkability_at_risk(int migrated, int cid_changed)
{
    return migrated && !cid_changed;
}
