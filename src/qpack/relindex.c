#include "qpack/relindex.h"

/* RFC 9204 3.2.5 */
u64 quic_qpack_rel_to_abs(u64 base, u64 rel)
{
    return base - rel - 1;
}

/* RFC 9204 3.2.6 */
u64 quic_qpack_postbase_to_abs(u64 base, u64 postbase)
{
    return base + postbase;
}
