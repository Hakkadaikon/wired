#include "path/prefaddr.h"

/* RFC 9000 9.6 */
int quic_prefaddr_may_migrate(int path_validated, int handshake_confirmed)
{
    return path_validated && handshake_confirmed;
}

/* RFC 9000 9.6 */
int quic_prefaddr_use_cid(int has_preferred_cid)
{
    return has_preferred_cid ? 1 : 0;
}
