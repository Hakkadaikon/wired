#include "h3/reuse.h"

/* RFC 9114 3.3: reuse requires a matching origin, a live connection, and a
 * compatible version. */
int quic_h3_conn_reusable(int same_origin, int conn_alive, int version_compatible)
{
    return same_origin && conn_alive && version_compatible;
}
