#include "datagram/zerortt_dgram.h"

/* RFC 9221 3 */
int quic_datagram_0rtt_ok(u64 remembered_max, u64 frame_size)
{
    return remembered_max != 0 && frame_size <= remembered_max;
}
