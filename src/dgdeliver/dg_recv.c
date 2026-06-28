#include "dgdeliver/dg_recv.h"
#include "datagram/datagram.h"

int quic_dgdeliver_extract(const u8 *frame, usz len, const u8 **payload, usz *payload_len)
{
    quic_datagram_frame f;
    if (quic_datagram_decode(frame, len, &f) == 0) return 0; /* RFC 9221 5 */
    *payload = f.data;
    *payload_len = (usz)f.length;
    return 1;
}
