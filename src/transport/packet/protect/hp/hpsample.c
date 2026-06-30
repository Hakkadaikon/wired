#include "transport/packet/protect/hp/hpsample.h"

/* RFC 9001 5.4.2 */
usz quic_hp_sample_offset(usz pn_offset)
{
    return pn_offset + 4;
}

/* RFC 9001 5.4.2: sample is 16 bytes; it must lie within the packet. */
int quic_hp_sample_ok(usz packet_len, usz sample_offset)
{
    return sample_offset + 16 <= packet_len;
}
