#include "transport/packet/header/packet/ptype.h"

int quic_packet_is_long(u8 byte0)
{
    return (byte0 & 0x80) != 0; /* RFC 9000 17.2 header form bit */
}

int quic_packet_long_type(u8 byte0)
{
    if (!quic_packet_is_long(byte0)) return QUIC_PT_NONE;
    return (byte0 >> 4) & 0x3; /* RFC 9000 17.2 type bits 5-4 */
}
