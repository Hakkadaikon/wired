#include "transport/packet/header/packet/pad.h"

usz quic_pad_needed(usz cur_len)
{
    if (cur_len >= QUIC_MIN_INITIAL_DATAGRAM) return 0;
    return QUIC_MIN_INITIAL_DATAGRAM - cur_len;
}
