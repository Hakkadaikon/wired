#include "transport/packet/build/pktbuild/initpad.h"
#include "transport/packet/header/packet/pad.h"
#include "transport/packet/frame/frame/frame.h"

/* True when padding to 1200 is both needed and fits in cap. */
static int pad_fits(usz current_len, usz need, usz cap)
{
    return need != 0 && current_len + need <= cap;
}

usz quic_pktbuild_init_pad(u8 *datagram, usz current_len, usz cap)
{
    usz need = quic_pad_needed(current_len);
    if (!pad_fits(current_len, need, cap)) return current_len;
    /* RFC 9000 14.1: PADDING frame is a single 0x00 octet, repeated. */
    for (usz i = 0; i < need; i++) datagram[current_len + i] = QUIC_FRAME_PADDING;
    return current_len + need;
}
