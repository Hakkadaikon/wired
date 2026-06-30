#include "transport/packet/protect/hp/hpapply.h"

/* RFC 9001 5.4.1: long header masks 4 low bits, short header masks 5. */
u8 quic_hp_protect_byte0(u8 byte0, u8 mask0, int is_long)
{
    return byte0 ^ (mask0 & (is_long ? 0x0f : 0x1f));
}

/* RFC 9001 5.4.1 */
void quic_hp_protect_pn(u8 *pn, usz pn_len, const u8 *mask)
{
    for (usz i = 0; i < pn_len; i++) pn[i] ^= mask[1 + i];
}
