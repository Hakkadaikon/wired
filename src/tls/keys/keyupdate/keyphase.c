#include "tls/keys/keyupdate/keyphase.h"

u8 quic_keyphase_bit(u64 generation)
{
    return (u8)(generation & 1);
}

int quic_keyphase_get(u8 byte0)
{
    return (byte0 >> 2) & 1;
}

u8 quic_keyphase_set(u8 byte0, int phase)
{
    /* RFC 9001 6: clear then set bit 0x04 from phase's low bit. */
    return (u8)((byte0 & ~QUIC_KEYPHASE_MASK) | ((phase & 1) << 2));
}
