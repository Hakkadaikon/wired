#include "hp/hp.h"

void quic_hp_mask(const quic_aes128 *hp, const u8 sample[QUIC_HP_SAMPLE],
                  u8 mask[5])
{
    u8 block[QUIC_AES_BLOCK];
    quic_aes128_encrypt(hp, sample, block);
    for (usz i = 0; i < 5; i++) mask[i] = block[i];
}

void quic_hp_apply(const u8 mask[5], u8 *byte0, u8 *pn, usz pn_len,
                   u8 bits_mask)
{
    *byte0 ^= mask[0] & bits_mask;
    for (usz i = 0; i < pn_len; i++) pn[i] ^= mask[1 + i];
}
