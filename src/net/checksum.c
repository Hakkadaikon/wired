#include "net/checksum.h"

/* Add big-endian 16-bit words; a trailing odd byte is padded with zero. */
u32 quic_cksum_accum(u32 sum, const u8 *data, usz len)
{
    usz i = 0;
    while (i + 1 < len) {
        sum += ((u32)data[i] << 8) | data[i + 1];
        i += 2;
    }
    if (i < len) sum += (u32)data[i] << 8; /* odd final byte, high half */
    return sum;
}

u16 quic_cksum_fold(u32 sum)
{
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16); /* end-around carry */
    return (u16)~sum;
}

u16 quic_cksum(const u8 *data, usz len)
{
    return quic_cksum_fold(quic_cksum_accum(0, data, len));
}
