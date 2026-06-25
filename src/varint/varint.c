#include "varint/varint.h"

/* Length class: 0->1B, 1->2B, 2->4B, 3->8B. Prefix bits = class << 6. */

usz quic_varint_len(u64 v)
{
    /* index by how many of the 4 thresholds v exceeds */
    static const u64 max[4] = {0x3F, 0x3FFF, 0x3FFFFFFF, QUIC_VARINT_MAX};
    static const usz len[5] = {1, 2, 4, 8, 0};
    usz i = 0;
    while (i < 4 && v > max[i]) i++;
    return len[i];
}

/* Write n bytes of v big-endian into buf, OR the 2-bit prefix into buf[0]. */
static void put_be(u8 *buf, u64 v, usz n, u8 prefix)
{
    usz i = n;
    while (i-- > 0) {
        buf[i] = (u8)(v & 0xFF);
        v >>= 8;
    }
    buf[0] |= prefix;
}

usz quic_varint_encode(u8 *buf, u64 v)
{
    usz n = quic_varint_len(v);
    static const u8 prefix[9] = {0, 0x00, 0x40, 0, 0x80, 0, 0, 0, 0xC0};
    if (n == 0) return 0;
    put_be(buf, v, n, prefix[n]);
    return n;
}

/* Read n big-endian bytes (first masked of its prefix) into *out. */
static u64 get_be(const u8 *buf, usz n)
{
    u64 v = buf[0] & 0x3F;
    for (usz i = 1; i < n; i++)
        v = (v << 8) | buf[i];
    return v;
}

usz quic_varint_decode(const u8 *buf, usz n, u64 *out)
{
    static const usz len[4] = {1, 2, 4, 8};
    usz need;
    if (n == 0) return 0;
    need = len[buf[0] >> 6];
    if (n < need) return 0;
    *out = get_be(buf, need);
    return need;
}
