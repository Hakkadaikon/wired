#include "transport/packet/header/shorthdr/shorthdr.h"
#include "common/bytes/util/bytes.h"

/* RFC 9000 17.3.1: 0 1 S R R K P P, reserved bits left clear. */
u8 quic_shorthdr_byte0(int spin, int key_phase, u8 pn_len)
{
    return (u8)(0x40 | ((spin & 1) << 5) | ((key_phase & 1) << 2) |
                (u8)(pn_len - 1));
}

/* True if pn_len is in range and the header fits in cap. */
static int shorthdr_ok(usz cap, u8 dcid_len, u8 pn_len)
{
    if (pn_len < 1 || pn_len > 4) return 0;
    return (usz)1 + dcid_len + pn_len <= cap;
}

/* Write pn as pn_len big-endian bytes at *off (room already checked). */
static void shdr_put_pn(u8 *out, usz *off, u64 pn, u8 pn_len)
{
    for (u8 i = 0; i < pn_len; i++)
        out[*off + i] = (u8)(pn >> ((pn_len - 1 - i) * 8));
    *off += pn_len;
}

int quic_shorthdr_build(int spin, int key_phase, const u8 *dcid, u8 dcid_len,
                        u64 pn, u8 pn_len, u8 *out, usz cap, usz *out_len)
{
    usz off = 1;
    if (!shorthdr_ok(cap, dcid_len, pn_len)) return 0;
    out[0] = quic_shorthdr_byte0(spin, key_phase, pn_len);
    quic_put_bytes(out, cap, &off, dcid, dcid_len); /* room checked above */
    shdr_put_pn(out, &off, pn, pn_len);
    *out_len = off;
    return 1;
}
