#include "tparam/tparam.h"
#include "varint/varint.h"

/* id + len(=value's varint length) + value, all varints. */
usz quic_tparam_put_int(u8 *buf, usz cap, u64 id, u64 value)
{
    usz vlen = quic_varint_len(value);
    usz need = quic_varint_len(id) + 1 + vlen;
    usz off;
    if (vlen == 0 || need > cap) return 0;
    off = quic_varint_encode(buf, id);
    off += quic_varint_encode(buf + off, vlen);
    off += quic_varint_encode(buf + off, value);
    return off;
}

/* Decode a varint at buf+*off (n total), advance *off. Returns 1 ok, 0 bad. */
static int take_varint(const u8 *buf, usz n, usz *off, u64 *out)
{
    usz used = quic_varint_decode(buf + *off, n - *off, out);
    if (used == 0) return 0;
    *off += used;
    return 1;
}

/* Read the value varint and require it to span exactly vlen bytes within n. */
static int take_value(const u8 *buf, usz n, usz *off, u64 vlen, u64 *value)
{
    usz before = *off;
    if (vlen > n - *off) return 0;
    if (!take_varint(buf, before + (usz)vlen, off, value)) return 0;
    return *off - before == (usz)vlen;
}

/* Read the id and length varints, advancing *off. Returns 1 ok, 0 bad. */
static int take_id_len(const u8 *buf, usz n, usz *off, u64 *id, u64 *vlen)
{
    if (!take_varint(buf, n, off, id)) return 0;
    return take_varint(buf, n, off, vlen);
}

usz quic_tparam_get_int(const u8 *buf, usz n, u64 *id, u64 *value)
{
    usz off = 0;
    u64 vlen;
    if (!take_id_len(buf, n, &off, id, &vlen)) return 0;
    if (!take_value(buf, n, &off, vlen, value)) return 0;
    return off;
}
