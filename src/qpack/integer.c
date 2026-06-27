#include "qpack/integer.h"

/* The all-ones prefix value 2^prefix_bits - 1, the threshold that triggers the
 * continuation encoding (RFC 7541 5.1). */
static u64 prefix_max(u8 prefix_bits) { return ((u64)1 << prefix_bits) - 1; }

/* Append one byte at *off, advancing it. Returns 1 ok, 0 if no room. */
static int put_byte(u8 *buf, usz cap, usz *off, u8 b)
{
    if (*off >= cap) return 0;
    buf[(*off)++] = b;
    return 1;
}

/* A continuation group needs the high bit when 7 or more bits remain. */
static int more_groups(u64 v) { return v >= 0x80; }

/* Write the trailing 7-bit continuation groups for v, all but the last
 * carrying the high bit. v is already reduced by prefix_max. Returns 1/0. */
static int put_groups(u8 *buf, usz cap, usz *off, u64 v)
{
    int ok = 1;
    while (more_groups(v)) {
        ok = put_byte(buf, cap, off, (u8)(v & 0x7f) | 0x80);
        v >>= 7;
    }
    return put_byte(buf, cap, off, (u8)v) && ok;
}

/* The value carried in the prefix byte: the value itself, or all-ones. */
static u8 prefix_byte(u64 value, u64 pmax)
{
    if (value < pmax) return (u8)value;
    return (u8)pmax;
}

/* Encode the body after the prefix byte: nothing if value fit, else groups. */
static int encode_body(u8 *buf, usz cap, usz *off, u64 value, u64 pmax)
{
    if (value < pmax) return 1;
    return put_groups(buf, cap, off, value - pmax);
}

usz quic_qpack_int_encode(u8 *buf, usz cap, u8 prefix_bits, u8 prefix_value,
                          u64 value)
{
    usz off = 0;
    u64 pmax = prefix_max(prefix_bits);
    if (!put_byte(buf, cap, &off, prefix_value | prefix_byte(value, pmax)))
        return 0;
    if (!encode_body(buf, cap, &off, value, pmax)) return 0;
    return off;
}

/* One decoded group: read a byte, fold its 7 bits in at shift m, report end. */
static int take_group(const u8 *buf, usz n, usz *off, u64 *value, u64 m, int *go)
{
    u8 b;
    if (*off >= n || m > 56) return 0;
    b = buf[(*off)++];
    *value += (u64)(b & 0x7f) << m;
    *go = (b & 0x80) != 0;
    return 1;
}

/* Accumulate the 7-bit continuation groups into *value. Returns 1 ok, 0 on
 * truncation or 64-bit overflow. */
static int take_groups(const u8 *buf, usz n, usz *off, u64 *value)
{
    int go = 1, ok = 1;
    for (u64 m = 0; go && ok; m += 7)
        ok = take_group(buf, n, off, value, m, &go);
    return ok;
}

/* Decode the body after the prefix value: done if it fit, else read groups. */
static usz decode_body(const u8 *buf, usz n, usz off, u64 *value, u64 pmax)
{
    if (*value < pmax) return off;
    if (!take_groups(buf, n, &off, value)) return 0;
    return off;
}

usz quic_qpack_int_decode(const u8 *buf, usz n, u8 prefix_bits, u64 *value)
{
    u64 pmax = prefix_max(prefix_bits);
    if (n == 0) return 0;
    *value = buf[0] & pmax;
    return decode_body(buf, n, 1, value, pmax);
}
