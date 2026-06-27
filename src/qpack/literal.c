#include "qpack/literal.h"
#include "qpack/integer.h"
#include "qpack/string.h"
#include "util/bytes.h"

/* RFC 9204 4.5.4 first-byte bits. */
#define QPACK_NAMREF 0x40
#define QPACK_NAMREF_N 0x20
#define QPACK_NAMREF_T 0x10
/* RFC 9204 4.5.6 first-byte bits. */
#define QPACK_LITNAME 0x20
#define QPACK_LITNAME_N 0x10
#define QPACK_LITNAME_H 0x08

/* off + w, or 0 if either is 0 (an empty field means failure). */
static usz join(usz off, usz w) { return (off && w) ? off + w : 0; }

/* A first byte's flag bit as a 0/1 int. */
static int flag(u8 b, u8 mask) { return (b & mask) ? 1 : 0; }

/* mask if set, else 0: a flag selected into the first byte's high bits. */
static u8 bit(int set, u8 mask) { return set ? mask : 0; }

/* After the header (off bytes), decode the trailing value string into val.
 * Returns total bytes, or 0 if the header failed or the value did not fit. */
static usz decode_value(const u8 *buf, usz n, usz off, u8 *val, usz vcap,
                        usz *vlen)
{
    usz w = off ? quic_qpack_string_decode(buf + off, n - off, val, vcap, vlen)
                : 0;
    return join(off, w);
}

/* High bits of the name-reference first byte for the given flags. */
static u8 namref_prefix(int is_static, int never)
{
    return QPACK_NAMREF | bit(never, QPACK_NAMREF_N)
         | bit(is_static, QPACK_NAMREF_T);
}

usz quic_qpack_literal_namref_encode(u8 *buf, usz cap, u64 index, int is_static,
                                     int never, const u8 *value, usz vlen)
{
    usz off = quic_qpack_int_encode(buf, cap, 4, namref_prefix(is_static, never),
                                    index);
    usz w = off ? quic_qpack_string_encode(buf + off, cap - off, value, vlen) : 0;
    return join(off, w);
}

/* RFC 9204 4.5.4: bit 6 set marks a name-reference field line. */
static int is_namref(const u8 *buf, usz n)
{
    return n != 0 && (buf[0] & 0xc0) == QPACK_NAMREF;
}

usz quic_qpack_literal_namref_decode(const u8 *buf, usz n, u64 *index,
                                     int *is_static, int *never, u8 *val,
                                     usz vcap, usz *vlen)
{
    usz off;
    if (!is_namref(buf, n)) return 0;
    *never = flag(buf[0], QPACK_NAMREF_N);
    *is_static = flag(buf[0], QPACK_NAMREF_T);
    off = quic_qpack_int_decode(buf, n, 4, index);
    return decode_value(buf, n, off, val, vcap, vlen);
}

/* Encode the 4.5.6 name: 3-bit prefixed length (H=0) then nlen octets. */
static usz litname_name_encode(u8 *buf, usz cap, int never, const u8 *name,
                               usz nlen)
{
    u8 hi = QPACK_LITNAME | bit(never, QPACK_LITNAME_N);
    usz off = quic_qpack_int_encode(buf, cap, 3, hi, nlen);
    if (off == 0) return 0;
    if (!quic_put_bytes(buf, cap, &off, name, nlen)) return 0;
    return off;
}

usz quic_qpack_literal_name_encode(u8 *buf, usz cap, int never, const u8 *name,
                                   usz nlen, const u8 *value, usz vlen)
{
    usz off = litname_name_encode(buf, cap, never, name, nlen);
    usz w = off ? quic_qpack_string_encode(buf + off, cap - off, value, vlen) : 0;
    return join(off, w);
}

/* RFC 9204 4.5.6: top three bits 001, and H (name Huffman) must be clear. */
static int is_litname(const u8 *buf, usz n)
{
    return n != 0 && (buf[0] & 0xe0) == QPACK_LITNAME
        && (buf[0] & QPACK_LITNAME_H) == 0;
}

/* Copy len name octets at *off into nm, bounded by ncap. Returns 1 ok, 0. */
static int take_name(const u8 *buf, usz n, usz *off, u8 *nm, usz ncap, u64 len)
{
    if (len > ncap) return 0;
    return quic_take_bytes(buf, n, off, nm, (usz)len);
}

/* Decode the 4.5.6 name into nm (ncap), length to *nlen. Returns bytes used
 * from buf, or 0 on truncation or overflow. */
static usz litname_name_decode(const u8 *buf, usz n, u8 *nm, usz ncap, usz *nlen)
{
    u64 len;
    usz off = quic_qpack_int_decode(buf, n, 3, &len);
    if (off == 0) return 0;
    if (!take_name(buf, n, &off, nm, ncap, len)) return 0;
    *nlen = (usz)len;
    return off;
}

usz quic_qpack_literal_name_decode(const u8 *buf, usz n, int *never, u8 *nm,
                                   usz ncap, usz *nlen, u8 *val, usz vcap,
                                   usz *vlen)
{
    usz off;
    if (!is_litname(buf, n)) return 0;
    *never = flag(buf[0], QPACK_LITNAME_N);
    off = litname_name_decode(buf, n, nm, ncap, nlen);
    return decode_value(buf, n, off, val, vcap, vlen);
}
