#include "qpack/string.h"
#include "qpack/integer.h"
#include "util/bytes.h"

/* The Huffman flag sits in the bit above the 7-bit length prefix. */
#define QPACK_STR_HUFFMAN 0x80

usz quic_qpack_string_encode(u8 *buf, usz cap, const u8 *src, usz len)
{
    usz off = quic_qpack_int_encode(buf, cap, 7, 0, len);
    if (off == 0) return 0;
    if (!quic_put_bytes(buf, cap, &off, src, len)) return 0;
    return off;
}

/* The first byte is decodable as a raw length: present and H flag clear. */
static int is_raw(const u8 *buf, usz n)
{
    return n != 0 && (buf[0] & QPACK_STR_HUFFMAN) == 0;
}

/* Read the H flag and length header. Returns 1 ok, 0 on Huffman or
 * truncation, advancing *off past the length integer. */
static int take_header(const u8 *buf, usz n, usz *off, usz *len)
{
    u64 v;
    usz used;
    if (!is_raw(buf, n)) return 0;
    used = quic_qpack_int_decode(buf, n, 7, &v);
    if (used == 0) return 0;
    *off = used;
    *len = (usz)v;
    return 1;
}

/* Copy len octets at *off into dst, bounded by dcap. Returns 1 ok, 0. */
static int take_data(const u8 *buf, usz n, usz *off, u8 *dst, usz dcap, usz len)
{
    if (len > dcap) return 0;
    return quic_take_bytes(buf, n, off, dst, len);
}

usz quic_qpack_string_decode(const u8 *buf, usz n, u8 *dst, usz dcap,
                             usz *out_len)
{
    usz off, len;
    if (!take_header(buf, n, &off, &len)) return 0;
    if (!take_data(buf, n, &off, dst, dcap, len)) return 0;
    *out_len = len;
    return off;
}
