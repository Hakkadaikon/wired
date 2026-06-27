#include "datagram/datagram.h"
#include "varint/varint.h"
#include "util/bytes.h"

/* Type 0x31 carries an explicit length varint; 0x30 does not. */
static u8 datagram_type(int with_len)
{
    return with_len ? QUIC_FRAME_DATAGRAM_LEN : QUIC_FRAME_DATAGRAM;
}

/* Write the type and, for 0x31, the length varint. Returns 1 ok, 0. */
static int put_datagram_head(u8 *buf, usz cap, usz *off,
                             const quic_datagram_frame *f, int with_len)
{
    if (!quic_varint_put(buf, cap, off, datagram_type(with_len))) return 0;
    if (!with_len) return 1;
    return quic_varint_put(buf, cap, off, f->length);
}

usz quic_datagram_encode(u8 *buf, usz cap, const quic_datagram_frame *f,
                         int with_len)
{
    usz off = 0;
    if (!put_datagram_head(buf, cap, &off, f, with_len)) return 0;
    if (!quic_put_bytes(buf, cap, &off, f->data, (usz)f->length)) return 0;
    return off;
}

/* For 0x30 the data is the remaining buffer; point f->data at buf+off. */
static usz decode_no_len(const u8 *buf, usz n, usz off, quic_datagram_frame *f)
{
    f->length = n - off;
    f->data = buf + off;
    return n;
}

/* For 0x31 read the length varint then a view of that many bytes. */
static usz decode_with_len(const u8 *buf, usz n, usz off,
                           quic_datagram_frame *f)
{
    if (!quic_varint_take(buf, n, &off, &f->length)) return 0;
    if (off + (usz)f->length > n) return 0;
    f->data = buf + off;
    return off + (usz)f->length;
}

usz quic_datagram_decode(const u8 *buf, usz n, quic_datagram_frame *f)
{
    if (n == 0) return 0;
    if (buf[0] == QUIC_FRAME_DATAGRAM) return decode_no_len(buf, n, 1, f);
    return decode_with_len(buf, n, 1, f);
}

int quic_datagram_allowed(u64 max_datagram_frame_size, u64 frame_len)
{
    if (max_datagram_frame_size == 0) return 0; /* peer does not support them */
    return frame_len <= max_datagram_frame_size;
}
