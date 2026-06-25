#include "frame/frame.h"
#include "varint/varint.h"

/* Append len bytes at buf+off (cap total). Returns off+len or 0 if no room. */
static usz write_bytes(u8 *buf, usz cap, usz off, const u8 *src, u64 len)
{
    if (off + (usz)len > cap) return 0;
    for (u64 i = 0; i < len; i++) buf[off + i] = src[i];
    return off + (usz)len;
}

/* Point f->data at the f->length bytes at buf+off (n total).
 * Returns off+length or 0 if the data runs past n. */
static usz read_bytes(const u8 *buf, usz n, usz off, quic_crypto_frame *f)
{
    if (off + (usz)f->length > n) return 0;
    f->data = buf + off;
    return off + (usz)f->length;
}

usz quic_frame_put_simple(u8 *buf, usz cap, u8 type)
{
    if (cap == 0) return 0;
    buf[0] = type;
    return 1;
}

/* Write type, offset, length varints at *off. Returns 1 ok, 0 on overflow. */
static int put_crypto_hdr(u8 *buf, usz cap, usz *off, const quic_crypto_frame *f)
{
    if (!quic_varint_put(buf, cap, off, QUIC_FRAME_CRYPTO)) return 0;
    if (!quic_varint_put(buf, cap, off, f->offset)) return 0;
    return quic_varint_put(buf, cap, off, f->length);
}

usz quic_frame_put_crypto(u8 *buf, usz cap, const quic_crypto_frame *f)
{
    usz off = 0;
    if (!put_crypto_hdr(buf, cap, &off, f)) return 0;
    return write_bytes(buf, cap, off, f->data, f->length);
}

/* Read offset and length varints at *off. Returns 1 ok, 0 on bad input. */
static int take_crypto_hdr(const u8 *buf, usz n, usz *off, quic_crypto_frame *f)
{
    if (!quic_varint_take(buf, n, off, &f->offset)) return 0;
    return quic_varint_take(buf, n, off, &f->length);
}

usz quic_frame_get_crypto(const u8 *buf, usz n, quic_crypto_frame *f)
{
    usz off = 1; /* type byte */
    if (!take_crypto_hdr(buf, n, &off, f)) return 0;
    return read_bytes(buf, n, off, f);
}
