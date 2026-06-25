#include "frame/frame.h"
#include "varint/varint.h"

/* Append len bytes at buf+off (cap total). Returns off+len or 0 if no room. */
static usz write_bytes(u8 *buf, usz cap, usz off, const u8 *src, u64 len)
{
    if (off + (usz)len > cap) return 0;
    for (u64 i = 0; i < len; i++) buf[off + i] = src[i];
    return off + (usz)len;
}

/* Point *data at the len bytes at buf+off (n total).
 * Returns off+len or 0 if the data runs past n. */
static usz read_bytes(const u8 *buf, usz n, usz off, u64 len, const u8 **data)
{
    if (off + (usz)len > n) return 0;
    *data = buf + off;
    return off + (usz)len;
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
    return read_bytes(buf, n, off, f->length, &f->data);
}

/* STREAM type byte: base 0x08 plus OFF (when offset!=0), always LEN, FIN. */
static u8 stream_type(const quic_stream_frame *f)
{
    u8 t = QUIC_FRAME_STREAM_BASE | QUIC_STREAM_LEN;
    if (f->offset != 0) t |= QUIC_STREAM_OFF;
    if (f->fin) t |= QUIC_STREAM_FIN;
    return t;
}

/* Write the offset varint only when nonzero (OFF bit). Returns 1 ok, 0. */
static int put_opt_offset(u8 *buf, usz cap, usz *off, u64 offset)
{
    if (offset == 0) return 1;
    return quic_varint_put(buf, cap, off, offset);
}

/* Write the type and stream id varints at *off. Returns 1 ok, 0. */
static int put_stream_prefix(u8 *buf, usz cap, usz *off,
                             const quic_stream_frame *f)
{
    if (!quic_varint_put(buf, cap, off, stream_type(f))) return 0;
    return quic_varint_put(buf, cap, off, f->stream_id);
}

/* Write type, stream id, optional offset, and length varints at *off. */
static int put_stream_hdr(u8 *buf, usz cap, usz *off, const quic_stream_frame *f)
{
    if (!put_stream_prefix(buf, cap, off, f)) return 0;
    if (!put_opt_offset(buf, cap, off, f->offset)) return 0;
    return quic_varint_put(buf, cap, off, f->length);
}

usz quic_frame_put_stream(u8 *buf, usz cap, const quic_stream_frame *f)
{
    usz off = 0;
    if (!put_stream_hdr(buf, cap, &off, f)) return 0;
    return write_bytes(buf, cap, off, f->data, f->length);
}

/* Read the offset varint only when the OFF bit is set. Returns 1 ok, 0. */
static int take_opt_offset(const u8 *buf, usz n, usz *off, u8 type, u64 *offset)
{
    *offset = 0;
    if ((type & QUIC_STREAM_OFF) == 0) return 1;
    return quic_varint_take(buf, n, off, offset);
}

/* Read stream id, optional offset (when OFF set), and length at *off. */
static int take_stream_hdr(const u8 *buf, usz n, usz *off, u8 type,
                           quic_stream_frame *f)
{
    if (!quic_varint_take(buf, n, off, &f->stream_id)) return 0;
    if (!take_opt_offset(buf, n, off, type, &f->offset)) return 0;
    return quic_varint_take(buf, n, off, &f->length);
}

usz quic_frame_get_stream(const u8 *buf, usz n, quic_stream_frame *f)
{
    u8 type = buf[0];
    usz off = 1;
    f->fin = (type & QUIC_STREAM_FIN) ? 1 : 0;
    if (!take_stream_hdr(buf, n, &off, type, f)) return 0;
    return read_bytes(buf, n, off, f->length, &f->data);
}

/* Write the frame_type varint only for the transport variant. Returns 1/0. */
static int put_opt_frame_type(u8 *buf, usz cap, usz *off,
                              const quic_conn_close_frame *f)
{
    if (f->is_app) return 1;
    return quic_varint_put(buf, cap, off, f->frame_type);
}

/* Write the type byte and error code varints at *off. Returns 1 ok, 0. */
static int put_cc_prefix(u8 *buf, usz cap, usz *off,
                         const quic_conn_close_frame *f)
{
    u8 type = f->is_app ? QUIC_FRAME_CONN_CLOSE_APP : QUIC_FRAME_CONN_CLOSE_TPT;
    if (!quic_varint_put(buf, cap, off, type)) return 0;
    return quic_varint_put(buf, cap, off, f->error_code);
}

/* Write type byte, error code, optional frame_type, and reason length. */
static int put_cc_hdr(u8 *buf, usz cap, usz *off, const quic_conn_close_frame *f)
{
    if (!put_cc_prefix(buf, cap, off, f)) return 0;
    if (!put_opt_frame_type(buf, cap, off, f)) return 0;
    return quic_varint_put(buf, cap, off, f->reason_len);
}

usz quic_frame_put_conn_close(u8 *buf, usz cap, const quic_conn_close_frame *f)
{
    usz off = 0;
    if (!put_cc_hdr(buf, cap, &off, f)) return 0;
    return write_bytes(buf, cap, off, f->reason, f->reason_len);
}

/* Read the frame_type varint only for the transport variant. Returns 1/0. */
static int take_opt_frame_type(const u8 *buf, usz n, usz *off,
                               quic_conn_close_frame *f)
{
    f->frame_type = 0;
    if (f->is_app) return 1;
    return quic_varint_take(buf, n, off, &f->frame_type);
}

/* Read error code, optional frame_type, and reason length at *off. */
static int take_cc_hdr(const u8 *buf, usz n, usz *off, quic_conn_close_frame *f)
{
    if (!quic_varint_take(buf, n, off, &f->error_code)) return 0;
    if (!take_opt_frame_type(buf, n, off, f)) return 0;
    return quic_varint_take(buf, n, off, &f->reason_len);
}

usz quic_frame_get_conn_close(const u8 *buf, usz n, quic_conn_close_frame *f)
{
    usz off = 1; /* type byte */
    f->is_app = (buf[0] == QUIC_FRAME_CONN_CLOSE_APP) ? 1 : 0;
    if (!take_cc_hdr(buf, n, &off, f)) return 0;
    return read_bytes(buf, n, off, f->reason_len, &f->reason);
}
