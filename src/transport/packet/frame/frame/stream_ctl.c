#include "transport/packet/frame/frame/stream_ctl.h"
#include "common/bytes/varint/varint.h"

/* Write type then stream_id (two varints). Returns 1 ok, 0 on overflow. */
static int put_rs_head(u8 *buf, usz cap, usz *off,
                       const quic_reset_stream_frame *f)
{
    if (!quic_varint_put(buf, cap, off, QUIC_FRAME_RESET_STREAM)) return 0;
    return quic_varint_put(buf, cap, off, f->stream_id);
}

/* Write error_code then final_size. Returns 1 ok, 0 on overflow. */
static int put_rs_tail(u8 *buf, usz cap, usz *off,
                       const quic_reset_stream_frame *f)
{
    if (!quic_varint_put(buf, cap, off, f->error_code)) return 0;
    return quic_varint_put(buf, cap, off, f->final_size);
}

usz quic_reset_stream_encode(u8 *buf, usz cap, const quic_reset_stream_frame *f)
{
    usz off = 0;
    if (!put_rs_head(buf, cap, &off, f)) return 0;
    if (!put_rs_tail(buf, cap, &off, f)) return 0;
    return off;
}

/* Read stream_id then error_code. Returns 1 ok, 0 truncated. */
static int take_rs_head(const u8 *buf, usz n, usz *off,
                        quic_reset_stream_frame *f)
{
    if (!quic_varint_take(buf, n, off, &f->stream_id)) return 0;
    return quic_varint_take(buf, n, off, &f->error_code);
}

usz quic_reset_stream_decode(const u8 *buf, usz n, quic_reset_stream_frame *f)
{
    usz off = 1; /* type byte */
    if (!take_rs_head(buf, n, &off, f)) return 0;
    if (!quic_varint_take(buf, n, &off, &f->final_size)) return 0;
    return off;
}

/* Write type then stream_id. Returns 1 ok, 0 on overflow. */
static int put_ss_head(u8 *buf, usz cap, usz *off,
                       const quic_stop_sending_frame *f)
{
    if (!quic_varint_put(buf, cap, off, QUIC_FRAME_STOP_SENDING)) return 0;
    return quic_varint_put(buf, cap, off, f->stream_id);
}

usz quic_stop_sending_encode(u8 *buf, usz cap, const quic_stop_sending_frame *f)
{
    usz off = 0;
    if (!put_ss_head(buf, cap, &off, f)) return 0;
    if (!quic_varint_put(buf, cap, &off, f->error_code)) return 0;
    return off;
}

usz quic_stop_sending_decode(const u8 *buf, usz n, quic_stop_sending_frame *f)
{
    usz off = 1; /* type byte */
    if (!quic_varint_take(buf, n, &off, &f->stream_id)) return 0;
    if (!quic_varint_take(buf, n, &off, &f->error_code)) return 0;
    return off;
}
