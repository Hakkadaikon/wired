#include "transport/packet/frame/frame/stream_ctl.h"

#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"

/* Write type then stream_id (two varints). Returns 1 ok, 0 on overflow. */
static int put_rs_head(wired_obuf* o, const quic_reset_stream_frame* f) {
  if (!varint_put(
          wired_mspan_of(o->p, o->cap), &o->len, QUIC_FRAME_RESET_STREAM))
    return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->stream_id);
}

/* Write error_code then final_size. Returns 1 ok, 0 on overflow. */
static int put_rs_tail(wired_obuf* o, const quic_reset_stream_frame* f) {
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->error_code))
    return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->final_size);
}

usz quic_reset_stream_encode(
    u8* buf, usz cap, const quic_reset_stream_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  if (!put_rs_head(&o, f)) return 0;
  if (!put_rs_tail(&o, f)) return 0;
  return o.len;
}

/* Read stream_id then error_code. Returns 1 ok, 0 truncated. */
static int take_rs_head(wired_span in, usz* off, quic_reset_stream_frame* f) {
  if (!varint_take(wired_span_of(in.p, in.n), off, &f->stream_id)) return 0;
  return varint_take(wired_span_of(in.p, in.n), off, &f->error_code);
}

usz quic_reset_stream_decode(const u8* buf, usz n, quic_reset_stream_frame* f) {
  wired_span in  = wired_span_of(buf, n);
  usz        off = 1; /* type byte */
  if (!take_rs_head(in, &off, f)) return 0;
  if (!varint_take(wired_span_of(buf, n), &off, &f->final_size)) return 0;
  return off;
}

/* Write type then stream_id. Returns 1 ok, 0 on overflow. */
static int put_ss_head(wired_obuf* o, const quic_stop_sending_frame* f) {
  if (!varint_put(
          wired_mspan_of(o->p, o->cap), &o->len, QUIC_FRAME_STOP_SENDING))
    return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->stream_id);
}

usz quic_stop_sending_encode(
    u8* buf, usz cap, const quic_stop_sending_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  if (!put_ss_head(&o, f)) return 0;
  if (!varint_put(wired_mspan_of(o.p, o.cap), &o.len, f->error_code)) return 0;
  return o.len;
}

usz quic_stop_sending_decode(const u8* buf, usz n, quic_stop_sending_frame* f) {
  usz off = 1; /* type byte */
  if (!varint_take(wired_span_of(buf, n), &off, &f->stream_id)) return 0;
  if (!varint_take(wired_span_of(buf, n), &off, &f->error_code)) return 0;
  return off;
}

/* draft-ietf-quic-reliable-stream-reset: reliable_size MUST be <=
 * final_size; a decode/encode violating this is a FRAME_ENCODING_ERROR. */
static int rs_at_size_ok(const quic_reset_stream_at_frame* f) {
  return f->reliable_size <= f->final_size;
}

/* Write type, stream_id, error_code. Returns 1 ok, 0 on overflow. */
static int put_rsat_head(wired_obuf* o, const quic_reset_stream_at_frame* f) {
  if (!varint_put(
          wired_mspan_of(o->p, o->cap), &o->len, QUIC_FRAME_RESET_STREAM_AT))
    return 0;
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->stream_id))
    return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->error_code);
}

/* Write final_size then reliable_size. Returns 1 ok, 0 on overflow. */
static int put_rsat_tail(wired_obuf* o, const quic_reset_stream_at_frame* f) {
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->final_size))
    return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->reliable_size);
}

/* Write all five fields. Returns 1 ok, 0 on overflow. */
static int put_rsat_body(wired_obuf* o, const quic_reset_stream_at_frame* f) {
  if (!put_rsat_head(o, f)) return 0;
  return put_rsat_tail(o, f);
}

usz quic_reset_stream_at_encode(
    u8* buf, usz cap, const quic_reset_stream_at_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  if (!rs_at_size_ok(f)) return 0;
  return put_rsat_body(&o, f) ? o.len : 0;
}

/* Read stream_id then error_code. Returns 1 ok, 0 truncated. */
static int take_rsat_head(
    wired_span in, usz* off, quic_reset_stream_at_frame* f) {
  if (!varint_take(in, off, &f->stream_id)) return 0;
  return varint_take(in, off, &f->error_code);
}

/* Read final_size then reliable_size. Returns 1 ok, 0 truncated. */
static int take_rsat_tail(
    wired_span in, usz* off, quic_reset_stream_at_frame* f) {
  if (!varint_take(in, off, &f->final_size)) return 0;
  return varint_take(in, off, &f->reliable_size);
}

/* Read all four fields after the type byte. Returns 1 ok, 0 truncated. */
static int take_rsat_body(
    wired_span in, usz* off, quic_reset_stream_at_frame* f) {
  if (!take_rsat_head(in, off, f)) return 0;
  return take_rsat_tail(in, off, f);
}

usz quic_reset_stream_at_decode(
    const u8* buf, usz n, quic_reset_stream_at_frame* f) {
  wired_span in  = wired_span_of(buf, n);
  usz        off = 1; /* type byte */
  if (!take_rsat_body(in, &off, f)) return 0;
  return rs_at_size_ok(f) ? off : 0;
}
