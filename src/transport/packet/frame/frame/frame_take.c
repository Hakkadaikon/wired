#include "transport/packet/frame/frame/frame_impl.h"

static int take_opt_offset(wired_span in, usz* off, u64* offset);
static int take_opt_length(wired_span in, usz* off, u64* length);
static int take_stream_hdr(wired_span in, usz* off, stream_frame* f);
static int take_stream_hdr_bounded(wired_span in, usz* off, stream_frame* f);
static int put_opt_frame_type(wired_obuf* o, const conn_close_frame* f);
static int put_cc_prefix(wired_obuf* o, const conn_close_frame* f);
static int put_cc_hdr(wired_obuf* o, const conn_close_frame* f);
static int take_opt_frame_type(wired_span in, usz* off, conn_close_frame* f);
static int take_cc_hdr(wired_span in, usz* off, conn_close_frame* f);

/* Read the offset varint only when the OFF bit (in the type byte at in.p[0])
 * is set. Returns 1 ok, 0. */
static int take_opt_offset(wired_span in, usz* off, u64* offset) {
  *offset = 0;
  if ((in.p[0] & STREAM_OFF) == 0) return 1;
  return varint_take(wired_span_of(in.p, in.n), off, offset);
}

/* RFC 9000 19.8: the Length field is present only when the LEN bit is set;
 * absent, the data extends to the end of the packet (the usual shape of a
 * packet's last frame -- Chrome ships its CONNECT HEADERS this way, so
 * reading a phantom Length varint here truncated every browser request). */
static int take_opt_length(wired_span in, usz* off, u64* length) {
  if ((in.p[0] & STREAM_LEN) == 0) {
    *length = in.n - *off;
    return 1;
  }
  return varint_take(wired_span_of(in.p, in.n), off, length);
}

/* Read stream id, optional offset (when OFF set), and length at *off. */
static int take_stream_hdr(wired_span in, usz* off, stream_frame* f) {
  if (!varint_take(wired_span_of(in.p, in.n), off, &f->stream_id)) return 0;
  if (!take_opt_offset(in, off, &f->offset)) return 0;
  return take_opt_length(in, off, &f->length);
}

/* RFC 9000 19.8 / 4.5: the header parsed and its final size (offset +
 * length) within 2^62-1; a larger sum is a FRAME_ENCODING_ERROR. */
static int take_stream_hdr_bounded(wired_span in, usz* off, stream_frame* f) {
  return take_stream_hdr(in, off, f) && stream_bounds_ok(f->offset, f->length);
}

usz frame_get_stream(const u8* buf, usz n, stream_frame* f) {
  wired_span in  = wired_span_of(buf, n);
  usz        off = 1; /* type byte */
  f->fin         = (buf[0] & STREAM_FIN) ? 1 : 0;
  if (!take_stream_hdr_bounded(in, &off, f)) return 0;
  f->data = buf + off;
  return frame_view_end(in, off, f->length);
}

/* Write the frame_type varint only for the transport variant. Returns 1/0. */
static int put_opt_frame_type(wired_obuf* o, const conn_close_frame* f) {
  if (f->is_app) return 1;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->frame_type);
}

/* Write the type byte and error code varints. Returns 1 ok, 0. */
static int put_cc_prefix(wired_obuf* o, const conn_close_frame* f) {
  u8 type = f->is_app ? FRAME_CONN_CLOSE_APP : FRAME_CONN_CLOSE_TPT;
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, type)) return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->error_code);
}

/* Write type byte, error code, optional frame_type, and reason length. */
static int put_cc_hdr(wired_obuf* o, const conn_close_frame* f) {
  if (!put_cc_prefix(o, f)) return 0;
  if (!put_opt_frame_type(o, f)) return 0;
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->reason_len);
}

usz frame_put_conn_close(u8* buf, usz cap, const conn_close_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  if (!put_cc_hdr(&o, f)) return 0;
  return frame_write_bytes(&o, f->reason, f->reason_len);
}

/* Read the frame_type varint only for the transport variant. Returns 1/0. */
static int take_opt_frame_type(wired_span in, usz* off, conn_close_frame* f) {
  f->frame_type = 0;
  if (f->is_app) return 1;
  return varint_take(wired_span_of(in.p, in.n), off, &f->frame_type);
}

/* Read error code, optional frame_type, and reason length at *off. */
static int take_cc_hdr(wired_span in, usz* off, conn_close_frame* f) {
  if (!varint_take(wired_span_of(in.p, in.n), off, &f->error_code)) return 0;
  if (!take_opt_frame_type(in, off, f)) return 0;
  return varint_take(wired_span_of(in.p, in.n), off, &f->reason_len);
}

usz frame_get_conn_close(const u8* buf, usz n, conn_close_frame* f) {
  wired_span in  = wired_span_of(buf, n);
  usz        off = 1; /* type byte */
  f->is_app      = (buf[0] == FRAME_CONN_CLOSE_APP) ? 1 : 0;
  if (!take_cc_hdr(in, &off, f)) return 0;
  f->reason = buf + off;
  return frame_view_end(in, off, f->reason_len);
}
