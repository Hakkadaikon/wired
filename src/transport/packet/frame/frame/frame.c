#include "transport/packet/frame/frame/frame.h"

#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"

/* Append len bytes at out->len. Returns the new total or 0 if no room. */
static usz write_bytes(quic_obuf* out, const u8* src, u64 len) {
  if (out->len + (usz)len > out->cap) return 0;
  for (u64 i = 0; i < len; i++) out->p[out->len + i] = src[i];
  return out->len + (usz)len;
}

/* End offset of len view bytes at off, or 0 if they run past in.n. */
static usz view_end(quic_span in, usz off, u64 len) {
  if (off + (usz)len > in.n) return 0;
  return off + (usz)len;
}

usz quic_frame_put_simple(u8* buf, usz cap, u8 type) {
  if (cap == 0) return 0;
  buf[0] = type;
  return 1;
}

/* Write type, offset, length varints. Returns 1 ok, 0 on overflow. */
static int put_crypto_hdr(quic_obuf* o, const quic_crypto_frame* f) {
  if (!quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, QUIC_FRAME_CRYPTO))
    return 0;
  if (!quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->offset))
    return 0;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->length);
}

usz quic_frame_put_crypto(u8* buf, usz cap, const quic_crypto_frame* f) {
  quic_obuf o = quic_obuf_of(buf, cap);
  if (!put_crypto_hdr(&o, f)) return 0;
  return write_bytes(&o, f->data, f->length);
}

/* Read offset and length varints at *off. Returns 1 ok, 0 on bad input. */
static int take_crypto_hdr(quic_span in, usz* off, quic_crypto_frame* f) {
  if (!quic_varint_take(quic_span_of(in.p, in.n), off, &f->offset)) return 0;
  return quic_varint_take(quic_span_of(in.p, in.n), off, &f->length);
}

usz quic_frame_get_crypto(const u8* buf, usz n, quic_crypto_frame* f) {
  quic_span in  = quic_span_of(buf, n);
  usz       off = 1; /* type byte */
  if (!take_crypto_hdr(in, &off, f)) return 0;
  f->data = buf + off;
  return view_end(in, off, f->length);
}

/* STREAM type byte: base 0x08 plus OFF (when offset!=0), always LEN, FIN. */
static u8 stream_type(const quic_stream_frame* f) {
  u8 t = QUIC_FRAME_STREAM_BASE | QUIC_STREAM_LEN;
  if (f->offset != 0) t |= QUIC_STREAM_OFF;
  if (f->fin) t |= QUIC_STREAM_FIN;
  return t;
}

/* Write the offset varint only when nonzero (OFF bit). Returns 1 ok, 0. */
static int put_opt_offset(quic_obuf* o, u64 offset) {
  if (offset == 0) return 1;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, offset);
}

/* Write the type and stream id varints. Returns 1 ok, 0. */
static int put_stream_prefix(quic_obuf* o, const quic_stream_frame* f) {
  if (!quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, stream_type(f)))
    return 0;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->stream_id);
}

/* Write type, stream id, optional offset, and length varints. */
static int put_stream_hdr(quic_obuf* o, const quic_stream_frame* f) {
  if (!put_stream_prefix(o, f)) return 0;
  if (!put_opt_offset(o, f->offset)) return 0;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->length);
}

usz quic_frame_put_stream(u8* buf, usz cap, const quic_stream_frame* f) {
  quic_obuf o = quic_obuf_of(buf, cap);
  if (!put_stream_hdr(&o, f)) return 0;
  return write_bytes(&o, f->data, f->length);
}

/* Read the offset varint only when the OFF bit (in the type byte at in.p[0])
 * is set. Returns 1 ok, 0. */
static int take_opt_offset(quic_span in, usz* off, u64* offset) {
  *offset = 0;
  if ((in.p[0] & QUIC_STREAM_OFF) == 0) return 1;
  return quic_varint_take(quic_span_of(in.p, in.n), off, offset);
}

/* Read stream id, optional offset (when OFF set), and length at *off. */
static int take_stream_hdr(quic_span in, usz* off, quic_stream_frame* f) {
  if (!quic_varint_take(quic_span_of(in.p, in.n), off, &f->stream_id)) return 0;
  if (!take_opt_offset(in, off, &f->offset)) return 0;
  return quic_varint_take(quic_span_of(in.p, in.n), off, &f->length);
}

usz quic_frame_get_stream(const u8* buf, usz n, quic_stream_frame* f) {
  quic_span in  = quic_span_of(buf, n);
  usz       off = 1; /* type byte */
  f->fin        = (buf[0] & QUIC_STREAM_FIN) ? 1 : 0;
  if (!take_stream_hdr(in, &off, f)) return 0;
  f->data = buf + off;
  return view_end(in, off, f->length);
}

/* Write the frame_type varint only for the transport variant. Returns 1/0. */
static int put_opt_frame_type(quic_obuf* o, const quic_conn_close_frame* f) {
  if (f->is_app) return 1;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->frame_type);
}

/* Write the type byte and error code varints. Returns 1 ok, 0. */
static int put_cc_prefix(quic_obuf* o, const quic_conn_close_frame* f) {
  u8 type = f->is_app ? QUIC_FRAME_CONN_CLOSE_APP : QUIC_FRAME_CONN_CLOSE_TPT;
  if (!quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, type)) return 0;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->error_code);
}

/* Write type byte, error code, optional frame_type, and reason length. */
static int put_cc_hdr(quic_obuf* o, const quic_conn_close_frame* f) {
  if (!put_cc_prefix(o, f)) return 0;
  if (!put_opt_frame_type(o, f)) return 0;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->reason_len);
}

usz quic_frame_put_conn_close(
    u8* buf, usz cap, const quic_conn_close_frame* f) {
  quic_obuf o = quic_obuf_of(buf, cap);
  if (!put_cc_hdr(&o, f)) return 0;
  return write_bytes(&o, f->reason, f->reason_len);
}

/* Read the frame_type varint only for the transport variant. Returns 1/0. */
static int take_opt_frame_type(
    quic_span in, usz* off, quic_conn_close_frame* f) {
  f->frame_type = 0;
  if (f->is_app) return 1;
  return quic_varint_take(quic_span_of(in.p, in.n), off, &f->frame_type);
}

/* Read error code, optional frame_type, and reason length at *off. */
static int take_cc_hdr(quic_span in, usz* off, quic_conn_close_frame* f) {
  if (!quic_varint_take(quic_span_of(in.p, in.n), off, &f->error_code))
    return 0;
  if (!take_opt_frame_type(in, off, f)) return 0;
  return quic_varint_take(quic_span_of(in.p, in.n), off, &f->reason_len);
}

usz quic_frame_get_conn_close(const u8* buf, usz n, quic_conn_close_frame* f) {
  quic_span in  = quic_span_of(buf, n);
  usz       off = 1; /* type byte */
  f->is_app     = (buf[0] == QUIC_FRAME_CONN_CLOSE_APP) ? 1 : 0;
  if (!take_cc_hdr(in, &off, f)) return 0;
  f->reason = buf + off;
  return view_end(in, off, f->reason_len);
}
