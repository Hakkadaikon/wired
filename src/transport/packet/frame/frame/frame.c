#include "transport/packet/frame/frame/frame_impl.h"

static int put_crypto_hdr(wired_obuf* o, const crypto_frame* f);
static int take_crypto_hdr(wired_span in, usz* off, crypto_frame* f);
static u8  stream_type(const stream_frame* f);
static int put_opt_offset(wired_obuf* o, u64 offset);
static int put_stream_prefix(wired_obuf* o, const stream_frame* f);
static int put_stream_hdr(wired_obuf* o, const stream_frame* f);

/* Append len bytes at out->len. Returns the new total or 0 if no room. */
usz frame_write_bytes(wired_obuf* out, const u8* src, u64 len) {
  if (out->len + (usz)len > out->cap) {
    return 0;
  }
  for (u64 i = 0; i < len; i++) {
    out->p[out->len + i] = src[i];
  }
  return out->len + (usz)len;
}

/* End offset of len view bytes at off, or 0 if they run past in.n. */
usz frame_view_end(wired_span in, usz off, u64 len) {
  if (off + (usz)len > in.n) {
    return 0;
  }
  return off + (usz)len;
}

usz frame_put_simple(u8* buf, usz cap, u8 type) {
  if (cap == 0) {
    return 0;
  }
  buf[0] = type;
  return 1;
}

/* Write type, offset, length varints. Returns 1 ok, 0 on overflow. */
static int put_crypto_hdr(wired_obuf* o, const crypto_frame* f) {
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, FRAME_CRYPTO)) {
    return 0;
  }
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->offset)) {
    return 0;
  }
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->length);
}

usz frame_put_crypto(u8* buf, usz cap, const crypto_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  if (!put_crypto_hdr(&o, f)) {
    return 0;
  }
  return frame_write_bytes(&o, f->data, f->length);
}

/* Read offset and length varints at *off. Returns 1 ok, 0 on bad input. */
static int take_crypto_hdr(wired_span in, usz* off, crypto_frame* f) {
  if (!varint_take(wired_span_of(in.p, in.n), off, &f->offset)) {
    return 0;
  }
  return varint_take(wired_span_of(in.p, in.n), off, &f->length);
}

usz frame_get_crypto(const u8* buf, usz n, crypto_frame* f) {
  wired_span in  = wired_span_of(buf, n);
  usz        off = 1; /* type byte */
  if (!take_crypto_hdr(in, &off, f)) {
    return 0;
  }
  f->data = buf + off;
  return frame_view_end(in, off, f->length);
}

/* STREAM type byte: base 0x08 plus OFF (when offset!=0), always LEN, FIN. */
static u8 stream_type(const stream_frame* f) {
  u8 t = FRAME_STREAM_BASE | STREAM_LEN;
  if (f->offset != 0) {
    t |= STREAM_OFF;
  }
  if (f->fin) {
    t |= STREAM_FIN;
  }
  return t;
}

/* Write the offset varint only when nonzero (OFF bit). Returns 1 ok, 0. */
static int put_opt_offset(wired_obuf* o, u64 offset) {
  if (offset == 0) {
    return 1;
  }
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, offset);
}

/* Write the type and stream id varints. Returns 1 ok, 0. */
static int put_stream_prefix(wired_obuf* o, const stream_frame* f) {
  if (!varint_put(wired_mspan_of(o->p, o->cap), &o->len, stream_type(f))) {
    return 0;
  }
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->stream_id);
}

/* Write type, stream id, optional offset, and length varints. */
static int put_stream_hdr(wired_obuf* o, const stream_frame* f) {
  if (!put_stream_prefix(o, f)) {
    return 0;
  }
  if (!put_opt_offset(o, f->offset)) {
    return 0;
  }
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, f->length);
}

usz frame_put_stream(u8* buf, usz cap, const stream_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  if (!put_stream_hdr(&o, f)) {
    return 0;
  }
  return frame_write_bytes(&o, f->data, f->length);
}
