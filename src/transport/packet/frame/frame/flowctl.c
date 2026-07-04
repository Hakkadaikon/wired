#include "transport/packet/frame/frame/flowctl.h"

#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"

/* Append a varint, returning 0 to halt a put chain on overflow. */
static int put_at(quic_obuf* o, u64 v) {
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, v);
}

/* One-varint frame body (MAX_DATA, DATA_BLOCKED): type then value. */
static usz put_one_varint_frame(quic_obuf* o, u64 type, u64 value) {
  if (!put_at(o, type)) return 0;
  if (!put_at(o, value)) return 0;
  return o->len;
}

/* Decode a one-varint frame, skipping the type byte at buf[0]. */
static usz get_one_varint_frame(const u8* buf, usz n, u64* value) {
  usz off = 1; /* type byte */
  if (!quic_varint_take(quic_span_of(buf, n), &off, value)) return 0;
  return off;
}

/* Two-varint frame body (MAX_STREAM_DATA, STREAM_DATA_BLOCKED): the
 * one-varint frame (type, stream_id) followed by the value. */
static usz put_two_varint_frame(
    quic_obuf* o, u64 type, const quic_stream_data_frame* f) {
  if (put_one_varint_frame(o, type, f->stream_id) == 0) return 0;
  if (!put_at(o, f->value)) return 0;
  return o->len;
}

/* Decode a two-varint frame: stream_id then value. */
static usz get_two_varint_frame(
    const u8* buf, usz n, quic_stream_data_frame* f) {
  usz off = get_one_varint_frame(buf, n, &f->stream_id);
  if (off == 0) return 0;
  if (!quic_varint_take(quic_span_of(buf, n), &off, &f->value)) return 0;
  return off;
}

usz quic_max_data_encode(u8* buf, usz cap, const quic_data_frame* f) {
  quic_obuf o = quic_obuf_of(buf, cap);
  return put_one_varint_frame(&o, QUIC_FRAME_MAX_DATA, f->value);
}

usz quic_max_data_decode(const u8* buf, usz n, quic_data_frame* f) {
  return get_one_varint_frame(buf, n, &f->value);
}

usz quic_data_blocked_encode(u8* buf, usz cap, const quic_data_frame* f) {
  quic_obuf o = quic_obuf_of(buf, cap);
  return put_one_varint_frame(&o, QUIC_FRAME_DATA_BLOCKED, f->value);
}

usz quic_data_blocked_decode(const u8* buf, usz n, quic_data_frame* f) {
  return get_one_varint_frame(buf, n, &f->value);
}

usz quic_max_stream_data_encode(
    u8* buf, usz cap, const quic_stream_data_frame* f) {
  quic_obuf o = quic_obuf_of(buf, cap);
  return put_two_varint_frame(&o, QUIC_FRAME_MAX_STREAM_DATA, f);
}

usz quic_max_stream_data_decode(
    const u8* buf, usz n, quic_stream_data_frame* f) {
  return get_two_varint_frame(buf, n, f);
}

usz quic_stream_data_blocked_encode(
    u8* buf, usz cap, const quic_stream_data_frame* f) {
  quic_obuf o = quic_obuf_of(buf, cap);
  return put_two_varint_frame(&o, QUIC_FRAME_STREAM_DATA_BLOCKED, f);
}

usz quic_stream_data_blocked_decode(
    const u8* buf, usz n, quic_stream_data_frame* f) {
  return get_two_varint_frame(buf, n, f);
}

/* Direction bit (uni) selects the odd-numbered type of a bidi/uni pair. */
static u64 streams_type(u64 bidi_type, int uni) {
  return bidi_type + (uni ? 1 : 0);
}

usz quic_max_streams_encode(u8* buf, usz cap, const quic_streams_frame* f) {
  quic_obuf o    = quic_obuf_of(buf, cap);
  u64       type = streams_type(QUIC_FRAME_MAX_STREAMS_BIDI, f->uni);
  return put_one_varint_frame(&o, type, f->max_streams);
}

usz quic_max_streams_decode(const u8* buf, usz n, quic_streams_frame* f) {
  f->uni = buf[0] & 1;
  return get_one_varint_frame(buf, n, &f->max_streams);
}

usz quic_streams_blocked_encode(u8* buf, usz cap, const quic_streams_frame* f) {
  quic_obuf o    = quic_obuf_of(buf, cap);
  u64       type = streams_type(QUIC_FRAME_STREAMS_BLOCKED_BIDI, f->uni);
  return put_one_varint_frame(&o, type, f->max_streams);
}

usz quic_streams_blocked_decode(const u8* buf, usz n, quic_streams_frame* f) {
  f->uni = buf[0] & 1;
  return get_one_varint_frame(buf, n, &f->max_streams);
}
