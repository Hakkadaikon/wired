#include "transport/packet/frame/frame/flowctl.h"

#include "common/bytes/span/span.h"
#include "common/bytes/varint/varint.h"

/* Append a varint, returning 0 to halt a put chain on overflow. */
static int put_at(wired_obuf* o, u64 v) {
  return varint_put(wired_mspan_of(o->p, o->cap), &o->len, v);
}

/* One-varint frame body (MAX_DATA, DATA_BLOCKED): type then value. */
static usz put_one_varint_frame(wired_obuf* o, u64 type, u64 value) {
  if (!put_at(o, type)) return 0;
  if (!put_at(o, value)) return 0;
  return o->len;
}

/* Decode a one-varint frame, skipping the type byte at buf[0]. */
static usz get_one_varint_frame(const u8* buf, usz n, u64* value) {
  usz off = 1; /* type byte */
  if (!varint_take(wired_span_of(buf, n), &off, value)) return 0;
  return off;
}

/* Two-varint frame body (MAX_STREAM_DATA, STREAM_DATA_BLOCKED): the
 * one-varint frame (type, stream_id) followed by the value. */
static usz put_two_varint_frame(
    wired_obuf* o, u64 type, const stream_data_frame* f) {
  if (put_one_varint_frame(o, type, f->stream_id) == 0) return 0;
  if (!put_at(o, f->value)) return 0;
  return o->len;
}

/* Decode a two-varint frame: stream_id then value. */
static usz get_two_varint_frame(const u8* buf, usz n, stream_data_frame* f) {
  usz off = get_one_varint_frame(buf, n, &f->stream_id);
  if (off == 0) return 0;
  if (!varint_take(wired_span_of(buf, n), &off, &f->value)) return 0;
  return off;
}

usz max_data_encode(u8* buf, usz cap, const data_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  return put_one_varint_frame(&o, FRAME_MAX_DATA, f->value);
}

usz max_data_decode(const u8* buf, usz n, data_frame* f) {
  return get_one_varint_frame(buf, n, &f->value);
}

usz data_blocked_encode(u8* buf, usz cap, const data_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  return put_one_varint_frame(&o, FRAME_DATA_BLOCKED, f->value);
}

usz data_blocked_decode(const u8* buf, usz n, data_frame* f) {
  return get_one_varint_frame(buf, n, &f->value);
}

usz max_stream_data_encode(u8* buf, usz cap, const stream_data_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  return put_two_varint_frame(&o, FRAME_MAX_STREAM_DATA, f);
}

usz max_stream_data_decode(const u8* buf, usz n, stream_data_frame* f) {
  return get_two_varint_frame(buf, n, f);
}

usz stream_data_blocked_encode(u8* buf, usz cap, const stream_data_frame* f) {
  wired_obuf o = obuf_of(buf, cap);
  return put_two_varint_frame(&o, FRAME_STREAM_DATA_BLOCKED, f);
}

usz stream_data_blocked_decode(const u8* buf, usz n, stream_data_frame* f) {
  return get_two_varint_frame(buf, n, f);
}

/* Direction bit (uni) selects the odd-numbered type of a bidi/uni pair. */
static u64 streams_type(u64 bidi_type, int uni) {
  return bidi_type + (uni ? 1 : 0);
}

usz max_streams_encode(u8* buf, usz cap, const streams_frame* f) {
  wired_obuf o    = obuf_of(buf, cap);
  u64        type = streams_type(FRAME_MAX_STREAMS_BIDI, f->uni);
  return put_one_varint_frame(&o, type, f->max_streams);
}

usz max_streams_decode(const u8* buf, usz n, streams_frame* f) {
  f->uni = buf[0] & 1;
  return get_one_varint_frame(buf, n, &f->max_streams);
}

usz streams_blocked_encode(u8* buf, usz cap, const streams_frame* f) {
  wired_obuf o    = obuf_of(buf, cap);
  u64        type = streams_type(FRAME_STREAMS_BLOCKED_BIDI, f->uni);
  return put_one_varint_frame(&o, type, f->max_streams);
}

usz streams_blocked_decode(const u8* buf, usz n, streams_frame* f) {
  f->uni = buf[0] & 1;
  return get_one_varint_frame(buf, n, &f->max_streams);
}
