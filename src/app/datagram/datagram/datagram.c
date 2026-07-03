#include "app/datagram/datagram/datagram.h"

#include "common/bytes/util/bytes.h"
#include "common/bytes/varint/varint.h"

/* Type 0x31 carries an explicit length varint; 0x30 does not. */
static u8 datagram_type(int with_len) {
  return with_len ? QUIC_FRAME_DATAGRAM_LEN : QUIC_FRAME_DATAGRAM;
}

/* Write the type and, for 0x31, the length varint. Returns 1 ok, 0. */
static int put_datagram_head(
    quic_obuf *o, const quic_datagram_frame *f, int with_len) {
  if (!quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, datagram_type(with_len)))
    return 0;
  if (!with_len) return 1;
  return quic_varint_put(quic_mspan_of(o->p, o->cap), &o->len, f->length);
}

usz quic_datagram_encode(
    quic_mspan buf, const quic_datagram_frame *f, int with_len) {
  quic_obuf o = quic_obuf_of(buf.p, buf.n);
  if (!put_datagram_head(&o, f, with_len)) return 0;
  if (!quic_put_bytes(quic_mspan_of(o.p, o.cap), &o.len, quic_span_of(f->data, (usz)f->length))) return 0;
  return o.len;
}

/* For 0x30 the data is the rest of the buffer past the type byte. */
static usz decode_no_len(const u8 *buf, usz n, quic_datagram_frame *f) {
  f->length = n - 1;
  f->data   = buf + 1;
  return n;
}

/* For 0x31 read the length varint then a view of that many bytes. */
static usz decode_with_len(const u8 *buf, usz n, quic_datagram_frame *f) {
  usz off = 1;
  if (!quic_varint_take(quic_span_of(buf, n), &off, &f->length)) return 0;
  if (off + (usz)f->length > n) return 0;
  f->data = buf + off;
  return off + (usz)f->length;
}

usz quic_datagram_decode(const u8 *buf, usz n, quic_datagram_frame *f) {
  if (n == 0) return 0;
  if (buf[0] == QUIC_FRAME_DATAGRAM) return decode_no_len(buf, n, f);
  return decode_with_len(buf, n, f);
}

int quic_datagram_allowed(u64 max_datagram_frame_size, u64 frame_len) {
  if (max_datagram_frame_size == 0) return 0; /* peer does not support them */
  return frame_len <= max_datagram_frame_size;
}
