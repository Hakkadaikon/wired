#include "app/http3/core/h3/stream_type.h"

#include "app/http3/core/h3/frame.h"
#include "common/bytes/varint/varint.h"

int quic_h3_stream_type_parse(quic_span buf, u64 *type, usz *consumed) {
  usz off = 0;
  if (!quic_varint_take(buf.p, buf.n, &off, type)) return 0;
  *consumed = off;
  return 1;
}

int quic_h3_stream_type_is_control(u64 type) {
  return type == QUIC_H3_STREAM_CONTROL;
}

int quic_h3_stream_type_is_push(u64 type) {
  return type == QUIC_H3_STREAM_PUSH;
}

/* RFC 9114 6.2: the two QPACK stream types (encoder 0x02, decoder 0x03). */
int quic_h3_stream_type_is_qpack(u64 type) {
  return type == QUIC_H3_STREAM_QPACK_ENCODER ||
         type == QUIC_H3_STREAM_QPACK_DECODER;
}
