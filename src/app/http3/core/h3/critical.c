#include "app/http3/core/h3/critical.h"

#include "app/http3/core/h3/frame.h"

/* RFC 9114 6.2 */
int quic_h3_stream_is_critical(u64 stream_type) {
  return stream_type == QUIC_H3_STREAM_CONTROL ||
         stream_type == QUIC_H3_STREAM_QPACK_ENCODER ||
         stream_type == QUIC_H3_STREAM_QPACK_DECODER;
}

u64 quic_h3_critical_close_error(u64 stream_type) {
  return quic_h3_stream_is_critical(stream_type)
             ? QUIC_H3_CLOSED_CRITICAL_STREAM
             : 0;
}
