#include "app/http3/core/h3settings/control_open.h"

#include "app/http3/core/h3/frame.h" /* QUIC_H3_STREAM_CONTROL */
#include "common/bytes/varint/varint.h"

/* RFC 9114 6.2.1 */
int quic_h3settings_control_prefix(u8 *out, usz cap, usz *out_len) {
  usz off = 0;
  if (!quic_varint_put(quic_mspan_of(out, cap), &off, QUIC_H3_STREAM_CONTROL))
    return 0;
  *out_len = off;
  return 1;
}
