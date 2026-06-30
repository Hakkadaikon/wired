#include "app/http3/request/h3cancel/cancel.h"

#include "app/http3/core/h3/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"

/* RFC 9114 4.1.1 / 8.1: reset the request stream's sending part. */
static usz put_reset(u8 *out, usz cap, u64 stream_id, u64 final_size) {
  quic_reset_stream_frame rs;
  rs.stream_id  = stream_id;
  rs.error_code = QUIC_H3_REQUEST_CANCELLED;
  rs.final_size = final_size;
  return quic_reset_stream_encode(out, cap, &rs);
}

/* RFC 9114 4.1.1 / 8.1: ask the peer to stop sending the response. */
static usz put_stop(u8 *out, usz cap, u64 stream_id) {
  quic_stop_sending_frame ss;
  ss.stream_id  = stream_id;
  ss.error_code = QUIC_H3_REQUEST_CANCELLED;
  return quic_stop_sending_encode(out, cap, &ss);
}

int quic_h3cancel_request(
    u64 stream_id, u64 final_size, u8 *out, usz cap, usz *len) {
  usz rn = put_reset(out, cap, stream_id, final_size);
  if (!rn) return 0;
  usz sn = put_stop(out + rn, cap - rn, stream_id);
  if (!sn) return 0;
  *len = rn + sn;
  return 1;
}
