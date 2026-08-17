#include "app/http3/request/h3cancel/cancel.h"

#include "app/http3/core/h3/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"

/* RFC 9114 4.1.1 / 8.1: reset the request stream's sending part. */
static usz put_reset(wired_obuf* out, const reset_stream_frame* rs) {
  return reset_stream_encode(out->p, out->cap, rs);
}

/* RFC 9114 4.1.1 / 8.1: ask the peer to stop sending the response. */
static usz put_stop(wired_obuf* out, u64 stream_id) {
  stop_sending_frame ss;
  ss.stream_id  = stream_id;
  ss.error_code = H3_REQUEST_CANCELLED;
  return stop_sending_encode(out->p, out->cap, &ss);
}

int h3cancel_request(u64 stream_id, u64 final_size, wired_obuf* out) {
  reset_stream_frame rs = {stream_id, H3_REQUEST_CANCELLED, final_size};
  wired_obuf         ob = obuf_of(out->p, out->cap);
  usz                rn, sn;
  rn = put_reset(&ob, &rs);
  if (!rn) return 0;
  ob = obuf_of(out->p + rn, out->cap - rn);
  sn = put_stop(&ob, stream_id);
  if (!sn) return 0;
  out->len = rn + sn;
  return 1;
}
