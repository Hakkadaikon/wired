#include "app/http3/core/h3conn/request.h"

#include "app/http3/request/h3req/reqbuild.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9114 4.1 / RFC 9000 19.8 */
int quic_h3conn_send_request(
    u64       stream_id,
    const u8 *qpack_headers,
    usz       h_len,
    const u8 *body,
    usz       body_len,
    u8       *out,
    usz       cap,
    usz      *out_len) {
  u8  h3[1500];
  usz h3_len = 0;
  if (!quic_h3req_build(
          qpack_headers, h_len, body, body_len, h3, sizeof(h3), &h3_len))
    return 0;
  {
    quic_stream_frame f  = {stream_id, 0, h3_len, h3, 1};
    quic_obuf         ob = quic_obuf_of(out, cap);
    if (!quic_appdata_stream_frame(&f, &ob)) return 0;
    *out_len = ob.len;
    return 1;
  }
}
