#include "app/http3/core/h3conn/request.h"

#include "app/http3/request/h3req/reqbuild.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9114 4.1 / RFC 9000 19.8 */
int quic_h3conn_send_request(
    u64 stream_id, const quic_h3conn_req_in* in, quic_obuf* out) {
  u8        h3[1500];
  quic_obuf h3ob = quic_obuf_of(h3, sizeof(h3));
  if (!quic_h3req_build(in->qpack_headers, in->body, &h3ob)) return 0;
  {
    quic_stream_frame f = {stream_id, 0, h3ob.len, h3, 1};
    if (!quic_appdata_stream_frame(&f, out)) return 0;
    return 1;
  }
}
