#include "transport/stream/data/appdata/app_send.h"

#include "transport/packet/build/hspkt/onertt.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9001 5: STREAM frame (RFC 9000 19.8) sealed in a 1-RTT packet. */
int appdata_send(const protect_keys* k, const appdata_tx* tx, wired_obuf* out) {
  u8           frame[1500];
  stream_frame f = {
      tx->stream_id, 0, tx->data.n, tx->data.p, (u8)(tx->fin ? 1 : 0)};
  wired_obuf fb = obuf_of(frame, sizeof(frame));
  if (!appdata_stream_frame(&f, &fb)) return 0;
  hspkt_onertt_desc d = {tx->dcid, tx->pn, wired_span_of(frame, fb.len), 0};
  return hspkt_onertt_build(k, &d, out);
}
