#include "transport/stream/data/appdata/app_send.h"

#include "transport/packet/build/hspkt/onertt.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9001 5: STREAM frame (RFC 9000 19.8) sealed in a 1-RTT packet. */
int quic_appdata_send(
    const quic_protect_keys* k, const quic_appdata_tx* tx, quic_obuf* out) {
  u8                frame[1500];
  quic_stream_frame f = {
      tx->stream_id, 0, tx->data.n, tx->data.p, (u8)(tx->fin ? 1 : 0)};
  quic_obuf fb = quic_obuf_of(frame, sizeof(frame));
  if (!quic_appdata_stream_frame(&f, &fb)) return 0;
  quic_hspkt_onertt_desc d = {tx->dcid, tx->pn, quic_span_of(frame, fb.len)};
  return quic_hspkt_onertt_build(k, &d, out);
}
