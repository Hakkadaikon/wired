#include "transport/stream/data/appdata/app_recv.h"

#include "transport/packet/build/hspkt/onertt.h"

/* RFC 9001 5 / RFC 9000 19.8: open the 1-RTT packet, then decode its STREAM
 * frame into f. */
int quic_appdata_recv(
    const quic_protect_keys *k,
    const quic_appdata_pkt  *p,
    quic_stream_frame       *f) {
  quic_span payload;
  /* ponytail: this one-shot entry opens a single packet with no receive
   * history, so largest_pn is 0; full-pn recovery across truncated PNs is the
   * srvloop path's job (RFC 9000 A.3). */
  quic_hspkt_onertt_open_desc d = {p->pkt, p->dcid_len, 0};
  if (!quic_hspkt_onertt_open(k, &d, &payload)) return 0;
  if (payload.n == 0) return 0;
  return quic_frame_get_stream(payload.p, payload.n, f) != 0;
}
