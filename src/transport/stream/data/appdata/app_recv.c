#include "transport/stream/data/appdata/app_recv.h"

#include "transport/packet/build/hspkt/onertt.h"
#include "transport/packet/frame/frame/frame.h"

/* RFC 9001 5: open the 1-RTT packet, then decode its STREAM frame into f.
 * Returns 1 on success, 0 on auth failure, empty payload, or malformed frame.
 */
static int open_and_decode(
    const quic_initial_keys *app_keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      len,
    u8                       dcid_len,
    quic_stream_frame       *f) {
  quic_span payload;
  /* ponytail: this one-shot helper opens a single packet with no receive
   * history, so largest_pn is 0; full-pn recovery across truncated PNs is the
   * srvloop path's job (RFC 9000 A.3). */
  quic_protect_keys           k = {app_keys, hp};
  quic_hspkt_onertt_open_desc d = {quic_mspan_of(pkt, len), dcid_len, 0};
  if (!quic_hspkt_onertt_open(&k, &d, &payload)) return 0;
  if (payload.n == 0) return 0;
  return quic_frame_get_stream(payload.p, payload.n, f) != 0;
}

/* RFC 9001 5 / RFC 9000 19.8 */
int quic_appdata_recv(
    const quic_initial_keys *app_keys,
    const quic_aes128       *hp,
    u8                      *pkt,
    usz                      len,
    u8                       dcid_len,
    u64                     *stream_id,
    u64                     *offset,
    const u8               **data,
    usz                     *data_len,
    int                     *fin) {
  quic_stream_frame f;
  if (!open_and_decode(app_keys, hp, pkt, len, dcid_len, &f)) return 0;
  *stream_id = f.stream_id;
  *offset    = f.offset;
  *data      = f.data;
  *data_len  = f.length;
  *fin       = f.fin;
  return 1;
}
