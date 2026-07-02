#include "transport/stream/data/appdata/app_send.h"

#include "transport/packet/build/hspkt/onertt.h"
#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9001 5: STREAM frame (RFC 9000 19.8) sealed in a 1-RTT packet. */
int quic_appdata_send(
    const quic_initial_keys *app_keys,
    const quic_aes128       *hp,
    const u8                *dcid,
    u8                       dcid_len,
    u64                      pn,
    u64                      stream_id,
    const u8                *data,
    usz                      len,
    int                      fin,
    u8                      *out,
    usz                      cap,
    usz                     *out_len) {
  u8  frame[1500];
  usz flen = 0;
  if (!quic_appdata_stream_frame(
          stream_id, 0, data, len, fin, frame, sizeof(frame), &flen))
    return 0;
  quic_protect_keys      k = {app_keys, hp};
  quic_hspkt_onertt_desc d = {
      quic_span_of(dcid, dcid_len), pn, quic_span_of(frame, flen)};
  quic_obuf o = quic_obuf_of(out, cap);
  if (!quic_hspkt_onertt_build(&k, &d, &o)) return 0;
  *out_len = o.len;
  return 1;
}
