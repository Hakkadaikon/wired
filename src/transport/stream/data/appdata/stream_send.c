#include "transport/stream/data/appdata/stream_send.h"

/* RFC 9000 19.8 */
int quic_appdata_stream_frame(const quic_stream_frame* f, quic_obuf* out) {
  usz n = quic_frame_put_stream(out->p, out->cap, f);
  if (n == 0) return 0;
  out->len = n;
  return 1;
}
