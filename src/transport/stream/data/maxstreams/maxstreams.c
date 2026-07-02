#include "transport/stream/data/maxstreams/maxstreams.h"

#include "transport/packet/frame/frame/flowctl.h"

/* RFC 9000 19.11 */
int quic_maxstreams_frame(int uni, u64 max, quic_obuf *out) {
  quic_streams_frame f;
  usz                n;
  f.uni         = uni ? 1 : 0;
  f.max_streams = max;
  n             = quic_max_streams_encode(out->p, out->cap, &f);
  if (n == 0) return 0;
  out->len = n;
  return 1;
}

/* RFC 9000 19.11 */
int quic_maxstreams_parse(quic_span in, int *uni, u64 *max) {
  quic_streams_frame f;
  if (quic_max_streams_decode(in.p, in.n, &f) == 0) return 0;
  *uni = f.uni;
  *max = f.max_streams;
  return 1;
}

/* RFC 9000 4.6 */
int quic_maxstreams_can_open(u64 opened, u64 max_streams) {
  return opened < max_streams;
}
