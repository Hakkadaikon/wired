#include "app/datagram/dgdeliver/dg_send.h"

#include "app/datagram/datagram/datagram.h"

int quic_dgdeliver_frame(
    quic_span data, const quic_dgdeliver_opts* o, quic_obuf* out) {
  quic_datagram_frame f = {.length = (u64)data.n, .data = data.p};
  usz                 w =
      quic_datagram_encode(quic_mspan_of(out->p, out->cap), &f, o->with_length);
  if (w == 0) return 0;
  if (!quic_datagram_allowed(o->max_frame_size, (u64)w)) return 0;
  /* RFC 9221 5 */
  out->len = w;
  return 1;
}
