#include "app/datagram/dgdeliver/dg_send.h"

#include "app/datagram/datagram/datagram.h"

int dgdeliver_frame(wired_span data, const dgdeliver_opts* o, wired_obuf* out) {
  datagram_frame f = {.length = (u64)data.n, .data = data.p};
  usz w = datagram_encode(wired_mspan_of(out->p, out->cap), &f, o->with_length);
  if (w == 0) return 0;
  if (!datagram_allowed(o->max_frame_size, (u64)w)) return 0;
  /* RFC 9221 5 */
  out->len = w;
  return 1;
}
