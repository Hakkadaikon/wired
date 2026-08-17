#include "app/datagram/dgdeliver/dg_recv.h"

#include "app/datagram/datagram/datagram.h"

int dgdeliver_extract(wired_span frame, wired_span* payload) {
  datagram_frame f;
  /* RFC 9221 5 */
  if (datagram_decode(frame.p, frame.n, &f) == 0) return 0;
  *payload = wired_span_of(f.data, (usz)f.length);
  return 1;
}
