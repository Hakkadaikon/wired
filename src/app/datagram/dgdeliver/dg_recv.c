#include "app/datagram/dgdeliver/dg_recv.h"

#include "app/datagram/datagram/datagram.h"

int quic_dgdeliver_extract(quic_span frame, quic_span *payload) {
  quic_datagram_frame f;
  /* RFC 9221 5 */
  if (quic_datagram_decode(frame.p, frame.n, &f) == 0) return 0;
  *payload = quic_span_of(f.data, (usz)f.length);
  return 1;
}
