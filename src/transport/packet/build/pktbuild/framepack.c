#include "transport/packet/build/pktbuild/framepack.h"

#include "common/bytes/util/bytes.h"

/* RFC 9000 12.4: a packet payload is a sequence of complete frames. */
int quic_pktbuild_framepack(
    quic_obuf *out, const quic_span *frames, usz n_frames) {
  for (usz i = 0; i < n_frames; i++) {
    if (!quic_put_bytes(
            quic_mspan_of(out->p, out->cap), &out->len,
            quic_span_of(frames[i].p, frames[i].n)))
      return 0;
  }
  return 1;
}
