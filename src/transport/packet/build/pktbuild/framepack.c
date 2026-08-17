#include "transport/packet/build/pktbuild/framepack.h"

#include "common/bytes/util/bytes.h"

/* RFC 9000 12.4: a packet payload is a sequence of complete frames. */
int pktbuild_framepack(
    wired_obuf* out, const wired_span* frames, usz n_frames) {
  for (usz i = 0; i < n_frames; i++) {
    if (!bytes_put(
            wired_mspan_of(out->p, out->cap), &out->len,
            wired_span_of(frames[i].p, frames[i].n)))
      return 0;
  }
  return 1;
}
