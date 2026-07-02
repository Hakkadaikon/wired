#include "transport/recovery/rtx/rtxbytes/collect.h"

#include "transport/recovery/rtx/rtxbytes/rebuild.h"

/* RFC 9002 13.3: rebuild one held pn's frame into out (appending at
 * out->len). Returns 1 on success (including a skipped pn or a
 * non-retransmittable frame), 0 if out has no room. */
static int collect_one(const quic_rtxbytes *st, u64 pn, quic_obuf *out) {
  quic_span frame;
  quic_obuf slice;

  if (!quic_rtxbytes_get(st, pn, &frame)) return 1;
  slice = (quic_obuf){out->p + out->len, out->cap - out->len, 0};
  if (!quic_rtxbytes_rebuild(frame, &slice)) return 0;
  out->len += slice.len;
  return 1;
}

int quic_rtxbytes_collect(
    const quic_rtxbytes *st, quic_lost_pns lost, quic_obuf *out) {
  out->len = 0;
  for (usz i = 0; i < lost.n; i++) {
    if (!collect_one(st, lost.pns[i], out)) return 0;
  }
  return 1;
}
