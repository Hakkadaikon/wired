#include "transport/recovery/rtx/rtxdrive/batch.h"

#include "transport/recovery/rtx/rtxdrive/build.h"

/* Append one lost pn's retransmittable bytes at out->p + out->len. Returns 1
 * if the frame fit (or was skipped), 0 if it would overflow and the batch
 * must stop. */
static int batch_one(const quic_rtxbytes* store, u64 pn, quic_obuf* out) {
  quic_obuf slice = {out->p + out->len, out->cap - out->len, 0};
  if (!quic_rtxdrive_build(store, pn, &slice)) return 0;
  out->len += slice.len;
  return 1;
}

int quic_rtxdrive_batch(
    const quic_rtxbytes* store, quic_lost_pns lost, quic_obuf* out) {
  out->len = 0;
  for (usz i = 0; i < lost.n; i++)
    if (!batch_one(store, lost.pns[i], out)) break;
  return 1;
}
