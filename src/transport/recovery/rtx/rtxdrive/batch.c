#include "transport/recovery/rtx/rtxdrive/batch.h"

#include "transport/recovery/rtx/rtxdrive/build.h"

/* Append one lost pn's retransmittable bytes at out->p + out->len. Returns 1
 * if the frame fit (or was skipped), 0 if it would overflow and the batch
 * must stop. */
static int batch_one(const rtxbytes* store, u64 pn, wired_obuf* out) {
  wired_obuf slice = {out->p + out->len, out->cap - out->len, 0};
  if (!rtxdrive_build(store, pn, &slice)) return 0;
  out->len += slice.len;
  return 1;
}

int rtxdrive_batch(const rtxbytes* store, lost_pns lost, wired_obuf* out) {
  out->len = 0;
  for (usz i = 0; i < lost.n; i++)
    if (!batch_one(store, lost.pns[i], out)) break;
  return 1;
}
