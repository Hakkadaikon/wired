#include "transport/recovery/rtx/rtxdrive/batch.h"

#include "transport/recovery/rtx/rtxdrive/build.h"

/* Append one lost pn's retransmittable bytes at out+*off. Returns 1 if the
 * frame fit (or was skipped), 0 if it would overflow and the batch must stop.
 */
static int batch_one(
    const quic_rtxbytes *store, u64 pn, u8 *out, usz cap, usz *off) {
  usz wrote;
  if (!quic_rtxdrive_build(store, pn, out + *off, cap - *off, &wrote)) return 0;
  *off += wrote;
  return 1;
}

int quic_rtxdrive_batch(
    const quic_rtxbytes *store,
    const u64           *lost_pns,
    usz                  n,
    u8                  *out,
    usz                  cap,
    usz                 *out_len) {
  usz off = 0;
  for (usz i = 0; i < n; i++)
    if (!batch_one(store, lost_pns[i], out, cap, &off)) break;
  *out_len = off;
  return 1;
}
