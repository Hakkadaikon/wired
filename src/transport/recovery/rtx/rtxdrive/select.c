#include "transport/recovery/rtx/rtxdrive/select.h"

#include "transport/recovery/rtx/rtxbytes/rebuild.h"

int rtxdrive_select(
    const rtxbytes* store, u64 lost_pn, int* is_retransmittable) {
  wired_span frame;

  if (!rtxbytes_get(store, lost_pn, &frame)) return 0;
  *is_retransmittable = rtxbytes_retransmittable(frame.p, frame.n) == 1;
  return 1;
}
