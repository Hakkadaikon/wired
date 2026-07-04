#include "transport/recovery/rtx/rtxdrive/select.h"

#include "transport/recovery/rtx/rtxbytes/rebuild.h"

int quic_rtxdrive_select(
    const quic_rtxbytes* store, u64 lost_pn, int* is_retransmittable) {
  quic_span frame;

  if (!quic_rtxbytes_get(store, lost_pn, &frame)) return 0;
  *is_retransmittable = quic_rtxbytes_retransmittable(frame.p, frame.n) == 1;
  return 1;
}
