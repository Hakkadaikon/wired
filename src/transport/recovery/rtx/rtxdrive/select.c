#include "transport/recovery/rtx/rtxdrive/select.h"

#include "transport/recovery/rtx/rtxbytes/rebuild.h"

int quic_rtxdrive_select(
    const quic_rtxbytes *store, u64 lost_pn, int *is_retransmittable) {
  const u8 *bytes;
  usz       len;

  if (!quic_rtxbytes_get(store, lost_pn, &bytes, &len)) return 0;
  *is_retransmittable = quic_rtxbytes_retransmittable(bytes, len) == 1;
  return 1;
}
