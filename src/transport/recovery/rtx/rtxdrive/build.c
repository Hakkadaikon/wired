#include "transport/recovery/rtx/rtxdrive/build.h"

#include "transport/recovery/rtx/rtxbytes/rebuild.h"

int quic_rtxdrive_build(
    const quic_rtxbytes* store, u64 lost_pn, quic_obuf* out) {
  quic_span frame;

  if (!quic_rtxbytes_get(store, lost_pn, &frame)) return (out->len = 0, 1);
  return quic_rtxbytes_rebuild(frame, out);
}
