#include "transport/recovery/rtx/rtxdrive/build.h"

#include "transport/recovery/rtx/rtxbytes/rebuild.h"

int rtxdrive_build(const rtxbytes* store, u64 lost_pn, wired_obuf* out) {
  wired_span frame;

  if (!rtxbytes_get(store, lost_pn, &frame)) return (out->len = 0, 1);
  return rtxbytes_rebuild(frame, out);
}
