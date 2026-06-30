#include "transport/recovery/rtx/rtxdrive/build.h"

#include "transport/recovery/rtx/rtxbytes/rebuild.h"

int quic_rtxdrive_build(
    const quic_rtxbytes *store, u64 lost_pn, u8 *out, usz cap, usz *out_len) {
  const u8 *bytes;
  usz       len;

  if (!quic_rtxbytes_get(store, lost_pn, &bytes, &len))
    return (*out_len = 0, 1);
  return quic_rtxbytes_rebuild(bytes, len, out, cap, out_len);
}
