#include "transport/io/udp/udploop/txloop.h"

#include "common/bytes/util/bytes.h"

usz udploop_pack(const pktsrc* src, wired_obuf* out) {
  usz       off = 0;
  const u8* p   = src->pkts;
  for (usz i = 0; i < src->n_pkts; i++) {
    if (!bytes_put(
            wired_mspan_of(out->p, out->cap), &off,
            wired_span_of(p, src->pkt_lens[i]))) {
      return 0;
    }
    p += src->pkt_lens[i];
  }
  out->len = off;
  return off;
}
