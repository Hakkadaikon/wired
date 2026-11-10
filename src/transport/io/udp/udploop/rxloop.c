#include "transport/io/udp/udploop/rxloop.h"

#include "transport/packet/header/packet/coalesce.h"

usz udploop_split(wired_span dgram, const pktlist* out) {
  coalesce_iter it;
  coalesced     pkt;
  usz           n = 0;
  coalesce_begin(&it, dgram.p, dgram.n);
  while (n < out->max_pkts && coalesce_next(&it, &pkt)) {
    out->pkts[n]        = pkt.data;
    out->pkt_offsets[n] = (usz)(pkt.data - dgram.p);
    out->pkt_lens[n]    = pkt.len;
    n += 1;
  }
  return n;
}
