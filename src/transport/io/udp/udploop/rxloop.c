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

usz udploop_rx(i64 fd, wired_mspan buf, const pktlist* out) {
  i64 r = wired_udp_recv(fd, buf); /* RFC 9000 12.2: one datagram */
  if (r <= 0) return 0;            /* EAGAIN/empty/error */
  return udploop_split(wired_span_of(buf.p, (usz)r), out);
}
