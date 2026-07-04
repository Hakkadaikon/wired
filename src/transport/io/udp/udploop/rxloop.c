#include "transport/io/udp/udploop/rxloop.h"

#include "transport/packet/header/packet/coalesce.h"

usz quic_udploop_split(quic_span dgram, const quic_pktlist* out) {
  quic_coalesce_iter it;
  quic_coalesced     pkt;
  usz                n = 0;
  quic_coalesce_begin(&it, dgram.p, dgram.n);
  while (n < out->max_pkts && quic_coalesce_next(&it, &pkt)) {
    out->pkts[n]        = pkt.data;
    out->pkt_offsets[n] = (usz)(pkt.data - dgram.p);
    out->pkt_lens[n]    = pkt.len;
    n += 1;
  }
  return n;
}

usz quic_udploop_rx(i64 fd, quic_mspan buf, const quic_pktlist* out) {
  i64 r = wired_udp_recv(fd, buf); /* RFC 9000 12.2: one datagram */
  if (r <= 0) return 0;            /* EAGAIN/empty/error */
  return quic_udploop_split(quic_span_of(buf.p, (usz)r), out);
}
