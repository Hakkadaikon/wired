#include "transport/io/socket/net/eth.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

usz quic_eth_build(u8* out, const quic_eth_head* h) {
  quic_memcpy(out, h->dst, 6);
  quic_memcpy(out + 6, h->src, 6);
  quic_put_be16(out + 12, h->ethertype);
  return QUIC_ETH_HDR;
}

int quic_eth_parse(quic_span frame, quic_eth_head* h) {
  if (frame.n < QUIC_ETH_HDR) return 0;
  quic_memcpy(h->dst, frame.p, 6);
  quic_memcpy(h->src, frame.p + 6, 6);
  h->ethertype = quic_get_be16(frame.p + 12);
  return 1;
}
