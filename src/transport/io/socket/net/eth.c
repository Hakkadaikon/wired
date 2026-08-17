#include "transport/io/socket/net/eth.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

usz eth_build(u8* out, const eth_head* h) {
  bytes_memcpy(out, h->dst, 6);
  bytes_memcpy(out + 6, h->src, 6);
  be_put_be16(out + 12, h->ethertype);
  return ETH_HDR;
}

int eth_parse(wired_span frame, eth_head* h) {
  if (frame.n < ETH_HDR) return 0;
  bytes_memcpy(h->dst, frame.p, 6);
  bytes_memcpy(h->src, frame.p + 6, 6);
  h->ethertype = be_get_be16(frame.p + 12);
  return 1;
}
