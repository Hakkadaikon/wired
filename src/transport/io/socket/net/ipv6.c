#include "transport/io/socket/net/ipv6.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

usz ipv6_build(u8 out[IPV6_HDR], const ipv6_head* h) {
  bytes_memset(out, 0, 8);
  out[0] = 0x60; /* version 6, traffic class and flow label 0 */
  be_put_be16(out + 4, h->payload_len);
  out[6] = h->next;
  out[7] = 64; /* Hop Limit */
  bytes_memcpy(out + 8, h->src, 16);
  bytes_memcpy(out + 24, h->dst, 16);
  return IPV6_HDR;
}
