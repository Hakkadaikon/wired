#include "transport/io/socket/net/ipv4.h"

#include "common/bytes/util/be.h"
#include "transport/io/socket/net/checksum.h"

#define put_be16 be_put_be16
#define put_be32 be_put_be32

usz ipv4_build(u8 out[IPV4_HDR], const ipv4_head* h) {
  for (usz i = 0; i < IPV4_HDR; i++) out[i] = 0;
  out[0] = 0x45; /* version 4, IHL 5 (20 bytes) */
  put_be16(out + 2, h->total_len);
  out[8] = 64; /* TTL */
  out[9] = h->proto;
  put_be32(out + 12, h->src);
  put_be32(out + 16, h->dst);
  put_be16(out + 10, cksum(out, IPV4_HDR)); /* checksum field was 0 */
  return IPV4_HDR;
}

int ipv4_check(const u8* hdr) {
  return cksum(hdr, IPV4_HDR) == 0; /* sum incl. checksum == 0 */
}
