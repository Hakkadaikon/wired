#include "transport/io/socket/net/ipv4.h"

#include "common/bytes/util/be.h"
#include "transport/io/socket/net/checksum.h"

#define put_be16 quic_put_be16
#define put_be32 quic_put_be32

usz quic_ipv4_build(u8 out[QUIC_IPV4_HDR], const quic_ipv4_head* h) {
  for (usz i = 0; i < QUIC_IPV4_HDR; i++) out[i] = 0;
  out[0] = 0x45; /* version 4, IHL 5 (20 bytes) */
  put_be16(out + 2, h->total_len);
  out[8] = 64; /* TTL */
  out[9] = h->proto;
  put_be32(out + 12, h->src);
  put_be32(out + 16, h->dst);
  put_be16(out + 10, quic_cksum(out, QUIC_IPV4_HDR)); /* checksum field was 0 */
  return QUIC_IPV4_HDR;
}

int quic_ipv4_check(const u8* hdr) {
  return quic_cksum(hdr, QUIC_IPV4_HDR) == 0; /* sum incl. checksum == 0 */
}
