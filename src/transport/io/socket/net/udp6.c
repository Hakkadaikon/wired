#include "transport/io/socket/net/udp6.h"

#include "common/bytes/util/be.h"
#include "transport/io/socket/net/checksum.h"
#include "transport/io/socket/net/ipv4.h"

/* RFC 8200 8.1: source, destination, upper-layer length (32-bit), three
 * zero bytes and Next Header. */
static u32 udp6_pseudo(ipv6addrs a, u32 len) {
  u8 tail[8] = {0, 0, 0, 0, 0, 0, 0, IP_PROTO_UDP};
  be_put_be32(tail, len);
  return cksum_accum(
      cksum_accum(cksum_accum(0, a.src, 16), a.dst, 16), tail, 8);
}

usz udp6_build(
    wired_obuf* out, udpports ports, ipv6addrs addrs, wired_span payload) {
  return udp4_build_pseudo(
      out, ports, payload, udp6_pseudo(addrs, (u32)(UDP_HDR + payload.n)));
}

/* A zero checksum field: never valid over IPv6. */
static int udp6_zero_sum(wired_span dgram) {
  return dgram.p[6] == 0 && dgram.p[7] == 0;
}

int udp6_check(wired_span dgram, ipv6addrs addrs) {
  if (dgram.n < UDP_HDR || udp6_zero_sum(dgram)) {
    return 0;
  }
  return udp4_sum_ok(dgram, udp6_pseudo(addrs, (u32)dgram.n));
}
