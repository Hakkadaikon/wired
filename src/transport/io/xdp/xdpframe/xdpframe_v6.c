#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "transport/io/socket/net/udp6.h"
#include "transport/io/xdp/xdpframe/xdpframe_impl.h"

/* RFC 8200 3/4: version 6, Next Header UDP (so no extension header), and
 * a Hop Limit that is not zero. */
static int xdpf_ip6_ok(const u8* ip) {
  return (ip[0] & 0xf0) == 0x60 && ip[6] == IP_PROTO_UDP && ip[7] != 0;
}

/* The Payload Length (read once rem holds the header) covers a UDP header
 * and fits within the rem bytes from ip to the frame end (anything past it
 * is ethernet padding). */
static int xdpf_ip6_plen_ok(const u8* ip, usz rem) {
  usz plen = be_get_be16(ip + 4);
  return plen >= UDP_HDR && plen <= rem - IPV6_HDR;
}

static int xdpf_ip6_len_ok(const u8* ip, usz rem) {
  return rem >= IPV6_HDR + UDP_HDR && xdpf_ip6_plen_ok(ip, rem);
}

/* RFC 8200 8.1: the checksum is present and verifies over the IPv6
 * pseudo-header, or the caller opted out (XDPFRAME_SKIP_UDP_CSUM). */
static int xdpf_udp6_csum_ok(const u8* ip, usz plen, u32 flags) {
  ipv6addrs a = {ip + 8, ip + 24};
  return (flags & XDPFRAME_SKIP_UDP_CSUM) ||
         udp6_check(wired_span_of(ip + IPV6_HDR, plen), a);
}

/* The peer's address and port as a native IPv6 sockaddr. */
static void xdpf_sa6(sockaddr* sa, const u8* addr, const u8* port_be) {
  wired_udp_addr(sa, 0, (const u8[4]){0, 0, 0, 0});
  bytes_memcpy(sa->addr, addr, 16);
  bytes_memcpy(&sa->port_be, port_be, 2);
}

/* Decode the UDP header after the 40-byte IPv6 header into out, after
 * checking its length (equal to the Payload Length) and checksum. */
static int xdpf_udp6(const u8* ip, u32 flags, xdpframe_rx* out) {
  const u8* udp  = ip + IPV6_HDR;
  usz       plen = be_get_be16(ip + 4);
  if (be_get_be16(udp + 4) != plen || !xdpf_udp6_csum_ok(ip, plen, flags)) {
    return 0;
  }
  xdpf_sa6(&out->src, ip + 8, udp);
  bytes_memcpy(out->our_ip, ip + 24, 16);
  out->dport       = be_get_be16(udp + 2);
  out->payload     = udp + UDP_HDR;
  out->payload_len = plen - UDP_HDR;
  return 1;
}

int xdpframe_parse6(const u8* ip, usz rem, u32 flags, xdpframe_rx* out) {
  if (!xdpf_ip6_len_ok(ip, rem) || !xdpf_ip6_ok(ip)) {
    return 0;
  }
  return xdpf_udp6(ip, flags, out);
}

/* eth + IPv6 + UDP around payload, or 0 if frame.n is too small. */
usz xdpframe_build6(
    wired_mspan frame, const xdpframe_tx* m, wired_span payload) {
  if (frame.n < XDPFRAME_HDRS6 + payload.n) {
    return 0;
  }
  ipv6_head  ih = {(u16)(UDP_HDR + payload.n), m->src, m->dst, IP_PROTO_UDP};
  ipv6addrs  a  = {m->src, m->dst};
  wired_obuf ob =
      obuf_of(frame.p + ETH_HDR + IPV6_HDR, frame.n - ETH_HDR - IPV6_HDR);
  xdpframe_put_eth(frame.p, m, ETH_TYPE_IPV6);
  ipv6_build(frame.p + ETH_HDR, &ih);
  udp6_build(&ob, m->ports, a, payload);
  return XDPFRAME_HDRS6 + payload.n;
}
