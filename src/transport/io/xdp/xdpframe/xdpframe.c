#include "transport/io/xdp/xdpframe/xdpframe.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* Record both MACs from the eth header; 1 iff the frame carries IPv4. */
static int xdpf_eth(quic_span frame, quic_xdpframe_rx* out) {
  quic_eth_head eh;
  if (!quic_eth_parse(frame, &eh)) return 0;
  quic_memcpy(out->peer_mac, eh.src, 6);
  quic_memcpy(out->our_mac, eh.dst, 6);
  return eh.ethertype == QUIC_ETH_TYPE_IPV4;
}

/* IHL=5 fixed header, protocol UDP, and not a fragment (MF and the 13-bit
 * fragment offset both zero). */
static int xdpf_ip_ok(const u8* ip) {
  return ip[0] == 0x45 && ip[9] == QUIC_IP_PROTO_UDP &&
         (quic_get_be16(ip + 6) & 0x3fffu) == 0;
}

/* The IP total length covers at least the IP+UDP headers and fits within
 * the rem bytes from ip to the frame end; anything past it is ethernet
 * minimum-frame padding and is ignored. */
static int xdpf_ip_len_ok(const u8* ip, usz rem) {
  u16 total = quic_get_be16(ip + 2);
  return total >= QUIC_IPV4_HDR + QUIC_UDP_HDR && (usz)total <= rem;
}

/* Decode the UDP header into out. The checksums are not verified here on
 * purpose — see quic_xdpframe_parse in the header. */
static int xdpf_udp(const u8* ip, quic_xdpframe_rx* out) {
  const u8*        udp = ip + QUIC_IPV4_HDR;
  quic_sockaddr_in dst;
  if (quic_get_be16(udp + 4) != quic_get_be16(ip + 2) - QUIC_IPV4_HDR) return 0;
  wired_udp_addr(&out->src, quic_get_be16(udp), ip + 12);
  wired_udp_addr(&dst, 0, ip + 16);
  out->our_ip_be   = dst.addr_be;
  out->dport       = quic_get_be16(udp + 2);
  out->payload     = udp + QUIC_UDP_HDR;
  out->payload_len = (usz)quic_get_be16(udp + 4) - QUIC_UDP_HDR;
  return 1;
}

/* Validate and decode the IPv4 + UDP part starting at ip (rem bytes). */
static int xdpf_ip(const u8* ip, usz rem, quic_xdpframe_rx* out) {
  if (!xdpf_ip_ok(ip) || !xdpf_ip_len_ok(ip, rem)) return 0;
  return xdpf_udp(ip, out);
}

int quic_xdpframe_parse(quic_span frame, quic_xdpframe_rx* out) {
  if (frame.n < QUIC_XDPFRAME_HDRS) return 0;
  if (!xdpf_eth(frame, out)) return 0;
  return xdpf_ip(frame.p + QUIC_ETH_HDR, frame.n - QUIC_ETH_HDR, out);
}

/* Write the eth header at the frame start. */
static void xdpf_put_eth(u8* p, const quic_xdpframe_tx* m) {
  quic_eth_head eh;
  quic_memcpy(eh.dst, m->dst_mac, 6);
  quic_memcpy(eh.src, m->src_mac, 6);
  eh.ethertype = QUIC_ETH_TYPE_IPV4;
  quic_eth_build(p, &eh);
}

usz quic_xdpframe_build(
    quic_mspan frame, const quic_xdpframe_tx* m, quic_span payload) {
  usz            total = QUIC_XDPFRAME_HDRS + payload.n;
  quic_ipv4_head ih    = {
      (u16)(QUIC_IPV4_HDR + QUIC_UDP_HDR + payload.n), m->udp.addrs.src,
      m->udp.addrs.dst, QUIC_IP_PROTO_UDP};
  quic_obuf ob;
  if (frame.n < total) return 0;
  xdpf_put_eth(frame.p, m);
  quic_ipv4_build(frame.p + QUIC_ETH_HDR, &ih);
  ob = quic_obuf_of(
      frame.p + QUIC_XDPFRAME_HDRS - QUIC_UDP_HDR,
      frame.n - QUIC_ETH_HDR - QUIC_IPV4_HDR);
  quic_udp4_build(&ob, &m->udp, payload);
  return total;
}
