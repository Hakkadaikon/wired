#include "transport/io/xdp/xdpframe/xdpframe.h"

#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"

/* Record both MACs from the eth header; 1 iff the frame carries IPv4. */
static int xdpf_eth(wired_span frame, xdpframe_rx* out) {
  eth_head eh;
  if (!eth_parse(frame, &eh)) return 0;
  bytes_memcpy(out->peer_mac, eh.src, 6);
  bytes_memcpy(out->our_mac, eh.dst, 6);
  return eh.ethertype == QUIC_ETH_TYPE_IPV4;
}

/* RFC 791 3.1/3.2: IHL is the header length in 32-bit words, minimum 5; a
 * sender is conservative (this SDK always builds IHL=5, see
 * ipv4_build) but a receiver is liberal and does not reject a technically
 * valid larger IHL (options present) it merely does not interpret -- only
 * version 4 with IHL below the minimum is malformed. */
static usz ip_hlen(const u8* ip) { return (usz)(ip[0] & 0x0f) * 4; }

/* Version 4 and IHL no smaller than the RFC 791 minimum of 5 words. */
static int xdpf_ver_ihl_ok(const u8* ip) {
  return (ip[0] & 0xf0) == 0x40 && (ip[0] & 0x0f) >= 5;
}

/* Not a fragment: MF and the 13-bit fragment offset both zero. */
static int xdpf_unfragmented(const u8* ip) {
  return (be_get_be16(ip + 6) & 0x3fffu) == 0;
}

/* Version 4, IHL >= 5 words, protocol UDP, and not a fragment. */
static int xdpf_ip_ok(const u8* ip) {
  return xdpf_ver_ihl_ok(ip) && ip[9] == QUIC_IP_PROTO_UDP &&
         xdpf_unfragmented(ip);
}

/* The IP total length covers at least the (possibly option-extended) IP
 * header plus a UDP header and fits within the rem bytes from ip to the
 * frame end; anything past it is ethernet minimum-frame padding and is
 * ignored. */
static int xdpf_ip_len_ok(const u8* ip, usz hlen, usz rem) {
  u16 total = be_get_be16(ip + 2);
  return total >= hlen + QUIC_UDP_HDR && (usz)total <= rem;
}

/* Decode the UDP header (starting hlen bytes into ip, past any IP options)
 * into out. The checksums are not verified here on purpose — see
 * xdpframe_parse in the header. */
static int xdpf_udp(const u8* ip, usz hlen, xdpframe_rx* out) {
  const u8* udp = ip + hlen;
  sockaddr  dst;
  if (be_get_be16(udp + 4) != be_get_be16(ip + 2) - hlen) return 0;
  wired_udp_addr(&out->src, be_get_be16(udp), ip + 12);
  wired_udp_addr(&dst, 0, ip + 16);
  out->our_ip      = wired_udp_addr4_be(&dst);
  out->dport       = be_get_be16(udp + 2);
  out->payload     = udp + QUIC_UDP_HDR;
  out->payload_len = (usz)be_get_be16(udp + 4) - QUIC_UDP_HDR;
  return 1;
}

/* Validate and decode the IPv4 + UDP part starting at ip (rem bytes). */
static int xdpf_ip(const u8* ip, usz rem, xdpframe_rx* out) {
  usz hlen = ip_hlen(ip);
  if (!xdpf_ip_ok(ip) || !xdpf_ip_len_ok(ip, hlen, rem)) return 0;
  return xdpf_udp(ip, hlen, out);
}

int xdpframe_parse(wired_span frame, xdpframe_rx* out) {
  if (frame.n < QUIC_XDPFRAME_HDRS) return 0;
  if (!xdpf_eth(frame, out)) return 0;
  return xdpf_ip(frame.p + QUIC_ETH_HDR, frame.n - QUIC_ETH_HDR, out);
}

/* Write the eth header at the frame start. */
static void xdpf_put_eth(u8* p, const xdpframe_tx* m) {
  eth_head eh;
  bytes_memcpy(eh.dst, m->dst_mac, 6);
  bytes_memcpy(eh.src, m->src_mac, 6);
  eh.ethertype = QUIC_ETH_TYPE_IPV4;
  eth_build(p, &eh);
}

usz xdpframe_build(
    wired_mspan frame, const xdpframe_tx* m, wired_span payload) {
  usz       total = QUIC_XDPFRAME_HDRS + payload.n;
  ipv4_head ih    = {
      (u16)(QUIC_IPV4_HDR + QUIC_UDP_HDR + payload.n), m->udp.addrs.src,
      m->udp.addrs.dst, QUIC_IP_PROTO_UDP};
  wired_obuf ob;
  if (frame.n < total) return 0;
  xdpf_put_eth(frame.p, m);
  ipv4_build(frame.p + QUIC_ETH_HDR, &ih);
  ob = obuf_of(
      frame.p + QUIC_XDPFRAME_HDRS - QUIC_UDP_HDR,
      frame.n - QUIC_ETH_HDR - QUIC_IPV4_HDR);
  udp4_build(&ob, &m->udp, payload);
  return total;
}
