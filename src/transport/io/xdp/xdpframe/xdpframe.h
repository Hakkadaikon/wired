#ifndef QUIC_XDPFRAME_H
#define QUIC_XDPFRAME_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/net/eth.h"
#include "transport/io/socket/net/ipv4.h"
#include "transport/io/socket/net/udp4.h"

/** @file
 * Frame codec for the AF_XDP datapath: parses a received eth+IPv4+UDP frame
 * down to its QUIC payload plus peer info, and builds a complete outgoing
 * frame around a QUIC payload (reusing the net/ IPv4 and UDP codecs). */

/** Total byte length of the eth + IPv4 + UDP headers in one frame. */
#define QUIC_XDPFRAME_HDRS (QUIC_ETH_HDR + QUIC_IPV4_HDR + QUIC_UDP_HDR)

/** Everything extracted from one received frame: where the QUIC payload is,
 * who sent it, and the addressing needed to reflect a reply. */
typedef struct {
  /** peer ip+port in kernel sockaddr_in form (big-endian port and address) */
  quic_sockaddr src;
  /** the frame's eth source MAC (the peer's) */
  u8 peer_mac[6];
  /** the frame's eth destination MAC (ours) */
  u8 our_mac[6];
  /** ip destination address as a host-order u32 (wired_udp_addr4_be) */
  u32 our_ip;
  /** udp destination port in host order */
  u16 dport;
  /** first byte of the UDP payload (a view into the parsed frame) */
  const u8* payload;
  /** byte length of the UDP payload */
  usz payload_len;
} quic_xdpframe_rx;

/** Parse one received frame. Accepts only ethertype IPv4, IHL=5, an
 * unfragmented datagram, protocol UDP, and consistent frame / IP total /
 * UDP lengths (trailing ethernet minimum-frame padding is ignored). The IP
 * and UDP checksums are deliberately NOT verified: veth delivers locally
 * originated frames as CHECKSUM_PARTIAL with the checksum unfilled, and
 * QUIC's AEAD already authenticates the payload end to end.
 * @param frame the received frame bytes
 * @param out   receives the payload view and peer info (views into frame)
 * @return 1 accepted, 0 rejected. */
int quic_xdpframe_parse(quic_span frame, quic_xdpframe_rx* out);

/** Addressing for one outgoing frame: the MACs plus the ports and addresses
 * consumed by the IPv4 and UDP builders (host order, as in quic_udp4meta). */
typedef struct {
  /** eth destination MAC (the peer's) */
  u8 dst_mac[6];
  /** eth source MAC (ours) */
  u8 src_mac[6];
  /** UDP ports and IPv4 addresses in host order */
  quic_udp4meta udp;
} quic_xdpframe_tx;

/** Build a complete eth+IPv4+UDP frame around payload, with the IPv4 header
 * checksum and the pseudo-header UDP checksum filled in.
 * @param frame   destination frame buffer
 * @param m       addressing for the frame
 * @param payload the UDP payload (the QUIC datagram)
 * @return QUIC_XDPFRAME_HDRS + payload.n, or 0 if frame.n is too small. */
usz quic_xdpframe_build(
    quic_mspan frame, const quic_xdpframe_tx* m, quic_span payload);

#endif
