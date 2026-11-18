#ifndef XDPFRAME_H
#define XDPFRAME_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/net/eth.h"
#include "transport/io/socket/net/ipv4.h"
#include "transport/io/socket/net/ipv6.h"
#include "transport/io/socket/net/udp4.h"

/** @file
 * Frame codec for the AF_XDP datapath: parses a received eth+IPv4+UDP or
 * eth+IPv6+UDP frame down to its QUIC payload plus peer info, and builds a
 * complete outgoing frame around a QUIC payload (reusing the net/ IP and
 * UDP codecs). Addresses are 16 bytes, an IPv4 one v4-mapped
 * (::ffff:a.b.c.d), as in sockaddr. */

/** Total byte length of the eth + IPv4 + UDP headers in one frame. */
#define XDPFRAME_HDRS (ETH_HDR + IPV4_HDR + UDP_HDR)
/** Total byte length of the eth + IPv6 + UDP headers in one frame. */
#define XDPFRAME_HDRS6 (ETH_HDR + IPV6_HDR + UDP_HDR)

/** Everything extracted from one received frame: where the QUIC payload is,
 * who sent it, and the addressing needed to reflect a reply. */
typedef struct {
  /** peer ip+port (big-endian port; native or v4-mapped address) */
  sockaddr src;
  /** the frame's eth source MAC (the peer's) */
  u8 peer_mac[6];
  /** the frame's eth destination MAC (ours) */
  u8 our_mac[6];
  /** the frame's ip destination address (ours; v4-mapped for IPv4) */
  u8 our_ip[16];
  /** udp destination port in host order */
  u16 dport;
  /** first byte of the UDP payload (a view into the parsed frame) */
  const u8* payload;
  /** byte length of the UDP payload */
  usz payload_len;
} xdpframe_rx;

/** xdpframe_parse flag: do not verify the UDP checksum. For veth, which
 * delivers locally originated frames as CHECKSUM_PARTIAL (the UDP checksum
 * field holds only the pseudo-header sum); the kernel always fills the IPv4
 * header checksum, so that one is verified regardless. */
#define XDPFRAME_SKIP_UDP_CSUM 1u

/** Parse one received frame. IPv4: only IHL >= 5 (any options are
 * skipped, not interpreted), an unfragmented datagram, a non-zero TTL (RFC
 * 791 3.1), a valid header checksum (RFC 791 3.1), protocol UDP, and a UDP
 * checksum that is zero or verifies (RFC 768). IPv6: version 6, Next Header
 * UDP (no extension headers), a non-zero Hop Limit, and a UDP checksum that
 * is present and verifies (RFC 8200 8.1). Both: consistent frame / IP /
 * UDP lengths (trailing ethernet minimum-frame padding is ignored), and the
 * UDP checksum is skipped when flags has XDPFRAME_SKIP_UDP_CSUM.
 * @param frame the received frame bytes
 * @param flags 0 or XDPFRAME_SKIP_UDP_CSUM
 * @param out   receives the payload view and peer info (views into frame)
 * @return 1 accepted, 0 rejected. */
int xdpframe_parse(wired_span frame, u32 flags, xdpframe_rx* out);

/** Addressing for one outgoing frame: the MACs, the ports (host order)
 * and the addresses; a v4-mapped dst builds an IPv4 frame, any other an
 * IPv6 one. */
typedef struct {
  /** eth destination MAC (the peer's) */
  u8 dst_mac[6];
  /** eth source MAC (ours) */
  u8 src_mac[6];
  /** UDP ports in host order */
  udpports ports;
  /** source address (ours; v4-mapped for IPv4) */
  u8 src[16];
  /** destination address (the peer's; v4-mapped for IPv4) */
  u8 dst[16];
  /** IPv4 Identification for this datagram (RFC 791 3.2; unused for IPv6) */
  u16 ip_id;
} xdpframe_tx;

/** 1 if a is v4-mapped (::ffff:a.b.c.d). */
int xdpframe_is_v4(const u8 a[16]);

/** Build a complete eth+IP+UDP frame around payload, with the IPv4 header
 * checksum (IPv4) and the pseudo-header UDP checksum filled in.
 * @param frame   destination frame buffer
 * @param m       addressing for the frame
 * @param payload the UDP payload (the QUIC datagram)
 * @return the frame length, or 0 if frame.n is too small. */
usz xdpframe_build(wired_mspan frame, const xdpframe_tx* m, wired_span payload);

#endif
