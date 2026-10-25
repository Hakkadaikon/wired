#ifndef XDPFRAME_H
#define XDPFRAME_H

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
#define XDPFRAME_HDRS (ETH_HDR + IPV4_HDR + UDP_HDR)

/** Everything extracted from one received frame: where the QUIC payload is,
 * who sent it, and the addressing needed to reflect a reply. */
typedef struct {
  /** peer ip+port in kernel sockaddr_in form (big-endian port and address) */
  sockaddr src;
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
} xdpframe_rx;

/** xdpframe_parse flag: do not verify the UDP checksum. For veth, which
 * delivers locally originated frames as CHECKSUM_PARTIAL (the UDP checksum
 * field holds only the pseudo-header sum); the kernel always fills the IPv4
 * header checksum, so that one is verified regardless. */
#define XDPFRAME_SKIP_UDP_CSUM 1u

/** Parse one received frame. Accepts only ethertype IPv4, IHL >= 5 (any
 * options are skipped, not interpreted), an unfragmented datagram, a
 * non-zero TTL (RFC 791 3.1), a valid header checksum (RFC 791 3.1),
 * protocol UDP, consistent frame / IP total / UDP lengths (trailing
 * ethernet minimum-frame padding is ignored), and a UDP checksum that is
 * zero or verifies (RFC 768) unless flags has XDPFRAME_SKIP_UDP_CSUM.
 * @param frame the received frame bytes
 * @param flags 0 or XDPFRAME_SKIP_UDP_CSUM
 * @param out   receives the payload view and peer info (views into frame)
 * @return 1 accepted, 0 rejected. */
int xdpframe_parse(wired_span frame, u32 flags, xdpframe_rx* out);

/** Addressing for one outgoing frame: the MACs plus the ports and addresses
 * consumed by the IPv4 and UDP builders (host order, as in udp4meta). */
typedef struct {
  /** eth destination MAC (the peer's) */
  u8 dst_mac[6];
  /** eth source MAC (ours) */
  u8 src_mac[6];
  /** UDP ports and IPv4 addresses in host order */
  udp4meta udp;
  /** IPv4 Identification for this datagram (RFC 791 3.2) */
  u16 ip_id;
} xdpframe_tx;

/** Build a complete eth+IPv4+UDP frame around payload, with the IPv4 header
 * checksum and the pseudo-header UDP checksum filled in.
 * @param frame   destination frame buffer
 * @param m       addressing for the frame
 * @param payload the UDP payload (the QUIC datagram)
 * @return XDPFRAME_HDRS + payload.n, or 0 if frame.n is too small. */
usz xdpframe_build(wired_mspan frame, const xdpframe_tx* m, wired_span payload);

#endif
