#ifndef QUIC_NET_ETH_H
#define QUIC_NET_ETH_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * Ethernet II framing: 6-byte destination MAC, 6-byte source MAC, 2-byte
 * big-endian EtherType. No VLAN tag; the FCS is handled by the NIC. */

/** Byte length of an Ethernet II header. */
#define QUIC_ETH_HDR 14

/** EtherType for IPv4. */
#define QUIC_ETH_TYPE_IPV4 0x0800u

/** Decoded Ethernet II header. */
typedef struct {
  /** destination MAC address */
  u8 dst[6];
  /** source MAC address */
  u8 src[6];
  /** EtherType in host order (e.g. QUIC_ETH_TYPE_IPV4) */
  u16 ethertype;
} quic_eth_head;

/** Build a 14-byte Ethernet II header into out per h.
 * @param out destination buffer, must be >= QUIC_ETH_HDR bytes
 * @param h   header fields to encode
 * @return QUIC_ETH_HDR. */
usz quic_eth_build(u8* out, const quic_eth_head* h);

/** Parse the Ethernet II header at the start of frame into h.
 * @param frame the received frame bytes
 * @param h     receives the decoded header
 * @return 1 ok, 0 if frame.n < QUIC_ETH_HDR. */
int quic_eth_parse(quic_span frame, quic_eth_head* h);

#endif
