#ifndef NET_UDP6_H
#define NET_UDP6_H

#include "transport/io/socket/net/udp4.h"

/* RFC 768 UDP over IPv6 (RFC 8200 8.1): the checksum covers the IPv6
 * pseudo-header (source, destination, 32-bit upper-layer length, three
 * zero bytes, Next Header 17) and is mandatory. */

/** The two IPv6 addresses (16 bytes each, network order). */
typedef struct {
  const u8* src;
  const u8* dst;
} ipv6addrs;

/* Build a UDP header + payload into out with the IPv6 pseudo-header
 * checksum. Returns 8 + payload.n, or 0 if it does not fit. */
usz udp6_build(
    wired_obuf* out, udpports ports, ipv6addrs addrs, wired_span payload);

/* RFC 8200 8.1: 1 when the checksum is present (not zero) and verifies. */
int udp6_check(wired_span dgram, ipv6addrs addrs);

#endif
