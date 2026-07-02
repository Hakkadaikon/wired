#ifndef QUIC_NET_IPV4_H
#define QUIC_NET_IPV4_H

#include "common/platform/sys/syscall.h"

/* RFC 791 IPv4. Minimal 20-byte header (no options), protocol 17 = UDP. */

#define QUIC_IPV4_HDR 20
#define QUIC_IP_PROTO_UDP 17

/* Total length (header + payload), addresses (host order), and protocol for
 * a 20-byte IPv4 header. */
typedef struct {
  u16 total_len;
  u32 src;
  u32 dst;
  u8  proto;
} quic_ipv4_head;

/* Build a 20-byte IPv4 header into out per h. Fills in the header checksum.
 * Returns QUIC_IPV4_HDR. */
usz quic_ipv4_build(u8 out[QUIC_IPV4_HDR], const quic_ipv4_head *h);

/* Verify a received header's checksum (recompute over 20 bytes == 0). */
int quic_ipv4_check(const u8 *hdr);

#endif
