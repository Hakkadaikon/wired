#ifndef QUIC_NET_UDP4_H
#define QUIC_NET_UDP4_H

#include "common/platform/sys/syscall.h"

/* RFC 768 UDP over IPv4. The checksum covers an IPv4 pseudo-header
 * (src, dst, zero, protocol=17, UDP length) plus the UDP header and data. */

#define QUIC_UDP_HDR 8

/* Build a UDP header + payload into out (cap bytes): 8-byte header followed
 * by the payload, with the pseudo-header checksum filled in. src/dst are the
 * IPv4 addresses (host order) needed for the pseudo-header. Returns the
 * datagram length (8 + payload_len), or 0 if it does not fit. */
usz quic_udp4_build(u8 *out, usz cap, u16 sport, u16 dport,
                    u32 src, u32 dst, const u8 *payload, usz payload_len);

/* Verify a received datagram's checksum given the addresses. */
int quic_udp4_check(const u8 *dgram, usz len, u32 src, u32 dst);

#endif
