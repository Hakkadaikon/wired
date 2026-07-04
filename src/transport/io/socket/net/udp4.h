#ifndef QUIC_NET_UDP4_H
#define QUIC_NET_UDP4_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/* RFC 768 UDP over IPv4. The checksum covers an IPv4 pseudo-header
 * (src, dst, zero, protocol=17, UDP length) plus the UDP header and data. */

#define QUIC_UDP_HDR 8

/* IPv4 addresses (host order) needed for the pseudo-header checksum. */
typedef struct {
  u32 src;
  u32 dst;
} quic_ipv4addrs;

/* Source and destination UDP ports (host order). */
typedef struct {
  u16 sport;
  u16 dport;
} quic_udpports;

/* Ports and addresses (both host order) for one UDP/IPv4 datagram. */
typedef struct {
  quic_udpports  ports;
  quic_ipv4addrs addrs;
} quic_udp4meta;

/* Build a UDP header + payload into out (8-byte header followed by the
 * payload, pseudo-header checksum filled in). Returns the datagram length
 * (8 + payload_len), or 0 if it does not fit in out->cap. */
usz quic_udp4_build(
    quic_obuf* out, const quic_udp4meta* meta, quic_span payload);

/* Verify a received datagram's checksum given the addresses. */
int quic_udp4_check(quic_span dgram, quic_ipv4addrs addrs);

#endif
