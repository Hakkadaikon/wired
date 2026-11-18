#ifndef NET_IPV6_H
#define NET_IPV6_H

#include "common/platform/sys/syscall.h"

/* RFC 8200 IPv6. The fixed 40-byte header with no extension headers. */
#define IPV6_HDR 40

/** Payload length (bytes after the 40-byte header), the two addresses
 * (16 bytes each, network order) and the Next Header for one header. */
typedef struct {
  u16       payload_len;
  const u8* src;
  const u8* dst;
  u8        next;
} ipv6_head;

/* RFC 8200 3: version 6, traffic class 0, flow label 0, Hop Limit 64.
 * Returns IPV6_HDR. */
usz ipv6_build(u8 out[IPV6_HDR], const ipv6_head* h);

#endif
