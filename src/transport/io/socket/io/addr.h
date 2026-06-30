#ifndef QUIC_IO_ADDR_H
#define QUIC_IO_ADDR_H

#include "common/platform/sys/syscall.h"

/* IPv4 address and port helpers. Addresses are big-endian (network order). */

/* Pack octets a.b.c.d into a big-endian u32 (a is the most significant byte). */
u32 quic_addr_from_octets(u8 a, u8 b, u8 c, u8 d);

/* Unpack a big-endian u32 into out[0..3] = a,b,c,d. */
void quic_addr_to_octets(u32 addr, u8 out[4]);

/* Convert a host-order port to network byte order. */
u16 quic_port_be(u16 port);

#endif
