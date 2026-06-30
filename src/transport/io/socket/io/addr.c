#include "transport/io/socket/io/addr.h"

u32 quic_addr_from_octets(u8 a, u8 b, u8 c, u8 d) {
  return ((u32)a << 24) | ((u32)b << 16) | ((u32)c << 8) | d;
}

void quic_addr_to_octets(u32 addr, u8 out[4]) {
  out[0] = (u8)(addr >> 24);
  out[1] = (u8)(addr >> 16);
  out[2] = (u8)(addr >> 8);
  out[3] = (u8)addr;
}

u16 quic_port_be(u16 port) { return (u16)((port >> 8) | (port << 8)); }
