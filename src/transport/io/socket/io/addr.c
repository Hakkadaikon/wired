#include "transport/io/socket/io/addr.h"

u32 quic_addr_from_octets(const u8 octets[4]) {
  return ((u32)octets[0] << 24) | ((u32)octets[1] << 16) |
         ((u32)octets[2] << 8) | octets[3];
}

void quic_addr_to_octets(u32 addr, u8 out[4]) {
  out[0] = (u8)(addr >> 24);
  out[1] = (u8)(addr >> 16);
  out[2] = (u8)(addr >> 8);
  out[3] = (u8)addr;
}

u16 quic_port_be(u16 port) { return (u16)((port >> 8) | (port << 8)); }
