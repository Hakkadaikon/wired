#include "transport/io/socket/io/udptransport.h"

#include "transport/io/socket/io/addr.h"
#include "transport/io/socket/io/udp.h"

int udp_transport_open(udp_transport* t, u16 local_port) {
  sockaddr sa;
  i64      fd = wired_udp_socket();
  if (fd < 0) return (int)fd;
  wired_udp_addr(&sa, local_port, (const u8[4]){0, 0, 0, 0});
  i64 r = wired_udp_bind(fd, &sa);
  if (r < 0) return (int)r;
  t->fd = fd;
  return 0;
}

int udp_transport_connect(udp_transport* t, u32 peer_addr, u16 peer_port) {
  t->peer_addr = peer_addr;
  t->peer_port = peer_port;
  return 0;
}

int udp_transport_send(udp_transport* t, const u8* buf, usz len) {
  sockaddr sa;
  u8       o[4];
  addr_to_octets(t->peer_addr, o);
  wired_udp_addr(&sa, t->peer_port, o);
  return wired_udp_send(t->fd, &sa, wired_span_of(buf, len)) >= 0 ? 1 : 0;
}

usz udp_transport_recv(udp_transport* t, u8* buf, usz cap) {
  i64 r = wired_udp_recv(t->fd, wired_mspan_of(buf, cap));
  return r > 0 ? (usz)r : 0;
}
