#include "transport/conn/lifecycle/session/session_impl.h"

/* Wrap a QUIC packet in UDP+IPv4 and push it onto the link (no syscall). */
int session_link_tx(memlink* l, wired_span qpkt, ipv4addrs addrs) {
  u8         udp[1500], ip[20], frame[1520];
  udp4meta   meta = {{4433, 4433}, addrs};
  wired_obuf ub   = obuf_of(udp, sizeof(udp));
  usz        un   = udp4_build(&ub, &meta, qpkt);
  ipv4_build(
      ip, &(ipv4_head){(u16)(20 + un), addrs.src, addrs.dst, IP_PROTO_UDP});
  for (usz i = 0; i < 20; i++) {
    frame[i] = ip[i];
  }
  for (usz i = 0; i < un; i++) {
    frame[20 + i] = udp[i];
  }
  return memlink_send(l, frame, 20 + un);
}
