#include "transport/io/socket/io/udp_impl.h"

static void udp_int_cmsg(u8* out, i32 level, i32 type, int val);
static void udp_tos_cmsgs(u8* out, u8 tos);

/* Per-send TOS / traffic-class marks (RFC 9000 13.4.2.2: a connection whose
 * ECN validation failed stops marking on a socket that marks ECT(0)). */

static void udp_int_cmsg(u8* out, i32 level, i32 type, int val) {
  bytes_memset(out, 0, WIRED_INT_CMSG_SPACE);
  *(u64*)(out + 0)  = 20;
  *(i32*)(out + 8)  = level;
  *(i32*)(out + 12) = type;
  *(int*)(out + 16) = val;
}

/* Both: a v4 (or v4-mapped) send reads IP_TOS, a native v6 send
 * IPV6_TCLASS; each stack skips the other's level. Writes
 * WIRED_TOS_CMSG_SPACE bytes. */
static void udp_tos_cmsgs(u8* out, u8 tos) {
  udp_int_cmsg(out, WIRED_IPPROTO_IP, WIRED_IP_TOS, tos);
  udp_int_cmsg(
      out + WIRED_INT_CMSG_SPACE, WIRED_IPPROTO_IPV6, WIRED_IPV6_TCLASS, tos);
}

i64 wired_udp_send_tos(i64 fd, const sockaddr* sa, wired_span buf, u8 tos) {
  u8 cmsg[WIRED_TOS_CMSG_SPACE];
  udp_tos_cmsgs(cmsg, tos);
  return udp_sendmsg_ctl(fd, sa, buf, cmsg, sizeof cmsg);
}

i64 wired_udp_send_gso_tos(
    i64 fd, const sockaddr* sa, wired_span buf, u16 segsize, u8 tos) {
  u8 cmsg[WIRED_GSO_TOS_CMSG_SPACE];
  wired_udp_gso_cmsg_build(cmsg, segsize);
  udp_tos_cmsgs(cmsg + WIRED_GSO_CMSG_SPACE, tos);
  return udp_sendmsg_ctl(fd, sa, buf, cmsg, sizeof cmsg);
}
