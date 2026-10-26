/* SOL_UDP setsockopt level constant (Linux). Internal-only: no caller outside
 * this file needs the raw setsockopt args. */
/* UDP_SEGMENT setsockopt name (Linux GSO, kernel >= 4.18). */

/* IPPROTO_IP setsockopt level constant (Linux uapi in.h). */
/* IP_TOS setsockopt/cmsg name (Linux uapi in.h): the IPv4 TOS byte, whose
 * low 2 bits carry the RFC 3168 ECN codepoint. */
/* IP_RECVTOS setsockopt name (Linux uapi in.h): ask the kernel to attach an
 * IP_TOS cmsg to every received datagram carrying the packet's ECN bits. */

#include "transport/io/socket/io/udp_impl.h"

static u16  hton16(u16 v);
static int  udp_octets_zero(const u8 octets[4]);
static void udp_addr_map4(u8 addr[16], const u8 octets[4]);
static void udp_kaddr_pack4(sockaddr* k);
static i64  udp_socket_v6(void);
static usz  udp_mtu_payload(const sockaddr* peer, int mtu);
static i64  udp_mtu_read(i64 fd, int* mtu);

/* Host-to-network for 16-bit values (x86_64 is little-endian). */
static u16 hton16(u16 v) { return (u16)((v >> 8) | (v << 8)); }

/* 1 if octets is 0.0.0.0 (branch-free: the bind-any request). */
static int udp_octets_zero(const u8 octets[4]) {
  return (octets[0] | octets[1] | octets[2] | octets[3]) == 0;
}

/* Write the v4-mapped ::ffff:a.b.c.d suffix into a zeroed 16-byte addr. */
static void udp_addr_map4(u8 addr[16], const u8 octets[4]) {
  addr[10] = 0xff;
  addr[11] = 0xff;
  for (usz i = 0; i < 4; i++) {
    addr[12 + i] = octets[i];
  }
}

void wired_udp_addr(sockaddr* sa, u16 port, const u8 octets[4]) {
  for (usz i = 0; i < 16; i++) {
    sa->addr[i] = 0;
  }
  sa->family   = WIRED_AF_INET6;
  sa->port_be  = hton16(port);
  sa->flowinfo = 0;
  sa->scope_id = 0;
  /* all-zero octets ask for the dual-stack any-address :: -- a mapped
   * ::ffff:0.0.0.0 would bind the socket IPv4-only (see udp.h). */
  if (!udp_octets_zero(octets)) {
    udp_addr_map4(sa->addr, octets);
  }
}

/* Family of every socket this process opens: AF_INET6 dual-stack, or
 * AF_INET once AF_INET6 proved unsupported. IPv6 support is a host-wide
 * fact, so one latch serves every fd. */
u16 udp_family = WIRED_AF_INET6;

void udp_kaddr_in(sockaddr* sa) {
  u8 a4[4];
  if (sa->family != WIRED_AF_INET) {
    return;
  }
  bytes_memcpy(a4, (const u8*)sa + 4, 4);
  wired_udp_addr(sa, hton16(sa->port_be), a4);
}

/* Re-lay k's v4-mapped IPv4 address in place as a kernel sockaddr_in in its
 * leading 16 bytes: the address sits where sin6_flowinfo is. */
static void udp_kaddr_pack4(sockaddr* k) {
  u8  a4[4];
  u8* b = (u8*)k;
  bytes_memcpy(a4, k->addr + 12, 4);
  bytes_memset(b + 4, 0, sizeof(*k) - 4);
  k->family = WIRED_AF_INET;
  bytes_memcpy(b + 4, a4, 4);
}

u32 udp_kaddr_out(const sockaddr* sa, u16 family, sockaddr* out) {
  *out = *sa;
  udp_kaddr_in(out); /* a raw kernel sockaddr_in (getsockname) as well */
  if (family == WIRED_AF_INET6) {
    return sizeof(*out);
  }
  udp_kaddr_pack4(out);
  return WIRED_SOCKADDR_IN_LEN;
}

/* Open the dual-stack AF_INET6 socket (negative errno on failure). */
static i64 udp_socket_v6(void) {
  int v6only = 0;
  i64 fd     = wired_arch_socket(WIRED_AF_INET6, WIRED_SOCK_DGRAM, 0);
  if (fd < 0) {
    return fd;
  }
  /* dual stack: v4 peers arrive v4-mapped on the same fd. Linux defaults
   * IPV6_V6ONLY to 0 already; setting it explicitly pins the behavior
   * against a flipped net.ipv6.bindv6only sysctl. */
  wired_arch_setsockopt(
      fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_V6ONLY, &v6only, sizeof(v6only));
  return fd;
}

i64 wired_udp_socket(void) {
  i64 fd = udp_socket_v6();
  if (fd != -WIRED_EAFNOSUPPORT) {
    return fd;
  }
  udp_family = WIRED_AF_INET;
  return wired_arch_socket(WIRED_AF_INET, WIRED_SOCK_DGRAM, 0);
}

i64 wired_udp_bind(i64 fd, const sockaddr* sa) {
  sockaddr k;
  u32      n = udp_kaddr_out(sa, udp_family, &k);
  return wired_arch_bind(fd, &k, n);
}

i64 wired_udp_send(i64 fd, const sockaddr* sa, wired_span buf) {
  sockaddr k;
  u32      n = udp_kaddr_out(sa, udp_family, &k);
  return wired_arch_sendto(fd, buf.p, buf.n, 0, &k, n);
}

i64 wired_udp_recv(i64 fd, wired_mspan buf) {
  return wired_arch_recvfrom(fd, buf.p, buf.n, 0, 0, 0);
}

i64 wired_udp_recvfrom(i64 fd, wired_mspan buf, sockaddr* src) {
  /* addrlen is in/out: pass the buffer size, kernel writes the actual length.
   */
  u32 addrlen = sizeof(*src);
  i64 r       = wired_arch_recvfrom(fd, buf.p, buf.n, 0, src, &addrlen);
  udp_kaddr_in(src); /* an AF_INET fd's source, back to v4-mapped */
  return r;
}

i64 wired_udp_close(i64 fd) { return wired_arch_close(fd); }

void wired_udp_gso_cmsg_build(u8 out[WIRED_GSO_CMSG_SPACE], u16 segsize) {
  bytes_memset(out, 0, WIRED_GSO_CMSG_SPACE);
  /* cmsg_len (u64, offset 0) = CMSG_LEN(sizeof(u16)) = 16 + 2 = 18 */
  *(u64*)(out + 0) = 18;
  /* cmsg_level (i32, offset 8), cmsg_type (i32, offset 12) */
  *(i32*)(out + 8)  = WIRED_SOL_UDP;
  *(i32*)(out + 12) = WIRED_UDP_SEGMENT;
  /* payload: segsize as host-order u16 right after the header */
  *(u16*)(out + 16) = segsize;
}

i64 wired_udp_ect0_enable(i64 fd) {
  int val = WIRED_ECT0_TOS;
  /* dual stack: IP_TOS marks the v4-mapped sends, IPV6_TCLASS the native
   * v6 ones; the v6 option is best-effort (its failure never voids the
   * still-working v4 marking). */
  wired_arch_setsockopt(
      fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_TCLASS, &val, sizeof(val));
  return wired_arch_setsockopt(
      fd, WIRED_IPPROTO_IP, WIRED_IP_TOS, &val, sizeof(val));
}

i64 wired_udp_pmtu_probe_enable(i64 fd) {
  int val = WIRED_IP_PMTUDISC_PROBE;
  /* same dual-stack pairing as wired_udp_ect0_enable: the v6 option covers
   * native v6 peers and is best-effort. */
  wired_arch_setsockopt(
      fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_MTU_DISCOVER, &val, sizeof(val));
  return wired_arch_setsockopt(
      fd, WIRED_IPPROTO_IP, WIRED_IP_MTU_DISCOVER, &val, sizeof(val));
}

/* mtu (an IP packet size) less the headers for peer's family, or 0 when it
 * does not even cover them. A v4-mapped address (::ffff:a.b.c.d) is IPv4 on
 * the wire. */
static usz udp_mtu_payload(const sockaddr* peer, int mtu) {
  int v4  = (peer->addr[10] & peer->addr[11]) == 0xff;
  int hdr = v4 ? WIRED_UDP_V4_OVERHEAD : WIRED_UDP_V6_OVERHEAD;
  return mtu > hdr ? (usz)(mtu - hdr) : 0;
}

/* IP_MTU or IPV6_MTU, matching the socket family udp_family opened. */
static i64 udp_mtu_read(i64 fd, int* mtu) {
  i32 len = sizeof(*mtu);
  if (udp_family == WIRED_AF_INET) {
    return wired_arch_getsockopt(fd, WIRED_IPPROTO_IP, WIRED_IP_MTU, mtu, &len);
  }
  return wired_arch_getsockopt(
      fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_MTU, mtu, &len);
}

usz wired_udp_path_mtu(const sockaddr* peer) {
  sockaddr k;
  int      mtu = 0;
  u32      n   = udp_kaddr_out(peer, udp_family, &k);
  i64      fd  = wired_arch_socket(udp_family, WIRED_SOCK_DGRAM, 0);
  if (fd < 0) {
    return 0;
  }
  if (wired_arch_connect(fd, &k, n) == 0) {
    udp_mtu_read(fd, &mtu);
  }
  wired_arch_close(fd);
  return udp_mtu_payload(peer, mtu);
}

i64 wired_udp_recvtos_enable(i64 fd) {
  int val = 1;
  /* same dual-stack pairing as wired_udp_ect0_enable above. */
  wired_arch_setsockopt(
      fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_RECVTCLASS, &val, sizeof(val));
  return wired_arch_setsockopt(
      fd, WIRED_IPPROTO_IP, WIRED_IP_RECVTOS, &val, sizeof(val));
}
