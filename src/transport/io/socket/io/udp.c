#include "transport/io/socket/io/udp.h"

#include "common/bytes/util/bytes.h"

/* SOL_UDP setsockopt level constant (Linux). Internal-only: no caller outside
 * this file needs the raw setsockopt args. */
#define WIRED_SOL_UDP 17
/* UDP_SEGMENT setsockopt name (Linux GSO, kernel >= 4.18). */
#define WIRED_UDP_SEGMENT 103

/* Host-to-network for 16- and 32-bit values (x86_64 is little-endian). */
static u16 hton16(u16 v) { return (u16)((v >> 8) | (v << 8)); }

static u32 hton32(u32 v) {
  return ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) | ((v << 8) & 0xff0000) |
         ((v << 24) & 0xff000000);
}

void wired_udp_addr(quic_sockaddr_in *sa, u16 port, const u8 octets[4]) {
  u32 addr = ((u32)octets[0] << 24) | ((u32)octets[1] << 16) |
             ((u32)octets[2] << 8) | octets[3];
  for (usz i = 0; i < 8; i++) sa->zero[i] = 0;
  sa->family  = WIRED_AF_INET;
  sa->port_be = hton16(port);
  sa->addr_be = hton32(addr);
}

i64 wired_udp_socket(void) {
  return syscall3(SYS_socket, WIRED_AF_INET, WIRED_SOCK_DGRAM, 0);
}

i64 wired_udp_bind(i64 fd, const quic_sockaddr_in *sa) {
  return syscall3(SYS_bind, fd, sa, sizeof(*sa));
}

i64 wired_udp_send(i64 fd, const quic_sockaddr_in *sa, quic_span buf) {
  return syscall6(
      SYS_sendto, fd, (i64)buf.p, (i64)buf.n, 0, (i64)sa, sizeof(*sa));
}

i64 wired_udp_recv(i64 fd, quic_mspan buf) {
  return syscall6(SYS_recvfrom, fd, (i64)buf.p, (i64)buf.n, 0, 0, 0);
}

i64 wired_udp_recvfrom(i64 fd, quic_mspan buf, quic_sockaddr_in *src) {
  /* addrlen is in/out: pass the buffer size, kernel writes the actual length.
   */
  u32 addrlen = sizeof(*src);
  return syscall6(
      SYS_recvfrom, fd, (i64)buf.p, (i64)buf.n, 0, (i64)src, (i64)&addrlen);
}

i64 wired_udp_close(i64 fd) { return syscall1(SYS_close, fd); }

/* x86_64 Linux struct iovec (16 bytes): base pointer + length. Manually
 * defined per naming-and-unity-build.md — src/ may not include <sys/uio.h>. */
typedef struct {
  const void *iov_base;
  u64         iov_len;
} quic_iovec;

/* x86_64 Linux struct msghdr (56 bytes), manually laid out to match the
 * kernel ABI for sendmsg(2) (man 2 sendmsg / uapi socket.h). */
typedef struct {
  const void *msg_name;
  u32         msg_namelen;
  u32         msg_namelen_pad; /* kernel struct has 4B padding here (LP64) */
  quic_iovec *msg_iov;
  u64         msg_iovlen;
  void       *msg_control;
  u64         msg_controllen;
  u32         msg_flags;
  u32         msg_flags_pad;
} quic_msghdr;

void wired_udp_gso_cmsg_build(u8 out[WIRED_GSO_CMSG_SPACE], u16 segsize) {
  quic_memset(out, 0, WIRED_GSO_CMSG_SPACE);
  /* cmsg_len (u64, offset 0) = CMSG_LEN(sizeof(u16)) = 16 + 2 = 18 */
  *(u64 *)(out + 0) = 18;
  /* cmsg_level (i32, offset 8), cmsg_type (i32, offset 12) */
  *(i32 *)(out + 8)  = WIRED_SOL_UDP;
  *(i32 *)(out + 12) = WIRED_UDP_SEGMENT;
  /* payload: segsize as host-order u16 right after the header */
  *(u16 *)(out + 16) = segsize;
}

i64 wired_udp_gso_enable(i64 fd, u16 segsize) {
  u16 val = segsize;
  return syscall6(
      SYS_setsockopt, fd, WIRED_SOL_UDP, WIRED_UDP_SEGMENT, (i64)&val,
      sizeof(val), 0);
}

i64 wired_udp_send_gso(
    i64 fd, const quic_sockaddr_in *sa, quic_span buf, u16 segsize) {
  u8          cmsg[WIRED_GSO_CMSG_SPACE];
  quic_iovec  iov = {buf.p, buf.n};
  quic_msghdr msg = {0};
  wired_udp_gso_cmsg_build(cmsg, segsize);
  msg.msg_name       = sa;
  msg.msg_namelen    = sizeof(*sa);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = cmsg;
  msg.msg_controllen = WIRED_GSO_CMSG_SPACE;
  return syscall3(SYS_sendmsg, fd, &msg, 0);
}

/* Length of the next segment starting at off: segsize, or the remainder if
 * shorter (the trailing segment). */
static usz gso_batch_seglen(usz remaining, u16 segsize) {
  return remaining < segsize ? remaining : segsize;
}

i64 wired_udp_send_batch(
    i64 fd, const quic_sockaddr_in *sa, quic_span buf, u16 segsize) {
  usz off  = 0;
  i64 sent = 0;
  while (off < buf.n) {
    usz n = gso_batch_seglen(buf.n - off, segsize);
    i64 r = wired_udp_send(fd, sa, quic_span_of(buf.p + off, n));
    if (r < 0) return r;
    sent += r;
    off += n;
  }
  return sent;
}
