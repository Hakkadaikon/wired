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

void wired_udp_addr(quic_sockaddr_in* sa, u16 port, const u8 octets[4]) {
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

i64 wired_udp_bind(i64 fd, const quic_sockaddr_in* sa) {
  return syscall3(SYS_bind, fd, sa, sizeof(*sa));
}

i64 wired_udp_send(i64 fd, const quic_sockaddr_in* sa, quic_span buf) {
  return syscall6(
      SYS_sendto, fd, (i64)buf.p, (i64)buf.n, 0, (i64)sa, sizeof(*sa));
}

i64 wired_udp_recv(i64 fd, quic_mspan buf) {
  return syscall6(SYS_recvfrom, fd, (i64)buf.p, (i64)buf.n, 0, 0, 0);
}

i64 wired_udp_recvfrom(i64 fd, quic_mspan buf, quic_sockaddr_in* src) {
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
  const void* iov_base;
  u64         iov_len;
} quic_iovec;

/* x86_64 Linux struct msghdr (56 bytes), manually laid out to match the
 * kernel ABI for sendmsg(2) (man 2 sendmsg / uapi socket.h). */
typedef struct {
  const void* msg_name;
  u32         msg_namelen;
  u32         msg_namelen_pad; /* kernel struct has 4B padding here (LP64) */
  quic_iovec* msg_iov;
  u64         msg_iovlen;
  void*       msg_control;
  u64         msg_controllen;
  u32         msg_flags;
  u32         msg_flags_pad;
} quic_msghdr;

void wired_udp_gso_cmsg_build(u8 out[WIRED_GSO_CMSG_SPACE], u16 segsize) {
  quic_memset(out, 0, WIRED_GSO_CMSG_SPACE);
  /* cmsg_len (u64, offset 0) = CMSG_LEN(sizeof(u16)) = 16 + 2 = 18 */
  *(u64*)(out + 0) = 18;
  /* cmsg_level (i32, offset 8), cmsg_type (i32, offset 12) */
  *(i32*)(out + 8)  = WIRED_SOL_UDP;
  *(i32*)(out + 12) = WIRED_UDP_SEGMENT;
  /* payload: segsize as host-order u16 right after the header */
  *(u16*)(out + 16) = segsize;
}

i64 wired_udp_gso_enable(i64 fd, u16 segsize) {
  u16 val = segsize;
  return syscall6(
      SYS_setsockopt, fd, WIRED_SOL_UDP, WIRED_UDP_SEGMENT, (i64)&val,
      sizeof(val), 0);
}

i64 wired_udp_send_gso(
    i64 fd, const quic_sockaddr_in* sa, quic_span buf, u16 segsize) {
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
    i64 fd, const quic_sockaddr_in* sa, quic_span buf, u16 segsize) {
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

/* x86_64 Linux struct mmsghdr (man 2 recvmmsg / uapi socket.h): the msghdr
 * above plus the kernel-filled received length. */
typedef struct {
  quic_msghdr msg_hdr;
  u32         msg_len;
  u32         msg_len_pad; /* kernel struct has 4B padding here (LP64) */
} quic_mmsghdr;

/* recvmmsg() caps count at IOV_MAX-equivalent batch sizes in practice; QUIC
 * datagram batches are always small, so a fixed on-stack cap is enough
 * (ponytail: fixed cap, raise WIRED_RECVMMSG_MAX if a caller ever needs more).
 */
#define WIRED_RECVMMSG_MAX 64

/* Point one iovec+msghdr+mmsghdr slot at bufs[i].buf so the kernel writes
 * directly into the caller's storage; src doubles as msg_name. Zeroes the
 * whole slot first so no uninitialized stack bytes (e.g. msg_control/
 * msg_controllen) ever reach the recvmmsg(2) syscall. */
static void recvmmsg_fill_slot(
    quic_mmsghdr* slot, quic_iovec* iov, quic_mmsg_buf* b) {
  *slot                     = (quic_mmsghdr){0};
  iov->iov_base             = b->buf.p;
  iov->iov_len              = b->buf.n;
  slot->msg_hdr.msg_name    = &b->src;
  slot->msg_hdr.msg_namelen = sizeof(b->src);
  slot->msg_hdr.msg_iov     = iov;
  slot->msg_hdr.msg_iovlen  = 1;
}

/* Fill every slot the syscall will read from. */
static void recvmmsg_fill_all(
    quic_mmsghdr* slots, quic_iovec* iovs, quic_mmsg_buf* bufs, usz n) {
  for (usz i = 0; i < n; i++) recvmmsg_fill_slot(&slots[i], &iovs[i], &bufs[i]);
}

/* Copy the kernel-filled length back into each received slot. */
static void recvmmsg_read_lens(
    quic_mmsg_buf* bufs, const quic_mmsghdr* slots, i64 r) {
  for (i64 i = 0; i < r; i++) bufs[i].len = slots[i].msg_len;
}

/* MSG_WAITFORONE (linux/socket.h): block for the first datagram only, then
 * return with whatever else is already queued. Without it, a blocking socket
 * with a NULL timeout waits until ALL count slots are filled — a receive
 * loop asking for a full batch would hang on a single arriving datagram. */
#define WIRED_MSG_WAITFORONE 0x10000

i64 wired_udp_recvmmsg(i64 fd, quic_mmsg_buf* bufs, usz count) {
  quic_mmsghdr slots[WIRED_RECVMMSG_MAX] = {0};
  quic_iovec   iovs[WIRED_RECVMMSG_MAX]  = {0};
  usz          n = count < WIRED_RECVMMSG_MAX ? count : WIRED_RECVMMSG_MAX;
  i64          r;
  recvmmsg_fill_all(slots, iovs, bufs, n);
  r = syscall6(
      SYS_recvmmsg, fd, (i64)slots, (i64)n, WIRED_MSG_WAITFORONE, 0, 0);
  if (r < 0) return r;
  recvmmsg_read_lens(bufs, slots, r);
  return r;
}

i64 wired_udp_recvmmsg_fallback(i64 fd, quic_mmsg_buf* bufs, usz count) {
  usz n = 0;
  while (n < count) {
    i64 r = wired_udp_recvfrom(fd, bufs[n].buf, &bufs[n].src);
    if (r <= 0) break;
    bufs[n].len = (u32)r;
    n += 1;
  }
  return (i64)n;
}

/* SOL_SOCKET setsockopt level constant (Linux). */
#define WIRED_SOL_SOCKET 1
/* SO_REUSEPORT setsockopt name (Linux, kernel >= 3.9). */
#define WIRED_SO_REUSEPORT 15

i64 wired_udp_reuseport_enable(i64 fd) {
  int val = 1;
  return syscall6(
      SYS_setsockopt, fd, WIRED_SOL_SOCKET, WIRED_SO_REUSEPORT, (i64)&val,
      sizeof(val), 0);
}

/* MSG_DONTWAIT (linux/socket.h): non-blocking for this call only, unlike
 * O_NONBLOCK which is a persistent open-file-description flag. */
#define WIRED_MSG_DONTWAIT 0x40

i64 wired_udp_recvmmsg_nowait(i64 fd, quic_mmsg_buf* bufs, usz count) {
  quic_mmsghdr slots[WIRED_RECVMMSG_MAX] = {0};
  quic_iovec   iovs[WIRED_RECVMMSG_MAX]  = {0};
  usz          n = count < WIRED_RECVMMSG_MAX ? count : WIRED_RECVMMSG_MAX;
  i64          r;
  recvmmsg_fill_all(slots, iovs, bufs, n);
  r = syscall6(
      SYS_recvmmsg, fd, (i64)slots, (i64)n,
      WIRED_MSG_WAITFORONE | WIRED_MSG_DONTWAIT, 0, 0);
  if (r < 0) return r;
  recvmmsg_read_lens(bufs, slots, r);
  return r;
}

/* SO_BUSY_POLL setsockopt name (Linux, needs CONFIG_NET_RX_BUSY_POLL). Level
 * is SOL_SOCKET (reused from wired_udp_reuseport_enable above) with an int
 * microsecond value — unlike WIRED_SOL_UDP/u16 used by the GSO setsockopt. */
#define WIRED_SO_BUSY_POLL 46

i64 wired_udp_busy_poll_enable(i64 fd, int microseconds) {
  return syscall6(
      SYS_setsockopt, fd, WIRED_SOL_SOCKET, WIRED_SO_BUSY_POLL,
      (i64)&microseconds, sizeof(microseconds), 0);
}
