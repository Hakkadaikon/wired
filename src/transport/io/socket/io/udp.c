#include "transport/io/socket/io/udp.h"

#include "common/bytes/util/bytes.h"

/* SOL_UDP setsockopt level constant (Linux). Internal-only: no caller outside
 * this file needs the raw setsockopt args. */
#define WIRED_SOL_UDP 17
/* UDP_SEGMENT setsockopt name (Linux GSO, kernel >= 4.18). */
#define WIRED_UDP_SEGMENT 103

/* IPPROTO_IP setsockopt level constant (Linux uapi in.h). */
#define WIRED_IPPROTO_IP 0
/* IP_TOS setsockopt/cmsg name (Linux uapi in.h): the IPv4 TOS byte, whose
 * low 2 bits carry the RFC 3168 ECN codepoint. */
#define WIRED_IP_TOS 1
/* IP_RECVTOS setsockopt name (Linux uapi in.h): ask the kernel to attach an
 * IP_TOS cmsg to every received datagram carrying the packet's ECN bits. */
#define WIRED_IP_RECVTOS 13

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
  for (usz i = 0; i < 4; i++) addr[12 + i] = octets[i];
}

void wired_udp_addr(quic_sockaddr* sa, u16 port, const u8 octets[4]) {
  for (usz i = 0; i < 16; i++) sa->addr[i] = 0;
  sa->family   = WIRED_AF_INET6;
  sa->port_be  = hton16(port);
  sa->flowinfo = 0;
  sa->scope_id = 0;
  /* all-zero octets ask for the dual-stack any-address :: -- a mapped
   * ::ffff:0.0.0.0 would bind the socket IPv4-only (see udp.h). */
  if (!udp_octets_zero(octets)) udp_addr_map4(sa->addr, octets);
}

/* IPPROTO_IPV6 setsockopt level constant (Linux uapi in.h). */
#define WIRED_IPPROTO_IPV6 41
/* IPV6_V6ONLY setsockopt name (Linux uapi in6.h). */
#define WIRED_IPV6_V6ONLY 26

i64 wired_udp_socket(void) {
  int v6only = 0;
  i64 fd     = syscall3(SYS_socket, WIRED_AF_INET6, WIRED_SOCK_DGRAM, 0);
  if (fd < 0) return fd;
  /* dual stack: v4 peers arrive v4-mapped on the same fd. Linux defaults
   * IPV6_V6ONLY to 0 already; setting it explicitly pins the behavior
   * against a flipped net.ipv6.bindv6only sysctl. */
  syscall6(
      SYS_setsockopt, fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_V6ONLY, (i64)&v6only,
      sizeof(v6only), 0);
  return fd;
}

i64 wired_udp_bind(i64 fd, const quic_sockaddr* sa) {
  return syscall3(SYS_bind, fd, sa, sizeof(*sa));
}

i64 wired_udp_send(i64 fd, const quic_sockaddr* sa, quic_span buf) {
  return syscall6(
      SYS_sendto, fd, (i64)buf.p, (i64)buf.n, 0, (i64)sa, sizeof(*sa));
}

i64 wired_udp_recv(i64 fd, quic_mspan buf) {
  return syscall6(SYS_recvfrom, fd, (i64)buf.p, (i64)buf.n, 0, 0, 0);
}

i64 wired_udp_recvfrom(i64 fd, quic_mspan buf, quic_sockaddr* src) {
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

/* RFC 3168 / RFC 9000 13.4.1: ECT(0) codepoint (0b10) as the IPv4 TOS byte's
 * low 2 bits (the upper 6 bits, DSCP, are left 0). */
#define WIRED_ECT0_TOS 2

/* IPV6_TCLASS setsockopt/cmsg name (Linux uapi in6.h): the IPv6 traffic
 * class byte, ECN in the low 2 bits like the v4 TOS. */
#define WIRED_IPV6_TCLASS 67
/* IPV6_RECVTCLASS setsockopt name (Linux uapi in6.h). */
#define WIRED_IPV6_RECVTCLASS 66

i64 wired_udp_ect0_enable(i64 fd) {
  int val = WIRED_ECT0_TOS;
  /* dual stack: IP_TOS marks the v4-mapped sends, IPV6_TCLASS the native
   * v6 ones; the v6 option is best-effort (its failure never voids the
   * still-working v4 marking). */
  syscall6(
      SYS_setsockopt, fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_TCLASS, (i64)&val,
      sizeof(val), 0);
  return syscall6(
      SYS_setsockopt, fd, WIRED_IPPROTO_IP, WIRED_IP_TOS, (i64)&val,
      sizeof(val), 0);
}

i64 wired_udp_recvtos_enable(i64 fd) {
  int val = 1;
  /* same dual-stack pairing as wired_udp_ect0_enable above. */
  syscall6(
      SYS_setsockopt, fd, WIRED_IPPROTO_IPV6, WIRED_IPV6_RECVTCLASS, (i64)&val,
      sizeof(val), 0);
  return syscall6(
      SYS_setsockopt, fd, WIRED_IPPROTO_IP, WIRED_IP_RECVTOS, (i64)&val,
      sizeof(val), 0);
}

i64 wired_udp_send_gso(
    i64 fd, const quic_sockaddr* sa, quic_span buf, u16 segsize) {
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
    i64 fd, const quic_sockaddr* sa, quic_span buf, u16 segsize) {
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

/* Byte capacity of the recvmmsg() cmsg buffer allocated per slot: room for one
 * IP_TOS cmsg (CMSG_SPACE(sizeof(int)) = 24, same layout family as
 * WIRED_GSO_CMSG_SPACE) plus WIRED_CMSG_SLACK bytes so an unrelated cmsg
 * ahead of IP_TOS is not itself truncated by MSG_CTRUNC. */
#define WIRED_CMSG_SLACK 32
#define WIRED_RECV_CMSG_CAP (WIRED_GSO_CMSG_SPACE + WIRED_CMSG_SLACK)

/* Linux cmsghdr (man 3 cmsg / uapi socket.h): cmsg_len covers the header
 * itself plus payload; the next entry starts at CMSG_ALIGN(cmsg_len) (8-byte
 * boundary), mirroring wired_udp_gso_cmsg_build's manual layout. */
#define WIRED_CMSG_HDR_LEN 16
static u64 cmsg_align(u64 n) { return (n + 7) & ~(u64)7; }

/* 1 if [off, off + WIRED_CMSG_HDR_LEN) is a well-formed cmsg header inside
 * [0, controllen): cmsg_len is read only after this passes, so a malformed
 * or truncated header never drives an out-of-bounds read of the length
 * field or the payload it claims to have. */
static int cmsg_entry_in_bounds(const u8* control, u64 controllen, u64 off) {
  u64 cmsg_len;
  if (off + WIRED_CMSG_HDR_LEN > controllen) return 0;
  cmsg_len = *(const u64*)(control + off);
  /* cmsg_len must cover at least its own header and fit inside the buffer
   * the kernel actually wrote: 0 or an overflowing length is not a valid
   * entry, not "no ECN reported". */
  return cmsg_len >= WIRED_CMSG_HDR_LEN && off + cmsg_len <= controllen;
}

/* 1 if (level, type) names an ECN-carrying byte: the v4 IP_TOS or the v6
 * IPV6_TCLASS (a dual-stack socket delivers whichever family the datagram
 * actually arrived under). */
static int cmsg_is_ip_tos_pair(i32 level, i32 type) {
  return level == WIRED_IPPROTO_IP && type == WIRED_IP_TOS;
}

static int cmsg_type_carries_ecn(i32 level, i32 type) {
  if (cmsg_is_ip_tos_pair(level, type)) return 1;
  return level == WIRED_IPPROTO_IPV6 && type == WIRED_IPV6_TCLASS;
}

static int cmsg_entry_is_ip_tos(const u8* control, u64 off, u8* tos) {
  i32 level = *(const i32*)(control + off + 8);
  i32 type  = *(const i32*)(control + off + 12);
  if (!cmsg_type_carries_ecn(level, type)) return 0;
  *tos = control[off + WIRED_CMSG_HDR_LEN] & 0x03;
  return 1;
}

/* Walk the cmsg buffer the kernel filled (IP_RECVTOS) looking for an IP_TOS
 * entry, skipping any unrelated ones ahead of it. Returns the ECN codepoint
 * (0..3) found, or 0 (Not-ECT) when absent/truncated/malformed -- 0 is
 * always the safe fallback since it never falsely inflates the ECT/CE
 * accumulators. */
static u8 cmsg_read_ip_tos(const u8* control, u64 controllen) {
  u64 off = 0;
  u8  tos;
  while (cmsg_entry_in_bounds(control, controllen, off)) {
    u64 cmsg_len = *(const u64*)(control + off);
    if (cmsg_entry_is_ip_tos(control, off, &tos)) return tos;
    off += cmsg_align(cmsg_len);
  }
  return 0;
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
 * directly into the caller's storage; src doubles as msg_name. cmsgbuf is a
 * caller-owned WIRED_RECV_CMSG_CAP-byte scratch slot for the kernel to fill
 * with the IP_TOS ancillary message (RFC 3168 ECN bits) when IP_RECVTOS is
 * enabled on fd; a socket without it enabled simply gets msg_controllen
 * back as 0. Zeroes the whole slot first so no uninitialized stack bytes
 * (e.g. msg_control/msg_controllen) ever reach the recvmmsg(2) syscall. */
static void recvmmsg_fill_slot(
    quic_mmsghdr* slot, quic_iovec* iov, quic_mmsg_buf* b, u8* cmsgbuf) {
  *slot                        = (quic_mmsghdr){0};
  iov->iov_base                = b->buf.p;
  iov->iov_len                 = b->buf.n;
  slot->msg_hdr.msg_name       = &b->src;
  slot->msg_hdr.msg_namelen    = sizeof(b->src);
  slot->msg_hdr.msg_iov        = iov;
  slot->msg_hdr.msg_iovlen     = 1;
  slot->msg_hdr.msg_control    = cmsgbuf;
  slot->msg_hdr.msg_controllen = WIRED_RECV_CMSG_CAP;
}

/* Fill every slot the syscall will read from. cmsgbufs is WIRED_RECVMMSG_MAX
 * slots of WIRED_RECV_CMSG_CAP bytes each, one per bufs[i]: distinct scratch
 * per slot, so batched ECN bits never cross-contaminate. */
static void recvmmsg_fill_all(
    quic_mmsghdr*  slots,
    quic_iovec*    iovs,
    quic_mmsg_buf* bufs,
    usz            n,
    u8             cmsgbufs[][WIRED_RECV_CMSG_CAP]) {
  for (usz i = 0; i < n; i++)
    recvmmsg_fill_slot(&slots[i], &iovs[i], &bufs[i], cmsgbufs[i]);
}

/* Copy the kernel-filled length back into each received slot. */
static void recvmmsg_read_lens(
    quic_mmsg_buf* bufs, const quic_mmsghdr* slots, i64 r) {
  for (i64 i = 0; i < r; i++) bufs[i].len = slots[i].msg_len;
}

/* MSG_CTRUNC (linux/socket.h): the kernel truncated the ancillary (cmsg)
 * data because msg_controllen was too small -- a partially-written cmsg
 * buffer must not be trusted, so this slot falls back to Not-ECT (0) the
 * same as cmsg_read_ip_tos's other malformed-input paths. */
#define WIRED_MSG_CTRUNC 0x20

/* Read each received slot's ECN bits from the cmsg buffer the kernel
 * filled, honoring MSG_CTRUNC. */
static void recvmmsg_read_ecn(
    quic_mmsg_buf* bufs, const quic_mmsghdr* slots, i64 r) {
  for (i64 i = 0; i < r; i++) {
    const quic_msghdr* h = &slots[i].msg_hdr;
    bufs[i].ecn = (h->msg_flags & WIRED_MSG_CTRUNC)
                      ? 0
                      : cmsg_read_ip_tos(h->msg_control, h->msg_controllen);
  }
}

/* MSG_WAITFORONE (linux/socket.h): block for the first datagram only, then
 * return with whatever else is already queued. Without it, a blocking socket
 * with a NULL timeout waits until ALL count slots are filled — a receive
 * loop asking for a full batch would hang on a single arriving datagram. */
#define WIRED_MSG_WAITFORONE 0x10000

i64 wired_udp_recvmmsg(i64 fd, quic_mmsg_buf* bufs, usz count) {
  quic_mmsghdr slots[WIRED_RECVMMSG_MAX]                         = {0};
  quic_iovec   iovs[WIRED_RECVMMSG_MAX]                          = {0};
  u8           cmsgbufs[WIRED_RECVMMSG_MAX][WIRED_RECV_CMSG_CAP] = {0};
  usz          n = count < WIRED_RECVMMSG_MAX ? count : WIRED_RECVMMSG_MAX;
  i64          r;
  recvmmsg_fill_all(slots, iovs, bufs, n, cmsgbufs);
  r = syscall6(
      SYS_recvmmsg, fd, (i64)slots, (i64)n, WIRED_MSG_WAITFORONE, 0, 0);
  if (r < 0) return r;
  recvmmsg_read_lens(bufs, slots, r);
  recvmmsg_read_ecn(bufs, slots, r);
  return r;
}

i64 wired_udp_recvmmsg_fallback(i64 fd, quic_mmsg_buf* bufs, usz count) {
  usz n = 0;
  while (n < count) {
    i64 r = wired_udp_recvfrom(fd, bufs[n].buf, &bufs[n].src);
    if (r <= 0) break;
    bufs[n].len = (u32)r;
    /* wired_udp_recvfrom carries no cmsg (recvfrom(2) has none): Not-ECT (0)
     * is the safe fallback, same as an absent IP_TOS cmsg. */
    bufs[n].ecn = 0;
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
  quic_mmsghdr slots[WIRED_RECVMMSG_MAX]                         = {0};
  quic_iovec   iovs[WIRED_RECVMMSG_MAX]                          = {0};
  u8           cmsgbufs[WIRED_RECVMMSG_MAX][WIRED_RECV_CMSG_CAP] = {0};
  usz          n = count < WIRED_RECVMMSG_MAX ? count : WIRED_RECVMMSG_MAX;
  i64          r;
  recvmmsg_fill_all(slots, iovs, bufs, n, cmsgbufs);
  r = syscall6(
      SYS_recvmmsg, fd, (i64)slots, (i64)n,
      WIRED_MSG_WAITFORONE | WIRED_MSG_DONTWAIT, 0, 0);
  if (r < 0) return r;
  recvmmsg_read_lens(bufs, slots, r);
  recvmmsg_read_ecn(bufs, slots, r);
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

/* SO_PREFER_BUSY_POLL setsockopt name (Linux). Only has kernel effect when
 * SO_BUSY_POLL is also enabled. */
#define WIRED_SO_PREFER_BUSY_POLL 69

i64 wired_udp_prefer_busy_poll_enable(i64 fd, int enable) {
  return syscall6(
      SYS_setsockopt, fd, WIRED_SOL_SOCKET, WIRED_SO_PREFER_BUSY_POLL,
      (i64)&enable, sizeof(enable), 0);
}

/* SO_BUSY_POLL_BUDGET setsockopt name (Linux): caps packets processed per
 * busy-poll spin. */
#define WIRED_SO_BUSY_POLL_BUDGET 70

i64 wired_udp_busy_poll_budget_set(i64 fd, int budget) {
  return syscall6(
      SYS_setsockopt, fd, WIRED_SOL_SOCKET, WIRED_SO_BUSY_POLL_BUDGET,
      (i64)&budget, sizeof(budget), 0);
}

/* SO_INCOMING_CPU setsockopt name (Linux). SET direction only: no
 * getsockopt wrapper exists in this libc-free SDK, and adding the first one
 * is out of scope for this feature. */
#define WIRED_SO_INCOMING_CPU 49

i64 wired_udp_incoming_cpu_set(i64 fd, int cpu) {
  return syscall6(
      SYS_setsockopt, fd, WIRED_SOL_SOCKET, WIRED_SO_INCOMING_CPU, (i64)&cpu,
      sizeof(cpu), 0);
}
