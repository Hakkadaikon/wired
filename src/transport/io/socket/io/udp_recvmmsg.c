#include "transport/io/socket/io/udp_impl.h"

static void recvmmsg_fill_slot(
    mmsghdr* slot, iovec* iov, mmsg_buf* b, u8* cmsgbuf);
static void recvmmsg_fill_all(
    mmsghdr*  slots,
    iovec*    iovs,
    mmsg_buf* bufs,
    usz       n,
    u8        cmsgbufs[][WIRED_RECV_CMSG_CAP]);
static void recvmmsg_read_lens(mmsg_buf* bufs, const mmsghdr* slots, i64 r);
static void recvmmsg_read_ecn(mmsg_buf* bufs, const mmsghdr* slots, i64 r);

/* Point one iovec+msghdr+mmsghdr slot at bufs[i].buf so the kernel writes
 * directly into the caller's storage; src doubles as msg_name. cmsgbuf is a
 * caller-owned WIRED_RECV_CMSG_CAP-byte scratch slot for the kernel to fill
 * with the IP_TOS ancillary message (RFC 3168 ECN bits) when IP_RECVTOS is
 * enabled on fd; a socket without it enabled simply gets msg_controllen
 * back as 0. Zeroes the whole slot first so no uninitialized stack bytes
 * (e.g. msg_control/msg_controllen) ever reach the recvmmsg(2) syscall. */
static void recvmmsg_fill_slot(
    mmsghdr* slot, iovec* iov, mmsg_buf* b, u8* cmsgbuf) {
  *slot                        = (mmsghdr){0};
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
    mmsghdr*  slots,
    iovec*    iovs,
    mmsg_buf* bufs,
    usz       n,
    u8        cmsgbufs[][WIRED_RECV_CMSG_CAP]) {
  for (usz i = 0; i < n; i++)
    recvmmsg_fill_slot(&slots[i], &iovs[i], &bufs[i], cmsgbufs[i]);
}

/* Copy the kernel-filled length back into each received slot, and turn an
 * AF_INET fd's source address back into the v4-mapped form. */
static void recvmmsg_read_lens(mmsg_buf* bufs, const mmsghdr* slots, i64 r) {
  for (i64 i = 0; i < r; i++) {
    bufs[i].len = slots[i].msg_len;
    udp_kaddr_in(&bufs[i].src);
  }
}

/* Read each received slot's ECN bits from the cmsg buffer the kernel
 * filled, honoring MSG_CTRUNC. */
static void recvmmsg_read_ecn(mmsg_buf* bufs, const mmsghdr* slots, i64 r) {
  for (i64 i = 0; i < r; i++) {
    const msghdr* h = &slots[i].msg_hdr;
    bufs[i].ecn = (h->msg_flags & WIRED_MSG_CTRUNC)
                      ? 0
                      : udp_cmsg_read_ip_tos(h->msg_control, h->msg_controllen);
  }
}

i64 wired_udp_recvmmsg(i64 fd, mmsg_buf* bufs, usz count) {
  mmsghdr slots[WIRED_RECVMMSG_MAX]                         = {0};
  iovec   iovs[WIRED_RECVMMSG_MAX]                          = {0};
  u8      cmsgbufs[WIRED_RECVMMSG_MAX][WIRED_RECV_CMSG_CAP] = {0};
  usz     n = count < WIRED_RECVMMSG_MAX ? count : WIRED_RECVMMSG_MAX;
  i64     r;
  recvmmsg_fill_all(slots, iovs, bufs, n, cmsgbufs);
  r = wired_arch_recvmmsg(fd, slots, n, WIRED_MSG_WAITFORONE, 0);
  if (r < 0) return r;
  recvmmsg_read_lens(bufs, slots, r);
  recvmmsg_read_ecn(bufs, slots, r);
  return r;
}

i64 wired_udp_recvmmsg_fallback(i64 fd, mmsg_buf* bufs, usz count) {
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

i64 wired_udp_reuseport_enable(i64 fd) {
  int val = 1;
  return wired_arch_setsockopt(
      fd, WIRED_SOL_SOCKET, WIRED_SO_REUSEPORT, &val, sizeof(val));
}

i64 wired_udp_recvmmsg_nowait(i64 fd, mmsg_buf* bufs, usz count) {
  mmsghdr slots[WIRED_RECVMMSG_MAX]                         = {0};
  iovec   iovs[WIRED_RECVMMSG_MAX]                          = {0};
  u8      cmsgbufs[WIRED_RECVMMSG_MAX][WIRED_RECV_CMSG_CAP] = {0};
  usz     n = count < WIRED_RECVMMSG_MAX ? count : WIRED_RECVMMSG_MAX;
  i64     r;
  recvmmsg_fill_all(slots, iovs, bufs, n, cmsgbufs);
  r = wired_arch_recvmmsg(
      fd, slots, n, WIRED_MSG_WAITFORONE | WIRED_MSG_DONTWAIT, 0);
  if (r < 0) return r;
  recvmmsg_read_lens(bufs, slots, r);
  recvmmsg_read_ecn(bufs, slots, r);
  return r;
}

i64 wired_udp_busy_poll_enable(i64 fd, int microseconds) {
  return wired_arch_setsockopt(
      fd, WIRED_SOL_SOCKET, WIRED_SO_BUSY_POLL, &microseconds,
      sizeof(microseconds));
}

i64 wired_udp_prefer_busy_poll_enable(i64 fd, int enable) {
  return wired_arch_setsockopt(
      fd, WIRED_SOL_SOCKET, WIRED_SO_PREFER_BUSY_POLL, &enable, sizeof(enable));
}

i64 wired_udp_busy_poll_budget_set(i64 fd, int budget) {
  return wired_arch_setsockopt(
      fd, WIRED_SOL_SOCKET, WIRED_SO_BUSY_POLL_BUDGET, &budget, sizeof(budget));
}

i64 wired_udp_incoming_cpu_set(i64 fd, int cpu) {
  return wired_arch_setsockopt(
      fd, WIRED_SOL_SOCKET, WIRED_SO_INCOMING_CPU, &cpu, sizeof(cpu));
}
