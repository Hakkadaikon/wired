#include "transport/io/socket/io/udp_impl.h"

static void udp_int_cmsg(u8* out, i32 level, i32 type, int val);
static usz  gso_batch_seglen(usz remaining, u16 segsize);
static u64  cmsg_align(u64 n);
static int  cmsg_entry_in_bounds(const u8* control, u64 controllen, u64 off);
static int  cmsg_is_ip_tos_pair(i32 level, i32 type);
static int  cmsg_type_carries_ecn(i32 level, i32 type);
static int  cmsg_entry_is_ip_tos(const u8* control, u64 off, u8* tos);

i64 wired_udp_send_gso(
    i64 fd, const sockaddr* sa, wired_span buf, u16 segsize) {
  u8       cmsg[WIRED_GSO_CMSG_SPACE];
  iovec    iov = {buf.p, buf.n};
  msghdr   msg = {0};
  sockaddr k;
  wired_udp_gso_cmsg_build(cmsg, segsize);
  msg.msg_name       = &k;
  msg.msg_namelen    = udp_kaddr_out(sa, udp_family, &k);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = cmsg;
  msg.msg_controllen = WIRED_GSO_CMSG_SPACE;
  return wired_arch_sendmsg(fd, &msg, 0);
}

static void udp_int_cmsg(u8* out, i32 level, i32 type, int val) {
  bytes_memset(out, 0, WIRED_INT_CMSG_SPACE);
  *(u64*)(out + 0)  = 20;
  *(i32*)(out + 8)  = level;
  *(i32*)(out + 12) = type;
  *(int*)(out + 16) = val;
}

i64 wired_udp_send_tos(i64 fd, const sockaddr* sa, wired_span buf, u8 tos) {
  u8       cmsg[2 * WIRED_INT_CMSG_SPACE];
  iovec    iov = {buf.p, buf.n};
  msghdr   msg = {0};
  sockaddr k;
  /* both: a v4 (or v4-mapped) send reads IP_TOS, a native v6 send
   * IPV6_TCLASS; each stack skips the other's level. */
  udp_int_cmsg(cmsg, WIRED_IPPROTO_IP, WIRED_IP_TOS, tos);
  udp_int_cmsg(
      cmsg + WIRED_INT_CMSG_SPACE, WIRED_IPPROTO_IPV6, WIRED_IPV6_TCLASS, tos);
  msg.msg_name       = &k;
  msg.msg_namelen    = udp_kaddr_out(sa, udp_family, &k);
  msg.msg_iov        = &iov;
  msg.msg_iovlen     = 1;
  msg.msg_control    = cmsg;
  msg.msg_controllen = sizeof cmsg;
  return wired_arch_sendmsg(fd, &msg, 0);
}

/* Length of the next segment starting at off: segsize, or the remainder if
 * shorter (the trailing segment). */
static usz gso_batch_seglen(usz remaining, u16 segsize) {
  return remaining < segsize ? remaining : segsize;
}

i64 wired_udp_send_batch(
    i64 fd, const sockaddr* sa, wired_span buf, u16 segsize) {
  usz off  = 0;
  i64 sent = 0;
  while (off < buf.n) {
    usz n = gso_batch_seglen(buf.n - off, segsize);
    i64 r = wired_udp_send(fd, sa, wired_span_of(buf.p + off, n));
    if (r < 0) {
      return r;
    }
    sent += r;
    off += n;
  }
  return sent;
}

static u64 cmsg_align(u64 n) { return (n + 7) & ~(u64)7; }

/* 1 if [off, off + WIRED_CMSG_HDR_LEN) is a well-formed cmsg header inside
 * [0, controllen): cmsg_len is read only after this passes, so a malformed
 * or truncated header never drives an out-of-bounds read of the length
 * field or the payload it claims to have. */
static int cmsg_entry_in_bounds(const u8* control, u64 controllen, u64 off) {
  u64 cmsg_len;
  if (off + WIRED_CMSG_HDR_LEN > controllen) {
    return 0;
  }
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
  if (cmsg_is_ip_tos_pair(level, type)) {
    return 1;
  }
  return level == WIRED_IPPROTO_IPV6 && type == WIRED_IPV6_TCLASS;
}

static int cmsg_entry_is_ip_tos(const u8* control, u64 off, u8* tos) {
  i32 level = *(const i32*)(control + off + 8);
  i32 type  = *(const i32*)(control + off + 12);
  if (!cmsg_type_carries_ecn(level, type)) {
    return 0;
  }
  *tos = control[off + WIRED_CMSG_HDR_LEN] & 0x03;
  return 1;
}

/* Walk the cmsg buffer the kernel filled (IP_RECVTOS) looking for an IP_TOS
 * entry, skipping any unrelated ones ahead of it. Returns the ECN codepoint
 * (0..3) found, or 0 (Not-ECT) when absent/truncated/malformed -- 0 is
 * always the safe fallback since it never falsely inflates the ECT/CE
 * accumulators. */
u8 udp_cmsg_read_ip_tos(const u8* control, u64 controllen) {
  u64 off = 0;
  u8  tos;
  while (cmsg_entry_in_bounds(control, controllen, off)) {
    u64 cmsg_len = *(const u64*)(control + off);
    if (cmsg_entry_is_ip_tos(control, off, &tos)) {
      return tos;
    }
    off += cmsg_align(cmsg_len);
  }
  return 0;
}
