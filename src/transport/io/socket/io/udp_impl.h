#ifndef TRANSPORT_IO_SOCKET_IO_UDP_IMPL_H
#define TRANSPORT_IO_SOCKET_IO_UDP_IMPL_H

/* Internal to the udp*.c pieces of this directory: shared types, macros
 * and the functions and tables more than one piece uses. Not public API. */

#include "common/bytes/util/bytes.h"
#include "transport/io/socket/io/udp.h"

#define WIRED_SOL_UDP 17
#define WIRED_UDP_SEGMENT 103
#define WIRED_IPPROTO_IP 0
#define WIRED_IP_TOS 1
#define WIRED_IP_RECVTOS 13

/* IPPROTO_IPV6 setsockopt level constant (Linux uapi in.h). */
#define WIRED_IPPROTO_IPV6 41
/* IPV6_V6ONLY setsockopt name (Linux uapi in6.h). */
#define WIRED_IPV6_V6ONLY 26

/* EAFNOSUPPORT (Linux uapi errno-base.h): the kernel has no IPv6 at all
 * (booted with ipv6.disable=1), so no AF_INET6 socket can be created. */
#define WIRED_EAFNOSUPPORT 97

/* Kernel struct sockaddr_in size (uapi in.h): family, port, 4-byte address,
 * 8 bytes of zero padding. */
#define WIRED_SOCKADDR_IN_LEN 16

/* x86_64 Linux struct iovec (16 bytes): base pointer + length. Manually
 * defined per naming-and-unity-build.md — src/ may not include <sys/uio.h>. */
typedef struct {
  const void* iov_base;
  u64         iov_len;
} iovec;

/* x86_64 Linux struct msghdr (56 bytes), manually laid out to match the
 * kernel ABI for sendmsg(2) (man 2 sendmsg / uapi socket.h). */
typedef struct {
  const void* msg_name;
  u32         msg_namelen;
  u32         msg_namelen_pad; /* kernel struct has 4B padding here (LP64) */
  iovec*      msg_iov;
  u64         msg_iovlen;
  void*       msg_control;
  u64         msg_controllen;
  u32         msg_flags;
  u32         msg_flags_pad;
} msghdr;

/* RFC 3168 / RFC 9000 13.4.1: ECT(0) codepoint (0b10) as the IPv4 TOS byte's
 * low 2 bits (the upper 6 bits, DSCP, are left 0). */
#define WIRED_ECT0_TOS 2

/* IPV6_TCLASS setsockopt/cmsg name (Linux uapi in6.h): the IPv6 traffic
 * class byte, ECN in the low 2 bits like the v4 TOS. */
#define WIRED_IPV6_TCLASS 67
/* IPV6_RECVTCLASS setsockopt name (Linux uapi in6.h). */
#define WIRED_IPV6_RECVTCLASS 66

/* IP_MTU_DISCOVER setsockopt name (Linux uapi in.h). */
#define WIRED_IP_MTU_DISCOVER 10
/* IP_PMTUDISC_PROBE (Linux uapi in.h, ip(7)): set the DF bit but ignore the
 * kernel's own path MTU -- RFC 8899 4.5: network-layer PMTU enforcement is
 * suspended for a flow running DPLPMTUD, so a probe above a stale kernel
 * PMTU still leaves instead of failing locally with EMSGSIZE. The IPv6
 * option (IPV6_PMTUDISC_PROBE) shares the value. */
#define WIRED_IP_PMTUDISC_PROBE 3
/* IPV6_MTU_DISCOVER setsockopt name (Linux uapi in6.h). */
#define WIRED_IPV6_MTU_DISCOVER 23

/* One int-valued cmsg (CMSG_SPACE(sizeof(int)) = 24 bytes: u64 cmsg_len =
 * CMSG_LEN(4) = 20, i32 level, i32 type, the int, 4 pad) at out. */
#define WIRED_INT_CMSG_SPACE 24

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

/* x86_64 Linux struct mmsghdr (man 2 recvmmsg / uapi socket.h): the msghdr
 * above plus the kernel-filled received length. */
typedef struct {
  msghdr msg_hdr;
  u32    msg_len;
  u32    msg_len_pad; /* kernel struct has 4B padding here (LP64) */
} mmsghdr;

/* recvmmsg() caps count at IOV_MAX-equivalent batch sizes in practice; QUIC
 * datagram batches are always small, so a fixed on-stack cap is enough
 * (ponytail: fixed cap, raise WIRED_RECVMMSG_MAX if a caller ever needs more).
 */
#define WIRED_RECVMMSG_MAX 64

/* MSG_CTRUNC (linux/socket.h): the kernel truncated the ancillary (cmsg)
 * data because msg_controllen was too small -- a partially-written cmsg
 * buffer must not be trusted, so this slot falls back to Not-ECT (0) the
 * same as udp_cmsg_read_ip_tos's other malformed-input paths. */
#define WIRED_MSG_CTRUNC 0x20

/* MSG_WAITFORONE (linux/socket.h): block for the first datagram only, then
 * return with whatever else is already queued. Without it, a blocking socket
 * with a NULL timeout waits until ALL count slots are filled — a receive
 * loop asking for a full batch would hang on a single arriving datagram. */
#define WIRED_MSG_WAITFORONE 0x10000

/* SOL_SOCKET setsockopt level constant (Linux). */
#define WIRED_SOL_SOCKET 1
/* SO_REUSEPORT setsockopt name (Linux, kernel >= 3.9). */
#define WIRED_SO_REUSEPORT 15

/* MSG_DONTWAIT (linux/socket.h): non-blocking for this call only, unlike
 * O_NONBLOCK which is a persistent open-file-description flag. */
#define WIRED_MSG_DONTWAIT 0x40

/* SO_BUSY_POLL setsockopt name (Linux, needs CONFIG_NET_RX_BUSY_POLL). Level
 * is SOL_SOCKET (reused from wired_udp_reuseport_enable above) with an int
 * microsecond value — unlike WIRED_SOL_UDP/u16 used by the GSO cmsg. */
#define WIRED_SO_BUSY_POLL 46

/* SO_PREFER_BUSY_POLL setsockopt name (Linux). Only has kernel effect when
 * SO_BUSY_POLL is also enabled. */
#define WIRED_SO_PREFER_BUSY_POLL 69

/* SO_BUSY_POLL_BUDGET setsockopt name (Linux): caps packets processed per
 * busy-poll spin. */
#define WIRED_SO_BUSY_POLL_BUDGET 70

/* SO_INCOMING_CPU setsockopt name (Linux). SET direction only: no
 * getsockopt wrapper exists in this libc-free SDK, and adding the first one
 * is out of scope for this feature. */
#define WIRED_SO_INCOMING_CPU 49

u8 udp_cmsg_read_ip_tos(const u8* control, u64 controllen);

extern u16 udp_family;

#endif
