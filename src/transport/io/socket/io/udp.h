#ifndef WIRED_IO_UDP_H
#define WIRED_IO_UDP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * UDP via direct x86_64 syscalls, dual-stack (one AF_INET6 socket serves
 * IPv6 natively and IPv4 as v4-mapped addresses). No libc. */

/** AF_INET address family constant. */
#define WIRED_AF_INET 2
/** AF_INET6 address family constant. */
#define WIRED_AF_INET6 10
/** SOCK_DGRAM socket type constant. */
#define WIRED_SOCK_DGRAM 2

/** A sockaddr_in6 laid out for the kernel (big-endian port; a 16-byte
 * address that is either native IPv6 or an IPv4-mapped ::ffff:a.b.c.d).
 * Every socket this SDK opens is AF_INET6 with IPV6_V6ONLY off, so this one
 * shape addresses both families. */
typedef struct {
  u16 family;   /**< WIRED_AF_INET6 */
  u16 port_be;  /**< network byte order */
  u32 flowinfo; /**< sin6_flowinfo, zeroed */
  u8  addr[16]; /**< native IPv6, or v4-mapped ::ffff:a.b.c.d */
  u32 scope_id; /**< sin6_scope_id, zeroed */
} quic_sockaddr;

/** Build an address from host-order port and IPv4 octets[0..3] = a.b.c.d,
 * as the v4-mapped ::ffff:a.b.c.d — or, when the octets are all zero, the
 * unspecified :: (the dual-stack bind-any address; a mapped 0.0.0.0 would
 * bind IPv4-only).
 * @param sa receives the kernel-ready address
 * @param port UDP port in host byte order
 * @param octets IPv4 address octets a.b.c.d */
void wired_udp_addr(quic_sockaddr* sa, u16 port, const u8 octets[4]);

/** Read a v4-mapped (or any) address's IPv4 bytes as a big-endian u32 —
 * the accessor the IPv4-only paths (AF_XDP framing, MAC learning) use.
 * @param sa the address to read
 * @return addr[12..15] as a big-endian u32 */
static inline u32 wired_udp_addr4_be(const quic_sockaddr* sa) {
  return ((u32)sa->addr[12] << 24) | ((u32)sa->addr[13] << 16) |
         ((u32)sa->addr[14] << 8) | sa->addr[15];
}

/** Create a dual-stack UDP socket: AF_INET6 with IPV6_V6ONLY disabled, so
 * IPv4 peers arrive as v4-mapped addresses on the same fd.
 * @return the fd, or a negative errno on failure. */
i64 wired_udp_socket(void);

/** Bind fd to sa. Ownership of fd stays with the caller; wired_udp_bind
 * neither closes it on failure nor takes it over on success.
 * @param fd the socket fd
 * @param sa the local address to bind
 * @return 0 on success or a negative errno. */
i64 wired_udp_bind(i64 fd, const quic_sockaddr* sa);

/** Send buf to sa.
 * @param fd the socket fd
 * @param sa the destination address
 * @param buf the datagram to send
 * @return bytes sent or a negative errno. */
i64 wired_udp_send(i64 fd, const quic_sockaddr* sa, quic_span buf);

/** Receive up to buf.n bytes into buf.p.
 * @param fd the socket fd
 * @param buf destination buffer
 * @return bytes read or a negative errno. */
i64 wired_udp_recv(i64 fd, quic_mspan buf);

/** Receive up to buf.n bytes into buf.p and write the source address into
 * src.
 * @param fd the socket fd
 * @param buf destination buffer
 * @param src receives the datagram's source address
 * @return bytes read or a negative errno. */
i64 wired_udp_recvfrom(i64 fd, quic_mspan buf, quic_sockaddr* src);

/** Close fd. Takes ownership of fd: after this call fd is invalid regardless
 * of the return value, and the caller must not use or close it again.
 * @param fd the socket fd
 * @return 0 on success or a negative errno. */
i64 wired_udp_close(i64 fd);

/** Byte length of a UDP_SEGMENT cmsg (header + u16 payload, 8-byte aligned). */
#define WIRED_GSO_CMSG_SPACE 24

/** Enable UDP GSO on fd: kernel will split a large sendmsg() payload into
 * segsize-byte datagrams (Linux UDP_SEGMENT, kernel >= 4.18).
 * @param fd the socket fd
 * @param segsize per-segment byte size
 * @return 0 on success, or a negative errno (e.g. unsupported kernel). */
i64 wired_udp_gso_enable(i64 fd, u16 segsize);

/** Build a UDP_SEGMENT cmsg buffer for sendmsg() into
 * out[0..WIRED_GSO_CMSG_SPACE). Pure byte-layout builder, no syscall:
 * cmsg_len=18, cmsg_level=SOL_UDP, cmsg_type=UDP_SEGMENT, followed by segsize
 * as a little-endian u16, zero- padded to WIRED_GSO_CMSG_SPACE bytes (Linux
 * CMSG_SPACE(sizeof(u16))).
 * @param out destination buffer, must be >= WIRED_GSO_CMSG_SPACE bytes
 * @param segsize per-segment byte size to encode */
void wired_udp_gso_cmsg_build(u8 out[WIRED_GSO_CMSG_SPACE], u16 segsize);

/** Send count back-to-back segsize-byte segments (the last may be shorter,
 * total = buf.n) to sa in one sendmsg() syscall using UDP GSO.
 * @param fd the socket fd (GSO already enabled via wired_udp_gso_enable)
 * @param sa the destination address
 * @param buf the concatenated segments to send
 * @param segsize per-segment byte size (last segment may be shorter)
 * @return total bytes sent, or a negative errno (e.g. the caller should fall
 *   back to wired_udp_send_batch when fd has no UDP_SEGMENT support). */
i64 wired_udp_send_gso(
    i64 fd, const quic_sockaddr* sa, quic_span buf, u16 segsize);

/** Send count back-to-back segsize-byte segments to sa via one sendto() call
 * per segment (no GSO). The last segment may be shorter (total = buf.n). The
 * fallback path for a kernel without UDP_SEGMENT support.
 * @param fd the socket fd
 * @param sa the destination address
 * @param buf the concatenated segments to send
 * @param segsize per-segment byte size (last segment may be shorter)
 * @return total bytes sent, or a negative errno on the first failure. */
i64 wired_udp_send_batch(
    i64 fd, const quic_sockaddr* sa, quic_span buf, u16 segsize);

/** One slot of a recvmmsg() batch: caller-owned receive buffer and source
 * address, filled in by wired_udp_recvmmsg on return. */
typedef struct {
  quic_mspan    buf; /**< in: destination buffer; unused bytes untouched */
  quic_sockaddr src; /**< out: datagram's source address */
  u32           len; /**< out: bytes received into buf.p */
  /** out: RFC 3168 ECN codepoint of the received IP header (0 = Not-ECT,
   * 1 = ECT(1), 2 = ECT(0), 3 = CE), read from the IP_TOS cmsg when
   * IP_RECVTOS is enabled on the socket (wired_udp_ect0_enable does not
   * itself enable it -- see its doc). 0 when no cmsg was present, the cmsg
   * was truncated (MSG_CTRUNC), or the receive path (e.g.
   * wired_udp_recvmmsg_fallback) has no cmsg support at all -- always the
   * safe "not ECN-marked" reading, never a false ECT/CE count. */
  u8 ecn;
} quic_mmsg_buf;

/** Receive up to count datagrams in one recvmmsg() syscall (Linux GRO-style
 * batched receive, kernel >= 2.6.33). Each bufs[i].buf is a caller-owned
 * destination buffer; on return bufs[i].len and bufs[i].src are filled for
 * the first N slots actually received. On a blocking socket the call waits
 * for the first datagram only (MSG_WAITFORONE) and then returns with
 * whatever else was already queued, so a receive loop may always offer a
 * full batch of slots without risking a wait for the whole batch.
 * @param fd the socket fd
 * @param bufs array of count receive slots
 * @param count number of slots in bufs
 * @return number of datagrams received, or a negative errno (e.g. ENOSYS on
 *   a kernel without recvmmsg) — the caller should fall back to
 *   wired_udp_recvmmsg_fallback in that case. */
i64 wired_udp_recvmmsg(i64 fd, quic_mmsg_buf* bufs, usz count);

/** Receive up to count datagrams via a wired_udp_recvfrom() loop (one syscall
 * per datagram), stopping at the first empty/error result. The always-
 * available fallback path for a kernel without recvmmsg support — symmetric
 * with wired_udp_send_batch on the send side.
 * @param fd the socket fd
 * @param bufs array of count receive slots
 * @param count number of slots in bufs
 * @return number of datagrams received (0..count). */
i64 wired_udp_recvmmsg_fallback(i64 fd, quic_mmsg_buf* bufs, usz count);

/** Enable ECT(0) marking (RFC 3168, RFC 9000 13.4.1) on every packet fd sends:
 * sets the IPv4 TOS byte's low 2 bits to 0b10 via IP_TOS (Linux uapi in.h).
 * RFC 9000 13.4.1 recommends ECT(0) as the default codepoint; this SDK never
 * sends ECT(1) (see udp.c's cmsg reader, which still accepts ECT(1) on
 * receive for a peer that does).
 * ponytail: no fallback path on setsockopt failure -- the error propagates
 * to the caller as-is. quic-interop-runner's execution environment
 * (Linux container, IPv4 UDP) has IP_TOS/IP_RECVTOS available unconditionally,
 * so a degraded-but-functional non-ECN send path is out of this SDK's scope;
 * add one if a real deployment target ever lacks IP_TOS.
 * @param fd the socket fd
 * @return 0 on success, or a negative errno. */
i64 wired_udp_ect0_enable(i64 fd);

/** Enable IP_RECVTOS on fd (Linux uapi in.h) so wired_udp_recvmmsg/
 * wired_udp_recvmmsg_nowait attach each received datagram's ECN codepoint
 * into quic_mmsg_buf.ecn via an IP_TOS cmsg. Independent of
 * wired_udp_ect0_enable: a socket may receive ECN reports without marking
 * its own outgoing packets, or vice versa.
 * ponytail: no fallback on failure, same scope note as wired_udp_ect0_enable.
 * @param fd the socket fd
 * @return 0 on success, or a negative errno. */
i64 wired_udp_recvtos_enable(i64 fd);

/** Enable SO_REUSEPORT on fd so multiple sockets (e.g. one per worker
 * process) can bind the same port; the kernel shards incoming datagrams
 * across them by a 4-tuple hash (Linux, kernel >= 3.9).
 * @param fd the socket fd
 * @return 0 on success, or a negative errno. */
i64 wired_udp_reuseport_enable(i64 fd);

/** Same as wired_udp_recvmmsg but non-blocking (MSG_DONTWAIT): returns
 * immediately with a negative errno (e.g. EAGAIN) if no datagram is queued,
 * instead of waiting for the first one.
 * @param fd the socket fd
 * @param bufs array of count receive slots
 * @param count number of slots in bufs
 * @return number of datagrams received, or a negative errno. */
i64 wired_udp_recvmmsg_nowait(i64 fd, quic_mmsg_buf* bufs, usz count);

/** Enable SO_BUSY_POLL on fd: the kernel spins the driver's poll routine for
 * up to microseconds before sleeping (Linux, needs CONFIG_NET_RX_BUSY_POLL
 * and driver support; a no-op on kernels/drivers without it). The codec does
 * not interpret magnitude — 0 is a valid value, it just disables this knob.
 * @param fd the socket fd
 * @param microseconds busy-poll budget in microseconds
 * @return 0 on success, or a negative errno. */
i64 wired_udp_busy_poll_enable(i64 fd, int microseconds);

/** Enable/disable SO_PREFER_BUSY_POLL on fd: prefers busy-polling over
 * interrupts for this socket. Only has kernel effect when SO_BUSY_POLL
 * (wired_udp_busy_poll_enable with microseconds > 0) is also enabled on the
 * same fd (Linux, needs CONFIG_NET_RX_BUSY_POLL and driver support).
 * @param fd the socket fd
 * @param enable 0 or 1
 * @return 0 on success, or a negative errno. */
i64 wired_udp_prefer_busy_poll_enable(i64 fd, int enable);

/** Set SO_BUSY_POLL_BUDGET on fd: caps how many packets a single busy-poll
 * spin processes before yielding (Linux, needs CONFIG_NET_RX_BUSY_POLL).
 * @param fd the socket fd
 * @param budget packet budget per spin
 * @return 0 on success, or a negative errno. */
i64 wired_udp_busy_poll_budget_set(i64 fd, int budget);

/** Set SO_INCOMING_CPU on fd: hints the kernel to steer this socket's
 * incoming packets toward the given CPU (RPS/RSS steering, Linux). SET
 * direction only -- this libc-free SDK has no getsockopt infrastructure, so
 * there is no corresponding getter.
 * @param fd the socket fd
 * @param cpu target CPU number
 * @return 0 on success, or a negative errno. */
i64 wired_udp_incoming_cpu_set(i64 fd, int cpu);

#endif
