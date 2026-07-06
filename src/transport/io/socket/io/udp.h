#ifndef WIRED_IO_UDP_H
#define WIRED_IO_UDP_H

#include "common/bytes/span/span.h"
#include "common/platform/sys/syscall.h"

/** @file
 * UDP over IPv4 via direct x86_64 syscalls. No libc. */

/** AF_INET address family constant. */
#define WIRED_AF_INET 2
/** SOCK_DGRAM socket type constant. */
#define WIRED_SOCK_DGRAM 2

/** A sockaddr_in laid out for the kernel (big-endian port and address). */
typedef struct {
  u16 family;  /**< WIRED_AF_INET */
  u16 port_be; /**< network byte order */
  u32 addr_be; /**< network byte order */
  u8  zero[8]; /**< padding, zeroed */
} quic_sockaddr_in;

/** Build a sockaddr_in from host-order port and IPv4 octets[0..3] = a.b.c.d.
 * @param sa receives the kernel-ready address
 * @param port UDP port in host byte order
 * @param octets IPv4 address octets a.b.c.d */
void wired_udp_addr(quic_sockaddr_in* sa, u16 port, const u8 octets[4]);

/** Create a UDP socket.
 * @return the fd, or a negative errno on failure. */
i64 wired_udp_socket(void);

/** Bind fd to sa. Ownership of fd stays with the caller; wired_udp_bind
 * neither closes it on failure nor takes it over on success.
 * @param fd the socket fd
 * @param sa the local address to bind
 * @return 0 on success or a negative errno. */
i64 wired_udp_bind(i64 fd, const quic_sockaddr_in* sa);

/** Send buf to sa.
 * @param fd the socket fd
 * @param sa the destination address
 * @param buf the datagram to send
 * @return bytes sent or a negative errno. */
i64 wired_udp_send(i64 fd, const quic_sockaddr_in* sa, quic_span buf);

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
i64 wired_udp_recvfrom(i64 fd, quic_mspan buf, quic_sockaddr_in* src);

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
    i64 fd, const quic_sockaddr_in* sa, quic_span buf, u16 segsize);

/** Send count back-to-back segsize-byte segments to sa via one sendto() call
 * per segment (no GSO). The last segment may be shorter (total = buf.n). The
 * fallback path for a kernel without UDP_SEGMENT support.
 * @param fd the socket fd
 * @param sa the destination address
 * @param buf the concatenated segments to send
 * @param segsize per-segment byte size (last segment may be shorter)
 * @return total bytes sent, or a negative errno on the first failure. */
i64 wired_udp_send_batch(
    i64 fd, const quic_sockaddr_in* sa, quic_span buf, u16 segsize);

/** One slot of a recvmmsg() batch: caller-owned receive buffer and source
 * address, filled in by wired_udp_recvmmsg on return. */
typedef struct {
  quic_mspan       buf; /**< in: destination buffer; unused bytes untouched */
  quic_sockaddr_in src; /**< out: datagram's source address */
  u32              len; /**< out: bytes received into buf.p */
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

#endif
