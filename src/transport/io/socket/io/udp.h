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
void wired_udp_addr(quic_sockaddr_in *sa, u16 port, const u8 octets[4]);

/** Create a UDP socket.
 * @return the fd, or a negative errno on failure. */
i64 wired_udp_socket(void);

/** Bind fd to sa.
 * @param fd the socket fd
 * @param sa the local address to bind
 * @return 0 on success or a negative errno. */
i64 wired_udp_bind(i64 fd, const quic_sockaddr_in *sa);

/** Send buf to sa.
 * @param fd the socket fd
 * @param sa the destination address
 * @param buf the datagram to send
 * @return bytes sent or a negative errno. */
i64 wired_udp_send(i64 fd, const quic_sockaddr_in *sa, quic_span buf);

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
i64 wired_udp_recvfrom(i64 fd, quic_mspan buf, quic_sockaddr_in *src);

/** Close fd.
 * @param fd the socket fd
 * @return 0 on success or a negative errno. */
i64 wired_udp_close(i64 fd);

#endif
