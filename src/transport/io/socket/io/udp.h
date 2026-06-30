#ifndef QUIC_IO_UDP_H
#define QUIC_IO_UDP_H

#include "common/platform/sys/syscall.h"

/* UDP over IPv4 via direct x86_64 syscalls. No libc. */

#define QUIC_AF_INET    2
#define QUIC_SOCK_DGRAM 2

/* A sockaddr_in laid out for the kernel (big-endian port and address). */
typedef struct {
    u16 family;
    u16 port_be;   /* network byte order */
    u32 addr_be;   /* network byte order */
    u8  zero[8];
} quic_sockaddr_in;

/* Build a sockaddr_in from host-order port and IPv4 octets a.b.c.d. */
void quic_udp_addr(quic_sockaddr_in *sa, u16 port, u8 a, u8 b, u8 c, u8 d);

/* Create a UDP socket. Returns the fd, or a negative errno on failure. */
i64 quic_udp_socket(void);

/* Bind fd to sa. Returns 0 on success or a negative errno. */
i64 quic_udp_bind(i64 fd, const quic_sockaddr_in *sa);

/* Send len bytes to sa. Returns bytes sent or a negative errno. */
i64 quic_udp_send(i64 fd, const quic_sockaddr_in *sa, const u8 *buf, usz len);

/* Receive up to len bytes into buf. Returns bytes read or a negative errno. */
i64 quic_udp_recv(i64 fd, u8 *buf, usz len);

/* Receive up to len bytes into buf and write the source address into src.
 * Returns bytes read or a negative errno. */
i64 quic_udp_recvfrom(i64 fd, u8 *buf, usz len, quic_sockaddr_in *src);

/* Close fd. Returns 0 on success or a negative errno. */
i64 quic_udp_close(i64 fd);

#endif
