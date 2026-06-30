#include "transport/io/socket/io/udp.h"

/* Host-to-network for 16- and 32-bit values (x86_64 is little-endian). */
static u16 hton16(u16 v) { return (u16)((v >> 8) | (v << 8)); }

static u32 hton32(u32 v)
{
    return ((v >> 24) & 0xff) | ((v >> 8) & 0xff00) |
           ((v << 8) & 0xff0000) | ((v << 24) & 0xff000000);
}

void quic_udp_addr(quic_sockaddr_in *sa, u16 port, u8 a, u8 b, u8 c, u8 d)
{
    u32 addr = ((u32)a << 24) | ((u32)b << 16) | ((u32)c << 8) | d;
    for (usz i = 0; i < 8; i++) sa->zero[i] = 0;
    sa->family = QUIC_AF_INET;
    sa->port_be = hton16(port);
    sa->addr_be = hton32(addr);
}

i64 quic_udp_socket(void)
{
    return syscall3(SYS_socket, QUIC_AF_INET, QUIC_SOCK_DGRAM, 0);
}

i64 quic_udp_bind(i64 fd, const quic_sockaddr_in *sa)
{
    return syscall3(SYS_bind, fd, sa, sizeof(*sa));
}

i64 quic_udp_send(i64 fd, const quic_sockaddr_in *sa, const u8 *buf, usz len)
{
    return syscall6(SYS_sendto, fd, (i64)buf, (i64)len, 0,
                    (i64)sa, sizeof(*sa));
}

i64 quic_udp_recv(i64 fd, u8 *buf, usz len)
{
    return syscall6(SYS_recvfrom, fd, (i64)buf, (i64)len, 0, 0, 0);
}

i64 quic_udp_recvfrom(i64 fd, u8 *buf, usz len, quic_sockaddr_in *src)
{
    /* addrlen is in/out: pass the buffer size, kernel writes the actual length. */
    u32 addrlen = sizeof(*src);
    return syscall6(SYS_recvfrom, fd, (i64)buf, (i64)len, 0,
                    (i64)src, (i64)&addrlen);
}

i64 quic_udp_close(i64 fd)
{
    return syscall1(SYS_close, fd);
}
