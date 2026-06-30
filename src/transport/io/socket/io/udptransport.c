#include "transport/io/socket/io/udptransport.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/io/addr.h"

int quic_udp_transport_open(quic_udp_transport *t, u16 local_port)
{
    quic_sockaddr_in sa;
    i64 fd = quic_udp_socket();
    if (fd < 0) return (int)fd;
    quic_udp_addr(&sa, local_port, 0, 0, 0, 0);
    i64 r = quic_udp_bind(fd, &sa);
    if (r < 0) return (int)r;
    t->fd = fd;
    return 0;
}

int quic_udp_transport_connect(quic_udp_transport *t, u32 peer_addr, u16 peer_port)
{
    t->peer_addr = peer_addr;
    t->peer_port = peer_port;
    return 0;
}

int quic_udp_transport_send(quic_udp_transport *t, const u8 *buf, usz len)
{
    quic_sockaddr_in sa;
    u8 o[4];
    quic_addr_to_octets(t->peer_addr, o);
    quic_udp_addr(&sa, t->peer_port, o[0], o[1], o[2], o[3]);
    return quic_udp_send(t->fd, &sa, buf, len) >= 0 ? 1 : 0;
}

usz quic_udp_transport_recv(quic_udp_transport *t, u8 *buf, usz cap)
{
    i64 r = quic_udp_recv(t->fd, buf, cap);
    return r > 0 ? (usz)r : 0;
}
