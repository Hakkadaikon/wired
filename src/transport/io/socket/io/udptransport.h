#ifndef QUIC_IO_UDPTRANSPORT_H
#define QUIC_IO_UDPTRANSPORT_H

#include "common/platform/sys/syscall.h"

/* A real-socket datagram transport. Mirrors the memlink send/recv contract so
 * a session can run over either an in-process link or a kernel UDP socket. */

typedef struct {
    i64 fd;
    u32 peer_addr;   /* big-endian (network order) */
    u16 peer_port;   /* host order */
} quic_udp_transport;

/* Open a UDP socket and bind it to local_port. Returns 0 on success or a
 * negative errno. */
int quic_udp_transport_open(quic_udp_transport *t, u16 local_port);

/* Set the peer datagrams are sent to. Returns 0. */
int quic_udp_transport_connect(quic_udp_transport *t, u32 peer_addr, u16 peer_port);

/* Send len bytes to the peer. Returns 1 on success, 0 on failure. */
int quic_udp_transport_send(quic_udp_transport *t, const u8 *buf, usz len);

/* Receive up to cap bytes into buf. Returns bytes read, or 0 on empty/error. */
usz quic_udp_transport_recv(quic_udp_transport *t, u8 *buf, usz cap);

#endif
