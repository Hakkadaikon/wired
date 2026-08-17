#ifndef IO_UDPTRANSPORT_H
#define IO_UDPTRANSPORT_H

#include "common/platform/sys/syscall.h"

/* A real-socket datagram transport. Mirrors the memlink send/recv contract so
 * a session can run over either an in-process link or a kernel UDP socket. */

/** A real-socket datagram transport: an open fd and the current peer
 * address/port. */
typedef struct {
  i64 fd;
  u32 peer_addr; /* big-endian (network order) */
  u16 peer_port; /* host order */
} udp_transport;

/* Open a UDP socket and bind it to local_port. Returns 0 on success or a
 * negative errno. */
int udp_transport_open(udp_transport* t, u16 local_port);

/* Set the peer datagrams are sent to. Returns 0. */
int udp_transport_connect(udp_transport* t, u32 peer_addr, u16 peer_port);

/* Send len bytes to the peer. Returns 1 on success, 0 on failure. */
int udp_transport_send(udp_transport* t, const u8* buf, usz len);

/* Receive up to cap bytes into buf. Returns bytes read, or 0 on empty/error. */
usz udp_transport_recv(udp_transport* t, u8* buf, usz cap);

#endif
