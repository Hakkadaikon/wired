#ifndef QUIC_SRVRUN_SRVRUN_H
#define QUIC_SRVRUN_SRVRUN_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvloop/srvloop.h"

/* The application's request responder: the callback and its opaque context,
 * registered on the loop as a pair (quic_srvloop_set_handler takes the same
 * pair). */
typedef struct {
  quic_srvloop_handler cb;
  void                 *ctx;
} wired_srvrun_handler;

/* The complete server event loop: bind a UDP socket on `port`, then forever
 * receive datagrams and drive them — a fresh client Initial cold-starts a
 * connection (wired_srvboot_accept), any later datagram steps the live loop
 * (quic_srvloop_step) — sealing every reply straight back. `id` is the fixed
 * server identity, `h` the application's request responder. This owns the
 * socket and blocks in recvfrom, the sanctioned socket-owning layer over the
 * socket-free srvboot/srvloop core. Returns 0 if the socket cannot be opened
 * or bound; otherwise runs until the process is killed. RFC 9000 7: one
 * connection at a time, in arrival order. */
int wired_server_run(
    u16 port, const wired_srvboot_id *id, wired_srvrun_handler h);

#endif
