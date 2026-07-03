#ifndef QUIC_SRVRUN_SRVRUN_H
#define QUIC_SRVRUN_SRVRUN_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvloop/srvloop.h"

/** @file
 * The complete server event loop: the sanctioned socket-owning layer over the
 * socket-free srvboot/srvloop core. */

/** The application's request responder: the callback and its opaque context,
 * registered on the loop as a pair (quic_srvloop_set_handler takes the same
 * pair). */
typedef struct {
  quic_srvloop_handler cb;  /**< the response-body builder callback */
  void                *ctx; /**< opaque context passed back to cb */
} wired_srvrun_handler;

/** The complete server event loop: bind a UDP socket on `port`, then forever
 * receive datagrams and drive them — a fresh client Initial cold-starts a
 * connection (wired_srvboot_accept), any later datagram steps the live loop
 * (quic_srvloop_step) — sealing every reply straight back. `id` is the fixed
 * server identity, `h` the application's request responder. This owns the
 * socket and blocks in recvfrom, the sanctioned socket-owning layer over the
 * socket-free srvboot/srvloop core. RFC 9000 7: one connection at a time, in
 * arrival order.
 * @param port UDP port to bind
 * @param id the fixed server identity
 * @param h the application's request responder
 * @return 0 if the socket cannot be opened or bound; otherwise runs until the
 *   process is killed. */
int wired_server_run(
    u16 port, const wired_srvboot_id *id, wired_srvrun_handler h);

#endif
