#ifndef QUIC_SRVRUN_SRVRUN_H
#define QUIC_SRVRUN_SRVRUN_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvloop/srvloop.h"

/* The complete server event loop: bind a UDP socket on `port`, then forever
 * receive datagrams and drive them — a fresh client Initial cold-starts a
 * connection (wired_srvboot_accept), any later datagram steps the live loop
 * (quic_srvloop_step) — sealing every reply straight back. `id` is the fixed
 * server identity, `handler`/`ctx` the application's request responder
 * (registered on the loop). This owns the socket and blocks in recvfrom, the
 * sanctioned socket-owning layer over the socket-free srvboot/srvloop core.
 * Returns 0 if the socket cannot be opened or bound; otherwise runs until the
 * process is killed. RFC 9000 7: one connection at a time, in arrival order. */
int wired_server_run(
    u16                     port,
    const wired_srvboot_id *id,
    quic_srvloop_handler    handler,
    void                   *ctx);

#endif
