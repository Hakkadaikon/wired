#ifndef WIRED_SRVRUN_SRVRUN_H
#define WIRED_SRVRUN_SRVRUN_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvloop/srvloop.h"

/** @file
 * The complete server event loop: the sanctioned socket-owning layer over the
 * socket-free srvboot/srvloop core. */

/** The application's request responder: the callback and its opaque context,
 * registered on the loop as a pair (wired_srvloop_set_handler takes the same
 * pair). */
typedef struct {
  wired_srvloop_handler cb;  /**< the response-body builder callback */
  void*                 ctx; /**< opaque context passed back to cb */
} wired_srvrun_handler;

/** Optional debug-log file paths, each 0 to disable (the default): a qlog
 * (RFC 9002-shaped packet_sent/packet_received events, JSON-SEQ framed) and an
 * NSS key log (SSLKEYLOGFILE format) for decrypting a capture in Wireshark.
 * cert_path/key_path, when both set, enable certificate hot reload on SIGHUP
 * (re-reads the same PEM pair id was built from); 0 (either) disables it. */
typedef struct {
  const char* qlog_path;   /**< qlog file path, or 0 to disable */
  const char* keylog_path; /**< NSS key log file path, or 0 to disable */
  const char* cert_path;   /**< cert.pem path, or 0 to disable SIGHUP reload */
  const char* key_path;    /**< key.pem path, or 0 to disable SIGHUP reload */
} wired_srvrun_obs;

/** The complete server event loop: bind a UDP socket on `port`, then forever
 * receive datagrams and drive them — a fresh client Initial cold-starts a
 * connection (wired_srvboot_accept), any later datagram steps the live loop
 * (wired_srvloop_step) — sealing every reply straight back. `id` is the fixed
 * server identity, `h` the application's request responder. This owns the
 * socket and blocks in recvfrom, the sanctioned socket-owning layer over the
 * socket-free srvboot/srvloop core. RFC 9000 7: one connection at a time, in
 * arrival order.
 *
 * Graceful shutdown (RFC 9114 5.2): installs a SIGTERM handler before
 * serving. On receipt, new connections stop being accepted, GOAWAY is sent
 * once to every live connection, and the process exits once every connection
 * has drained or a bounded grace period elapses.
 * ponytail: a SIGTERM delivered before this handler is installed (a narrow
 * startup race) falls back to the default action (immediate exit, no
 * GOAWAY) — acceptable for a demo; a process supervisor should signal only
 * after observing the "listening" log line.
 *
 * Certificate hot reload (SIGHUP): when obs.cert_path/key_path are both set,
 * installs a SIGHUP handler; on receipt, re-reads and re-decodes the PEM pair
 * and updates *id in place (chain/chain_count/cert_seed only) so every
 * connection cold-started afterward uses the new material. A connection
 * already past its handshake never re-reads id, so a reload never disturbs
 * it. `id` is therefore NOT const: the caller must keep it (and its backing
 * PEM-derived buffers) alive and mutable for the whole run. A reload that
 * fails to read or decode the new PEM pair leaves the previous identity in
 * place.
 * @param port UDP port to bind
 * @param id the fixed server identity; updated in place on a SIGHUP reload
 * @param h the application's request responder
 * @param obs optional qlog/keylog file paths and cert reload paths, each 0
 *   to disable
 * @return 0 if the socket cannot be opened or bound; otherwise runs until
 *   shutdown completes (SIGTERM) or the process is killed. */
int wired_server_run(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs);

#endif
