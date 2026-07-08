#ifndef WIRED_SRVRUN_SRVRUN_H
#define WIRED_SRVRUN_SRVRUN_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "app/webtransport/session/session/session.h"

/** @file
 * The complete server event loop: the sanctioned socket-owning layer over the
 * socket-free srvboot/srvloop core. */

/** draft-ietf-webtrans-http3-15 SS4: app-facing delivery of one received
 * QUIC DATAGRAM (RFC 9221 5) associated with a WebTransport session, drained
 * from wired_srvloop's rx_datagrams queue once per connection step. data is a
 * view into per-step scratch, not valid past the call.
 * @param app_ctx opaque context registered alongside this callback
 * @param s the session the datagram is associated with
 * @param data the datagram's payload bytes */
typedef void (*wired_wt_on_datagram)(
    void* app_ctx, wired_wt_session* s, quic_span data);

/** draft-ietf-webtrans-http3-15 4.3: app-facing delivery of one reassembled
 * chunk of a WebTransport bidi/uni stream's bytes, drained from wired_srvloop's
 * wt_streams/wt_uni_streams once per connection step. data is a view into
 * per-step scratch, not valid past the call. fin=1 marks the stream's end.
 * @param app_ctx opaque context registered alongside this callback
 * @param s the session the stream is associated with
 * @param stream_id the WT bidi/uni stream id
 * @param data the stream's reassembled bytes so far past the signal/type byte
 * @param fin 1 once the stream's FIN has been seen */
typedef void (*wired_wt_on_stream_data)(
    void* app_ctx, wired_wt_session* s, u64 stream_id, quic_span data, int fin);

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
  int         cc_algo;     /**< QUIC_CC_ALGO_* (0 = NewReno, the default) */
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

/** Opt-in polling-driver knobs (tasks/polling-driver-plan.md), both off (0)
 * by default so wired_server_run's behavior is unchanged. */
typedef struct {
  int busy_poll; /**< 1: MSG_DONTWAIT spin loop instead of blocking poll(2) */
  int so_busy_poll_us; /**< >0: also enable SO_BUSY_POLL (microseconds).
                        * Independent of busy_poll; a no-op on a kernel/driver
                        * without CONFIG_NET_RX_BUSY_POLL support. */
  /** draft-ietf-webtrans-http3-15 SS4: app-facing WebTransport datagram
   * delivery, 0 to disable (the default) — a 0 callback makes the per-step
   * drain of received QUIC DATAGRAMs a no-op consume (the queue still empties,
   * nothing is delivered). */
  wired_wt_on_datagram wt_on_datagram;
  void* wt_datagram_ctx; /**< opaque ctx passed to wt_on_datagram */
  /** draft-ietf-webtrans-http3-15 4.3: app-facing WebTransport bidi/uni
   * stream-data delivery, 0 to disable (the default) — a 0 callback makes the
   * per-step delta-delivery of reassembled WT stream bytes a no-op (reassembly
   * and offer_stream association still happen, nothing is delivered). */
  wired_wt_on_stream_data wt_on_stream_data;
  void* wt_stream_data_ctx;  /**< opaque ctx passed to wt_on_stream_data */
  int   so_prefer_busy_poll; /**< 0 = disabled (default); 1 = also enable
                              * SO_PREFER_BUSY_POLL (requires so_busy_poll_us > 0
                              * to have kernel effect, see srvrun.c's guard). */
  int so_busy_poll_budget;   /**< > 0: also enable SO_BUSY_POLL_BUDGET with this
                              * packet budget; 0 = disabled (default). */
  /** tasks/core-pinning-plan.md PIN-007, SET direction only. -1 = disabled
   * (the default) -- a dedicated sentinel, not 0, because CPU 0 is itself a
   * valid target and there is no natural "0 means off" value here (unlike
   * so_busy_poll_us/so_busy_poll_budget, where 0 already means "no budget").
   * >= 0: also enable SO_INCOMING_CPU with this CPU number. */
  int incoming_cpu;
} wired_srvrun_opt;

/** Same as wired_server_run, plus opt-in polling-driver behavior. `opt` must
 * not be 0; wired_server_run itself passes an opt with every knob at its
 * disabled default (all-zero except incoming_cpu, which is -1; see
 * wired_srvrun_opt) so its behavior is byte-identical to before this was
 * added.
 * @param port UDP port to bind
 * @param id the fixed server identity; updated in place on a SIGHUP reload
 * @param h the application's request responder
 * @param obs optional qlog/keylog file paths and cert reload paths, each 0
 *   to disable
 * @param opt busy_poll / so_busy_poll_us knobs, see wired_srvrun_opt
 * @return same as wired_server_run. */
int wired_server_run_opt(
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt);

/** RFC 9221 5 / draft-ietf-webtrans-http3-15 SS4: broadcast data as a QUIC
 * DATAGRAM to every connection with an active WebTransport session (queued
 * for each such connection's own next step, same single-slot last-writer-
 * wins contract as this SDK's per-connection DATAGRAM queue). Typically
 * called from inside a wired_wt_on_datagram callback to fan a received
 * message out to every other participant (e.g. a chat app) — that callback
 * has no handle to the connection table itself, so this is the only way to
 * reach connections other than the one that just received data.
 * Callable only from inside the server's own loop (i.e. from a callback);
 * this SDK's server loop is single-threaded and this call is neither
 * signal-safe nor thread-safe.
 * @param data payload to broadcast; must fit the per-connection DATAGRAM cap
 * @return 1 if queued for every active WT session, 0 if data exceeds the cap
 */
int wired_server_broadcast_datagram(quic_span data);

#endif
