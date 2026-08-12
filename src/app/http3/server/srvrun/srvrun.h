#ifndef WIRED_SRVRUN_SRVRUN_H
#define WIRED_SRVRUN_SRVRUN_H

#include "app/http3/server/srvboot/srvboot.h"
#include "app/http3/server/srvinbox/srvinbox.h"
#include "app/http3/server/srvloop/srvloop.h"
#include "app/http3/server/srvxdp/srvxdp.h"
#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"
#include "app/webtransport/session/session/session.h"

/** @file
 * The complete server event loop: the sanctioned socket-owning layer over the
 * socket-free srvboot/srvloop core. */

/** Opaque: one server loop instance's mutable state (connection table,
 * response/rx storage, pacing scratch). wired_server_run/wired_server_run_opt
 * drive a single process-wide instance of this internally; wired_srvrun_env_*
 * plus wired_srvrun_serve_env let a caller allocate and run additional,
 * independent instances (e.g. one per thread). Never dereference members
 * directly -- allocate wired_srvrun_env_size() bytes and pass the pointer
 * through. */
typedef struct wired_srvrun_env wired_srvrun_env;

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

/** draft-ietf-webtrans-http3-15 4.4 (WTH3-040): app-facing delivery of a
 * RESET_STREAM/STOP_SENDING received on one of session s's own WT bidi/uni
 * streams. "If a RESET_STREAM or STOP_SENDING frame is received with an
 * error code outside the WT_APPLICATION_ERROR range, then the implementation
 * should deliver this to the application as a stream reset with no
 * application error code" -- mapped is 1 when the wire error code fell
 * inside the WT_APPLICATION_ERROR range (quic_wterrmap_from_http3 accepted
 * it) and app_error_code is the recovered WebTransport application error
 * code, or mapped is 0 (app_error_code left at 0, not itself meaningful) for
 * a wire code outside that range or on a reserved codepoint.
 * @param app_ctx opaque context registered alongside this callback
 * @param s the session the stream is associated with
 * @param stream_id the WT bidi/uni stream id the reset arrived on
 * @param mapped 1 if app_error_code is a recovered WT application error code
 * @param app_error_code the recovered code, valid only when mapped is 1 */
typedef void (*wired_wt_on_stream_reset)(
    void*             app_ctx,
    wired_wt_session* s,
    u64               stream_id,
    int               mapped,
    u32               app_error_code);

/** WebTransport subprotocol negotiation (draft-ietf-webtrans-http3-15 SS3.4):
 * app-facing notification that a WebTransport session was established (its
 * 2xx accept response has been built). path and protocol are views into
 * per-connection/per-call scratch, not valid past the call.
 * @param app_ctx opaque context registered alongside this callback
 * @param s the session that was just established
 * @param path the Extended CONNECT's :path value
 * @param protocol the negotiated subprotocol (the raw token, not its
 *   sf-string encoding); empty when no subprotocol was negotiated */
typedef void (*wired_wt_on_session)(
    void* app_ctx, wired_wt_session* s, quic_span path, quic_span protocol);

/** App-facing notification that a WebTransport session ended server-side:
 * its own CONNECT stream closed, it violated a WT flow-control limit, the
 * server sent WT_CLOSE_SESSION, or its whole connection tore down (peer
 * CONNECTION_CLOSE, boot failure, or the idle-timeout sweep). Fires once
 * per session, before the session object's storage can be reused by a
 * later connection -- an app keying its own per-session state on the
 * wired_wt_session pointer MUST release that state here, or a reconnecting
 * client landing in the reused slot inherits the dead session's identity.
 * s is only valid for the duration of the call.
 * @param app_ctx opaque context registered alongside this callback
 * @param s the session that ended */
typedef void (*wired_wt_on_session_close)(void* app_ctx, wired_wt_session* s);

/** draft-ietf-webtrans-http3-15 SS3.2 (WTH3-016/WTH3-018): the app's verdict
 * for one Extended CONNECT's :authority/:path, filled in by a registered
 * wired_wt_resource_check before the session is established.
 * status == 0 (the caller-zeroed default) means "resource recognized,
 * proceed to the normal Origin-check/session-establish path" -- a callback
 * that leaves every field at its zeroed default therefore accepts every
 * resource, matching the pre-callback behavior. A non-zero status short-
 * circuits establishment and is sent verbatim instead: 404 for "no
 * WebTransport server at this :authority/:path" (WTH3-016), or a 3xx to
 * redirect (WTH3-018), in which case location/location_len name the
 * Location response header's value (ignored for any other status). */
typedef struct {
  u16       status;       /**< 0 = accept; else the status to send instead */
  const u8* location;     /**< Location header value, only for a 3xx status */
  usz       location_len; /**< bytes at location */
} wired_wt_resource_decision;

/** draft-ietf-webtrans-http3-15 SS3.2: app-facing resource lookup for one
 * Extended CONNECT, called before Origin verification/session establishment.
 * authority/path are views into per-call scratch, not valid past the call.
 * out is caller-zeroed before the call (a callback that never touches it
 * accepts the resource, see wired_wt_resource_decision's own doc).
 * @param app_ctx opaque context registered alongside this callback
 * @param authority the Extended CONNECT's :authority value
 * @param path the Extended CONNECT's :path value
 * @param out the verdict to fill in */
typedef void (*wired_wt_resource_check)(
    void*                       app_ctx,
    quic_span                   authority,
    quic_span                   path,
    wired_wt_resource_decision* out);

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
  /** QUIC_CC_ALGO_* for fresh connections. 0 selects the build's default
   * (WIRED_CC_ALGO_DEFAULT in srvrun.c -- Cubic unless the build overrides
   * it); a build wanting NewReno overrides -DWIRED_CC_ALGO_DEFAULT=0, since
   * an explicit runtime NewReno request (QUIC_CC_ALGO_NEWRENO == 0) is
   * indistinguishable from "unset". */
  int cc_algo;
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

/** Opt-in polling-driver knobs, both off (0) by default so
 * wired_server_run's behavior is unchanged. */
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
  /** SET direction only. -1 = disabled (the default) -- a dedicated
   * sentinel, not 0, because CPU 0 is itself a valid target and there is no
   * natural "0 means off" value here (unlike so_busy_poll_us/
   * so_busy_poll_budget, where 0 already means "no budget"). >= 0: also
   * enable SO_INCOMING_CPU with this CPU number. */
  int incoming_cpu;
  /** 0 (the default) = unchanged UDP socket path;
   * non-0 = an already-open AF_XDP driver (wired_srvxdp_open), routing recv
   * and send through it instead. The UDP socket from `port` is still bound
   * (port reservation + PASS-frame absorption via the BPF filter's
   * fallback), so cfg->fd stays valid either way. */
  wired_srvxdp* xdp;
  /** 0 (the default) = install SIGTERM/SIGHUP as wired_server_run always has;
   * 1 = skip signal installation entirely. Set this when running more than
   * one wired_srvrun_serve_env instance in the same process (e.g. one per
   * thread) -- only one of them may own the process-wide signal handlers. */
  int no_signal_handlers;
  /** AF_XDP multi-queue core-routing: -1 = disabled (the default, a
   * dedicated sentinel like incoming_cpu since core 0 is itself valid).
   * >= 0, only when xdp is also set: this worker's own core/queue index,
   * packed into the leading byte of every SCID this worker generates
   * (quic_ncid_worker_encode, bits=8) so a BPF filter can route by CID
   * instead of NIC queue after a connection migrates. Ignored when xdp is 0
   * (SO_REUSEPORT/plain UDP mode never embeds a core id). */
  int core_id;
  /** WebTransport subprotocol negotiation (draft-ietf-webtrans-http3-15
   * SS3.4): the server's own supported subprotocols as a space-separated
   * string, 0 to disable (the default) -- with 0, an Extended CONNECT's
   * wt-available-protocols offer is ignored and the 2xx carries no
   * wt-protocol header, exactly the pre-negotiation behavior. */
  const char* wt_protocols;
  /** Session-established notification, 0 to disable (the default) -- called
   * once per accepted Extended CONNECT, after its 2xx response is built,
   * with the session's :path and the negotiated subprotocol (empty span when
   * none was negotiated). */
  wired_wt_on_session wt_on_session;
  void*               wt_session_ctx; /**< opaque ctx passed to wt_on_session */
  /** RFC 9000 8.1.2: 1 = answer every tokenless Initial with a stateless
   * Retry and only accept Initials presenting a valid Retry token (the
   * quic-interop-runner retry testcase's server mode). 0 (the default) =
   * accept directly, never send Retry. */
  int force_retry;
  /** draft-ietf-webtrans-http3-15 SS3.2: app-facing :authority/:path
   * resource lookup, 0 to disable (the default) -- with 0, every recognized
   * WebTransport Extended CONNECT proceeds straight to Origin verification/
   * session establishment, exactly the pre-callback behavior (WTH3-016's
   * 404 and WTH3-018's 3xx are both opt-in through this callback). */
  wired_wt_resource_check wt_resource_check;
  void* wt_resource_ctx; /**< opaque ctx passed to wt_resource_check */
  /** draft-ietf-webtrans-http3-15 4.4 (WTH3-040): app-facing WT stream-reset
   * delivery, 0 to disable (the default) -- a 0 callback makes a received
   * RESET_STREAM/STOP_SENDING on a WT bidi/uni stream a no-op consume (the
   * stream's slot is still torn down, nothing is delivered). */
  wired_wt_on_stream_reset wt_on_stream_reset;
  void* wt_stream_reset_ctx; /**< opaque ctx passed to wt_on_stream_reset */
  /** Session-ended notification, 0 to disable (the default) -- called once
   * per WT session when it ends server-side (CONNECT stream close, flow
   * violation, WT_CLOSE_SESSION, or whole-connection teardown). See
   * wired_wt_on_session_close's doc for the pointer-reuse hazard this
   * exists to close. */
  wired_wt_on_session_close wt_on_session_close;
  void* wt_session_close_ctx; /**< opaque ctx passed to wt_on_session_close */
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

/** Byte size of one wired_srvrun_env instance, for a caller allocating one
 * (statically, or via an SDK-external allocator) to pass to
 * wired_srvrun_env_init / wired_srvrun_serve_env. */
usz wired_srvrun_env_size(void);

/** Zero-initialize env (its connection table, response/rx storage, and
 * pacing scratch) before its first use with wired_srvrun_serve_env. */
void wired_srvrun_env_init(wired_srvrun_env* env);

/** Same as wired_server_run_opt, but driven off caller-owned `env` instead
 * of the SDK's single process-wide instance -- lets a caller run more than
 * one independent server loop in the same process (e.g. one per thread, each
 * with its own env and its own bound port). Set opt->no_signal_handlers=1
 * for every instance but one, since SIGTERM/SIGHUP are process-wide.
 * @param env caller-owned state, sized wired_srvrun_env_size() and
 *   initialized with wired_srvrun_env_init before the first call
 * @param port UDP port to bind
 * @param id the fixed server identity; updated in place on a SIGHUP reload
 * @param h the application's request responder
 * @param obs optional qlog/keylog file paths and cert reload paths, each 0
 *   to disable
 * @param opt busy_poll / so_busy_poll_us / no_signal_handlers knobs
 * @return same as wired_server_run. */
int wired_srvrun_serve_env(
    wired_srvrun_env*       env,
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt);

/** The process-wide graceful-shutdown word (RFC 9114 5.2): 0 until a
 * shutdown is requested, then monotonically 1 (never reset outside test
 * teardown). Every wired_srvrun_serve_env/wired_server_run loop in the
 * process polls this once per iteration (srvrun.c's srvrun_shutdown_requested)
 * to stop accepting new connections and start draining live ones -- the same
 * word wired_sigterm_install's default handler sets. A caller running its
 * own multi-threaded fan-out over wired_srvrun_serve_env (one instance per
 * thread, wired_srvrun_opt.no_signal_handlers=1 on every instance but the
 * one installing signals) uses the returned pointer to both observe the
 * word (e.g. a timed futex wait) and set it (e.g. from its own signal
 * handler), so every thread's loop sees the same 0->1 transition without a
 * separate flag to keep in sync.
 * @return pointer to the shared shutdown word; never 0 */
int* wired_srvrun_shutdown_word(void);

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
 *
 * Threaded fan-out: a caller running inside a srvthreads worker (registered
 * via wired_srvrun_broadcast_register) is fanned out into ITS OWN
 * registered env -- srvthreads gives every worker its own connection
 * table, so the single process-wide g_srvrun_env would be empty/unused for
 * a registered worker and reach no one. With 2 or more workers registered,
 * the payload is also pushed into every OTHER registered worker's inbox row
 * (wired_srvinbox_push) so each one's own wired_srvrun_serve_env loop
 * delivers it to its own WT sessions on a later step (srvrun.c drains the
 * calling worker's inbox row once per step). An unregistered caller (the
 * default, single-process wired_server_run(_opt) or a lone
 * wired_srvrun_serve_env instance) fans out directly to the single
 * g_srvrun_env. */
int wired_server_broadcast_datagram(quic_span data);

/** Queue one HTTP Datagram (RFC 9297) to EVERY active WebTransport session
 * in the caller's server loop -- the burst-safe sibling of
 * wired_server_broadcast_datagram. Where that API holds one pending payload
 * per connection (a second broadcast in the same loop step overwrites the
 * first, last-writer-wins), this one queues each target into the same
 * bounded ring wired_server_wt_send_datagram_to uses, so several broadcasts
 * inside one step -- an audio burst, say -- are all delivered on the loop's
 * next step, none overwritten. Each target session's own quarter-stream-id
 * varint (RFC 9297 2.1) is prefixed at queue time and the payload is copied,
 * so it need not outlive the call. A session is a target only when its
 * connection is up, this endpoint's SETTINGS have been sent (RFC 9297 2.1),
 * and the session's CONNECT stream send side is still open (RFC 9297 2) --
 * the same gates wired_server_wt_send_datagram_to applies. Frames exceeding
 * the peer's advertised max_datagram_frame_size are dropped at send time
 * (RFC 9221 3). Callable only from inside the server's own loop (a
 * callback), same contract as wired_server_broadcast_datagram.
 *
 * Single-process only: unlike wired_server_broadcast_datagram, this API does
 * not push into the srvthreads inbox mesh -- a registered worker reaches its
 * OWN env's sessions only. Reaching other workers' sessions burst-safely
 * would also need the inbox drain path to queue into the ring (it currently
 * feeds the single-slot queue), not built yet.
 * @param data the HTTP Datagram payload (qsid prefix NOT included); each
 *   target's prefixed copy must fit a ring slot
 * @return 1 if every target session was queued (including when there is no
 *   target at all), 0 when the ring filled up or the prefixed payload
 *   exceeds a ring slot for some target */
int wired_server_broadcast_datagram_ring(quic_span data);

/** Open a new server-initiated unidirectional stream on s's connection (RFC
 * 9000 2.1: id 3 mod 4) and send the whole payload on it, closing with FIN
 * on the final slice. payload must already carry the WebTransport stream
 * signal prefix (draft-ietf-webtrans-http3-15 4.2: varint 0x54 + the CONNECT
 * stream id, quic_wtwire_signal_put) -- this SDK sends the bytes verbatim.
 * A payload up to the send slot's own staging capacity (4096 bytes) is
 * COPIED: the caller's storage is free the moment the call returns. Only a
 * larger payload is held as a VIEW, and then the caller must keep it alive
 * and unmoved until every byte has been acknowledged (the send slot frees
 * itself then). Delivery is congestion/flow-control gated and paced
 * like any response stream (RFC 9000 4.1 / RFC 9002 7). Callable only from
 * inside the server's own loop (a callback), same contract as
 * wired_server_broadcast_datagram.
 * @param s the session whose connection the stream is opened on
 * @param payload the complete stream bytes, signal prefix included
 * @return the allocated stream id, or negative when s resolves to no live
 *   connection or every send slot is busy */
i64 wired_server_wt_open_uni(wired_wt_session* s, quic_span payload);

/** Same as wired_server_wt_open_uni, but a server-initiated bidirectional
 * stream (RFC 9000 2.1: id 1 mod 4; signal prefix varint 0x41).
 * @param s the session whose connection the stream is opened on
 * @param payload the complete stream bytes, signal prefix included
 * @return the allocated stream id, or negative on failure */
i64 wired_server_wt_open_bidi(wired_wt_session* s, quic_span payload);

/** Send payload on this endpoint's send direction of the client-initiated
 * bidirectional stream `stream_id` (a WebTransport data stream the client
 * opened), closing with FIN on the final slice. No prefix is added -- the
 * bytes go out verbatim, and the same view/liveness contract as
 * wired_server_wt_open_uni applies.
 * @param s the session whose connection carries the stream
 * @param stream_id the client-opened bidi stream to reply on
 * @param payload the bytes to send
 * @return 1 accepted, 0 when s resolves to no live connection or every send
 *   slot is busy */
int wired_server_wt_stream_reply(
    wired_wt_session* s, u64 stream_id, quic_span payload);

/** Same as wired_server_wt_open_uni, but WITHOUT closing the stream: no FIN
 * is sent after payload's final slice, and the stream stays open for
 * further wired_server_wt_stream_send rounds until one carries fin=1 (or
 * wired_server_wt_stream_reset aborts it). The same view/liveness contract
 * as wired_server_wt_open_uni applies to payload.
 * @param s the session whose connection the stream is opened on
 * @param payload the first round's bytes, signal prefix included
 * @return the allocated stream id, or negative on failure */
i64 wired_server_wt_open_uni_stream(wired_wt_session* s, quic_span payload);

/** Same as wired_server_wt_open_uni_stream, but a server-initiated
 * bidirectional stream (RFC 9000 2.1: id 1 mod 4; signal prefix varint
 * 0x41), its receive side pre-registered like wired_server_wt_open_bidi.
 * @param s the session whose connection the stream is opened on
 * @param payload the first round's bytes, signal prefix included
 * @return the allocated stream id, or negative on failure */
i64 wired_server_wt_open_bidi_stream(wired_wt_session* s, quic_span payload);

/** Same as wired_server_wt_stream_reply, but WITHOUT closing the stream --
 * the opening round of a reply on a client-initiated bidi stream that stays
 * open for further wired_server_wt_stream_send rounds.
 * @param s the session whose connection carries the stream
 * @param stream_id the client-opened bidi stream to reply on
 * @param payload the first round's bytes
 * @return 1 accepted, 0 on failure */
int wired_server_wt_stream_reply_open(
    wired_wt_session* s, u64 stream_id, quic_span payload);

/** Append one more round of bytes to a stream opened with wired_server_wt_
 * open_uni_stream/open_bidi_stream/stream_reply_open: payload goes out at
 * the stream's cumulative offset (RFC 9000 19.8), and fin=1 ends the stream
 * with FIN on this round's final slice, after which the send slot frees
 * itself once fully acknowledged (the one-shot opens' behavior). An
 * accepted round is COPIED into the slot's own staging (the caller's
 * storage is free the moment the call returns) and pipelines onto the wire
 * behind any earlier rounds still awaiting their ACKs -- rounds queue up
 * to the slot's staging capacity (4096 bytes of not-yet-ACKed rounds), and
 * only a round that no longer fits is refused. A stream whose OPENING
 * payload was oversized (held as a view) refuses appends until that view
 * fully ACKs.
 * @param s the session whose connection carries the stream
 * @param stream_id a stream opened by one of the three calls above
 * @param payload this round's bytes; must be non-empty (the FIN rides the
 *   final slice, so a bare-FIN round has nothing to carry it)
 * @param fin 1 to end the stream after this round, 0 to keep it open
 * @return 1 accepted, negative when s resolves to no live connection,
 *   stream_id names no open send slot, payload is empty, the staging
 *   capacity is exhausted, or the session's WT_MAX_DATA limit would be
 *   exceeded */
int wired_server_wt_stream_send(
    wired_wt_session* s, u64 stream_id, quic_span payload, int fin);

/** Ends a stream opened for appending with NO further bytes: a bare FIN on
 * an otherwise-empty final round (RFC 9000 19.8 permits a zero-length
 * STREAM frame carrying only FIN). Use this instead of
 * wired_server_wt_stream_send when the app has determined the stream is
 * over but has no new bytes to send with it -- e.g. the peer's own source
 * stream closed with no trailing data of its own on that side (a
 * WebTransport writer's close() can arrive as its own byte-less frame,
 * separate from the data written just before it). The send slot frees
 * itself once this round is fully acknowledged, same as
 * wired_server_wt_stream_send's fin=1 round.
 * @param s the session whose connection carries the stream
 * @param stream_id a stream opened by one of the three open_*_stream calls,
 *   or already appended to via wired_server_wt_stream_send(fin=0)
 * @return 1 accepted, negative when s resolves to no live connection,
 *   stream_id names no open send slot, or the previous round is still in
 *   flight */
int wired_server_wt_stream_fin(wired_wt_session* s, u64 stream_id);

/** Abort a stream opened for appending: queue a standard RESET_STREAM (RFC
 * 9000 19.4) on stream_id carrying error_code mapped into HTTP/3's
 * WebTransport range (draft-ietf-webtrans-http3-15 SS4.4/8.2) and the
 * stream's bytes-armed-so-far as its Final Size, delivered on one of the
 * loop's next steps. Resets queue into a small bounded latch (several
 * streams can be aborted between steps -- e.g. a relay fanning one source
 * out to many subscribers); a FULL latch refuses the call and leaves the
 * stream untouched, so a caller can retry once a later step drains it. On
 * success the stream's send slot is freed at once, releasing the app's
 * payload view and dropping any not-yet-sent bytes (RFC 9000 19.4:
 * delivery is abandoned). No STOP_SENDING accompanies the reset: the
 * streams this API opens are server-initiated uni streams, which have no
 * peer-to-server half to stop (RFC 9000 19.5).
 * @param s the session whose connection carries the stream
 * @param stream_id the stream to abort
 * @param error_code the WebTransport application error code to report
 * @return 1 queued, 0 when s resolves to no live connection or the reset
 *   latch is full (nothing changed; retry on a later step) */
int wired_server_wt_stream_reset(
    wired_wt_session* s, u64 stream_id, u32 error_code);

/** Queue one HTTP Datagram (RFC 9297) to this session's peer: the SDK
 * prefixes the quarter-stream-id varint (the session's CONNECT stream id /
 * 4, RFC 9297 2.1) and sends it as a QUIC DATAGRAM (RFC 9221) on one of the
 * loop's next steps. The payload is copied at queue time, so it need not
 * outlive the call. Unlike wired_server_broadcast_datagram's single
 * last-writer-wins slot, sends queue into a bounded ring, so a burst of
 * many datagrams is delivered without overwriting. Frames exceeding the
 * peer's advertised max_datagram_frame_size are dropped at send time (RFC
 * 9221 3), matching this SDK's existing per-connection DATAGRAM policy.
 * @param s the session the datagram is addressed to
 * @param payload the HTTP Datagram payload (qsid prefix NOT included)
 * @return 1 queued, 0 when s resolves to no live connection, this
 *   endpoint's SETTINGS have not been sent yet (RFC 9297 2.1), the ring is
 *   full, or the prefixed payload exceeds a ring slot */
int wired_server_wt_send_datagram_to(wired_wt_session* s, quic_span payload);

/** draft-ietf-webtrans-http3-15 SS4.2/SS4.4/8.2 (WTH3-067): close s's
 * WebTransport session: send a WT_CLOSE_SESSION capsule (app_error_code,
 * message) followed immediately by FIN on the session's own CONNECT stream,
 * then reset every other WT stream the session owns with WT_SESSION_GONE and
 * transition the session to closed. Queued (not sent inline) for delivery on
 * one of the loop's next steps, the same deferred shape as wired_server_wt_
 * send_datagram_to; a second call before the first drains overwrites the
 * pending one (last-writer-wins, same policy as this SDK's other single-slot
 * WT queues). Callable only from inside the server's own loop (a callback).
 * @param s the session to close
 * @param app_error_code the WebTransport application error code to report
 * @param message UTF-8 reason, message.n <= QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX
 *   (copied at call time, so it need not outlive the call); a longer message
 *   is truncated to the cap
 * @return 1 queued, 0 when s resolves to no live connection */
int wired_server_wt_close_session(
    wired_wt_session* s, u32 app_error_code, quic_span message);

/** Register the calling thread as srvthreads worker `index` of `n_total`,
 * with its own N-ring inbox row (inbox_row[j] receives broadcasts sent by
 * worker j, j != index only -- the caller's own broadcasts reach its own
 * connections directly, not through this row, so double-delivery to itself
 * never happens) and its own env (the connection table
 * wired_server_broadcast_datagram fans out into when this thread is the
 * caller). Called once by each worker before serving, typically right before
 * wired_srvrun_serve_env. n_total, inbox_row and env are owned by the caller
 * (srvthreads); srvrun only keeps pointers into them and never allocates or
 * frees them itself, so all three must stay live and unmoved until
 * wired_srvrun_broadcast_unregister.
 * @param index this worker's 0-based index, < n_total
 * @param n_total total worker count in the mesh, <= 16 (srvrun's fixed
 *   registry capacity)
 * @param inbox_row this worker's own row of n_total rings, row[j] fed by
 *   worker j's broadcasts (j != index; row[index] is never written)
 * @param env this worker's own wired_srvrun_env, the connection table a
 *   broadcast this thread sends is fanned out into directly */
void wired_srvrun_broadcast_register(
    int                  index,
    int                  n_total,
    wired_srvinbox_ring* inbox_row,
    wired_srvrun_env*    env);

/** Unregister the calling thread's broadcast registry entry (symmetric with
 * wired_srvrun_broadcast_register), typically at worker shutdown. A no-op if
 * the calling thread was never registered. */
void wired_srvrun_broadcast_unregister(void);

#endif
