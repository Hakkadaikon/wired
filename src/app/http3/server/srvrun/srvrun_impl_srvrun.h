#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_SRVRUN_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_SRVRUN_H

#include "app/http3/server/srvrun/srvrun_impl_cid.h"
#include "app/http3/server/srvrun/srvrun_impl_protos1.h"
#include "app/http3/server/srvrun/srvrun_impl_rst.h"
#include "transport/recovery/detect/recovery/rtt.h"
#include "transport/recovery/stats/stats.h"
#include "transport/stream/data/appdata/stream_send.h"
#include "transport/stream/data/maxstreams/maxstreams.h"
#include "transport/stream/data/stream/stream_role.h"

/* The server's fixed run context: the bound socket and the application's
 * identity + request handler. `id` points at the caller's identity struct
 * (examples/word_list's wired_main owns it) and is NOT const: a SIGHUP
 * reload (RFC 9114 5.2 note; see srvrun_reload_if_requested) overwrites
 * id->chain/chain_count/cert_seed in place so every later cold-started
 * connection (wired_srvboot_accept, via srvrun_slot_id) picks up the new
 * material. Live connections never re-read id after their handshake keys are
 * derived, so a reload never disturbs them (RFC 9001 4). cert_path/key_path
 * are 0 unless --cert/--key were given, disabling reload entirely. Passed by
 * pointer so no per-datagram copy (a Parameter Object folds what were 4
 * separate args threaded through every step). */
typedef struct {
  i64                   fd;
  wired_srvboot_id*     id;
  wired_srvloop_handler handler;
  void*                 ctx;
  const char*           qlog_path;   /**< qlog file path, or 0 to disable */
  const char*           keylog_path; /**< NSS key log path, or 0 to disable */
  const char*           cert_path; /**< cert.pem path, or 0 to disable reload */
  const char*           key_path;  /**< key.pem path, or 0 to disable reload */
  int                   cc_algo;   /**< CC_ALGO_* for fresh connections */
  int                   busy_poll; /**< 1: nonblocking spin instead of poll */
  wired_wt_on_datagram  wt_on_datagram;    /**< app WT datagram callback, 0 to
                                            * disable */
  void*                   wt_datagram_ctx; /**< opaque ctx for wt_on_datagram */
  wired_wt_on_stream_data wt_on_stream_data; /**< app WT stream-data callback,
                                              * 0 to disable */
  void*         wt_stream_data_ctx; /**< opaque ctx for wt_on_stream_data */
  wired_srvxdp* xdp; /**< 0 = UDP socket path; non-0 = AF_XDP driver */
  /** The mutable server state this run drives -- g_srvrun_env for
   * wired_server_run/wired_server_run_opt, or a caller-supplied instance for
   * wired_srvrun_serve_env. Never 0 once srvrun_loop is reached. */
  wired_srvrun_env* env;
  /** 1 when this instance does not own SIGTERM/SIGHUP (a srvthreads worker:
   * the control thread installs the handlers and owns the shutdown word,
   * this instance only polls it). Such an instance keeps SIGTERM/SIGHUP
   * blocked for its whole lifetime (srvthreads blocks before cloning), so an
   * unbounded blocking wait -- plain recvmmsg with nothing in flight -- would
   * never be interrupted and would never observe shutdown. Forces the same
   * timeout-bounded wait busy_poll/xdp already use, so the loop head's
   * shutdown poll (srvrun_step) is reached at least once per SRVRUN_PTO_MS
   * even when idle. */
  int no_signal_handlers;
  /** AF_XDP core-routing: -1 disabled, >= 0 (only meaningful when xdp is
   * also set) is this worker's own core/queue index, see
   * wired_srvrun_opt.core_id. */
  int core_id;
  /** WebTransport subprotocol negotiation (draft-ietf-webtrans-http3-15
   * SS3.4): space-separated server subprotocol list, 0 to disable. */
  const char* wt_protocols;
  /** Session-established notification, 0 to disable. */
  wired_wt_on_session wt_on_session;
  void*               wt_session_ctx; /**< opaque ctx for wt_on_session */
  /** RFC 9000 8.1.2 forced address validation, see wired_srvrun_opt. */
  int force_retry;
  /** WT resource lookup, 0 to disable, see wired_srvrun_opt. */
  wired_wt_resource_check wt_resource_check;
  void*                   wt_resource_ctx; /**< opaque ctx for
                                            * wt_resource_check */
  /** WT stream-reset delivery, 0 to disable, see wired_srvrun_opt. */
  wired_wt_on_stream_reset wt_on_stream_reset;
  void* wt_stream_reset_ctx; /**< opaque ctx for wt_on_stream_reset */
  /** WT session-ended delivery, 0 to disable, see wired_srvrun_opt. */
  wired_wt_on_session_close wt_on_session_close;
  void* wt_session_close_ctx; /**< opaque ctx for wt_on_session_close */
  /** Per-step app hook, 0 to disable, see wired_srvrun_opt. */
  wired_srvrun_on_step on_step;
  void*                on_step_ctx; /**< opaque ctx for on_step */
  /** status/header-aware app responder, used instead of handler when set
   * (wired_srvrun_handler.http) */
  wired_http_handler http;
  /** request-body streaming callback (wired_srvrun_handler.on_body) */
  wired_srvloop_on_body on_body;
  /** WT Origin verdict, 0 to disable, see wired_srvrun_opt. */
  int (*wt_origin_check)(void* ctx, wired_span origin, wired_span authority);
  void* wt_origin_ctx; /**< opaque ctx for wt_origin_check */
} srvrun_cfg;

/* One live connection's mutable state: the orchestrator, the HTTP/3 loop,
 * whether it has completed its first (Initial) reply, the peer address to
 * send replies to (recorded from the datagram that opened the slot, RFC 9000
 * 5.1 — every reply on this slot targets this address, not whichever peer's
 * datagram was received most recently), and this slot's own server source
 * connection id. scid is generated per slot (cid_generate): every slot
 * sharing cfg->id's fixed scid would make every connection answer to the same
 * DCID, collapsing conntable's routing to a single slot. Indexed in
 * parallel with the conntable slot of the same index. */
/* One in-flight response answering one request stream. The connection's PN
 * space (l.tx_pn) and congestion controller (cc, below) stay per-connection
 * -- only the send session (unsent/in-flight/requeue bookkeeping) is
 * per-stream, so up to SRVRUN_RESP_SLOTS requests can be in flight
 * concurrently on one connection (RFC 9000 2.2). */
/* draft-ietf-webtrans-http3-15 SS4 / RFC 9220 3: how many independent
 * WebTransport sessions one connection holds open (unest/est/draining, not
 * closed) at once. A small constant, not WIRED_SRVLOOP_MAX_WT_STREAMS/
 * WIRED_SRVLOOP_MAX_WT_UNI_STREAMS (24 and 6 by default) -- those bound one
 * connection's total reassembled WT stream slots, shared across however many
 * sessions are open, so SRVRUN_MAX_WT_SESSIONS must stay well under either
 * to leave every session room for more than one stream (checked below). */
#define SRVRUN_MAX_WT_SESSIONS 2

_Static_assert(SRVRUN_MAX_WT_SESSIONS >= 1, "at least one session slot");

_Static_assert(
    SRVRUN_MAX_WT_SESSIONS <= WIRED_SRVLOOP_MAX_WT_STREAMS,
    "every session needs room for a bidi stream in the shared table");

_Static_assert(
    SRVRUN_MAX_WT_SESSIONS <= WIRED_SRVLOOP_MAX_WT_UNI_STREAMS,
    "every session needs room for a uni stream in the shared table");

/* Bytes retained of an accepted Extended CONNECT's own :path pseudo-header
 * (draft-ietf-webtrans-http3-15 SS3.2), enough for typical endpoint paths
 * (e.g. quic-interop-runner's "/<endpoint>") without growing per-slot storage
 * for an arbitrarily long one; overflow is truncated, not rejected -- the
 * value is descriptive bookkeeping, not itself validated. */
#define SRVRUN_WT_PATH_CAP 128

/* RFC 9000 14.1/17.3.1: the largest CONNECTION_CLOSE frame that still seals
 * into one minimum-size (1200-byte) datagram whatever the peer's CID length:
 * 1200 - short header (byte0 1 + DCID <= 20 + 4-byte packet number) - AEAD
 * tag (16) = 1159. */
#define SRVRUN_CLOSE_PL_MAX \
  (MIN_INITIAL_DATAGRAM - (5 + WIRED_MAX_CID_LEN) - GCM_TAG)

/* RFC 9114 10.5.2: WebTransport (Extended CONNECT) sessions open across ALL
 * connections at once, on top of the per-connection SRVRUN_MAX_WT_SESSIONS.
 * One per connection slot on average -- half the structural ceiling of
 * WIRED_CONNTABLE_CAP * SRVRUN_MAX_WT_SESSIONS. Every open session costs
 * per-step CPU (srvrun_on_step walks each active slot's stream offers,
 * datagram queue and capsule scratch every step), so the aggregate stays
 * bounded no matter how many peers each open two; a CONNECT past this cap
 * gets the same 429 + H3_REQUEST_REJECTED as a per-connection-full one. */
#define SRVRUN_MAX_WT_SESSIONS_GLOBAL WIRED_CONNTABLE_CAP

/* RFC 9114 8.1/10.5 (CVE-2023-44487-class rapid reset): a connection that
 * sends more than this many RESET_STREAM/STOP_SENDING frames inside one
 * SRVRUN_RESET_WINDOW_MS fixed window is closed with H3_EXCESSIVE_LOAD.
 * Generous on purpose: a legitimate client cancels at most a handful of
 * requests per second (a page navigation abandons its in-flight fetches;
 * SRVRUN_RESP_SLOTS bounds what it can even have in flight), while an
 * attacker's value is in thousands per second, so 100/s separates the two
 * with a wide margin and never trips on a burst of browser tab closes. */
#define SRVRUN_MAX_RESETS_PER_WINDOW 100

/* draft-ietf-webtrans-http3-15 SS5.2: Extended CONNECT sessions one
 * connection may establish inside one SRVRUN_RESET_WINDOW_MS window (the
 * same fixed window as the reset limit, srvrun_roll_reset_window); the next
 * takes the 429 + H3_REQUEST_REJECTED path a full slot table takes. With
 * SRVRUN_MAX_WT_SESSIONS (2) concurrent, 10/s means a client opening and
 * closing a session five times a second -- no real app does, a churn
 * attacker (each accept costs a 2xx, a callback and slot bookkeeping) wants
 * thousands. */
#define SRVRUN_MAX_WT_SESSIONS_PER_WINDOW 10

/* RFC 9000 21.6 (Slowloris): a boot must confirm within this many ms of
 * claiming its slot, whatever its last fragment's age -- the idle sweep
 * alone lets a peer hold a pre-handshake slot forever by trickling one
 * Initial fragment (or Initial retransmit) just inside WIRED_SRVRUN_IDLE_MS
 * (30 s). 10 s clears even a 2 s-RTT path through a HelloRetryRequest round
 * trip plus a two-round antiamp-gated flight, and stays under the idle
 * timeout so the sweep's existing cadence reaps it. */
#define SRVRUN_BOOT_DEADLINE_MS 10000
#define SRVRUN_RESET_WINDOW_MS 1000

/* Pending wired_server_wt_stream_reset entries one connection holds between
 * steps (the wt_stream_reset_* latch below). A full latch refuses further
 * resets (nothing is overwritten or half-applied), and the caller retries
 * after the next step drains it -- so 8 need only cover one step's realistic
 * burst, not the whole SRVRUN_WT_SEND_SLOTS table. */
#define SRVRUN_WT_RESET_LATCH 8

#include "app/http3/server/srvrun/srvrun_impl_wtx.h"

typedef struct {
  int            in_use;
  u64            stream_id;
  wired_sendsess sess;
  /* -1: this response's body fit the connection slot's fixed respstore row.
   * >=0: the body instead lives in this wired_srvbigbuf row (env->bigbuf),
   * released back to the pool when this resp[] slot is reaped. */
  int bigbuf_row;
  /* RFC 9000 18.2/19.10: this stream's send credit -- the peer's
   * initial_max_stream_data_bidi_local (seeded when this slot starts,
   * srvrun_start_resp) raised by any MAX_STREAM_DATA the peer sends
   * naming this stream (never lowered, RFC 9000 4.1). Bytes sent past
   * this ceiling would be a FLOW_CONTROL_ERROR from the peer's own
   * accounting; srvrun_can_send_new gates new sends on it so that never
   * happens. */
  u64 stream_credit;
  /** RFC 9000 4.1: this stream's last STREAM_DATA_BLOCKED (its doc). */
  srvrun_blocked_mark sdb;
  /* 1 while the app handler has more response body to produce
   * (wired_srvloop_handler's *more): srvrun_resp_refill keeps feeding the
   * ring below and the slot must not be released even if its sendsess
   * momentarily drains. 0 for every ordinary (single-round) response. */
  int streaming;
  /* Ring capacity of this streaming response's storage row from the armed
   * q.p to the row's end (srvrun_resp_ring_init): the sendq cycles through
   * it forever instead of draining and re-arming per round -- the old
   * round boundary idled the link for ~1 RTT every buffer's worth (an
   * ~8% goodput loss on the interop link). 0 (unset) for non-streaming
   * responses, whose queue stays linear. */
  usz ring_cap;
  /* Response body bytes delivered to the handler/sendsess so far, across
   * every round of a streaming response (RFC 9000 19.8's absolute stream
   * offset for the NEXT round to arm at). Meaningless while !streaming. */
  u64 stream_off;
  /* 1 once the h3 HEADERS+DATA prefix has been written for this response
   * (only the first round writes it; every later round is raw body bytes
   * continuing the same DATA frame). Meaningless on the hq-interop path,
   * which never frames at all. */
  int stream_h3_framed;
  /* Round 0's request, every view copied out of c->l.req (a per-connection
   * mirror of "whichever request completed most recently this step" --
   * route_note_done overwrites it every time ANY stream on this connection
   * finishes, so a later round calling the handler with c->l.req directly
   * would silently serve a DIFFERENT stream's path the moment a sibling
   * response's request completes in between rounds; the bug this fixes
   * against a real quic-go client running 3 parallel large downloads:
   * whichever stream's request happened to complete last got served to
   * every other stream's later rounds too). Meaningless while !streaming. */
  u8                   stream_req_scratch[512];
  wired_h3reqdrive_req stream_req;
  /** 1 once the header section could not be framed (it did not fit the
   * prefix room) so the response was never armed: the next reap resets
   * the stream (H3_INTERNAL_ERROR) and frees the slot (srvrun_reap_one). */
  u8 arm_failed;
} srvrun_resp;

/* Matches WIRED_SRVLOOP_MAX_STREAMS: the receive side's stream-slot table
 * bounds how many distinct request streams a connection reassembles at
 * once, so the response side never needs more slots than that. */
#define SRVRUN_RESP_SLOTS WIRED_SRVLOOP_MAX_STREAMS

/* Bytes of append-round staging each WT send slot owns (roundbuf below):
 * payloads up to this size are copied in, larger ones stay caller-owned
 * views. Must hold the WT receive window (WIRED_SRVLOOP_WT_BUF_CAP,
 * 49152 -- one delivery can fill the whole window) plus the held relay
 * fragment (under WIRED_MOQTRUN_RELAY_FRAG_MAX, 16384), so a full-window
 * relayed payload (e.g. a screen-share frame) still copies instead of
 * falling back to a view_round (checked below, once both terms are in
 * scope). An app's open path adds its own overhead (moqt_chat: signal
 * prefix 9 + SUBGROUP_HEADER 40), so such an app refuses a payload past
 * this size rather than handing it over as a view (examples/moqt_chat
 * MOQT_OPEN_BUF). */
#define SRVRUN_WTSEND_BUF 131072

/* One in-flight server-initiated WebTransport stream send (wired_server_wt_
 * open_uni/open_bidi/stream_reply): the same wired_sendsess bookkeeping a
 * resp[] slot carries, minus every response-only concern (respstore/bigbuf
 * storage, streaming rounds, H3 framing). A payload that fits roundbuf is
 * copied in (the caller's storage is free the moment the call returns);
 * only a larger payload is held as the app's own view (srvrun.h's liveness
 * contract). stream_credit mirrors srvrun_resp.stream_credit (RFC
 * 9000 18.2/19.10), seeded from whichever peer TP matches the stream's
 * direction and raised by MAX_STREAM_DATA naming this stream. */
typedef struct {
  int            in_use;
  u64            stream_id;
  wired_sendsess sess;
  u64            stream_credit;
  /** RFC 9000 4.1: this stream's last STREAM_DATA_BLOCKED (its doc). */
  srvrun_blocked_mark sdb;
  /** 1 while the stream is held open for more app-driven rounds
   * (wired_server_wt_open_uni_stream/open_bidi_stream/stream_reply_open, or
   * wired_server_wt_stream_send with fin=0): the pump suppresses the wire
   * FIN at each round boundary (srvrun_wt_slice_fin) and the reap keeps the
   * slot past a fully-ACKed round (srvrun_wtsend_finished) -- the same
   * round shape as a streaming resp[] slot, minus its handler-driven
   * refills. 0 for the one-shot opens, which close with FIN. */
  int append_open;
  /** RFC 9000 19.8: cumulative stream bytes armed across every round so
   * far -- the base offset the next append round re-arms at
   * (wired_sendsess_set_base_offset), mirroring srvrun_resp's stream_off. */
  u64 stream_off;
  /** 1 while a bare-FIN round (wired_server_wt_stream_fin) is waiting to go
   * out: wired_sendq_next never yields a slice for a 0-byte arm (RFC 9000
   * 19.8's FIN needs SOME slice to ride, and an empty sendq is "already
   * done" by construction, sendq.c's wired_sendq_all_sent), so a stream
   * that must close with no further bytes to send (its last append_open
   * round already went out, and the caller has nothing new to append) has
   * no slice for the wire FIN to attach to through the normal sess.q path.
   * srvrun_pump_one_wt sends one synthetic 0-byte/fin=1 slice directly
   * when this is set, bypassing wired_sendsess_take. */
  int fin_only_pending;
  /** 1 while wired_server_wt_stream_fin was called but the previous round
   * was still in flight (wired_sendsess_done was false) -- the FIN could
   * not be armed immediately. Promoted to fin_only_pending (and cleared)
   * by srvrun_pump_one_wt the moment the in-flight round finishes, so the
   * app's FIN request is never silently dropped -- just deferred, same as
   * a data round would be. */
  int fin_requested;
  /** Slot-owned staging for append rounds (and any payload that fits):
   * wired_server_wt_stream_send copies each accepted round behind the
   * bytes already staged and EXTENDS the live sendsess over it
   * (wired_sendsess_extend), so rounds pipeline onto the wire without
   * waiting for the previous round's ACK, and the caller's buffer is free
   * the moment the call returns. The buffer recycles (fresh arm at the
   * cumulative stream offset, srvrun_wtsend_epoch_reset) once everything
   * staged so far is ACKed; a round that no longer fits is refused --
   * bounded retention, the caller decides whether to drop.
   * SRVRUN_WTSEND_BUF = ~24 bundled 20ms voice rounds (~170B each), about
   * half a second of ACK stall absorbed at 50 rounds/s. */
  u8 roundbuf[SRVRUN_WTSEND_BUF];
  /** 1 while sess is armed over the app's own storage instead of roundbuf
   * (a payload larger than SRVRUN_WTSEND_BUF: srvrun.h's keep-alive view
   * contract applies to it); appends wait until it fully ACKs. */
  int view_round;
  /** RFC 9218 2.1 urgency + 1 set by wired_server_wt_stream_priority; 0 =
   * never set, read as the default H3_URGENCY_DEFAULT
   * (srvrun_wtsend_urgency). */
  u8 urgency1;
  /** The rest of the send class wired_server_wt_stream_schedule set
   * (wired_wt_sched): fine breaks ties inside one urgency; a nonzero flow
   * lets only its lowest (order, tie) ready slots of the class send. All 0
   * when never set. */
  u16 fine;
  u64 flow;
  u64 order;
  u64 tie;
  /** The owning WT session's slot index for a stream opened/replied through
   * the wired_server_wt_* API, so that session's teardown can reset what it
   * owns (srvrun_reset_wt_sends_for_session); -1 for connection plumbing
   * (the QPACK encoder and decoder streams, CONNECT-stream capsule
   * sends), which no session teardown may touch. */
  int wt_session_slot;
} srvrun_wtsend;

/* Concurrent server-initiated stream sends per connection. Sized for a
 * 4-participant relay room's worst case, not a handful: 3 long-lived voice
 * relay streams stay claimed for the whole call (append_open never reaps),
 * and each relayed chat message is its OWN short-lived stream whose slot
 * only reaps once fully ACKed -- under loss, a 4-sender chat burst plus
 * ACK-delayed stragglers held more than the 3 remaining slots and the
 * overflow opens failed, silently losing whole messages. The QPACK encoder
 * and decoder streams (RFC 9204 4.2) each hold a slot for the connection's
 * whole life too. 3 voice + 2 QPACK + 4 senders x ~3 ACK-delayed messages
 * in flight = 17 (same fixed-slot policy as resp[]). */
#define SRVRUN_WT_SEND_SLOTS 17

/* Outbound broadcast DATAGRAMs (RFC 9221 5) one connection holds between
 * steps (dg_pending_buf). Same depth as one wired_srvinbox_ring (4), the
 * other leg of the broadcast fan-out, so a burst one worker's inbox can hold
 * also fits each local connection; 4 x 1200 B = 4.8 KB per connection. A
 * full queue refuses the newest -- DATAGRAMs are unreliable by design
 * (RFC 9221 1), but one already queued is never overwritten. */
#define SRVRUN_DG_PENDING_Q 4

/* Per-connection server state. Members are grouped by alignment (8-byte,
 * then 4-byte, then byte arrays) so the struct carries no padding. */
typedef struct {
  wired_server  s;
  wired_srvloop l;
  u64           last_ms; /**< monotonic ms of the last routed datagram */
  /** RFC 9000 10.1: monotonic ms of the first ack-eliciting (STREAM) send
   * since last_ms's receive, 0 = none yet; the idle timer restarts here. */
  u64 idle_tx_ms;
  /** RFC 9000 10.2: when the closing state (closing) ends -- three times
   * the PTO after the close went out. */
  u64 closing_until_ms;
  /** Packets received while closing; the close frame is resent on the
   * 1st, 2nd, 4th, 8th, ... one (RFC 9000 10.2.1 rate limit). */
  u64 closing_rx;
  /** Bytes used in close_pl. */
  usz         close_pln;
  srvrun_resp resp[SRVRUN_RESP_SLOTS]; /**< in-flight responses, one per
                                           answered request stream */
  cc cc; /**< congestion window gating every resp[]'s pump */
  /** RFC 9000 13.4.2 ECN validation for this connection's ACK feedback:
   * every packet leaves ECT(0)-marked (wired_udp_ect0_enable on the listen
   * socket), so a valid ACK-ECN report's CE increase feeds the congestion
   * controller (RFC 9002 8.1) and an inconsistent or absent report
   * disables ECN consumption (srvrun_feed_ecn). {0} fixtures leave it
   * disabled; srvrun_open_slot enables it. */
  ecn_track ecn;
  /** Per-step scratch for srvrun_feed_ecn, reset by srvrun_feed_acks: how
   * many logged packets this step's ACK ranges newly acknowledged (RFC 9000
   * 13.4.2.1's lower bound on the ECN count increase) and the newest send
   * time among them (RFC 9002 7.1.2's sent_time for the CE congestion
   * event). Both only count resp[]/wtsend[] log entries, so the bound is
   * lenient, never a false failure. */
  u64     ecn_newly;
  u64     ecn_sent_ms;
  hystart hs;           /**< slow-start exit detector (RFC 9406) */
  u64     srtt_ms;      /**< smoothed RTT of this connection's acks (pacing) */
  u64     next_send_ms; /**< pacing: earliest time to send again */
  /** RFC 9002 6.1.1: highest pn ACKed anywhere on this connection's ONE
   * packet number space (monotone) -- every resp[]'s packet-loss threshold
   * check must compare against this, not a per-stream value. Packet numbers
   * are shared across every resp[] slot (c->l.tx_pn), so with several
   * responses in flight at once a stream's own next ACK can lag well behind
   * pns its siblings have already burned through; a per-stream
   * largest_acked (sess.largest_acked, still used only to gate whether a
   * stream has been ACKed at all) reads that lag as reordering and
   * mass-requeues slices that were never actually lost. */
  u64 largest_acked;
  /** RFC 9000 18.2/19.9: this connection's send credit -- the peer's
   * initial_max_data (seeded once at handshake confirm, srvrun_boot_finish)
   * raised by any MAX_DATA the peer sends (never lowered, RFC 9000 4.1).
   * Every resp[] slot's send draws from this ONE connection-wide ceiling
   * (RFC 9000 4.1's max_data covers all streams combined), so the check
   * sums every slot's consumed bytes the same way srvrun_inflight_bytes_all
   * already sums in-flight bytes for cwnd -- a different quantity (consumed
   * is monotonic, in-flight drops on ACK), but the same fan-out shape. */
  u64 conn_credit;
  /** RFC 9000 4.1/19.12: the conn_credit value DATA_BLOCKED was last sent
   * for (sent_at, 0 meaning "never sent yet") and when -- so a sustained
   * block resends once per distinct ceiling, then once per PTO while
   * nothing is in flight, not once per pump opportunity (the gate below is
   * checked every slice attempt). A later MAX_DATA raising conn_credit
   * makes sent_at stale, so the next block at the new ceiling sends
   * again. */
  srvrun_blocked_mark data_blocked;
  /** RFC 9002 5/6.2: RTT estimator (smoothed_rtt/rttvar in us) feeding this
   * connection's PTO deadline (srvrun_pto_deadline_ms) -- separate from
   * srtt_ms above (ms, EWMA-only, pacing's simpler input) because PTO needs
   * rttvar too. */
  rtt rtt;
  /** RFC 9002 5.2/7.6.2: the newest RTT sample (ms), which min_rtt is reset
   * to on persistent congestion, and the next pn to be sent when the first
   * sample was taken -- a packet below it was sent before any sample, so
   * cannot start a persistent congestion period. */
  u64 latest_rtt_ms;
  u64 rtt_from_pn;
  /** RFC 9002 A.10 loss_time, us: when the earliest packet below the
   * largest acknowledged that is not yet lost would pass the time
   * threshold (srvrun_rec_detect); 0 = the loss timer is not armed. */
  u64 loss_time_us;
  /** RFC 9000 5.1.1/9.4: migration bookkeeping. */
  srvrun_mig mig;
  /** RFC 9001 6.5: monotonic ms this connection's Key Update generation last
   * advanced (s->ku.generation), used to floor how long the retained old
   * 1-RTT keys survive (srvrun_ku_discard_stale, 3x the PTO). Meaningless
   * until s->ku.have_old is set (a rotation at now_ms==0 is valid, so
   * have_old -- not this field being nonzero -- is the "has rotated" flag).
   */
  u64 ku_rotated_at_ms;
  /** ku.generation as of the last step, so a rotation can be detected without
   * srvloop itself tracking wall-clock time (recv.c has none). */
  u64 ku_seen_gen;
  /** boot-stage ClientHello reassembly across Initial datagrams (a
   * post-quantum-sized ClientHello spans two, RFC 9000 19.6).
   * ponytail: one fixed accumulator per slot (~4KB x 64 slots of BSS);
   * pool-share across slots if the footprint ever matters. */
  wired_srvboot_acc boot;
  /** Up to SRVRUN_MAX_WT_SESSIONS independent WebTransport sessions this
   * connection holds at once (draft-ietf-webtrans-http3-15 SS4). wt/wt_active
   * is slot 0 -- kept as the original scalar fields (not wt[0]/wt_active[0])
   * so every existing single-session caller/test outside this file that
   * constructs a srvrun_conn directly keeps compiling unchanged; wt1/
   * wt1_active is slot 1, the second concurrently-open session this
   * connection can now hold. srvrun_wt_slot/srvrun_wt_active below give both
   * slots a uniform index-based view so the routing helpers can loop 0..
   * SRVRUN_MAX_WT_SESSIONS instead of hand-unrolling 2 cases everywhere. Each
   * slot's own connect_stream_id (wired_wt_session's identity field) is its
   * routing key -- distinct sessions never share a slot, and closing one slot
   * never touches the other. */
  wired_wt_session wt;
  wired_wt_session wt1;
  /** Bytes used in each wt_path row. */
  usz wt_path_len[SRVRUN_MAX_WT_SESSIONS];
  /** draft-ietf-webtrans-http3-15 SS4.2/SS4.7 (WTH3-048/WTH3-067): the
   * CONNECT stream's own absolute QUIC stream offset (RFC 9000 19.8) just
   * past the last byte srvrun_start_wt/srvrun_send_wt_capsule has sealed onto
   * it -- captured once at the establishing 2xx (srvrun_start_wt, the HEADERS
   * frame's own byte length) and advanced by every later WT_DRAIN_SESSION/
   * WT_CLOSE_SESSION capsule append, since the response's own resp[] sendsess
   * is freed once its 2xx is fully ACKed (srvrun_resp_reap) and cannot be
   * appended to directly -- a later append instead seals a fresh 1-RTT packet
   * at THIS offset (srvrun_send_wt_capsule), so the two writers' bytes
   * concatenate correctly on the wire without either overlapping or leaving a
   * gap. */
  u64 wt_connect_sent_len[SRVRUN_MAX_WT_SESSIONS];
  /** draft-ietf-webtrans-http3-15 SS5.6 / RFC 9297 SS3.2: bytes at the
   * front of this slot's CONNECT stream receive window (the l.streams[]
   * slot's req_buf) that are not capsules. Set at establishment
   * (srvrun_start_wt) to the request's own HEADERS frame length; the next
   * capsule pass slides them out and resets it to 0 -- from then on the
   * window base is the capsule cursor. */
  usz wt_capsule_rx_at[SRVRUN_MAX_WT_SESSIONS];
  /** RFC 9297 3.2: capsule bytes received in this slot's CONNECT stream DATA
   * frames that do not yet make a whole capsule. Emptied at establishment
   * (srvrun_start_wt). */
  bodywin_capq wt_capq[SRVRUN_MAX_WT_SESSIONS];
  /** Bytes used in each wt_close_msg row. */
  usz wt_close_msg_len[SRVRUN_MAX_WT_SESSIONS];
  /** draft-ietf-webtrans-http3-15 SS4.4/8.2: wired_server_wt_stream_reset
   * calls pending -- latched (not sent inline) for the same
   * no-srvrun_cfg-in-a-callback reason as wt_close_pending, drained on the
   * next srvrun_on_step (srvrun_drain_wt_stream_reset): one standard
   * RESET_STREAM (RFC 9000 19.4) per entry, carrying the app code mapped
   * through wired_wterrmap_to_http3 and the final size captured at latch
   * time (the send slot's cumulative armed bytes; captured BEFORE the slot
   * is freed, because freeing loses the count and a final size below the
   * bytes already sent is an RFC 9000 4.5 FINAL_SIZE_ERROR at the peer).
   * A bounded queue, not wt_close_pending's single slot: one connection
   * can carry several app-driven streams (a relay fans one source out to
   * many), and a second reset latched in the same step must not silently
   * overwrite the first -- the peer would wait on the unnotified stream
   * forever. No STOP_SENDING rides along: every target is a
   * server-initiated uni stream, which has no peer-to-server half to stop
   * (RFC 9000 19.5 makes STOP_SENDING on it a STREAM_STATE_ERROR). */
  u64        wt_stream_reset_id[SRVRUN_WT_RESET_LATCH];
  srvrun_wtx wtx; /**< teardown/fairness state (srvrun_impl_wtx.h) */
  u64        wt_stream_reset_final[SRVRUN_WT_RESET_LATCH];
  /** Entries in use in the wt_stream_reset_* latch. */
  usz wt_stream_reset_n;
  /** Client-bidi stream ids whose server send part already ran to its end
   * (reply FIN ACKed and slot reaped, or a reset already sent) -- consulted
   * before building any further RESET_STREAM for the id. The record must
   * outlive BOTH the receive slot (freed once the request's FIN is
   * delivered; the reply usually comes on a later step) and the send slot
   * (reaped on the FIN ACK), so it lives in neither: same exact-id sliding
   * window as req_closed. Server-initiated ids are covered by the
   * wt_uni_opened/wt_bidi_opened counters instead (and would alias client
   * ids in this /4-indexed window, the same reason wt_closed_mark skips
   * them). */
  wired_srvloop_closed wt_send_done;
  /** RFC 9000 3.5: stream ids the peer sent RESET_STREAM for, one window
   * per stream type (id & 3, so the /4 indexes do not alias) -- this server
   * then never sends STOP_SENDING for them (srvrun_wt_abort_stop,
   * srvrun_wt_stop_refused). shortcut: the window's ceiling slide counts
   * ids left behind as reset too, which only drops a SHOULD-level
   * STOP_SENDING for a stream 1024+ indexes old. */
  wired_srvloop_closed peer_reset_seen[4];
  /** Bytes used in each dg_pending_buf entry. */
  usz dg_pending_len[SRVRUN_DG_PENDING_Q];
  /** Index of the oldest queued dg_pending_buf entry. */
  usz dg_pending_head;
  /** Bytes used in boot_ini; 0 until an accept flight is cached. */
  usz boot_ini_len;
  /** Lengths of the cached Handshake datagrams, laid back to back in
   * boot_hs; boot_dgram_count of them are used. */
  usz boot_dgram_len[WIRED_SRVBOOT_FLIGHT_MAX];
  usz boot_dgram_count;
  /** RFC 9000 8.1: how many of boot_dgram_len[0..boot_dgram_count) have
   * actually been sent so far -- the rest stay held back by the
   * anti-amplification gate (srvrun_boot_send_gated) until more bytes
   * arrive from the client. Meaningless (and unused) once
   * wired_server_is_confirmed, when the path is validated and the limit no
   * longer applies. */
  usz boot_dgram_sent;
  /** RFC 9000 8.1 antiamp budget inputs for this slot, tracked only through
   * boot (path validation): bytes physically received from this peer
   * (srvrun_serve_slot, every datagram regardless of whether it parses) and
   * bytes sent to it (srvrun_send, Initial + Handshake flight combined). */
  u64 boot_rx_bytes;
  u64 boot_tx_bytes;
  /** RFC 9002 6.2: monotonic ms this slot's boot flight (Initial +
   * Handshake) was last sent -- the first send in srvrun_boot_finish, or any
   * resend (srvrun_resend_boot_flight, or the timer-driven boot PTO itself,
   * srvrun_boot_pto_slot). Drives the boot-stage PTO deadline the same way
   * wired_sendsess's own sent_ms drives srvrun_sess_pto_due, but boot has no
   * wired_sendsess of its own (the flight is a raw cached byte span, not a
   * slice log) so this one timestamp stands in for it. Meaningless before
   * boot_ini_len is first set. */
  u64 boot_pto_sent_ms;
  /** RFC 9000 21.6: monotonic ms this slot was claimed (srvrun_open_slot);
   * a boot still unconfirmed SRVRUN_BOOT_DEADLINE_MS later is reaped by the
   * idle sweep regardless of last_ms (srvrun_boot_overdue). */
  u64 boot_claim_ms;
  /** Server-initiated WebTransport stream sends in flight on this
   * connection (wired_server_wt_open_uni/open_bidi/stream_reply), pumped/
   * ACKed/probed alongside resp[] under the same connection-wide gates. */
  srvrun_wtsend wtsend[SRVRUN_WT_SEND_SLOTS];
  /** Diagnostic counters for wired_server_wt_stream_send: rounds appended
   * (ok), live rounds refused only because the previous round was still
   * unACKed (busy -- the round the caller then drops), and rounds refused
   * by WT session flow control (flow). Cumulative, surfaced ~1/s via the
   * qlog recovery:metrics_updated record (srvrun_qlog_metrics). */
  u64 stat_wtsend_ok;
  u64 stat_wtsend_busy;
  u64 stat_wtsend_flow;
  /** STREAMS_BLOCKED frames actually sent (srvrun_send_streams_blocked):
   * the post-hoc proof a run's stream opens were ever capped by the peer's
   * ceiling, surfaced through the same qlog metrics record -- the send has
   * no other observable trace once the run ends. */
  u64 stat_streams_blocked;
  /** Monotonic ms of the last recovery:metrics_updated qlog emit. */
  u64 metrics_emit_ms;
  /** This connection's slot index, stamped at claim (srvrun_open_slot) and
   * emitted as every qlog record's group_id (qlogevent.h): one shared qlog
   * file carries every connection's records, and without per-record
   * attribution a multi-client run's streams interleave indistinguishably.
   * Slot indices recycle after eviction, so the pairing is unambiguous
   * within one connection's lifetime, not across the whole file. */
  u64 qlog_slot;
  /** Bumped on every claim of this slot (srvrun_open_slot), surviving the
   * claim's wipe: state that outlives the connection and names it only by
   * slot index (srvrun_dgring_entry) records it, so the next client on the
   * same slot is told apart. */
  u32 gen;
  /** RFC 9000 2.1: how many server-initiated uni streams this connection
   * has opened past the three fixed plumbing streams (H3 control id 3,
   * QPACK encoder id 7 and decoder id 11), so the next uni id is 15 + 4 *
   * wt_uni_opened -- ids only ever climb, a freed send slot never reuses
   * one. */
  u64 wt_uni_opened;
  /** RFC 9000 2.1: server-initiated bidi streams opened; the next bidi id
   * is 1 + 4 * wt_bidi_opened (nothing else opens server bidi streams). */
  u64 wt_bidi_opened;
  /** RFC 9000 4.1/19.9: this connection's own receive-side MAX_DATA last
   * advertised to the peer (0 before any raise past the initial transport
   * parameter) -- srvrun_wt_credit_due compares the sum of every WT slot's
   * delivered bytes against this to decide whether a fresh MAX_DATA is due
   * (an advertisement MUST NOT decrease, so this only ever grows). Distinct
   * from conn_credit, which is this connection's SEND-side ceiling (the
   * peer's own MAX_DATA to us) -- flow control is per-direction (RFC
   * 9000 4.1). */
  u64 rx_max_data_advertised;
  /** RFC 9000 4.6/19.11: the bidi stream limit last advertised to the peer
   * via MAX_STREAMS (0 before any raise past the server's own initial
   * transport parameter, STP_DEFAULT_MAX_STREAMS_BIDI). Raised by one every
   * time a client request stream's srvloop slot is released (srvrun_resp_
   * reap), keeping the advertised limit in lockstep with actual receive
   * capacity (WIRED_SRVLOOP_MAX_STREAMS) instead of promising room the
   * fixed-size slot table cannot back -- an advertisement MUST NOT decrease
   * (RFC 9000 4.6), so this only ever grows. */
  u64 stream_limit_advertised;
  /** RFC 9000 4.6: a MAX_STREAMS frame is not loss-tracked, so each bidi
   * raise arms a bounded PTO-spaced re-announce of the limit in force
   * (srvrun_grant_retry_slot) -- a grant tail-dropped in a full queue must
   * not leave the client polling with STREAMS_BLOCKED on its own PTO
   * backoff. grant_retry_ms is the next re-announce deadline; meaningful
   * only while grant_retries > 0. */
  u64 grant_retry_ms;
  /** Same as stream_limit_advertised, for the client-initiated UNI limit
   * (RFC 9000 4.6: independent limits per direction). Raised by one every
   * time a WT uni stream's reassembly slot is released (srvrun_reap_wt_uni_
   * slot), so a client opening one short-lived uni stream per message never
   * exhausts the initial limit -- streams it already finished keep paying
   * for new ones. Only ever grows. */
  u64 uni_stream_limit_advertised;
  /** RFC 9000 4.1: WT stream bytes delivered by slots ALREADY REAPED. The
   * connection-wide MAX_DATA ceiling is a cumulative protocol counter, but
   * srvrun_wt_rx_delivered_total only sums LIVE slots -- a reaped slot's
   * bytes silently left the sum and the advertised ceiling stagnated at
   * roughly the initial TP for a long session of short-lived streams (~10MB
   * = ~20 min of voice) and then wedged the connection. Accumulated at reap
   * time so the ceiling keeps counting up. Only ever grows. */
  u64 wt_rx_reaped_total;
  /** RFC 9000 4.6/19.11: the highest MAX_STREAMS(uni) the PEER has granted
   * this server for server-initiated uni streams (relay streams). 0 until
   * the first runtime raise; the ClientHello's initial_max_streams_uni
   * (sdrv) is the base before that. Opens beyond the limit are refused
   * locally (srvrun_wt_open_uni_common) -- a peer receiving one anyway may
   * treat it as a connection-fatal STREAM_LIMIT_ERROR, or silently discard
   * the stream and everything sent on it. */
  u64 peer_uni_stream_limit;
  /** RFC 9000 4.6/19.14: the peer_uni_stream_limit value a UNI
   * STREAMS_BLOCKED was last sent for (0 meaning "never sent yet") -- once
   * per distinct ceiling, mirroring data_blocked.sent_at's own doc. A later
   * MAX_STREAMS(uni) raise makes this stale, so blocking again at the new
   * ceiling sends again. Without this signal, a peer whose own uni-stream
   * accounting undercounts (or simply never re-grants after the initial
   * transport parameter) leaves this server's relay opens failing forever
   * with no hint that the SERVER, not the network, is the reason. */
  u64 uni_blocked_sent_at;
  /** RFC 9000 8.2/9: path validation -- the last validated path, two
   * outstanding challenges and a gated preferred target (srvrun_path_*). */
  pathsel path;
  /** RFC 9000 5.1/9.5: the client's connection IDs, one bound per path. */
  peercid pcid;
  /** RFC 9000 9.6.2: the local socket this connection's replies leave
   * through -- the primary listen fd normally, the preferred-address fd
   * once that path validated (srvrun_path_move). 0 only on test-fabricated
   * slots, read as "primary". */
  i64 tx_fd;
  /** 1 while held early datagrams are being replayed
   * (srvrun_boot_flush_zerortt): they are stepped with the triggering
   * datagram's address, so they never move the send path. */
  int replay;
  /** RFC 8899 DPLPMTUD: this connection's Packetization Layer PMTU
   * Discovery search state (pmtu), giving pmtu_mps the Maximum
   * Packet Size to fill instead of a fixed guess. Initialized alongside
   * every other slot-scoped state machine on slot claim (srvrun_open_slot);
   * probing/ACK-LOSS integration is a later step -- today only the search's
   * static initial MPS (PMTU_BASE-derived) feeds send sizing. */
  pmtu pmtu;
  /** RFC 8899 DPLPMTUD probe tracking: srvrun has no pn-scoped ACK/LOSS log
   * (resp[]/wtsend[] each track their own range-based log instead, see
   * srvrun_feed_acks), so a sent probe's pn/size/send-time are held here,
   * outside any slot, until the ACK/LOSS reconciliation step (a later
   * addition) consumes them. pmtu_probe_pn == SRVRUN_PMTU_NO_PROBE means no
   * probe is outstanding -- at most one probe is ever outstanding at a time
   * (RFC 8899 5.1.3 PROBED_SIZE is a single value), mirroring connrunner's
   * own pmtu_probe_held/pmtu_probe_pn pair (pmtudrive.c). */
  u64 pmtu_probe_pn;
  usz pmtu_probe_size;
  u64 pmtu_probe_sent_ms;
  /** Cached cross-slot totals the per-slice send gates read instead of
   * re-walking every resp[]/wtsend slot per slice (O(slots^2) per pass):
   * acct_inflight mirrors srvrun_inflight_bytes_all, acct_consumed mirrors
   * srvrun_conn_consumed_bytes. Resynced from the full scans once per step
   * (srvrun_acct_resync -- so ACK/requeue/reap effects are picked up
   * wholesale, never tracked per event) and delta-adjusted around each
   * slice attempt (srvrun_pump_one/_wt), so drift cannot outlive a step by
   * construction. The full scans stay as the source of truth and the test
   * oracle. */
  usz acct_inflight;
  usz acct_consumed;
  /** RFC 9218 visiting order for resp[] (h3prio_order output), built
   * once per pump pass (srvrun_prio_refresh) instead of once per round --
   * claims/releases/PRIORITY_UPDATEs only happen between passes, so the
   * order is stable within one. */
  usz prio_order[SRVRUN_RESP_SLOTS];
  /** RFC 9002 7.7 pacer token bucket for the sub-poll-tick regime
   * (srvrun_pace_within_poll_tick): bytes sendable right now, refilled at
   * 1.25 * cwnd / srtt per elapsed ms (srvrun_pace_refill, once per pump
   * pass) and capped at SRVRUN_PACE_BURST, charged per sent slice. Idle
   * until the first RTT sample (srtt_ms == 0: unpaced, like next_send_ms).
   */
  u64 pace_tokens;
  u64 pace_refill_ms; /**< monotonic ms of the last token refill */
  /** RFC 9114 10.5 rapid-reset window: monotonic ms the current
   * SRVRUN_RESET_WINDOW_MS window began; l.peer_reset_count is cleared when
   * a step starts a new one (srvrun_roll_reset_window). */
  u64 reset_window_start_ms;
  /** draft-ietf-webtrans-http3-15 SS3.1: one bit per l.streams[] slot whose
   * Extended CONNECT arrived before the client's SETTINGS -- held without
   * a response, then processed once when the SETTINGS arrive
   * (srvrun_start_held_resps). Zeroed with the slot on reuse. */
  u64 wt_held_mask;
  /** The stream id each wt_held_mask bit was set for: a held slot released
   * and reused by another stream before SETTINGS arrive no longer holds it
   * (HTTP/3 never reuses a stream id), so it is not started as the held
   * CONNECT (srvrun_held_still). */
  u64 wt_held_id[WIRED_SRVLOOP_MAX_STREAMS];
  /** RFC 9114 5.2: the stream id the GOAWAY carried (l.req_next_id when it
   * was sent); meaningful only once goaway_sent. */
  u64 goaway_id;
  /** RFC 9000 4.6: client WT bidi streams ended (FIN reaped, refused, reset,
   * torn down with their session) since the last bidi MAX_STREAMS raise --
   * each gives its stream credit back (srvrun_grant_wt_streams), the WT twin of
   * srvrun_reap_resps' own request-slot grant. */
  usz wt_bidi_credit_owed;
  /** wt_bidi_credit_owed's uni twin: client WT uni streams ended (FIN
   * reaped, refused at offer, reset by the peer, torn down with their
   * session) since the last MAX_STREAMS(uni) raise. Every uni receive slot
   * is client-initiated, so each one owes credit back. */
  usz wt_uni_credit_owed;
  /** RFC 9000 13.3: stream aborts sent and not yet ACKed, resent on their
   * probe deadline (srvrun_rst_retry_slot) until acknowledged. */
  srvrun_rst rst[SRVRUN_RST_RETX];
  int        up;
  sockaddr   peer;
  int        goaway_sent; /**< 1 once graceful-shutdown GOAWAY sent */
  /** RFC 9000 10.2.1: 1 once this server sent a CONNECTION_CLOSE -- the
   * closing state (srvrun_close_send). No app delivery and no send but the
   * same close frame again until the slot is reaped at closing_until_ms. */
  int closing;
  int wt_active; /**< 1 once wired_wt_session_init has been called for slot 0 */
  int wt1_active; /**< slot 1's own wt_active */
  /** draft-ietf-webtrans-http3-15 SS4.2/SS4.4/8.2 (WTH3-067): a
   * wired_server_wt_close_session call for this slot is pending -- latched
   * rather than sent inline (that entry point runs in an app callback with
   * no srvrun_cfg in hand to seal wire bytes with, mirroring
   * closed_stream_seen's own latch-in-a-callback/consume-at-step-time shape,
   * wired_srvloop.h), drained on the next srvrun_on_step
   * (srvrun_drain_wt_close_pending): send WT_CLOSE_SESSION (wt_close_code/
   * wt_close_msg/wt_close_msg_len) with FIN on the CONNECT stream, then reset
   * every OTHER WT stream this session owns with WT_SESSION_GONE (the
   * CONNECT stream itself was just cleanly FIN'd, not reset) and close the
   * session. */
  int wt_close_pending[SRVRUN_MAX_WT_SESSIONS];
  /** WT_CLOSE_SESSION error code for each wt_close_pending slot. */
  u32 wt_close_code[SRVRUN_MAX_WT_SESSIONS];
  /** draft-ietf-webtrans-http3-15 4.7: a wired_server_wt_drain_session call
   * for this slot is pending, latched like wt_close_pending and sent on the
   * next step (srvrun_flush_wt_drain). */
  int wt_drain_pending[SRVRUN_MAX_WT_SESSIONS];
  /** App error code of each wt_stream_reset_id entry (see its doc). */
  u32 wt_stream_reset_app_code[SRVRUN_WT_RESET_LATCH];
  int dg_pending; /**< datagrams queued in dg_pending_buf, undrained */
  /** RFC 9002 6.2: consecutive boot-stage probe count, the boot-flight
   * counterpart to wired_sendsess.pto_count -- scales srvrun_pto_deadline_ms'
   * backoff and, at SRVRUN_PTO_MAX, tears the slot down the same way
   * srvrun_pto_slot's budget exhaustion does. Reset to 0 whenever the boot
   * flight is (re)sent for a reason other than this timer (a fresh accept or
   * a client-triggered retransmit both prove the peer is still reachable). */
  int boot_pto_count;
  /** RFC 9204 4.2: 1 once this connection's own QPACK encoder stream (id 7)
   * has been opened (srvrun_open_qenc_stream) -- opened exactly once, right
   * after SETTINGS is confirmed sent (c->l.h3.settings_sent), never reaped
   * for the life of the connection (its wtsend[] slot's append_open stays
   * set). Guards against re-claiming a second slot on a later step. */
  int qenc_stream_opened;
  /** wtsend[] slot index (see srvrun_wtsend_claim) the QPACK encoder stream
   * lives on once qenc_stream_opened is set; meaningless before then. */
  int qenc_wtsend_slot;
  /** RFC 9204 4.2: 1 once this connection's QPACK decoder stream (id 11)
   * has been opened -- with the encoder stream, right after SETTINGS is
   * sent (srvrun_open_qpack_streams); never closed. */
  int qdec_stream_opened;
  /** wtsend[] slot of the decoder stream once qdec_stream_opened is set. */
  int qdec_wtsend_slot;
  /** RFC 9000 4.1 / 19.10: the last MAX_STREAM_DATA sent for the peer's
   * encoder stream (0: none -- the initial credit still stands). */
  u64 qenc_credit_advertised;
  /** 1 while a server-initiated uni open was refused by peer_uni_stream_
   * limit since the last srvrun_pump_sess pass (srvrun_wt_uni_open_ok's own
   * doc) -- latched here because the refusal happens on the app's own
   * open_uni_stream call (moqtrun.c), which has no srvrun_cfg to send a
   * STREAMS_BLOCKED through; srvrun_pump_sess (which does have cfg) checks
   * and clears this every pass. */
  int uni_blocked_seen;
  /** draft-ietf-webtrans-http3-15 SS5.2: Extended CONNECT sessions
   * established in the current window (srvrun_start_wt), cleared with it
   * (srvrun_roll_reset_window); SRVRUN_MAX_WT_SESSIONS_PER_WINDOW refuses. */
  u32 wt_sess_window_count;
  /** draft-ietf-webtrans-http3-15 4.7: 1 once the peer's WT_DRAIN_SESSION
   * reached the app for this session slot, so a repeated DRAIN does not
   * call wt_on_session_draining again; cleared when a session starts. */
  int wt_drain_rcvd[SRVRUN_MAX_WT_SESSIONS];
  u8  scid[WIRED_MAX_CID_LEN];
  /** The CONNECTION_CLOSE frame sent, kept to resend it unchanged. */
  u8 close_pl[SRVRUN_CLOSE_PL_MAX];
  /** RFC 9000 12.3: the next unused server Initial packet number, carried
   * over from the boot accumulator (its ack_pn) when the slot came up. */
  u64 ini_next_pn;
  /** Each active slot's own Extended CONNECT :path value, copied rather than
   * viewed since the decoded request's own storage does not outlive the step
   * that established the session. Meaningless while the corresponding slot is
   * inactive. */
  u8 wt_path[SRVRUN_MAX_WT_SESSIONS][SRVRUN_WT_PATH_CAP];
  /** WT_CLOSE_SESSION reason for each wt_close_pending slot,
   * wt_close_msg_len bytes. */
  u8 wt_close_msg[SRVRUN_MAX_WT_SESSIONS][WTCAPSULE_CLOSE_MESSAGE_MAX];
  /** 1 when the wt_stream_reset_id entry is a wired_server_wt_stream_stop
   * ask instead: the
   * drain builds one STOP_SENDING (RFC 9000 19.5) for the PEER-initiated
   * stream rather than a RESET_STREAM -- a client uni has no server send
   * part to reset, and a RESET_STREAM for it would be connection-fatal
   * at the client. */
  u8 wt_stream_reset_stop[SRVRUN_WT_RESET_LATCH];
  /** Pending outbound QUIC DATAGRAMs (RFC 9221 5), a FIFO ring of
   * SRVRUN_DG_PENDING_Q queued by srvrun_queue_datagram and drained by
   * srvrun_send_pending_datagram on the next step. */
  u8 dg_pending_buf[SRVRUN_DG_PENDING_Q][1200];
  /** RFC 9000 13.3: until the handshake is confirmed, a client Initial
   * retransmission (same DCID, a fresh datagram because the prior flight was
   * lost or delayed) must get the identical flight resent, not a fresh boot.
   * Cached verbatim from the accept flight this slot last sealed; replayed
   * by srvrun_resend_boot_flight, untouched once wired_server_is_confirmed
   * is true (srvrun_is_boot_retransmit then stops routing them here). */
  u8 boot_ini[1500];
  /** Sized past a real 9-cert amplificationlimit chain's Handshake flight
   * (EncryptedExtensions + 9 CERTIFICATE entries + CertificateVerify +
   * Finished) with headroom -- see TLS_CERT_CHAIN_MAX/
   * WIRED_CERTRELOAD_CHAIN_MAX. */
  u8 boot_hs[16384];
  /** Which half of the cached flight a resend offers the antiamp budget
   * first: 1 = the Handshake datagrams, 0 = the Initial. While the budget
   * fits only part of the flight, a fixed order starves the other half --
   * under bursty loss a client holding the ServerHello but not the flight
   * behind it timed out (Handshake starved), and a client that lost every
   * ServerHello while the budget burned on the Handshake half died keyless
   * (Initial starved). A client Initial retransmit sets this from its own
   * DCID (srvrun_boot_flip_from_dcid: still addressing the ODCID = it has
   * never processed any server packet, so the ServerHello must go first;
   * addressing our SCID = it has the ServerHello, RFC 9000 7.2); each
   * timer-driven replay then alternates from there. */
  u8 boot_resend_flip;
  /** 1 once an early 1-RTT datagram was held for this still-unconfirmed
   * connection (srvrun_boot_early_onertt, RFC 9001 5.7): the client sends
   * 1-RTT only after finishing its handshake, so a held 1-RTT datagram
   * proves the client already has the whole flight and only the server's
   * receipt of its Finished is missing -- flight replays are pure waste
   * from here (duplicate pns the client discards) and the boot probe
   * switches to a minimal fresh keepalive instead
   * (srvrun_send_boot_probe). */
  u8 peer_at_onertt;
  /** RFC 9000 7.3 after a Retry (force_retry mode): the true original DCID
   * recovered from the client's validated Retry token, advertised as
   * original_destination_connection_id while the post-Retry Initial's own
   * header DCID (the Retry's SCID) becomes retry_source_connection_id.
   * Length 0 on the normal no-Retry path. */
  u8 retry_odcid[WIRED_MAX_CID_LEN];
  /** Bytes used in retry_odcid; 0 = no Retry happened on this slot. */
  u8 retry_odcid_len;
  /** RFC 9000 8.1: 1 when the client's first Initial carried a valid Retry
   * or NEW_TOKEN token -- its address is validated, so the
   * anti-amplification limit does not apply. */
  u8 addr_validated;
  /** RFC 9000 8.1.3/9.3: 1 while a NEW_TOKEN token is owed (confirmation
   * or a newly validated address) but not sent yet (srvrun_send_new_token).
   */
  u8 newtok_owed;
  /** Bidi MAX_STREAMS re-announces left (see grant_retry_ms). */
  u8 grant_retries;
  /** RFC 9000 9.5: the server connection ID the client's last opened 1-RTT
   * packet carried; a migration that keeps it may keep the peer's ID. */
  u8 rx_dcid[WIRED_MAX_CID_LEN];
  /** RFC 9000 5.1.1/19.15: the transport error a NEW_CONNECTION_ID caused,
   * closed on at the step's end (srvrun_close_on_cid); 0 = none. */
  u8 cid_err;
} srvrun_conn;

_Static_assert(
    WIRED_SRVLOOP_MAX_STREAMS <= 64, "wt_held_mask holds one bit per slot");

_Static_assert(
    QDYN_ENCRX_CAP == STP_DEFAULT_STREAM_DATA_LOCAL,
    "the encoder window holds exactly the peer uni stream credit");

/* Response storage, one row per (connection slot, response slot): 512-byte
 * prefix room (HEADERS + DATA header framed in place, h3resp_prefix)
 * followed by the handler's body. 512 fits the largest HEADERS a
 * wired_http_handler can produce: WIRED_HTTP_FIELD_BYTES_MAX (384) field
 * bytes plus per-line QPACK overhead (<= 6 x 8 fields), :status, the
 * section prefix and both frame headers (< 80). Taken out of the row, so
 * the body cap shrinks by 448 bytes instead of BSS growing: one fixed-row
 * round holds at most WIRED_SRVRUN_RESP_MAX - SRVRUN_RESP_HDR_ROOM =
 * 15872 body bytes (a larger body takes a bigbuf row or streams).
 * ponytail: 16KB per response, 64 conns x 4 response slots = 4MB BSS; raise
 * WIRED_SRVRUN_RESP_MAX when a deployment needs bigger bodies (srvbigbuf.h
 * covers the >16KB case without growing this fixed grid). A srvthreads
 * deployment (--cores N) holds one wired_srvrun_env per worker, so this
 * multiplies by N there too. */
#define WIRED_SRVRUN_RESP_MAX 16384
#define SRVRUN_RESP_HDR_ROOM 512
/* Fallback stream bytes per packet (fits a 1500 MTU) -- no longer used to
 * size an actual send (srvrun_mps below drives that from c->pmtu instead);
 * kept only as the value srvrun_mps itself falls back to for a not-yet-
 * initialized pmtu (validated == 0, e.g. a test fixture's `{0}`
 * srvrun_conn that never routes through srvrun_open_slot). */
#define SRVRUN_CHUNK 1100

/* A fully-staged WT send round slices into ceil(SRVRUN_WTSEND_BUF /
 * SRVRUN_CHUNK) pieces, every one of which lands in sendsess's in-flight
 * log (wired_sendsess_sent) before the next is taken -- so the round's
 * slice count must fit WIRED_SENDSESS_LOG or the log fills mid-round.
 * wired_sendsess_sent's caller sends the packet over the wire BEFORE
 * trying to log it (sendsess.h), so a full log does not just stall: it
 * leaves an already-sent packet unlogged, and
 * test_srvrun_wt_stream_send_queue_bound's blocking-socket drain loop
 * (which recvs exactly that many slices) hangs forever waiting on a
 * packet that was never recorded. */
_Static_assert(
    (SRVRUN_WTSEND_BUF + SRVRUN_CHUNK - 1) / SRVRUN_CHUNK <= WIRED_SENDSESS_LOG,
    "one staged WT send round's slices must fit the sendsess log");

/* Plaintext capacity for one STREAM-frame slice: the largest slice
 * srvrun_mps can yield (at most PMTU_MAX - PMTU_OVERHEAD) plus the
 * worst-case RFC 9000 19.8 STREAM header (1 type byte + three 8-byte
 * varints = 25). Derived from the PMTU constants, not a bare number: a
 * fixed 1400 held every SRVRUN_CHUNK-sized slice but not a full
 * DPLPMTUD-search-complete one (1411 bytes), and the resulting frame-encode
 * failure struck AFTER wired_sendsess_take had consumed the slice's bytes
 * -- black-holing them (never logged in flight, so never loss-detected or
 * resent) and stalling every large transfer once the search completed. */
#define SRVRUN_SLICE_PL (PMTU_MAX - PMTU_OVERHEAD + 25)
/* Payload room reserved ahead of a slice for a piggybacked multi-range ACK
 * -- same sizing rationale as respond.c's emit_ack_only pl[288] (room for
 * ACK_MAX_RANGES ranges, not just one pn). */
#define SRVRUN_ACK_ROOM 288
/* Sealed datagrams one GSO staging batch can hold: 16 x 1500 = 24KB per env
 * lands in the 14-48 packets/syscall ballpark quiche/quic-go batch at;
 * raise if profiling shows flush-bound pumps. */
#define SRVRUN_GSO_SEGS 16
/* RFC 9002 7.7: byte ceiling of one uninterrupted send burst (the pacer
 * token bucket's capacity) -- 10 full packets, the initial-window-sized
 * burst allowance the RFC recommends. Sized UNDER the interop goodput
 * link's 25-packet bottleneck queue: bursting a whole cwnd used to
 * overflow that queue every time cwnd approached BDP, capping cwnd at
 * ~BDP (39.6kB observed) instead of BDP+queue and costing ~18% goodput. */
#define SRVRUN_PACE_BURST (10 * MAX_DATAGRAM)

/* RFC 9000 19.8: the largest STREAM frame header a slice can carry -- type
 * byte + 8-byte stream id + 8-byte offset + 2-byte length (a slice never
 * reaches 16384 bytes, the 4-byte varint threshold). */
#define SRVRUN_STREAM_HDR_MAX 19

/* srvrun_conn.pmtu_probe_pn sentinel: no probe outstanding. A real pn never
 * reaches this value (RFC 9000 12.3 packet numbers are monotonic from 0 in
 * this SDK, nowhere near 2^64-1 in any run's lifetime). */
#define SRVRUN_PMTU_NO_PROBE ((u64) - 1)
/* srvrun_wait_input's poll(2) timeout: how often srvrun_step wakes up to
 * check whether any in-flight resp[] has crossed its own RTT-derived PTO
 * deadline (srvrun_pto_deadline_ms) -- this is a poll cadence, NOT the PTO
 * duration itself (that used to be conflated: firing a probe on every
 * SRVRUN_PTO_MS tick regardless of actual RTT resent real, merely-slow
 * packets on any link faster than ~300ms RTT, stalling large transfers --
 * see interop http3 500KB case). Short enough that the deadline check below
 * still fires close to on time even on a fast link (RFC 9002 6.2's own PTO
 * floor is far below this). */
#define SRVRUN_PTO_MS 25
/* How often srvrun_qlog_metrics snapshots one connection's recovery state
 * into the qlog (recovery:metrics_updated): frequent enough to plot a
 * voice run's RTT/cwnd/drop counters, rare enough not to bloat the file. */
#define SRVRUN_METRICS_INTERVAL_MS 1000
/* Consecutive PTO probes (RFC 9002 6.2's exponential backoff) with no
 * intervening ACK before this SDK gives up on the connection. 5 proved too
 * short against a real network outage: quic-interop-runner's blackhole case
 * (a 2s link cutoff, --off=2s) exhausted all 5 probes and tore the
 * connection down well before the link came back, even though the peer
 * (quic-go) itself keeps probing past 20s before giving up. 10 roughly
 * doubles the backoff's total span, giving a short real-world outage room
 * to recover without changing anything about how a probe is sent or
 * accounted (RFC 9002 doesn't mandate a specific budget). */
#define SRVRUN_PTO_MAX 10

/* Boot flight replays cap their probe spacing here instead of letting the
 * RFC 9002 6.2 doubling run free: an unconfirmed handshake is a mutual-
 * backoff trap -- the client's own loss timers inflate under the same
 * losses, and once both sides wait out multi-second timers a 30%-loss
 * handshake takes tens of seconds. The boot RTT seed is one arrival
 * sample and can only overestimate (a loss-delayed sample reads ~1-2s on
 * a 30ms path), so an uncapped or softly-capped deadline lands every
 * replay behind the peer's own ~1s handshake timer -- the peer's probe
 * always fires first and its timers keep inflating (observed live:
 * quiche's post-download close then waits 3xPTO, and with an inflated PTO
 * single connections idled 30-50s). 300ms tracks what a correctly
 * measured ~30-60ms RTT PTO would probe at; a fully blocked replay
 * consumes no probe budget, so on slow or quiet paths the antiamp gate --
 * not this cap -- sets the real pace. The replay is antiamp-bounded
 * (<= 3x client bytes) and boot-only, so the capped cadence cannot
 * amplify; congestion backoff for real data still applies post-confirm
 * via srvrun_pto_slot's uncapped deadline. */
#define SRVRUN_BOOT_RESEND_CAP_MS 300

/* Boot-stage probe budget: sized so the capped cadence still outlives a
 * peer's default 30s idle window (RFC 9000 10.1) before the slot is
 * reclaimed -- 120 fires x <=300ms spans ~36s. Fully antiamp-blocked fires
 * do not consume this budget (srvrun_resend_boot_flight's 0 return), so a
 * silent unbudgeted peer is bounded by the idle sweep, not this count. */
#define SRVRUN_BOOT_PTO_MAX 120

/* Receive batch: srvrun drains up to this many datagrams per recvmmsg call.
 * ponytail: 16 x 2048B storage (32KB) per env; raise if a profile ever shows
 * the loop syscall-bound at higher fan-in. Hoisted here (from its former
 * point of use, next to g_srvrun_rxstorage) so wired_srvrun_env below can
 * size its rxstorage member. */
#define SRVRUN_RX_BATCH 16

/* RFC 9297 5 / RFC 9221 5: one queued session-addressed HTTP Datagram
 * (wired_server_wt_send_datagram_to) -- the qsid prefix is already applied
 * at queue time, so buf is the complete DATAGRAM payload, addressed to the
 * connection slot it targets. The slot size leaves the qsid varint room on
 * top of the 1200-byte payload cap the single-slot broadcast queue uses. */
#define SRVRUN_DGRING_CAP 256
#define SRVRUN_DGRING_SLOT 1224

typedef struct {
  int conn_slot; /**< target connection's slot index in env->conns */
  u32 conn_gen;  /**< that slot's srvrun_conn.gen at queue time */
  usz len;       /**< bytes used at buf (qsid prefix included) */
  u8  buf[SRVRUN_DGRING_SLOT];
} srvrun_dgring_entry;

/* One server loop instance's whole mutable state, formerly a set of separate
 * file-scope globals (a single-threaded server needed exactly one instance of
 * each). Bundled into one struct, still with exactly one process-wide
 * instance (g_srvrun_env below) for wired_server_run/wired_server_run_opt,
 * but now also allocatable by a caller wanting more than one independent
 * server loop (wired_srvrun_env_size/init + wired_srvrun_serve_env).
 * shutdown/reload live outside this struct (srvrun.h's doc): they are
 * process-wide signal-driven flags, not per-instance state. */
/* RFC 9000 10.2.2: a just-closed connection's scid, remembered briefly so
 * its stragglers (the peer's CONNECTION_CLOSE retransmit, a final ack) are
 * swallowed instead of answered with a stateless reset -- freeing the slot
 * instantly made them unroutable, and the reset (RFC 9000 10.3) read to
 * one peer as a transport error on a cleanly closed connection (neqo
 * aborted its whole multiconnect run over it). */
typedef struct {
  u8  scid[WIRED_MAX_CID_LEN];
  u8  len;
  u64 until_ms;
} srvrun_ghost;

/* How many freshly closed connections to remember, and for how long --
 * covers the peer's own closing period (a few RTTs to a few seconds)
 * without holding real slots. */
#define SRVRUN_GHOST_SLOTS 8
#define SRVRUN_GHOST_MS 2000

struct wired_srvrun_env {
  /* RFC 9000 5.1: a fixed pool of connection slots keyed by DCID, so one
   * socket serves several clients at once. */
  conntable   table[WIRED_CONNTABLE_CAP];
  srvrun_conn conns[WIRED_CONNTABLE_CAP];
  /* Ring of freshly closed connections (srvrun_ghost above). */
  srvrun_ghost ghosts[SRVRUN_GHOST_SLOTS];
  usz          ghost_at;
  /* Response storage, one row per (connection slot, response slot) (see
   * WIRED_SRVRUN_RESP_MAX above). */
  u8 respstore[WIRED_CONNTABLE_CAP][SRVRUN_RESP_SLOTS][WIRED_SRVRUN_RESP_MAX];
  /* Receive batch storage (SRVRUN_RX_BATCH above). */
  u8 rxstorage[SRVRUN_RX_BATCH][2048];
  /* Backing storage for the large-body pool (srvbigbuf.h) plus the pool
   * itself, a view over it. A response body that does not fit
   * WIRED_SRVRUN_RESP_MAX (16KB) borrows a row here instead. */
  u8              bigbuf_rows[WIRED_SRVBIGBUF_ROWS][WIRED_SRVBIGBUF_ROW_CAP];
  wired_srvbigbuf bigbuf;
  /* Storage a SIGHUP reload decodes into — must outlive the identity built
   * from it. */
  wired_certreload_store certstore;
  /* Self-signed certificate built once before the loop (certcache.h) so a
   * chain-less identity stops rebuilding it on every accept. */
  wired_certcache certcache;
  /* PTO probe deadline for the polling drivers (srvrun_polling_ptos). */
  u64 pto_next_ms;
  /* Spin-iteration counter pacing the clock read in srvrun_pto_due. */
  u32 pto_spin;
  /* Test-only: how many times srvrun_send has fired since the last
   * srvrun_test_reset_send_count (see its doc below). */
  usz send_count;
  /* Test-only: wire flushes (send syscall batches -- an ordinary sendto or
   * one whole GSO sendmsg each count 1) since srvrun_test_reset_flush_count.
   */
  usz tx_flush_count;
  /* Test-only: the largest datagram srvrun_send/srvrun_send_staged has put
   * out since the test last zeroed it (RFC 8899 4.4 PLPMTU bound checks). */
  usz tx_max_len;
  /* GSO staging (srvrun_stage_put/srvrun_stage_flush): equal-size sealed
   * datagrams for one peer accumulated during a pump pass, flushed as one
   * UDP_SEGMENT sendmsg. seg_size is the first datagram's size; GSO's one
   * legal shorter tail closes the batch early. count == 0 means empty. */
  u8       gso_stage[SRVRUN_GSO_SEGS * 1500];
  usz      gso_seg_size;
  usz      gso_len;
  usz      gso_count;
  sockaddr gso_peer;
  /* The reload generation this env has already applied (srvrun_reload_
   * if_requested); a single-threaded run sees at most one pending generation
   * at a time, so "gen != seen" behaves exactly like the old boolean flag. */
  u32 reload_seen_gen;
  /* RFC 9000 10.3: a copy of the start-time cert_seed that stateless-reset
   * tokens derive from (srvrun_pin_reset_seed), kept apart from the
   * id->cert_seed a SIGHUP reload rewrites. */
  u8 reset_seed[SRESET_KEY];
  /* wired_srvrun_handler.on_body_abort, copied onto each connection's loop
   * at accept (kept here, not in srvrun_cfg, which the run builds once). */
  wired_srvloop_on_body_abort on_body_abort;
  /* Session-addressed HTTP Datagram send ring (wired_server_wt_send_
   * datagram_to): FIFO of dgring_n entries starting at dgring_head, drained
   * once per loop step (srvrun_dgring_drain). Env-level, not per-connection,
   * so one step's burst across many sessions shares one bounded pool. */
  srvrun_dgring_entry dgring[SRVRUN_DGRING_CAP];
  usz                 dgring_head;
  usz                 dgring_n;
  /* Earliest monotonic time the next drain slice may go out (0 = at once);
   * paces the ring so ack-clocked steps cannot amplify into a line-rate
   * burst (srvrun_dgring_drain). */
  u64 dgring_next_drain_ms;
  /* RFC 9000 9.6.2: the second UDP socket bound on the preferred address's
   * port, so replies on a migrated path leave FROM that port (a
   * single-socket NAT redirect left the reply source flapping between
   * ports and the client discarded the challenges). 0 = none configured. */
  i64 pref_fd;
  /* The fd the batch currently being served arrived on (0 = the primary
   * cfg->fd). Set around srvrun_serve_batch by the two-socket receive
   * path; single-threaded, so a plain field, not a parameter, keeps every
   * positional srvrun_step_ctx initializer in the tests compiling. */
  i64 rx_fd;
  /* The fd the staged GSO batch must flush through (srvrun_stage_put
   * records the owning connection's path fd; 0 = primary). */
  i64 gso_fd;
  /* RFC 9114 10.5 rapid-reset limit: RESET_STREAM/STOP_SENDING frames one
   * connection may send per SRVRUN_RESET_WINDOW_MS before it is closed with
   * H3_EXCESSIVE_LOAD; 0 = SRVRUN_MAX_RESETS_PER_WINDOW. A plain env field
   * rather than a srvrun_cfg member for the same reason as rx_fd above:
   * every positional srvrun_cfg initializer in the tests keeps compiling. */
  u32 max_resets_per_window;
  /* draft-ietf-webtrans-http3-15 SS8: WebTransport feature-usage totals
   * (wired_srvrun_env_wt_usage) -- sessions established (srvrun_start_wt),
   * incoming streams offered to a session (srvrun_offer_wt_slot/_uni_slot),
   * datagrams received for a session (srvrun_deliver_to_known_session). */
  wired_srvrun_wt_usage wt_usage;
  /* wired_srvrun_opt.wt_on_session_draining and its ctx, copied in at serve
   * time -- held here rather than in srvrun_cfg for the same reason as
   * max_resets_per_window above. */
  wired_wt_on_session_draining wt_on_session_draining;
  void*                        wt_session_draining_ctx;
  /* wired_srvrun_opt.raw_on_session and its ctx, held here for the same
   * reason (srvrun_raw_notify). */
  wired_rawq_on_session raw_on_session;
  void*                 raw_session_ctx;
};

#endif
