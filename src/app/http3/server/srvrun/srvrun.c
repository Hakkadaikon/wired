#include "app/http3/server/srvrun/srvrun.h"

#include "app/datagram/dgdeliver/dg_send.h"
#include "app/http3/core/h3/connect.h"
#include "app/http3/core/h3/errclass.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3/grease.h"
#include "app/http3/core/h3/method.h"
#include "app/http3/core/h3conn/establish.h"
#include "app/http3/core/h3prio/h3prio.h"
#include "app/http3/core/sfield/sfield.h"
#include "app/http3/request/h3resp/resp_build.h"
#include "app/http3/server/certcache/certcache.h"
#include "app/http3/server/certreload/certreload.h"
#include "app/http3/server/sendsess/sendsess.h"
#include "app/http3/server/sigterm/sigterm.h"
#include "app/http3/server/srvbigbuf/srvbigbuf.h"
#include "app/http3/server/srvloop/respond.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvpoll/srvpoll.h"
#include "app/http3/server/srvwire/wire.h"
#include "app/http3/server/srvxdp/srvxdp.h"
#include "app/webtransport/capsule/wtcapsule/wtcapsule.h"
#include "app/webtransport/errmap/errmap/errmap.h"
#include "app/webtransport/session/session/session.h"
#include "app/webtransport/wtwire/wtwire.h"
#include "common/bytes/util/be.h"
#include "common/bytes/util/bytes.h"
#include "common/bytes/util/ct.h"
#include "common/bytes/util/num.h"
#include "common/diag/error/error.h"
#include "common/platform/clock/mono.h"
#include "common/platform/debug/debug.h"
#include "common/platform/qlog/qlog.h"
#include "common/platform/qlog/qlogevent.h"
#include "common/platform/rng/challenge.h"
#include "common/platform/rng/cidgen.h"
#include "common/platform/rng/rng.h"
#include "common/platform/thread/thread.h"
#include "tls/ext/stp/server_tp.h"
#include "tls/handshake/core/tls/retry_tag.h"
#include "tls/keys/kuswitch/twogen.h"
#include "transport/conn/cid/migrate/migrate.h"
#include "transport/conn/cid/path/antiamp.h"
#include "transport/conn/cid/pmtu/pmtu.h"
#include "transport/conn/cid/retrytoken/retrytoken.h"
#include "transport/conn/cid/sreset/sreset.h"
#include "transport/conn/lifecycle/conntable/conntable.h"
#include "transport/conn/loop/manage/middlebox.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/poll/wait.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/frame/frame/connctl.h"
#include "transport/packet/frame/frame/flowctl.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/ncid_worker.h"
#include "transport/packet/frame/frame/stream_ctl.h"
#include "transport/packet/header/dcidresolve/dcidresolve.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/header/packet/header.h"
#include "transport/packet/header/packet/pad.h"
#include "transport/packet/header/packet/ptype.h"
#include "transport/packet/header/packet/retry.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "transport/recovery/congestion/cc/hystart.h"
#include "transport/recovery/congestion/cc/pacing.h"
#include "transport/recovery/detect/recovery/pto.h"
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
  int                   cc_algo;   /**< QUIC_CC_ALGO_* for fresh connections */
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
} srvrun_cfg;

/* One live connection's mutable state: the orchestrator, the HTTP/3 loop,
 * whether it has completed its first (Initial) reply, the peer address to
 * send replies to (recorded from the datagram that opened the slot, RFC 9000
 * 5.1 — every reply on this slot targets this address, not whichever peer's
 * datagram was received most recently), and this slot's own server source
 * connection id. scid is generated per slot (cid_generate): every slot
 * sharing cfg->id's fixed scid would make every connection answer to the same
 * DCID, collapsing quic_conntable's routing to a single slot. Indexed in
 * parallel with the conntable slot of the same index. */
/* One in-flight response answering one request stream. The connection's PN
 * space (l.tx_pn) and congestion controller (cc, below) stay per-connection
 * -- only the send session (unsent/in-flight/requeue bookkeeping) is
 * per-stream, so up to SRVRUN_RESP_SLOTS requests can be in flight
 * concurrently on one connection (RFC 9000 2.2). */
/* draft-ietf-webtrans-http3-15 SS4 / RFC 9220 3: how many independent
 * WebTransport sessions one connection holds open (unest/est/draining, not
 * closed) at once. A small constant, not WIRED_SRVLOOP_MAX_WT_STREAMS/
 * WIRED_SRVLOOP_MAX_WT_UNI_STREAMS (each 4) -- those bound one connection's
 * total reassembled WT stream slots, shared across however many sessions are
 * open, so SRVRUN_MAX_WT_SESSIONS must stay well under either to leave every
 * session room for more than one stream (see srvrun_wt_session_limit_fits_
 * stream_table_capacity's compile-time check below). */
#define SRVRUN_MAX_WT_SESSIONS 2

/* Bytes retained of an accepted Extended CONNECT's own :path pseudo-header
 * (draft-ietf-webtrans-http3-15 SS3.2), enough for typical endpoint paths
 * (e.g. quic-interop-runner's "/<endpoint>") without growing per-slot storage
 * for an arbitrarily long one; overflow is truncated, not rejected -- the
 * value is descriptive bookkeeping, not itself validated. */
#define SRVRUN_WT_PATH_CAP 128

/* Pending wired_server_wt_stream_reset entries one connection holds between
 * steps (the wt_stream_reset_* latch below). A full latch refuses further
 * resets (nothing is overwritten or half-applied), and the caller retries
 * after the next step drains it -- so 8 need only cover one step's realistic
 * burst, not the whole SRVRUN_WT_SEND_SLOTS table. */
#define SRVRUN_WT_RESET_LATCH 8

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
  /* Round 0's request method/path, copied out of c->l.req (a per-connection
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
} srvrun_resp;
/* Matches WIRED_SRVLOOP_MAX_STREAMS: the receive side's stream-slot table
 * bounds how many distinct request streams a connection reassembles at
 * once, so the response side never needs more slots than that. */
#define SRVRUN_RESP_SLOTS WIRED_SRVLOOP_MAX_STREAMS

/* Bytes of append-round staging each WT send slot owns (roundbuf below):
 * payloads up to this size are copied in, larger ones stay caller-owned
 * views. 4096 = ~24 bundled 20ms voice rounds. */
#define SRVRUN_WTSEND_BUF 4096

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
} srvrun_wtsend;
/* Concurrent server-initiated WT stream sends per connection. Sized for a
 * 4-participant relay room's worst case, not a handful: 3 long-lived voice
 * relay streams stay claimed for the whole call (append_open never reaps),
 * and each relayed chat message is its OWN short-lived stream whose slot
 * only reaps once fully ACKed -- under loss, a 4-sender chat burst plus
 * ACK-delayed stragglers held more than the 3 remaining slots and the
 * overflow opens failed, silently losing whole messages. 3 persistent +
 * 4 senders x ~3 ACK-delayed messages in flight = 15; 16 with one spare
 * (same fixed-slot policy as resp[]). */
#define SRVRUN_WT_SEND_SLOTS 16

typedef struct {
  wired_server  s;
  wired_srvloop l;
  int           up;
  quic_sockaddr peer;
  u8            scid[WIRED_MAX_CID_LEN];
  int           goaway_sent; /**< 1 once graceful-shutdown GOAWAY sent */
  u64           last_ms;     /**< monotonic ms of the last routed datagram */
  srvrun_resp   resp[SRVRUN_RESP_SLOTS]; /**< in-flight responses, one per
                                             answered request stream */
  quic_cc      cc;      /**< congestion window gating every resp[]'s pump */
  quic_hystart hs;      /**< slow-start exit detector (RFC 9406) */
  u64          srtt_ms; /**< smoothed RTT of this connection's acks (pacing) */
  u64          next_send_ms; /**< pacing: earliest time to send again */
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
   * for (0 meaning "never sent yet") -- so a sustained block resends at
   * most once per distinct ceiling, not once per pump opportunity (the
   * gate below is checked every slice attempt). A later MAX_DATA raising
   * conn_credit makes this stale, so the next block at the new ceiling
   * sends again. */
  u64 data_blocked_sent_at;
  /** RFC 9002 5/6.2: RTT estimator (smoothed_rtt/rttvar in us) feeding this
   * connection's PTO deadline (srvrun_pto_deadline_ms) -- separate from
   * srtt_ms above (ms, EWMA-only, pacing's simpler input) because PTO needs
   * rttvar too. */
  quic_rtt rtt;
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
  int wt_active; /**< 1 once wired_wt_session_init has been called for slot 0 */
  wired_wt_session wt1;
  int              wt1_active; /**< slot 1's own wt_active */
  /** Each active slot's own Extended CONNECT :path value, copied rather than
   * viewed since the decoded request's own storage does not outlive the step
   * that established the session. Meaningless while the corresponding slot is
   * inactive. */
  u8  wt_path[SRVRUN_MAX_WT_SESSIONS][SRVRUN_WT_PATH_CAP];
  usz wt_path_len[SRVRUN_MAX_WT_SESSIONS];
  /** draft-ietf-webtrans-http3-15 SS5.3/5.4/8.2 (WTH3-058/WTH3-061): 1 once
   * this slot's session has exceeded a peer-advertised WT_MAX_STREAMS/WT_MAX_
   * DATA limit (wired_server_wt_open_uni/_bidi/_stream_reply, checked against
   * wired_wt_session_stream_open_allowed/data_send_allowed) and must be
   * closed with WT_FLOW_CONTROL_ERROR. Latched rather than closed on the
   * spot: those entry points are called from app callbacks with no srvrun_cfg
   * in hand to seal the RESET_STREAM/STOP_SENDING wire bytes with, so the
   * actual close (srvrun_close_wt_flow_violations) runs on the next
   * srvrun_on_step, which does have one -- mirrors closed_stream_seen's own
   * latch-in-a-callback/consume-at-step-time shape (wired_srvloop.h). */
  int wt_flow_violation[SRVRUN_MAX_WT_SESSIONS];
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
  /** draft-ietf-webtrans-http3-15 SS4.2/SS4.4/8.2 (WTH3-067): a
   * wired_server_wt_close_session call for this slot is pending -- latched
   * (not sent inline) for the same no-srvrun_cfg-in-a-callback reason as
   * wt_flow_violation, drained on the next srvrun_on_step
   * (srvrun_drain_wt_close_pending): send WT_CLOSE_SESSION (wt_close_code/
   * wt_close_msg/wt_close_msg_len) with FIN on the CONNECT stream, then reset
   * every OTHER WT stream this session owns with WT_SESSION_GONE (the
   * CONNECT stream itself was just cleanly FIN'd, not reset) and close the
   * session. */
  int wt_close_pending[SRVRUN_MAX_WT_SESSIONS];
  u32 wt_close_code[SRVRUN_MAX_WT_SESSIONS];
  u8  wt_close_msg[SRVRUN_MAX_WT_SESSIONS][QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX];
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
   * (RFC 9000 19.5 makes STOP_SENDING on it a STREAM_STATE_ERROR). And no
   * RESET_STREAM_AT (0x24): that is a draft-ietf-quic-reliable-stream-reset
   * extension frame this SDK never negotiates, so a peer (Chrome included)
   * treats it as an unknown frame and kills the whole connection with
   * FRAME_ENCODING_ERROR. */
  u64 wt_stream_reset_id[SRVRUN_WT_RESET_LATCH];
  u32 wt_stream_reset_app_code[SRVRUN_WT_RESET_LATCH];
  u64 wt_stream_reset_final[SRVRUN_WT_RESET_LATCH];
  usz wt_stream_reset_n;
  /** One pending outbound QUIC DATAGRAM (RFC 9221 5), queued by
   * srvrun_wt_send_datagram and drained by srvrun_send_pending_datagram on
   * the next step. ponytail: single-slot, not a queue — a second send
   * request before the first drains overwrites dg_pending_buf/dg_pending_len
   * (last-writer-wins). Acceptable first-cut simplification (DATAGRAM
   * delivery is unreliable/unordered by design, RFC 9221 1); a real queue can
   * replace this if an app needs to burst more than one per step. */
  u8  dg_pending_buf[1200];
  usz dg_pending_len;
  int dg_pending; /**< 1 while dg_pending_buf holds an undrained datagram */
  /** RFC 9000 13.3: until the handshake is confirmed, a client Initial
   * retransmission (same DCID, a fresh datagram because the prior flight was
   * lost or delayed) must get the identical flight resent, not a fresh boot.
   * Cached verbatim from the accept flight this slot last sealed; replayed
   * by srvrun_resend_boot_flight, untouched once wired_server_is_confirmed
   * is true (srvrun_reinit_ok then stops routing retransmits here at all). */
  u8  boot_ini[1500];
  usz boot_ini_len;
  /** Sized past a real 9-cert amplificationlimit chain's Handshake flight
   * (EncryptedExtensions + 9 CERTIFICATE entries + CertificateVerify +
   * Finished) with headroom -- see QUIC_TLS_CERT_CHAIN_MAX/
   * WIRED_CERTRELOAD_CHAIN_MAX. */
  u8  boot_hs[16384];
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
  /** RFC 9002 6.2: consecutive boot-stage probe count, the boot-flight
   * counterpart to wired_sendsess.pto_count -- scales srvrun_pto_deadline_ms'
   * backoff and, at SRVRUN_PTO_MAX, tears the slot down the same way
   * srvrun_pto_slot's budget exhaustion does. Reset to 0 whenever the boot
   * flight is (re)sent for a reason other than this timer (a fresh accept or
   * a client-triggered retransmit both prove the peer is still reachable). */
  int boot_pto_count;
  /** RFC 9000 7.3 after a Retry (force_retry mode): the true original DCID
   * recovered from the client's validated Retry token, advertised as
   * original_destination_connection_id while the post-Retry Initial's own
   * header DCID (the Retry's SCID) becomes retry_source_connection_id.
   * Length 0 on the normal no-Retry path. */
  u8 retry_odcid[WIRED_MAX_CID_LEN];
  /** Bytes used in retry_odcid; 0 = no Retry happened on this slot. */
  u8 retry_odcid_len;
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
  /** RFC 9000 2.1: how many server-initiated uni streams this connection
   * has opened past the H3 control stream (id 3), so the next uni id is
   * 7 + 4 * wt_uni_opened -- ids only ever climb, a freed send slot never
   * reuses one. */
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
   * per distinct ceiling, mirroring data_blocked_sent_at's own doc. A later
   * MAX_STREAMS(uni) raise makes this stale, so blocking again at the new
   * ceiling sends again. Without this signal, a peer whose own uni-stream
   * accounting undercounts (or simply never re-grants after the initial
   * transport parameter) leaves this server's relay opens failing forever
   * with no hint that the SERVER, not the network, is the reason. */
  u64 uni_blocked_sent_at;
  /** 1 while a server-initiated uni open was refused by peer_uni_stream_
   * limit since the last srvrun_pump_sess pass (srvrun_wt_uni_open_ok's own
   * doc) -- latched here because the refusal happens on the app's own
   * open_uni_stream call (moqtrun.c), which has no srvrun_cfg to send a
   * STREAMS_BLOCKED through; srvrun_pump_sess (which does have cfg) checks
   * and clears this every pass. */
  int uni_blocked_seen;
  /** RFC 9000 8.2/9: this connection's ONE path-validation state machine
   * (quic_migrate), tracking the naive rebind-follow in srvrun_rebind_peer
   * through detect -> challenge -> validate. One instance, not one per path:
   * this SDK tracks only the single most-recently-seen path (see
   * path_challenge_data's doc) -- multiple concurrent paths (RFC 9000 9.3.1)
   * are out of scope (see srvrun_rebind_peer's own doc for the full
   * list of what this slice deliberately does not implement). */
  quic_migrate migrate;
  /** RFC 9000 8.2.2: the 8-byte PATH_CHALLENGE data last sent for the path
   * currently being validated, valid only while migrate.challenged and not
   * yet migrate.validated. Re-armed (overwritten) on every new rebind
   * detected before the prior challenge validates -- srvrun_rebind_peer only
   * ever tracks the single latest path, so an in-flight PATH_RESPONSE for a
   * since-superseded challenge simply fails to compare equal. */
  u8 path_challenge_data[QUIC_PATH_DATA];
  /** RFC 8899 DPLPMTUD: this connection's Packetization Layer PMTU
   * Discovery search state (quic_pmtu), giving quic_pmtu_mps the Maximum
   * Packet Size to fill instead of a fixed guess. Initialized alongside
   * every other slot-scoped state machine on slot claim (srvrun_open_slot);
   * probing/ACK-LOSS integration is a later step -- today only the search's
   * static initial MPS (QUIC_PMTU_BASE-derived) feeds send sizing. */
  quic_pmtu pmtu;
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
  /** RFC 9218 visiting order for resp[] (quic_h3prio_order output), built
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
} srvrun_conn;

/* Response storage, one row per (connection slot, response slot): 64-byte
 * prefix room (HEADERS + DATA header framed in place, quic_h3resp_prefix)
 * followed by the handler's body.
 * ponytail: 16KB per response, 64 conns x 4 response slots = 4MB BSS; raise
 * WIRED_SRVRUN_RESP_MAX when a deployment needs bigger bodies (srvbigbuf.h
 * covers the >16KB case without growing this fixed grid). A srvthreads
 * deployment (--cores N) holds one wired_srvrun_env per worker, so this
 * multiplies by N there too. */
#define WIRED_SRVRUN_RESP_MAX 16384
#define SRVRUN_RESP_HDR_ROOM 64
/* Fallback stream bytes per packet (fits a 1500 MTU) -- no longer used to
 * size an actual send (srvrun_mps below drives that from c->pmtu instead);
 * kept only as the value srvrun_mps itself falls back to for a not-yet-
 * initialized quic_pmtu (validated == 0, e.g. a test fixture's `{0}`
 * srvrun_conn that never routes through srvrun_open_slot). */
#define SRVRUN_CHUNK 1100
/* Plaintext capacity for one STREAM-frame slice: the largest slice
 * srvrun_mps can yield (QUIC_PMTU_MAX - QUIC_PMTU_OVERHEAD) plus the
 * worst-case RFC 9000 19.8 STREAM header (1 type byte + three 8-byte
 * varints = 25). Derived from the PMTU constants, not a bare number: a
 * fixed 1400 held every SRVRUN_CHUNK-sized slice but not a full
 * DPLPMTUD-search-complete one (1411 bytes), and the resulting frame-encode
 * failure struck AFTER wired_sendsess_take had consumed the slice's bytes
 * -- black-holing them (never logged in flight, so never loss-detected or
 * resent) and stalling every large transfer once the search completed. */
#define SRVRUN_SLICE_PL (QUIC_PMTU_MAX - QUIC_PMTU_OVERHEAD + 25)
/* Payload room reserved ahead of a slice for a piggybacked multi-range ACK
 * -- same sizing rationale as respond.c's emit_ack_only pl[288] (room for
 * QUIC_ACK_MAX_RANGES ranges, not just one pn). */
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
#define SRVRUN_PACE_BURST (10 * QUIC_MAX_DATAGRAM)

/* RFC 8899 4.4: the Maximum Packet Size c's DPLPMTUD search has validated so
 * far, in stream bytes per packet -- every send-sizing call site in this
 * file (wired_sendsess_arm's chunk argument, and the cwnd/credit gates that
 * must reserve room for the same chunk they will actually send) goes
 * through this one function instead of quic_pmtu_mps directly, so a
 * srvrun_conn whose pmtu was never quic_pmtu_init'd (validated == 0 --
 * every non-production `srvrun_conn c = {0}` test fixture in this file)
 * falls back to SRVRUN_CHUNK rather than underflowing quic_pmtu_mps's
 * unsigned subtraction. */
static usz srvrun_mps(const srvrun_conn* c) {
  return c->pmtu.validated ? quic_pmtu_mps(&c->pmtu) : SRVRUN_CHUNK;
}

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
/* RFC 9000 18.2's default when the peer's own transport parameter isn't
 * tracked (srvrun does not parse the client's max_ack_delay yet -- YAGNI
 * until a deployment needs a non-default value). */
#define SRVRUN_MAX_ACK_DELAY_US 25000
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
struct wired_srvrun_env {
  /* RFC 9000 5.1: a fixed pool of connection slots keyed by DCID, so one
   * socket serves several clients at once. */
  quic_conntable table[QUIC_CONNTABLE_CAP];
  srvrun_conn    conns[QUIC_CONNTABLE_CAP];
  /* Response storage, one row per (connection slot, response slot) (see
   * WIRED_SRVRUN_RESP_MAX above). */
  u8 respstore[QUIC_CONNTABLE_CAP][SRVRUN_RESP_SLOTS][WIRED_SRVRUN_RESP_MAX];
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
  /* GSO staging (srvrun_stage_put/srvrun_stage_flush): equal-size sealed
   * datagrams for one peer accumulated during a pump pass, flushed as one
   * UDP_SEGMENT sendmsg. seg_size is the first datagram's size; GSO's one
   * legal shorter tail closes the batch early. count == 0 means empty. */
  u8            gso_stage[SRVRUN_GSO_SEGS * 1500];
  usz           gso_seg_size;
  usz           gso_len;
  usz           gso_count;
  quic_sockaddr gso_peer;
  /* The reload generation this env has already applied (srvrun_reload_
   * if_requested); a single-threaded run sees at most one pending generation
   * at a time, so "gen != seen" behaves exactly like the old boolean flag. */
  u32 reload_seen_gen;
  /* Session-addressed HTTP Datagram send ring (wired_server_wt_send_
   * datagram_to): FIFO of dgring_n entries starting at dgring_head, drained
   * once per loop step (srvrun_dgring_drain). Env-level, not per-connection,
   * so one step's burst across many sessions shares one bounded pool. */
  srvrun_dgring_entry dgring[SRVRUN_DGRING_CAP];
  usz                 dgring_head;
  usz                 dgring_n;
};

/* The one process-wide instance wired_server_run/wired_server_run_opt drive
 * -- a single-threaded server needs exactly one. wired_srvrun_serve_env lets
 * a caller supply its own instead, for more than one independent loop. */
static wired_srvrun_env g_srvrun_env;

/* Aliases so every existing reference below (and in tests/app/srvrun_test.c,
 * which reaches into these by name) keeps compiling unchanged against the one
 * process-wide instance -- the env split moved the storage, not the names. */
#define g_srvrun_table (g_srvrun_env.table)
#define g_srvrun_state (g_srvrun_env)
#define g_srvrun_respstore (g_srvrun_env.respstore)
#define g_srvrun_rxstorage (g_srvrun_env.rxstorage)
#define g_srvrun_certstore (g_srvrun_env.certstore)
#define g_srvrun_pto_next_ms (g_srvrun_env.pto_next_ms)
#define g_srvrun_pto_spin (g_srvrun_env.pto_spin)
#define g_srvrun_send_count (g_srvrun_env.send_count)

typedef struct {
  quic_conntable* table;
  srvrun_conn*    conns;
} srvrun_state;

/* Everything one datagram-serving step needs besides the datagram itself and
 * the resolved slot: the fixed run config, the peer address the datagram
 * arrived from, and the mutable server state. Folded into one parameter so
 * srvrun_send/on_initial/on_step/serve stay <=3 args. */
typedef struct {
  const srvrun_cfg*    cfg;
  const quic_sockaddr* peer;
  srvrun_state*        st;
  u64                  now_ms; /**< monotonic ms this step started at */
  /** RFC 9000 13.4 / RFC 9002 19.3.2: the ECN codepoint (RFC 3168, 0..3) this
   * datagram's UDP layer read off its IP_TOS cmsg (quic_mmsg_buf.ecn in
   * udp.h), carried through so srvrun_serve_slot can hand it to the routed
   * slot's wired_srvloop_ecn_note. 0 (Not-ECT) for any caller that does not
   * set it explicitly. */
  u8 ecn;
} srvrun_step_ctx;

/* qlog packet_sent (pn/time are not tracked at this layer, so both are logged
 * as 0 — the record still proves a packet of `bytes` size went out). group_id
 * is c's slot (srvrun_conn.qlog_slot's doc). No-op when no qlog path is set.
 */
static void srvrun_qlog_sent(
    const srvrun_cfg* cfg, const srvrun_conn* c, usz bytes) {
  char rec[128];
  usz  n;
  if (!cfg->qlog_path) return;
  n = wired_qlogevent_packet_sent(rec, sizeof rec, 0, c->qlog_slot, 0, bytes);
  if (n) wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, n));
}

/* qlog packet_received (time not tracked at this layer; bytes is the whole
 * datagram, matching packet_sent's granularity). No-op without a qlog path.
 */
static void srvrun_qlog_recv(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 pn, usz bytes) {
  char rec[128];
  usz  n;
  if (!cfg->qlog_path) return;
  n = wired_qlogevent_packet_received(
      rec, sizeof rec, 0, c->qlog_slot, pn, bytes);
  if (n) wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, n));
}

/* qlog stream_frame_sent (RFC 9000 19.8): every STREAM frame this connection
 * sends, fired unconditionally including retransmits -- how many times an
 * offset range went out is itself the forensic signal this exists for. */
static void srvrun_qlog_stream_sent(
    const srvrun_cfg*        cfg,
    const srvrun_conn*       c,
    u64                      now_ms,
    u64                      pn,
    const quic_stream_frame* f) {
  char                            rec[192];
  usz                             n;
  wired_qlogevent_stream_frame_in in;
  if (!cfg->qlog_path) return;
  in = (wired_qlogevent_stream_frame_in){
      f->stream_id, f->offset, f->length, f->fin, pn};
  n = wired_qlogevent_stream_frame(
      rec, sizeof rec, now_ms, c->qlog_slot, "stream_frame_sent", &in);
  if (n) wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, n));
}

/* Snapshot of the loop's per-space receive marks, taken before a step; a
 * post-step difference proves the datagram carried at least one packet that
 * actually opened (an undecryptable datagram advances nothing). */
typedef struct {
  int app_seen;
  u64 app_pn;
  int hs_seen;
  u64 hs_pn;
} srvrun_rxmark;

static srvrun_rxmark srvrun_rx_mark(const wired_srvloop* l) {
  return (srvrun_rxmark){
      l->app_rx_seen, l->app_rx_pn, l->hs_rx_seen, l->hs_rx_pn};
}

static int srvrun_rx_app_adv(const srvrun_rxmark* m, const wired_srvloop* l) {
  return l->app_rx_seen != m->app_seen || l->app_rx_pn != m->app_pn;
}

static int srvrun_rx_hs_adv(const srvrun_rxmark* m, const wired_srvloop* l) {
  return l->hs_rx_seen != m->hs_seen || l->hs_rx_pn != m->hs_pn;
}

static int srvrun_rx_advanced(const srvrun_rxmark* m, const wired_srvloop* l) {
  return srvrun_rx_app_adv(m, l) || srvrun_rx_hs_adv(m, l);
}

/* The PN to log for this step: the 1-RTT space's if it moved, else the
 * Handshake space's. */
static u64 srvrun_rx_pn(const srvrun_rxmark* m, const wired_srvloop* l) {
  return srvrun_rx_app_adv(m, l) ? l->app_rx_pn : l->hs_rx_pn;
}

/* Log packet_received once per datagram that advanced a receive PN. */
static void srvrun_note_recv(
    const srvrun_step_ctx* ctx,
    const srvrun_rxmark*   m,
    const srvrun_conn*     c,
    usz                    bytes) {
  if (srvrun_rx_advanced(m, &c->l))
    srvrun_qlog_recv(ctx->cfg, c, srvrun_rx_pn(m, &c->l), bytes);
}

/* Send a sealed buffer to c's recorded peer, with a trace line (skip an empty
 * buffer). Always targets the slot's own peer (RFC 9000 5.1), not whichever
 * datagram was received most recently. */
/* Test-only send counter: how many times srvrun_send has fired since the
 * last srvrun_test_reset_send_count, so a test can assert an exact number of
 * UDP sends happened (e.g. proving a boot retransmit resent a flight)
 * without needing a real socket to observe bytes on. Not signal-safe/thread-
 * safe -- fine, each env's own send_count is only touched by that env's own
 * loop, and tests are the only other caller. */
__attribute__((unused)) static void srvrun_test_reset_send_count(void) {
  g_srvrun_send_count = 0;
}

__attribute__((unused)) static usz srvrun_test_send_count(void) {
  return g_srvrun_send_count;
}

/* Test-only wire-flush counter (env.tx_flush_count's doc): syscall batches,
 * where one whole GSO sendmsg counts 1 -- so a test can pin how many
 * syscalls a burst of datagrams costs, independent of the per-datagram
 * send_count above. */
__attribute__((unused)) static void srvrun_test_reset_flush_count(
    const srvrun_cfg* cfg) {
  cfg->env->tx_flush_count = 0;
}

__attribute__((unused)) static usz srvrun_test_flush_count(
    const srvrun_cfg* cfg) {
  return cfg->env->tx_flush_count;
}

/* The one TX seam: AF_XDP when cfg->xdp is set, the UDP socket otherwise.
 * Both srvrun_send and the direct Version Negotiation send route through
 * this. */
static void srvrun_tx(
    const srvrun_cfg* cfg, const quic_sockaddr* sa, wired_span pkt) {
  cfg->env->tx_flush_count++;
  if (cfg->xdp)
    wired_srvxdp_send(cfg->xdp, sa, pkt);
  else
    wired_udp_send(cfg->fd, sa, pkt);
}

static void srvrun_send(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    wired_span         pkt,
    const char*        what) {
  (void)what; /* WIRED_LOG compiles out without -DQUIC_DEBUG */
  if (pkt.n) {
    srvrun_tx(cfg, &c->peer, pkt);
    srvrun_qlog_sent(cfg, c, pkt.n);
    WIRED_LOG(what);
    g_srvrun_send_count++;
  }
}

/* --- GSO staging: sealed datagrams batched into one sendmsg ------------- */

static void srvrun_stage_reset(wired_srvrun_env* e) {
  e->gso_count    = 0;
  e->gso_len      = 0;
  e->gso_seg_size = 0;
}

/* Multi-segment wire-out: one UDP GSO sendmsg for the whole batch, or --
 * when the kernel lacks UDP_SEGMENT (negative return) -- a sendto per
 * segment. Either way it is one flush. */
static void srvrun_stage_tx_multi(const srvrun_cfg* cfg) {
  wired_srvrun_env* e   = cfg->env;
  wired_span        all = wired_span_of(e->gso_stage, e->gso_len);
  e->tx_flush_count++;
  if (wired_udp_send_gso(cfg->fd, &e->gso_peer, all, (u16)e->gso_seg_size) >= 0)
    return;
  wired_udp_send_batch(cfg->fd, &e->gso_peer, all, (u16)e->gso_seg_size);
}

/* Flush the staged batch to the wire: a single staged datagram goes out the
 * ordinary srvrun_tx path, several leave as one GSO sendmsg. No-op when the
 * stage is empty. Per-datagram bookkeeping (qlog, send_count) already
 * happened at staging time (srvrun_send_staged). */
static void srvrun_stage_flush(const srvrun_cfg* cfg) {
  wired_srvrun_env* e = cfg->env;
  if (e->gso_count == 0) return;
  if (e->gso_count == 1)
    srvrun_tx(cfg, &e->gso_peer, wired_span_of(e->gso_stage, e->gso_len));
  else
    srvrun_stage_tx_multi(cfg);
  srvrun_stage_reset(e);
}

/* 1 if a pkt.n-byte datagram still has stage room: batch open, not full,
 * and no larger than the batch's segment size (a smaller one is GSO's one
 * legal short tail -- srvrun_stage_put closes the batch right after it). */
static int srvrun_stage_room(const wired_srvrun_env* e, usz n) {
  return e->gso_count != 0 && e->gso_count < SRVRUN_GSO_SEGS &&
         n <= e->gso_seg_size;
}

/* 1 if sa is the same address:port the open batch is headed to. */
static int srvrun_stage_same_peer(
    const wired_srvrun_env* e, const quic_sockaddr* sa) {
  return sa->port_be == e->gso_peer.port_be &&
         ct_diffn(sa->addr, e->gso_peer.addr, 16) == 0;
}

static int srvrun_stage_extends(
    const wired_srvrun_env* e, const quic_sockaddr* sa, usz n) {
  return srvrun_stage_room(e, n) && srvrun_stage_same_peer(e, sa);
}

/* Stage one sealed datagram for c's peer. A datagram that cannot extend the
 * open batch (different peer, larger than the segment size, or the batch is
 * full) flushes it first and opens a new one; a shorter-than-segment
 * datagram joins as the batch's legal short tail and closes it. */
static void srvrun_stage_put(
    const srvrun_cfg* cfg, const srvrun_conn* c, wired_span pkt) {
  wired_srvrun_env* e = cfg->env;
  if (!srvrun_stage_extends(e, &c->peer, pkt.n)) {
    srvrun_stage_flush(cfg);
    e->gso_seg_size = pkt.n;
    e->gso_peer     = c->peer;
  }
  bytes_memcpy(e->gso_stage + e->gso_len, pkt.p, pkt.n);
  e->gso_len += pkt.n;
  e->gso_count++;
  if (pkt.n < e->gso_seg_size) srvrun_stage_flush(cfg);
}

/* srvrun_send, except the wire syscall is deferred into the env's GSO stage
 * (srvrun_stage_flush sends it); the per-datagram bookkeeping happens now.
 * AF_XDP has its own TX path with no GSO, so it sends immediately. Staged
 * packets can leave the wire AFTER a direct srvrun_send issued later in the
 * same pump pass (e.g. DATA_BLOCKED) -- plain datagram reordering, which
 * any QUIC peer already tolerates (RFC 9000 12.3). */
static void srvrun_send_staged(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    wired_span         pkt,
    const char*        what) {
  (void)what;
  if (cfg->xdp || pkt.n == 0) {
    srvrun_send(cfg, c, pkt, what);
    return;
  }
  srvrun_stage_put(cfg, c, pkt);
  srvrun_qlog_sent(cfg, c, pkt.n);
  WIRED_LOG(what);
  g_srvrun_send_count++;
}

/* RFC 9000 8.1: this slot's remaining antiamp budget before path validation.
 * Once wired_server_is_confirmed the path is validated and the limit no
 * longer applies -- callers must check that first (this alone would just
 * report the frozen boot_rx/tx_bytes snapshot forever). */
static u64 srvrun_boot_budget(const srvrun_conn* c) {
  return quic_antiamp_budget(c->boot_rx_bytes, c->boot_tx_bytes);
}

/* Send one datagram through the boot-phase antiamp gate, bumping
 * boot_tx_bytes (Initial and Handshake both count). The antiamp
 * budget check itself lives in the callers (srvrun_boot_gate_blocks) -- this
 * just sends and accounts, so a caller that already decided (e.g. because
 * the path is confirmed) never gets silently overruled here. */
static void srvrun_boot_send(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span pkt, const char* what) {
  srvrun_send(cfg, c, pkt, what);
  c->boot_tx_bytes += pkt.n;
}

/* The antiamp gate applies only until the path is validated. */
static int srvrun_boot_gate_blocks(
    const srvrun_conn* c, int confirmed, usz want) {
  return !confirmed && want > srvrun_boot_budget(c);
}

/* Send/resend the boot Initial through the same antiamp gate as the
 * Handshake flight (one decision point covers both). The very first
 * Initial always fits in practice (it never exceeds the client's own
 * first-Initial-derived budget, RFC 9000 14.1's 1200-byte floor); this stays
 * gated anyway so srvrun_boot_send has exactly one caller-side check to
 * reason about, not a special case for whoever calls it first. */
static void srvrun_boot_send_initial(
    const srvrun_cfg* cfg, srvrun_conn* c, const char* what) {
  int confirmed = wired_server_is_confirmed(&c->s);
  if (!srvrun_boot_gate_blocks(c, confirmed, c->boot_ini_len))
    srvrun_boot_send(cfg, c, wired_span_of(c->boot_ini, c->boot_ini_len), what);
}

/* Offset into boot_hs where the first not-yet-sent datagram starts. */
static usz srvrun_boot_sent_off(const srvrun_conn* c) {
  usz off = 0;
  for (usz i = 0; i < c->boot_dgram_sent; i++) off += c->boot_dgram_len[i];
  return off;
}

/* RFC 9000 8.1: send boot_dgram_len[boot_dgram_sent..dgram_count) in order,
 * stopping at the first one that would exceed the antiamp budget -- the
 * rest stays held for a later round once more client bytes arrive.
 * Once the path is validated (confirmed) the limit is lifted and everything
 * remaining goes out in one pass. */
static void srvrun_boot_send_hs_gated(
    const srvrun_cfg* cfg, srvrun_conn* c, int confirmed) {
  usz off = srvrun_boot_sent_off(c);
  while (c->boot_dgram_sent < c->boot_dgram_count) {
    wired_span pkt =
        wired_span_of(c->boot_hs + off, c->boot_dgram_len[c->boot_dgram_sent]);
    if (srvrun_boot_gate_blocks(c, confirmed, pkt.n)) return;
    srvrun_boot_send(cfg, c, pkt, "server Handshake flight sent\n");
    off += pkt.n;
    c->boot_dgram_sent++;
  }
}

/* Build this slot's own wired_srvboot_id: every field from cfg->id except
 * scid, which is c's own per-connection id — sharing cfg->id's fixed scid
 * across every slot would make every connection answer to the same DCID,
 * collapsing quic_conntable's routing to a single slot (RFC 9000 5.1). */
static wired_srvboot_id srvrun_slot_id(
    const wired_srvboot_id* base, const srvrun_conn* c) {
  wired_srvboot_id id = *base;
  id.scid             = c->scid;
  id.retry_odcid      = c->retry_odcid;
  id.retry_odcid_len  = c->retry_odcid_len;
  return id;
}

/* First datagram on this slot: cold-start the connection, register the
 * handler, send the server Initial and each Handshake flight datagram (the
 * Initial alone is padded to 1200 bytes, RFC 9000 14.1, so coalescing them
 * would exceed a 1500-byte MTU datagram). Returns 1 once the connection is
 * up. */
/* RFC 9000 10.2: answer an authenticated-but-unservable boot with an
 * Initial CONNECTION_CLOSE so the peer fails fast instead of retrying into
 * its handshake timeout. Always reports the boot failed. */
static int srvrun_refuse(const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  u8  pkt[1500];
  u64 err = sdrv_last_error(&c->s.sdrv);
  usz n   = wired_srvboot_refusal(
      &c->boot, wired_span_of(c->scid, ctx->cfg->id->scid_len), err, pkt,
      sizeof pkt);
  WIRED_LOG("srvboot accept failed\n");
  if (n) srvrun_send(ctx->cfg, c, wired_span_of(pkt, n), "boot refused\n");
  return 0;
}

/* Forward-declared: srvrun_boot_flush_zerortt (below) drives each buffered
 * 0-RTT datagram through the exact same pair of real-wire steps every later
 * live datagram takes -- srvrun_on_step (open/dispatch) then
 * srvrun_sess_on_step (starts the response for whatever request that step's
 * dispatch completed, mirrors srvrun_step_and_reap) -- both defined further
 * down this file once the response-pumping helpers they depend on exist. */
static void srvrun_on_step(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg);
static void srvrun_sess_on_step(const srvrun_step_ctx* ctx, int slot);

/* RFC 9001 4.6.1: dg's boot accumulator held every 0-RTT datagram that
 * arrived before this boot's early keys existed (wired_srvboot_acc_feed) --
 * now that sdrv_early_keys is available (or the PSK/early data was
 * rejected, in which case wired_srvloop_recv's recv_zerortt simply fails
 * open and each step is a no-op), replay them through the exact same
 * real-wire step pair a later live 0-RTT/1-RTT datagram takes (RFC 9000
 * 12.3: 0-RTT opens into the shared App pn space) -- srvrun_sess_on_step is
 * what actually starts a response for a request wired_srvloop_dispatch
 * completed (srvrun_step_and_reap's own pairing); without it a 0-RTT-carried
 * request opens and ACKs but never gets answered. A peer CONNECTION_CLOSE
 * seen mid-replay (vanishingly unlikely this early) stops the replay rather
 * than stepping a freed slot. */
static void srvrun_boot_flush_zerortt(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot) {
  usz n = wired_srvboot_acc_zerortt_count(&c->boot);
  for (usz i = 0; i < n && !c->l.peer_closed; i++) {
    wired_span dg = wired_srvboot_acc_zerortt_take(&c->boot, i);
    srvrun_on_step(ctx, c, wired_mspan_of((u8*)dg.p, dg.n));
    srvrun_sess_on_step(ctx, slot);
  }
}

static int srvrun_boot_finish(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, wired_mspan dg) {
  wired_obuf         iob  = obuf_of(c->boot_ini, sizeof c->boot_ini);
  wired_obuf         hob  = obuf_of(c->boot_hs, sizeof c->boot_hs);
  wired_srvboot_conn conn = {&c->s, &c->l};
  wired_srvboot_id   sid  = srvrun_slot_id(ctx->cfg->id, c);
  wired_srvboot_out  out  = {&iob, &hob, {0}, 0, 0};
  if (!wired_srvboot_accept_acc(&conn, &sid, &c->boot, &out))
    return srvrun_refuse(ctx, c);
  srvrun_qlog_recv(ctx->cfg, c, out.client_pn, dg.n);
  wired_server_set_keylog_path(&c->s, ctx->cfg->keylog_path);
  wired_srvloop_set_handler(&c->l, ctx->cfg->handler, ctx->cfg->ctx);
  c->l.resp_external = 1; /* srvrun streams the response (multi-packet) */
  /* RFC 9221 3: this connection's own advertised max_datagram_frame_size,
   * threaded to dispatch.c's DATAGRAM-gathering size check (see
   * wired_srvloop.we_advertised_max_datagram's doc). Same sid/base value
   * stp_build_server_lim already sends in the transport parameters --
   * sid is this slot's own copy of cfg->id, built above. */
  c->l.we_advertised_max_datagram = sid.max_datagram_frame_size;
  /* RFC 9000 18.2/19.9: seed this connection's send credit from the peer's
   * ClientHello TP now that sdrv_recv_client_hello has run (inside
   * wired_srvboot_accept_acc above); MAX_DATA frames only ever raise it
   * from here (srvrun_ku_discard_stale's neighbors gather_max_data /
   * srvrun_sess_on_step apply those raises each step). */
  c->conn_credit  = c->s.sdrv.peer_initial_max_data;
  c->boot_ini_len = iob.len;
  for (usz i = 0; i < out.dgram_count; i++)
    c->boot_dgram_len[i] = out.dgram_len[i];
  c->boot_dgram_count = out.dgram_count;
  c->boot_dgram_sent  = 0;
  srvrun_boot_send_initial(ctx->cfg, c, "server Initial sent\n");
  srvrun_boot_send_hs_gated(ctx->cfg, c, wired_server_is_confirmed(&c->s));
  srvrun_boot_flush_zerortt(ctx, c, slot);
  wired_srvboot_acc_reset(&c->boot); /* the reassembly buffer is spent */
  /* RFC 9002 6.2: the accept flight just went out -- start this slot's boot
   * PTO clock fresh (any real send, not just the timer's own probe,
   * pushes the next deadline out so the two re-send paths never double
   * fire). */
  c->boot_pto_sent_ms = ctx->now_ms;
  c->boot_pto_count   = 0;
  return 1;
}

/* srvrun_on_initial: the datagram was absorbed but the ClientHello is not
 * whole yet — keep the slot claimed and wait for the next Initial. */
#define SRVRUN_BOOT_PENDING 2

/* Feed dg into c's boot accumulator, restarting it for a fresh attempt (a
 * just-claimed slot, or a confirmed connection re-cold-starting). */
static int srvrun_boot_feed(srvrun_conn* c, wired_mspan dg) {
  if (c->up || !c->boot.any) wired_srvboot_acc_reset(&c->boot);
  return wired_srvboot_acc_feed(&c->boot, dg);
}

/* First datagram(s) on this slot: reassemble the ClientHello across Initial
 * datagrams and cold-start the connection once it is whole (the server
 * Initial is padded to 1200 bytes, RFC 9000 14.1, so the flight is sent as
 * separate datagrams). Returns 1 once the connection is up, 0 on a failed
 * boot, SRVRUN_BOOT_PENDING while more ClientHello is owed. */
/* A refused datagram settles a claim that never authenticated anything
 * (junk unclaims immediately) but does not tear down a boot that has real
 * packets absorbed — spoofed garbage must not kill a half-open handshake. */
static int srvrun_boot_salvage(const srvrun_conn* c) {
  return c->boot.opened ? SRVRUN_BOOT_PENDING : 0;
}

static int srvrun_on_initial(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, wired_mspan dg) {
  if (!srvrun_boot_feed(c, dg)) return srvrun_boot_salvage(c);
  if (!wired_srvboot_acc_complete(&c->boot)) return SRVRUN_BOOT_PENDING;
  return srvrun_boot_finish(ctx, slot, c, dg);
}

/* Cumulative armed bytes on stream_id's WT send slot, 0 when none holds
 * the id -- defined next to wired_server_wt_stream_reset below. */
static u64 srvrun_wtsend_final_size(srvrun_conn* c, u64 stream_id);

/* One standard RESET_STREAM (RFC 9000 19.4) at plb->p + at, its Final Size
 * the bytes already armed on stream_id's send slot (0 for a stream this
 * server never replied on -- every abort caller fires before any response
 * bytes exist; only a WT stream_reply's own slot can carry a count). */
static usz srvrun_wt_abort_reset(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb, usz at) {
  quic_reset_stream_frame rs = {
      stream_id, err_code, srvrun_wtsend_final_size(c, stream_id)};
  return quic_reset_stream_encode(plb->p + at, plb->cap - at, &rs);
}

/* One STOP_SENDING (RFC 9000 19.5) at plb->p + at. */
static usz srvrun_wt_abort_stop(
    u64 stream_id, u64 err_code, wired_obuf* plb, usz at) {
  quic_stop_sending_frame ss = {stream_id, err_code};
  return quic_stop_sending_encode(plb->p + at, plb->cap - at, &ss);
}

/* RESET_STREAM followed by STOP_SENDING -- the full abort of a bidi
 * stream's both halves, same pair shape as quic_h3cancel_request. */
static usz srvrun_wt_abort_pair(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb) {
  usz rn = srvrun_wt_abort_reset(c, stream_id, err_code, plb, 0);
  usz sn;
  if (!rn) return 0;
  sn = srvrun_wt_abort_stop(stream_id, err_code, plb, rn);
  if (!sn) return 0;
  return rn + sn;
}

/* RFC 9114 4.1.1/8.1: a server aborts a stream with the frames RFC 9000
 * 19.4/19.5 allow it to send FOR THAT STREAM'S TYPE, carrying err_code --
 * an HTTP/3-level code (e.g. H3_REQUEST_REJECTED) or a WebTransport
 * application code already mapped through wired_wterrmap_to_http3:
 *
 * - bidi (either initiator): RESET_STREAM + STOP_SENDING, both halves.
 * - client uni: STOP_SENDING alone. This server has no send part, and a
 *   RESET_STREAM arriving for what the client sees as its send-only stream
 *   is a connection-fatal STREAM_STATE_ERROR at the client.
 * - server uni: RESET_STREAM alone. The client cannot send on it, and a
 *   STOP_SENDING arriving for what the client sees as a receive-only
 *   stream is likewise connection-fatal (RFC 9000 19.5).
 *
 * Standard RESET_STREAM (0x04), never RESET_STREAM_AT (0x24): 0x24 is a
 * draft-ietf-quic-reliable-stream-reset extension frame this SDK never
 * negotiates, so a peer (Chrome included) treats it as an unknown frame
 * and kills the whole connection with FRAME_ENCODING_ERROR. */
static usz srvrun_wt_busy_reset_payload(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* plb) {
  if (!quic_stream_can_send(0, stream_id)) /* client uni */
    return srvrun_wt_abort_stop(stream_id, err_code, plb, 0);
  if (!quic_stream_can_receive(0, stream_id)) /* server uni */
    return srvrun_wt_abort_reset(c, stream_id, err_code, plb, 0);
  return srvrun_wt_abort_pair(c, stream_id, err_code, plb);
}

/* Seal the type-appropriate abort frames above into out as their own 1-RTT
 * packet on stream_id. Returns 1 with out->len set, 0 if the payload or the
 * seal failed. */
static int srvrun_seal_wt_busy_reset(
    srvrun_conn* c, u64 stream_id, u64 err_code, wired_obuf* out) {
  u8                    pl[64];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  usz pln = srvrun_wt_busy_reset_payload(c, stream_id, err_code, &plb);
  if (!pln) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal and send the type-appropriate abort frames carrying err_code as
 * their own 1-RTT packet. */
static void srvrun_send_wt_busy_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 err_code) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_wt_busy_reset(c, stream_id, err_code, &ob)) return;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "WT stream abort sent\n");
}

/* RFC 9000 10.2.3: an application-level CONNECTION_CLOSE (type 0x1d,
 * is_app=1) carrying an HTTP/3 or WebTransport-level error code and reason.
 * Mirrors wired_srvboot_refusal's is_app=0 handshake-rejection pattern
 * (srvboot.c) but for use OUTSIDE handshake rejection -- an established
 * connection closing itself for an application-level protocol violation. */
static usz srvrun_app_close_payload(
    u64 error_code, wired_span reason, wired_obuf* plb) {
  quic_conn_close_frame cc = {1, error_code, 0, reason.n, reason.p};
  return quic_frame_put_conn_close(plb->p, plb->cap, &cc);
}

/* Seal the CONNECTION_CLOSE above into out as its own 1-RTT packet. Returns
 * 1 with out->len set, 0 if the payload or the seal failed. */
static int srvrun_seal_app_close(
    srvrun_conn* c, u64 error_code, wired_span reason, wired_obuf* out) {
  u8                    pl[64];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  usz pln = srvrun_app_close_payload(error_code, reason, &plb);
  if (!pln) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal and send an application-level CONNECTION_CLOSE as its own 1-RTT
 * packet (e.g. srvrun_close_on_bad_qsid's RFC 9297 2.1 H3_DATAGRAM_ERROR). */
static void srvrun_send_app_close(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 error_code, wired_span reason) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_app_close(c, error_code, reason, &ob)) return;
  srvrun_send(
      cfg, c, wired_span_of(out, ob.len), "app CONNECTION_CLOSE sent\n");
}

/* RFC 9110 10.1.1: build a bare "100 Continue" HEADERS frame (no DATA, RFC
 * 9114 4.1) wrapped in a STREAM frame at absolute offset 0 of the request
 * stream -- an interim response, so unlike the final response it is not
 * ACK-tracked by wired_sendsess: losing it costs nothing (RFC 9110 10.1.1
 * lets a client proceed after its own timeout regardless), matching
 * srvrun_seal_app_close's own fire-and-forget idiom for single-packet sends.
 * *h3_len receives the HEADERS frame's own byte length (the request stream's
 * new base offset the final response must continue from). Returns 1 with
 * plb->len set, 0 on overflow. */
static int srvrun_continue_payload(
    u64 stream_id, wired_obuf* plb, usz* h3_len) {
  u8                h3[16];
  wired_obuf        h3b = obuf_of(h3, sizeof h3);
  quic_stream_frame f;
  if (!quic_h3resp_prefix(100, 0, 0, &h3b)) return 0;
  f       = (quic_stream_frame){stream_id, 0, h3b.len, h3, 0};
  *h3_len = h3b.len;
  return quic_appdata_stream_frame(&f, plb) != 0;
}

/* Seal the 100-continue payload above into out as its own 1-RTT packet.
 * *h3_len receives the HEADERS frame's byte length (see
 * srvrun_continue_payload). Returns 1 with out->len set, 0 if nothing was
 * built/sealed. */
static int srvrun_seal_continue(
    srvrun_conn* c, u64 stream_id, wired_obuf* out, usz* h3_len) {
  u8                    pl[64];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  if (!srvrun_continue_payload(stream_id, &plb, h3_len)) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, plb.len), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Send RFC 9110 10.1.1's "100 Continue" interim response for stream_id, an
 * informational HEADERS frame issued before the final response -- srvrun's
 * one caller (srvrun_start_app_resp) uses the returned byte length as the
 * final response's wired_sendsess_set_base_offset so it continues the same
 * QUIC stream right after this frame rather than overlapping it. Returns 0
 * (no base offset shift) if sealing failed or cfg has no socket to send on. */
static usz srvrun_send_continue(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id) {
  u8         out[128];
  wired_obuf ob     = obuf_of(out, sizeof out);
  usz        h3_len = 0;
  if (!srvrun_seal_continue(c, stream_id, &ob, &h3_len)) return 0;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "100 Continue sent\n");
  return h3_len;
}

/* RFC 9000 10.2.3: a transport-level CONNECTION_CLOSE (type 0x1c, is_app=0)
 * carrying a standard RFC 9000 20.1 error code -- the sibling of
 * srvrun_seal_app_close for a violation the transport itself detects (e.g.
 * RFC 9221 3's PROTOCOL_VIOLATION), rather than an HTTP/3/WebTransport
 * application error. frame_type 0 (unknown/unspecified) matches
 * wired_srvboot_refusal's own transport-close payload. */
static usz srvrun_transport_close_payload(
    u64 error_code, wired_span reason, wired_obuf* plb) {
  quic_conn_close_frame cc = {0, error_code, 0, reason.n, reason.p};
  return quic_frame_put_conn_close(plb->p, plb->cap, &cc);
}

/* Seal the CONNECTION_CLOSE above into out as its own 1-RTT packet. Returns
 * 1 with out->len set, 0 if the payload or the seal failed. */
static int srvrun_seal_transport_close(
    srvrun_conn* c, u64 error_code, wired_span reason, wired_obuf* out) {
  u8                    pl[64];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  usz pln = srvrun_transport_close_payload(error_code, reason, &plb);
  if (!pln) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal and send a transport-level CONNECTION_CLOSE as its own 1-RTT packet
 * (RFC 9000 20.1 error code, e.g. QUIC_ERR_PROTOCOL_VIOLATION). */
static void srvrun_send_transport_close(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 error_code, wired_span reason) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_transport_close(c, error_code, reason, &ob)) return;
  srvrun_send(
      cfg, c, wired_span_of(out, ob.len), "transport CONNECTION_CLOSE sent\n");
}

/* Index-based view over the two physical slots (wt/wt_active, wt1/wt1_active)
 * so every routing helper below can loop 0..SRVRUN_MAX_WT_SESSIONS uniformly
 * instead of hand-unrolling both cases. c is never NULL in this file's own
 * call sites (every caller already holds a live srvrun_conn*); i is always
 * either 0 or 1 in-bounds since every caller loops against
 * SRVRUN_MAX_WT_SESSIONS==2. */
static wired_wt_session* srvrun_wt_slot(srvrun_conn* c, int i) {
  return i == 0 ? &c->wt : &c->wt1;
}

static int* srvrun_wt_active_slot(srvrun_conn* c, int i) {
  return i == 0 ? &c->wt_active : &c->wt1_active;
}

/* const-correct sibling of srvrun_wt_slot for read-only callers. */
static const wired_wt_session* srvrun_wt_slot_c(const srvrun_conn* c, int i) {
  return i == 0 ? &c->wt : &c->wt1;
}

static int srvrun_wt_is_active(const srvrun_conn* c, int i) {
  return i == 0 ? c->wt_active : c->wt1_active;
}

/* The session slot index whose OWN connect_stream_id equals stream_id and is
 * currently active, or -1 if none (draft-ietf-webtrans-http3-15 SS4.3 / RFC
 * 9220 3: a WebTransport session's identity IS its CONNECT stream's id, so
 * this is the routing key every stream/datagram reference resolves through).
 * A stream_id with no matching active slot is a foreign reference: the
 * caller must not route it to any session. */
static int wt_slot_is_connect_id(const srvrun_conn* c, int i, u64 stream_id) {
  return srvrun_wt_is_active(c, i) &&
         srvrun_wt_slot_c(c, i)->connect_stream_id == stream_id;
}

static int srvrun_wt_slot_by_connect_id(const srvrun_conn* c, u64 stream_id) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (wt_slot_is_connect_id(c, i, stream_id)) return i;
  return -1;
}

/* The first currently-inactive session slot, or -1 if every slot holds an
 * open session (SRVRUN_MAX_WT_SESSIONS reached) -- the accept-path capacity
 * check (accept below the limit, reject at it) and the reuse point once a
 * slot frees. */
static int srvrun_wt_free_slot(const srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (!srvrun_wt_is_active(c, i)) return i;
  return -1;
}

/* The first active session slot willing to accept stream_id: one it already
 * tracks (wired_wt_session_offer_stream is idempotent-by-buffering/
 * associates-directly once established, session.c), else the first active
 * slot in order with room. This is the only signal available at this layer
 * for "which session a WT data stream belongs to" -- the wire format this SDK
 * parses (dispatch.c's 0x41/0x54 signal) carries no session id, so a
 * production caller cannot yet name an explicit target the way
 * srvrun_wt_slot_by_connect_id's CONNECT-stream-close routing can. First-fit
 * across active slots keeps today's one-session behavior unchanged (with one
 * active slot there is exactly one candidate) while still being structurally
 * exclusive (a stream offered here lands in at most one slot per call).
 * Returns -1 if no active slot exists (mirrors
 * the pre-multi-session no-active-session fallback). */
static int srvrun_wt_slot_for_new_stream(const srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (srvrun_wt_is_active(c, i)) return i;
  return -1;
}

/* draft-ietf-webtrans-http3-15 4.3/8.2: a buffered-stream-capacity rejection
 * (wired_wt_session_offer_stream returned 0, i.e. WIRED_WT_MAX_BUFFERED_
 * STREAMS is full on an unestablished session) is the caller's own contract
 * to enforce (session.h's offer_stream doc): reset the stream with
 * WT_BUFFERED_STREAM_REJECTED, mapped through wired_wterrmap_to_http3 since
 * it is a WebTransport application error code, not an HTTP/3-level one. */
static void srvrun_reject_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id) {
  srvrun_send_wt_busy_reset(
      cfg, c, stream_id,
      wired_wterrmap_to_http3(QUIC_WTERR_BUFFERED_STREAM_REJECTED));
}

/* draft-ietf-webtrans-http3-15 4.3: associate one newly-reassembled WT bidi
 * stream slot with c's WebTransport session, exactly once (slot->offered
 * latches it) — the session only needs to know the stream id, not its bytes
 * (wired_wt_session_offer_stream's own signature, session.h). A stray WT bidi
 * stream on a connection with no active session (srvrun_wt_slot_for_new_
 * stream returns -1) is a protocol-level mismatch this slice leaves as
 * accepted-and-ignored, matching
 * the pre-Slice-3 fallback: routing to a session that does not exist is not
 * meaningful, so nothing is offered and the slot is simply left reassembled
 * but unclaimed by any session. A 0 return (buffer full) is rejected on the
 * wire and the slot freed so a retry does not loop forever re-offering the
 * same doomed stream id. */
static void srvrun_offer_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  int sidx = srvrun_wt_slot_for_new_stream(c);
  if (sidx < 0) return;
  if (!wired_wt_session_offer_stream(
          srvrun_wt_slot(c, sidx), slot->stream_id)) {
    srvrun_reject_wt_slot(cfg, c, slot->stream_id);
    slot->in_use = 0;
    return;
  }
  slot->offered         = 1;
  slot->wt_session_slot = sidx;
}

/* A reassembled-but-not-yet-associated slot: in_use (claimed by a WT-bidi
 * stream) and not already offered to the session this connection owns. */
static int wt_slot_needs_offer(const wired_srvloop_wt_stream_slot* slot) {
  return slot->in_use && !slot->offered;
}

/* The absolute stream offset the slot's receive window has contiguously
 * reassembled up to so far (RFC 9000 2.2) -- the caller may only deliver up
 * to here, never past a gap, however far an out-of-order frame's own
 * high-water mark reaches (wired_srvloop_wt_window's own frontier doc). */
static u64 wt_frontier_abs(const wired_srvloop_wt_window* win) {
  return win->base + win->frontier;
}

/* A fresh, not-yet-delivered FIN — the one case wt_stream_delta_pending's
 * plain frontier > delivered_len check misses (a stream whose closing frame,
 * or whose only frame, carries no new bytes past the frontier already
 * delivered). fin_delivered (not delivered_len) is the guard: delivered_len
 * alone cannot tell "FIN already delivered" apart from "nothing delivered
 * yet" when both are 0. A FIN is deliverable only once the frontier has
 * actually reached the offset it was seen at (fin_off) -- FIN itself can
 * arrive out of order, same as any other STREAM frame (RFC 9000 19.8). */
static int wt_stream_fin_only(
    u8 fin, u64 fin_off, u64 frontier_abs, int fin_delivered) {
  return fin && !fin_delivered && frontier_abs >= fin_off;
}

/* Whether this step has anything new worth delivering for one WT stream slot:
 * either fresh bytes past the last delivery, or a fresh FIN (see
 * wt_stream_fin_only). */
static int wt_stream_delta_pending(
    u64 frontier_abs,
    u8  fin,
    u64 fin_off,
    u64 delivered_len,
    int fin_delivered) {
  if (frontier_abs > delivered_len) return 1;
  return wt_stream_fin_only(fin, fin_off, frontier_abs, fin_delivered);
}

/* Whether srvrun_deliver_wt_stream_delta has anything to do at all: an active
 * session slot (sidx >= 0, from srvrun_wt_slot_for_new_stream), a registered
 * callback, and a pending delta (wt_stream_delta_pending) — folded into one
 * predicate so the caller is a single guarded early return. */
static int wt_stream_delta_ready(
    const srvrun_cfg* cfg,
    int               sidx,
    u64               frontier_abs,
    u8                fin,
    u64               fin_off,
    u64               delivered_len,
    int               fin_delivered) {
  if (sidx < 0 || !cfg->wt_on_stream_data) return 0;
  return wt_stream_delta_pending(
      frontier_abs, fin, fin_off, delivered_len, fin_delivered);
}

/* draft-ietf-webtrans-http3-15 4.3 (Phase 7b Slice 4): deliver the bytes a WT
 * bidi/uni slot has reassembled contiguously (up to its window's frontier)
 * since the last delivery to the app callback. buf is window-relative (buf[0]
 * is win->base's own first byte), so "new data this step" is buf[delivered_
 * len - win->base .. frontier - win->base) — the caller passes pointers to
 * the slot's own delivered_len/fin_delivered so this can advance them in
 * place. sidx is the session slot this stream was offered to
 * (srvrun_offer_wt_slot's own resolution), so the callback's session pointer
 * always matches the slot the stream is actually associated with. Called
 * every step for every in_use slot regardless of offered, so bytes that
 * arrive before the stream's session association still reach the app once
 * one exists, mirroring srvrun_offer_wt_slot's own no-active-session fallback
 * (silently skip rather than buffer growing unboundedly). */
/* 1 if this delivery includes the stream's FIN -- a FIN was seen AND the
 * frontier has reached the offset it was seen at (RFC 9000 19.8: FIN can
 * itself arrive out of order, so "seen" alone is not "deliverable yet").
 * Shared by both call sites in srvrun_deliver_wt_stream_delta that need this
 * exact condition, keeping its own branch count at the gate. */
static int wt_delivered_fin(u8 fin, u64 frontier_abs, u64 fin_off) {
  return fin && frontier_abs >= fin_off;
}

static void srvrun_deliver_wt_stream_delta(
    const srvrun_cfg*              cfg,
    srvrun_conn*                   c,
    int                            sidx,
    u64                            stream_id,
    const u8*                      buf,
    const wired_srvloop_wt_window* win,
    u8                             fin,
    u64                            fin_off,
    u64*                           delivered_len,
    int*                           fin_delivered) {
  u64 frontier_abs = wt_frontier_abs(win);
  int fin_now      = wt_delivered_fin(fin, frontier_abs, fin_off);
  if (!wt_stream_delta_ready(
          cfg, sidx, frontier_abs, fin, fin_off, *delivered_len,
          *fin_delivered))
    return;
  cfg->wt_on_stream_data(
      cfg->wt_stream_data_ctx, srvrun_wt_slot(c, sidx), stream_id,
      wired_span_of(
          buf + (*delivered_len - win->base),
          (usz)(frontier_abs - *delivered_len)),
      fin_now);
  *delivered_len = frontier_abs;
  if (fin_now) *fin_delivered = 1;
}

/* RFC 9000 2.2 / 19.8: once a WT bidi slot's FIN has been delivered to the
 * app, its stream is fully spent -- free the slot (raising the table's
 * released-id watermark, wired_srvloop_wt_slot_release) so a later Extended
 * CONNECT's worth of new streams is not permanently blocked by
 * WIRED_SRVLOOP_MAX_WT_STREAMS exhausting after that many sequential
 * streams, mirroring srvrun_resp_reap's own release of streams[]. */
static void srvrun_reap_wt_slot(
    srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  if (!slot->in_use || !slot->fin_delivered) return;
  c->wt_rx_reaped_total += slot->delivered_len;
  wired_srvloop_wt_slot_release(&c->l, slot->stream_id);
}

/* One wt_streams slot's per-step work: offer it to the session if this step
 * (or an earlier one) claimed it but has not yet offered it, deliver any new
 * contiguous bytes to the app callback, slide the receive window forward once
 * everything contiguous has been delivered (making room for more), then reap
 * the slot if its FIN has now been fully delivered — split out of
 * srvrun_offer_wt_streams so the loop itself stays at the CCN gate. */
static void srvrun_offer_and_deliver_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  int sidx;
  if (wt_slot_needs_offer(slot)) srvrun_offer_wt_slot(cfg, c, slot);
  if (!slot->in_use) return;
  sidx = srvrun_wt_slot_for_new_stream(c);
  srvrun_deliver_wt_stream_delta(
      cfg, c, sidx, slot->stream_id, slot->buf, &slot->win, slot->fin,
      slot->fin_off, &slot->delivered_len, &slot->fin_delivered);
  wired_srvloop_wt_window_slide(
      &slot->win, slot->buf, sizeof slot->buf, slot->delivered_len);
  srvrun_reap_wt_slot(c, slot);
}

/* draft-ietf-webtrans-http3-15 4.3: after a step has reassembled this
 * datagram's frames into c->l.wt_streams[], run srvrun_offer_and_deliver_wt_
 * slot over every slot. */
static void srvrun_offer_wt_streams(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    srvrun_offer_and_deliver_wt_slot(cfg, c, &c->l.wt_streams[i]);
}

/* RFC 9297 2.1: close the connection with H3_DATAGRAM_ERROR because a
 * received HTTP Datagram's Quarter Stream ID field was truncated/missing or
 * exceeded 2^60-1 (wired_wtwire_qsid_take rejects both the same way). */
static void srvrun_close_on_bad_qsid(const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "bad HTTP Datagram Quarter Stream ID";
  srvrun_send_app_close(
      cfg, c, QUIC_H3_DATAGRAM_ERROR, wired_span_of(reason, sizeof reason - 1));
}

/* RFC 9297 2.1 (9297-009): a datagram naming a not-yet-established session is
 * buffered (wired_wt_session_offer_datagram, session.h) rather than delivered
 * -- the app callback only fires once the session has associated it directly
 * (established or draining), never while it merely sits in the
 * pre-establishment buffer. Checked BEFORE offer_datagram runs, since offer_
 * datagram's own return (1) does not distinguish "buffered" from
 * "associated". */
static int wt_session_delivers_directly(const wired_wt_session* s) {
  return s->state != WIRED_WT_UNESTABLISHED;
}

/* RFC 9297 2.1 (9297-007): "HTTP/3 Datagrams MUST NOT be sent unless the
 * corresponding stream's send side is open." A WT session's CONNECT stream
 * (its identity, session.h) has the server's send side open exactly while
 * the session is ESTABLISHED or DRAINING -- not yet (UNESTABLISHED, no 2xx
 * sent, also 9297-001's own gate) and not anymore (CLOSED: the CONNECT
 * stream itself closed, session.h's wired_wt_session_close doc). */
static int wt_session_send_side_open(const wired_wt_session* s) {
  return s->state == WIRED_WT_ESTABLISHED || s->state == WIRED_WT_DRAINING;
}

/* RFC 9221 5 / draft-ietf-webtrans-http3-15 SS4 (Phase 7b Slice 2): route one
 * queued received DATAGRAM's post-prefix bytes to the session whose OWN
 * connect_stream_id equals connect_id (srvrun_wt_slot_by_connect_id) rather
 * than to whichever session happens to be active most recently -- with
 * SRVRUN_MAX_WT_SESSIONS > 1 concurrent sessions, the two are not the same
 * slot. Still calls offer_datagram unconditionally so the session's own state
 * (buffered-vs-associated) stays consistent regardless of whether an app
 * callback is registered; the callback itself only fires when wt_session_
 * delivers_directly says the datagram was associated, not merely buffered
 * (9297-009). Split out of srvrun_deliver_rx_datagram so its own branch count
 * stays at the CCN gate. */
static int srvrun_dg_should_deliver(
    const srvrun_cfg* cfg, const wired_wt_session* s) {
  return wt_session_delivers_directly(s) && cfg->wt_on_datagram != 0;
}

/* Same transport-parameter-or-default computation as srvrun_stream_limit_base,
 * but from cfg alone (this call site has no srvrun_step_ctx). */
static u64 srvrun_dg_stream_limit_base(const srvrun_cfg* cfg) {
  u64 configured = cfg->id ? cfg->id->max_streams_bidi : 0;
  return configured ? configured : QUIC_STP_DEFAULT_MAX_STREAMS_BIDI;
}

/* RFC 9297 2.1 (9297-010): the client-initiated bidi stream limit last
 * advertised via MAX_STREAMS, falling back to the transport-parameter
 * default before any raise -- same base-or-advertised pattern as
 * srvrun_grant_streams. */
static u64 srvrun_dg_stream_limit(const srvrun_cfg* cfg, const srvrun_conn* c) {
  u64 base = srvrun_dg_stream_limit_base(cfg);
  return c->stream_limit_advertised ? c->stream_limit_advertised : base;
}

/* RFC 9297 2.1 (9297-010): connect_id names a client-initiated bidi stream
 * (RFC 9000 2.1, id = 4*n) beyond the limit this connection has advertised
 * -- such a stream can never legally be opened by the client, so a
 * datagram naming it is distinguished from the ordinary "no session yet"
 * case below. */
static int srvrun_dg_id_exceeds_limit(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 connect_id) {
  return connect_id / 4 >= srvrun_dg_stream_limit(cfg, c);
}

/* RFC 9297 2 (9297-002): "If an HTTP Datagram is received and it is
 * associated with a request that has no known semantics for HTTP Datagrams,
 * the receiver MUST terminate the request. If HTTP/3 is in use, the request
 * stream MUST be aborted with H3_DATAGRAM_ERROR (0x33)." A connect_id with no
 * matching active WT session slot names exactly such a request -- this SDK's
 * only HTTP Datagram semantics are WebTransport's, so a Quarter Stream ID
 * that does not resolve to a live WebTransport session is a request this
 * server never assigned any HTTP Datagram meaning to. connect_id doubles as
 * the request stream id (wired_wtwire_qsid_take already multiplies the parsed
 * quarter back by 4), so it is aborted directly with the same RESET_STREAM
 * + STOP_SENDING pair srvrun_reject_wt_slot uses for a different rejection
 * reason -- UNLESS connect_id names a stream beyond the advertised
 * MAX_STREAMS limit (9297-010), which RFC 9297 2.1 calls out as its own
 * H3_ID_ERROR case since such a stream could never have been created at
 * all. */
static void srvrun_abort_unknown_dg_request(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 connect_id) {
  u64 err = srvrun_dg_id_exceeds_limit(cfg, c, connect_id)
                ? QUIC_H3_ID_ERROR
                : QUIC_H3_DATAGRAM_ERROR;
  srvrun_send_wt_busy_reset(cfg, c, connect_id, err);
}

/* RFC 9297 2.1 (9297-008): "If a datagram is received after the
 * corresponding stream's receive side is closed, the received datagrams MUST
 * be silently dropped." A WT session's CONNECT stream closes both directions
 * at once (session.h's wired_wt_session_close doc), so WIRED_WT_CLOSED is
 * exactly "receive side closed" here. */
static int wt_session_receive_side_closed(const wired_wt_session* s) {
  return s->state == WIRED_WT_CLOSED;
}

/* The known-session half of srvrun_route_rx_datagram, split out so the
 * dispatcher itself stays at the CCN gate: s is a session a live slot
 * resolved to (never NULL), already past the unknown-semantics and
 * receive-side-closed checks. */
static void srvrun_deliver_to_known_session(
    const srvrun_cfg* cfg, wired_wt_session* s, wired_span data) {
  int deliver = srvrun_dg_should_deliver(cfg, s);
  wired_wt_session_offer_datagram(s, data);
  if (deliver) cfg->wt_on_datagram(cfg->wt_datagram_ctx, s, data);
}

static void srvrun_route_rx_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 connect_id, wired_span data) {
  int               sidx = srvrun_wt_slot_by_connect_id(c, connect_id);
  wired_wt_session* s;
  if (sidx < 0) {
    srvrun_abort_unknown_dg_request(cfg, c, connect_id);
    return;
  }
  s = srvrun_wt_slot(c, sidx);
  if (wt_session_receive_side_closed(s)) return;
  srvrun_deliver_to_known_session(cfg, s, data);
}

/* RFC 9297 2.1: the payload is prefixed with varint(quarter stream id) --
 * decode that prefix, rejecting a short/oversized field with
 * H3_DATAGRAM_ERROR (srvrun_close_on_bad_qsid, same failure signal
 * wired_wtwire_qsid_take gives both cases), then hand the derived stream id
 * and the remaining bytes to srvrun_route_rx_datagram. */
static void srvrun_deliver_rx_datagram(
    const srvrun_cfg*                cfg,
    srvrun_conn*                     c,
    const wired_srvloop_rx_datagram* dg) {
  wired_span raw = wired_span_of(dg->buf, dg->len);
  u64        connect_id;
  usz        prefix = wired_wtwire_qsid_take(raw, &connect_id);
  if (!prefix) {
    srvrun_close_on_bad_qsid(cfg, c);
    return;
  }
  srvrun_route_rx_datagram(
      cfg, c, connect_id, wired_span_of(dg->buf + prefix, dg->len - prefix));
}

/* RFC 9221 5 (Phase 7b Slice 2): drain every DATAGRAM this step's
 * gather_rx_datagrams (dispatch.c) queued into c->l.rx_datagrams, delivering
 * each to the app callback (srvrun_deliver_rx_datagram) in arrival order, then
 * empty the queue -- rx_datagram_n persists across steps until drained (only
 * wired_srvloop_init resets it), so this must run every step regardless of
 * whether this step itself added anything. */
static void srvrun_drain_rx_datagrams(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < c->l.rx_datagram_n; i++)
    srvrun_deliver_rx_datagram(cfg, c, &c->l.rx_datagrams[i]);
  c->l.rx_datagram_n = 0;
}

/* draft-ietf-webtrans-http3-15 4.3: associate one newly-reassembled WT uni
 * stream slot with c's WebTransport session, mirroring srvrun_offer_wt_slot's
 * bidi counterpart exactly (same offer_stream contract, same no-active-
 * session fallback of leaving the slot reassembled but unclaimed, same
 * reject-and-free-the-slot handling of a buffer-full 0 return). */
static void srvrun_offer_wt_uni_slot(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot) {
  int sidx = srvrun_wt_slot_for_new_stream(c);
  if (sidx < 0) return;
  if (!wired_wt_session_offer_stream(
          srvrun_wt_slot(c, sidx), slot->stream_id)) {
    srvrun_reject_wt_slot(cfg, c, slot->stream_id);
    slot->in_use = 0;
    return;
  }
  slot->offered         = 1;
  slot->wt_session_slot = sidx;
}

/* A reassembled-but-not-yet-associated uni slot, mirroring wt_slot_needs_offer
 * for the separate uni table. */
static int wt_uni_slot_needs_offer(
    const wired_srvloop_wt_uni_stream_slot* slot) {
  return slot->in_use && !slot->offered;
}

/* RFC 9000 2.2 / 19.8: same reap-once-FIN-delivered policy as
 * srvrun_reap_wt_slot, for the separate uni table. Returns 1 when the slot
 * was released (its uni stream-limit grant is owed), 0 otherwise. */
static int srvrun_reap_wt_uni_slot(
    srvrun_conn* c, wired_srvloop_wt_uni_stream_slot* slot) {
  if (!slot->in_use || !slot->fin_delivered) return 0;
  c->wt_rx_reaped_total += slot->delivered_len;
  wired_srvloop_wt_uni_slot_release(&c->l, slot->stream_id);
  return 1;
}

/* One wt_uni_streams slot's per-step work, mirroring
 * srvrun_offer_and_deliver_wt_slot for the separate uni table. Returns 1
 * when the slot's reap released it (its uni stream-limit grant is owed). */
static int srvrun_offer_and_deliver_wt_uni_slot(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot) {
  int sidx;
  if (wt_uni_slot_needs_offer(slot)) srvrun_offer_wt_uni_slot(cfg, c, slot);
  if (!slot->in_use) return 0;
  sidx = srvrun_wt_slot_for_new_stream(c);
  srvrun_deliver_wt_stream_delta(
      cfg, c, sidx, slot->stream_id, slot->buf, &slot->win, slot->fin,
      slot->fin_off, &slot->delivered_len, &slot->fin_delivered);
  wired_srvloop_wt_window_slide(
      &slot->win, slot->buf, sizeof slot->buf, slot->delivered_len);
  return srvrun_reap_wt_uni_slot(c, slot);
}

static void srvrun_grant_uni_streams(
    const srvrun_cfg* cfg, srvrun_conn* c, usz n);

/* draft-ietf-webtrans-http3-15 4.3: after a step has reassembled this
 * datagram's frames into c->l.wt_uni_streams[], run srvrun_offer_and_deliver_
 * wt_uni_slot over every slot, mirroring srvrun_offer_wt_streams for the
 * separate uni table -- then raise the uni stream limit by the number of
 * slots the pass released (RFC 9000 4.6/19.11). */
static void srvrun_offer_wt_uni_streams(const srvrun_cfg* cfg, srvrun_conn* c) {
  usz freed = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    freed += (usz)srvrun_offer_and_deliver_wt_uni_slot(
        cfg, c, &c->l.wt_uni_streams[i]);
  srvrun_grant_uni_streams(cfg, c, freed);
}

/* RFC 9000 4.1: the most a WT slot's receive window can currently absorb --
 * bytes already delivered (and reclaimed, wired_srvloop_wt_window_slide) plus
 * one full buffer's worth ahead of them, i.e. the credit that keeps the
 * peer's send window always fully covered by buffer capacity (this SDK's own
 * invariant: never advertise more than buf can actually hold). */
static u64 wt_slot_credit_ceiling(u64 delivered_len) {
  return delivered_len + WIRED_SRVLOOP_WT_BUF_CAP;
}

/* RFC 9000 4.1/19.10: whether stream_id's MAX_STREAM_DATA is worth
 * re-announcing right now -- the window has advanced enough that the new
 * ceiling exceeds what was last advertised. An advertisement MUST NOT
 * decrease, so a ceiling at or below credit_advertised is never sent. */
static int wt_credit_stream_due(u64 ceiling, u64 credit_advertised) {
  return ceiling > credit_advertised;
}

/* Seal one MAX_STREAM_DATA frame (RFC 9000 19.10) naming stream_id/value as
 * its own 1-RTT packet and send it, mirroring srvrun_seal_wt_busy_reset's
 * shape for a different frame. */
static int srvrun_seal_max_stream_data(
    srvrun_conn* c, u64 stream_id, u64 value, wired_obuf* out) {
  u8                     pl[32];
  wired_obuf             plb = obuf_of(pl, sizeof pl);
  quic_stream_data_frame f   = {stream_id, value};
  wired_srvloop_send_in  sin;
  usz                    pln = quic_max_stream_data_encode(plb.p, plb.cap, &f);
  if (!pln) return 0;
  plb.len = pln;
  sin     = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

static void srvrun_send_max_stream_data(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 value) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_max_stream_data(c, stream_id, value, &ob)) return;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "WT MAX_STREAM_DATA sent\n");
}

/* RFC 9000 4.1/19.10: re-grant stream_id's receive credit if the window has
 * advanced enough to be worth it (wt_credit_stream_due), recording the new
 * ceiling so a later step's absence of further progress does not re-send the
 * same value. Shared body for both the bidi (wt_streams) and uni
 * (wt_uni_streams) tables -- each caller passes its own slot's stream_id/
 * delivered_len/credit_advertised. */
static void srvrun_grant_stream_credit(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    u64               stream_id,
    u64               delivered_len,
    u64*              credit_advertised) {
  u64 ceiling = wt_slot_credit_ceiling(delivered_len);
  if (!wt_credit_stream_due(ceiling, *credit_advertised)) return;
  srvrun_send_max_stream_data(cfg, c, stream_id, ceiling);
  *credit_advertised = ceiling;
}

/* One in-use wt_streams slot's own credit re-grant, split out so the driving
 * loop stays at the CCN gate. */
static void srvrun_grant_wt_slot_credit(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  if (!slot->in_use) return;
  srvrun_grant_stream_credit(
      cfg, c, slot->stream_id, slot->delivered_len, &slot->credit_advertised);
}

static void srvrun_grant_wt_uni_slot_credit(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot) {
  if (!slot->in_use) return;
  srvrun_grant_stream_credit(
      cfg, c, slot->stream_id, slot->delivered_len, &slot->credit_advertised);
}

/* RFC 9000 4.1/19.9: this connection's total WT receive progress across every
 * in-use bidi and uni slot -- the raw ingredient srvrun_grant_conn_credit
 * sums into one connection-wide MAX_DATA ceiling, mirroring
 * srvrun_conn_consumed_bytes' send-side fan-out shape for the opposite
 * direction. */
/* Sum of delivered_len across every in-use wt_streams (bidi) slot -- the
 * bidi half of srvrun_wt_rx_delivered_total's fan-out, split out so each
 * loop stays at the CCN gate. */
static u64 srvrun_wt_bidi_delivered_total(const srvrun_conn* c) {
  u64 total = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (c->l.wt_streams[i].in_use) total += c->l.wt_streams[i].delivered_len;
  return total;
}

/* Sum of delivered_len across every in-use wt_uni_streams slot -- the uni
 * half of srvrun_wt_rx_delivered_total's fan-out. */
static u64 srvrun_wt_uni_delivered_total(const srvrun_conn* c) {
  u64 total = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    if (c->l.wt_uni_streams[i].in_use)
      total += c->l.wt_uni_streams[i].delivered_len;
  return total;
}

static u64 srvrun_wt_rx_delivered_total(const srvrun_conn* c) {
  return srvrun_wt_bidi_delivered_total(c) + srvrun_wt_uni_delivered_total(c);
}

/* Seal one PATH_CHALLENGE frame (RFC 9000 8.2.2/19.17) as its own 1-RTT
 * packet, mirroring srvrun_seal_max_data for a different single-frame
 * payload. Sent to c->peer -- the caller (srvrun_rebind_peer) has already
 * updated c->peer to the new path this challenges, RFC 9000 8.2.1. */
static int srvrun_seal_path_challenge(
    srvrun_conn* c, const u8 data[QUIC_PATH_DATA], wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  usz pln = quic_path_encode(plb.p, plb.cap, QUIC_FRAME_PATH_CHALLENGE, data);
  if (!pln) return 0;
  plb.len = pln;
  sin     = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* RFC 9000 8.2.1: an endpoint MUST expand datagrams that contain a
 * PATH_CHALLENGE frame to at least the smallest allowed maximum datagram
 * size (1200 bytes), so a path that only tolerates smaller datagrams cannot
 * be used before the amplification limit is even relevant. */
static int pad_challenge_fits(usz len, usz need, usz cap) {
  return need != 0 && len + need <= cap;
}

static usz srvrun_pad_path_challenge(u8* out, usz len, usz cap) {
  usz need = quic_pad_needed(len);
  if (!pad_challenge_fits(len, need, cap)) return len;
  for (usz i = 0; i < need; i++) out[len + i] = 0; /* PADDING frame (0x00) */
  return len + need;
}

static void srvrun_send_path_challenge(
    const srvrun_cfg* cfg, srvrun_conn* c, const u8 data[QUIC_PATH_DATA]) {
  u8         out[QUIC_MIN_INITIAL_DATAGRAM];
  wired_obuf ob = obuf_of(out, sizeof out);
  usz        n;
  if (!srvrun_seal_path_challenge(c, data, &ob)) return;
  n = srvrun_pad_path_challenge(out, ob.len, sizeof out);
  srvrun_send(cfg, c, wired_span_of(out, n), "PATH_CHALLENGE sent\n");
}

/* Seal one MAX_DATA frame (RFC 9000 19.9) as its own 1-RTT packet and send
 * it, mirroring srvrun_seal_max_stream_data for the connection-wide frame. */
static int srvrun_seal_max_data(srvrun_conn* c, u64 value, wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  quic_data_frame       f   = {value};
  wired_srvloop_send_in sin;
  usz                   pln = quic_max_data_encode(plb.p, plb.cap, &f);
  if (!pln) return 0;
  plb.len = pln;
  sin     = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

static void srvrun_send_max_data(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 value) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_max_data(c, value, &ob)) return;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "WT MAX_DATA sent\n");
}

/* Seal one DATA_BLOCKED frame (RFC 9000 19.12) as its own 1-RTT packet and
 * send it, mirroring srvrun_seal_max_data for the connection-wide limit. */
static int srvrun_seal_data_blocked(
    srvrun_conn* c, u64 limit, wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  quic_data_frame       f   = {limit};
  wired_srvloop_send_in sin;
  usz                   pln = quic_data_blocked_encode(plb.p, plb.cap, &f);
  if (!pln) return 0;
  plb.len = pln;
  sin     = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* RFC 9000 4.1/19.12: "A sender SHOULD send a DATA_BLOCKED... This can be
 * useful for debugging purposes... at the connection level" -- letting the
 * peer know the SERVER (not just the client) is flow-control-blocked so it
 * knows to raise MAX_DATA sooner than its own autotuning would otherwise.
 * limit is c->conn_credit itself (the ceiling that blocked this send). */
static void srvrun_send_data_blocked(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 limit) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_data_blocked(c, limit, &ob)) return;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "DATA_BLOCKED sent\n");
}

/* Seal one MAX_STREAMS frame (RFC 9000 19.11, uni selects 0x13) as its own
 * 1-RTT packet and send it. */
static int srvrun_seal_max_streams(
    srvrun_conn* c, int uni, u64 value, wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  if (!quic_maxstreams_frame(uni, value, &plb)) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, plb.len), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal one STREAMS_BLOCKED frame (RFC 9000 19.14, uni selects 0x17) as its
 * own 1-RTT packet and send it -- srvrun_seal_max_streams' mirror for the
 * SENDER-blocked signal instead of the receiver-side grant. */
static int srvrun_seal_streams_blocked(
    srvrun_conn* c, int uni, u64 limit, wired_obuf* out) {
  u8                    pl[24];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  if (!quic_maxstreams_blocked_frame(uni, limit, &plb)) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, plb.len), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* RFC 9000 4.6 19.14: "A sender SHOULD send a STREAMS_BLOCKED frame... This
 * can be useful for debugging purposes" -- tells the peer this SERVER ran
 * out of its own uni-stream grant for server-initiated (relay) opens, once
 * per distinct ceiling (srvrun_notify_uni_blocked's own doc). limit is the
 * peer_uni_stream_limit that refused the open. */
static void srvrun_send_streams_blocked(
    const srvrun_cfg* cfg, srvrun_conn* c, int uni, u64 limit) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_streams_blocked(c, uni, limit, &ob)) return;
  c->stat_streams_blocked++;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "UNI STREAMS_BLOCKED sent\n");
}

static void srvrun_send_max_streams(
    const srvrun_cfg* cfg, srvrun_conn* c, int uni, u64 value) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_max_streams(c, uni, value, &ob)) return;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "MAX_STREAMS sent\n");
  if (uni)
    c->uni_stream_limit_advertised = value;
  else
    c->stream_limit_advertised = value;
}

/* RFC 9000 4.6/19.11: raise the advertised bidi stream limit by n to match
 * the receive-side capacity the srvloop slots a reap pass (srvrun_
 * reap_resps) just released freed up -- keeps "limit advertised to the
 * client" in lockstep with "requests this SDK can actually reassemble at
 * once" (WIRED_SRVLOOP_MAX_STREAMS) instead of promising room the
 * fixed-size slot table cannot back. One MAX_STREAMS frame carries the
 * whole batch (n released slots used to cost n separate datagrams). base
 * is the limit already in force (the connection's transport-parameter
 * default the first time this fires, srvrun_conn.stream_limit_advertised
 * after that). Keeping this invariant (raise == releases) means the
 * currently-advertised limit is always derivable, so a later
 * STREAMS_BLOCKED (srvrun_reannounce_stream_limit) never needs to compute
 * anything new -- it just repeats this same value. */
static void srvrun_grant_streams(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 base, usz n) {
  u64 current = c->stream_limit_advertised ? c->stream_limit_advertised : base;
  if (n) srvrun_send_max_streams(cfg, c, 0, current + n);
}

/* srvrun_grant_streams' uni mirror: raise the advertised UNI stream limit by
 * n (one per WT uni reassembly slot released this pass), from the slot-
 * backed initial advertisement (wired_srvloop_uni_stream_limit -- the TP
 * and this base must agree, RFC 9000 4.6's capacity lockstep). */
static void srvrun_grant_uni_streams(
    const srvrun_cfg* cfg, srvrun_conn* c, usz n) {
  u64 current = c->uni_stream_limit_advertised
                    ? c->uni_stream_limit_advertised
                    : wired_srvloop_uni_stream_limit();
  if (n) srvrun_send_max_streams(cfg, c, 1, current + (u64)n);
}

/* RFC 9000 4.6: "An endpoint that receives a STREAMS_BLOCKED frame SHOULD
 * send a MAX_STREAMS frame if it is willing to increase the limit." This
 * SDK's limit only ever advances in lockstep with real receive capacity
 * (srvrun_grant_streams, one batched raise per reap pass), so there is
 * nothing new to compute here -- just resend the limit already in force
 * (or the transport-parameter default if nothing has been granted yet) in
 * case the peer's own copy of it was lost. Never trusts the peer's own
 * claimed limit in the STREAMS_BLOCKED frame (the value itself is
 * not even latched, see wired_srvloop.streams_blocked_seen_flag's doc). */
static void srvrun_reannounce_stream_limit(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 base) {
  if (!c->l.streams_blocked_seen_flag) return;
  c->l.streams_blocked_seen_flag = 0;
  srvrun_send_max_streams(
      cfg, c, 0,
      c->stream_limit_advertised ? c->stream_limit_advertised : base);
}

/* srvrun_reannounce_stream_limit's uni mirror: a UNI STREAMS_BLOCKED
 * sighting re-sends the uni limit already in force (or the transport-
 * parameter default before any uni release raised it). */
static void srvrun_reannounce_uni_stream_limit(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!c->l.streams_blocked_uni_seen_flag) return;
  c->l.streams_blocked_uni_seen_flag = 0;
  srvrun_send_max_streams(
      cfg, c, 1,
      c->uni_stream_limit_advertised ? c->uni_stream_limit_advertised
                                     : wired_srvloop_uni_stream_limit());
}

/* 1 if any WT bidi or uni slot is currently in use -- srvrun_grant_conn_
 * credit's own gate: a connection with no WT reassembly activity at all has
 * nothing this MAX_DATA raise is for (the server's own initial_max_data
 * transport parameter, server_tp.c, already covers ordinary request/response
 * traffic), so sending one unconditionally every step would put an unasked-
 * for frame on the wire of every plain HTTP/3 connection too. */
static int wt_any_bidi_slot_in_use(const srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (c->l.wt_streams[i].in_use) return 1;
  return 0;
}

static int wt_any_uni_slot_in_use(const srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    if (c->l.wt_uni_streams[i].in_use) return 1;
  return 0;
}

static int wt_any_slot_in_use(const srvrun_conn* c) {
  return wt_any_bidi_slot_in_use(c) || wt_any_uni_slot_in_use(c);
}

/* RFC 9000 4.1: how many WT bidi/uni slots on c are currently in use -- the
 * connection-wide MAX_DATA ceiling needs one buffer's worth of slack PER
 * open slot (each slot's own MAX_STREAM_DATA independently opens up to a
 * full WIRED_SRVLOOP_WT_BUF_CAP ahead of what it delivered), not a single
 * buffer's worth shared across every slot -- undercounting this starved
 * every slot but one down to the connection ceiling once several were
 * active at once (found via a real webtransport-go interop run: streams
 * stalled hard the moment their combined MAX_STREAM_DATA ceilings outran a
 * one-buffer-wide MAX_DATA). */
static usz wt_bidi_slots_in_use(const srvrun_conn* c) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    if (c->l.wt_streams[i].in_use) n++;
  return n;
}

static usz wt_uni_slots_in_use(const srvrun_conn* c) {
  usz n = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    if (c->l.wt_uni_streams[i].in_use) n++;
  return n;
}

static usz wt_slots_in_use(const srvrun_conn* c) {
  return wt_bidi_slots_in_use(c) + wt_uni_slots_in_use(c);
}

/* RFC 9000 4.1/19.9: re-grant this connection's receive credit once its total
 * WT progress (every slot combined) has advanced enough past what was last
 * advertised -- the connection-wide counterpart of srvrun_grant_stream_
 * credit, using the same ceiling shape (delivered + one buffer's worth of
 * slack) so raising every open stream's own window never outruns the shared
 * connection ceiling. A no-op while no WT slot has ever been claimed
 * (wt_any_slot_in_use). */
static void srvrun_grant_conn_credit(const srvrun_cfg* cfg, srvrun_conn* c) {
  u64 ceiling = c->wt_rx_reaped_total + srvrun_wt_rx_delivered_total(c) +
                (u64)wt_slots_in_use(c) * WIRED_SRVLOOP_WT_BUF_CAP;
  if (!wt_any_slot_in_use(c)) return;
  if (!wt_credit_stream_due(ceiling, c->rx_max_data_advertised)) return;
  srvrun_send_max_data(cfg, c, ceiling);
  c->rx_max_data_advertised = ceiling;
}

/* draft-ietf-webtrans-http3-15 4.3 / RFC 9000 4.1: after a step's reassembly/
 * delivery/window-slide passes, re-grant flow-control credit for every WT
 * slot whose window has advanced (srvrun_grant_wt_slot_credit/_uni), then the
 * connection-wide ceiling once (srvrun_grant_conn_credit) -- called once per
 * step regardless of whether this step itself delivered anything, so a
 * connection with an idle WT slot still eventually catches up after a burst
 * a few steps earlier. */
static void srvrun_grant_wt_credit(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    srvrun_grant_wt_slot_credit(cfg, c, &c->l.wt_streams[i]);
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    srvrun_grant_wt_uni_slot_credit(cfg, c, &c->l.wt_uni_streams[i]);
  srvrun_grant_conn_credit(cfg, c);
}

/* draft-ietf-webtrans-http3-15 SS4.4: this step's stream-close gathering
 * (dispatch.c's gather_stream_closes) latched a RESET_STREAM/STOP_SENDING/FIN
 * on the exact stream id that is one of this connection's active WT
 * sessions' own CONNECT stream -- close that one session now, independent of
 * whether the rest of the connection is still alive. This is a precise
 * per-session trigger distinct from srvrun_free_slot's own whole-connection
 * teardown: without it, a CONNECT stream closing while the connection stays
 * open would leave that session established indefinitely. c->l.closed_
 * stream_seen is consumed (cleared) here every step regardless of whether it
 * matched, mirroring datagram_violation's own per-step latch-and-clear
 * shape. */
/* The active session slot whose OWN CONNECT stream is the one this step's
 * gather_stream_closes latched, or -1 if none matches (or nothing was
 * latched) — split out of srvrun_close_wt_on_stream_close to keep its own
 * branch count at the CCN gate. Only the ONE matching slot ever closes:
 * srvrun_wt_slot_by_connect_id's own exact-match lookup is what keeps every
 * other open session on this connection untouched. */
static int wt_connect_stream_slot(const srvrun_conn* c) {
  if (!c->l.closed_stream_seen) return -1;
  return srvrun_wt_slot_by_connect_id(c, c->l.closed_stream_id);
}

/* draft-ietf-webtrans-http3-15 8.2: WT_SESSION_GONE, mapped through the
 * HTTP/3-level error-code range (errmap.h), the application error code every
 * stream a closing session still owns is reset/stopped with below. */
static u64 srvrun_wt_session_gone_code(void) {
  return wired_wterrmap_to_http3(QUIC_WTERR_SESSION_GONE);
}

/* draft-ietf-webtrans-http3-15 SS5.3/5.4/8.2: WT_FLOW_CONTROL_ERROR, mapped
 * the same way as srvrun_wt_session_gone_code -- the application error code a
 * session closing for exceeding its peer-advertised WT_MAX_STREAMS/WT_MAX_
 * DATA limit is reset/stopped with (srvrun_close_flow_violated_slot). */
static u64 srvrun_wt_flow_control_code(void) {
  return wired_wterrmap_to_http3(QUIC_WTERR_FLOW_CONTROL_ERROR);
}

/* draft-ietf-webtrans-http3-15 SS4.4: abort one still-`in_use` WT bidi
 * stream that session_slot owned with err_code (RESET_STREAM +
 * STOP_SENDING via srvrun_send_wt_busy_reset, which picks the frames the
 * stream's type allows -- a client bidi gets both halves) and free its
 * slot, so a session's teardown never leaves its own streams
 * readable/writable past the session's own lifetime. A no-op for a stream
 * this session never owned (wt_session_slot mismatch) or one already free. */
static void srvrun_reset_wt_bidi_if_owned(
    const srvrun_cfg*             cfg,
    srvrun_conn*                  c,
    wired_srvloop_wt_stream_slot* slot,
    int                           session_slot,
    u64                           err_code) {
  if (!slot->in_use || slot->wt_session_slot != session_slot) return;
  srvrun_send_wt_busy_reset(cfg, c, slot->stream_id, err_code);
  slot->in_use = 0;
}

/* Same as srvrun_reset_wt_bidi_if_owned, for one WT uni stream slot -- a
 * client-initiated uni stream gets STOP_SENDING alone (this server has no
 * send part to reset on it, RFC 9000 19.4/19.5). */
static void srvrun_reset_wt_uni_if_owned(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot,
    int                               session_slot,
    u64                               err_code) {
  if (!slot->in_use || slot->wt_session_slot != session_slot) return;
  srvrun_send_wt_busy_reset(cfg, c, slot->stream_id, err_code);
  slot->in_use = 0;
}

/* draft-ietf-webtrans-http3-15 SS4.2/SS4.7 (WTH3-048): seal capsule_bytes as
 * a STREAM frame on session slot sidx's own CONNECT stream, continuing from
 * wt_connect_sent_len[sidx] (the offset doc explains why a fresh one-shot
 * seal is used here rather than resp[]/wtsend[]'s pump), and advance that
 * offset past it. Fire-and-forget, same as srvrun_send_goaway itself: both
 * WT_DRAIN_SESSION (advisory, session.h) and GOAWAY are non-critical
 * notifications this SDK does not retransmit on loss. fin sets the STREAM
 * frame's own FIN bit (WT_CLOSE_SESSION's own send, WTH3-067, sets it; every
 * other capsule here does not). Returns 1 with out->len set, 0 on overflow or
 * no 1-RTT key. */
static int srvrun_send_wt_capsule(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    int               sidx,
    wired_span        capsule_bytes,
    u8                fin,
    wired_obuf*       out) {
  /* +32: STREAM frame header room (type + stream id + offset + length
   * varints, RFC 9000 19.8) ahead of capsule_bytes -- sized to fit the
   * largest capsule this file sends, WT_CLOSE_SESSION's own worst case
   * (QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX, srvrun_send_wt_close's own body[]). */
  u8                    pl[32 + 16 + 4 + QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  quic_stream_frame     f = {
      srvrun_wt_slot(c, sidx)->connect_stream_id, c->wt_connect_sent_len[sidx],
      capsule_bytes.n, capsule_bytes.p, fin};
  if (!quic_appdata_stream_frame(&f, &plb)) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, plb.len), 0};
  if (!wired_srvloop_send_onertt(&c->s, &sin, out)) return 0;
  srvrun_send(cfg, c, wired_span_of(out->p, out->len), "WT capsule sent\n");
  c->wt_connect_sent_len[sidx] += capsule_bytes.n;
  return 1;
}

/* draft-ietf-webtrans-http3-15 SS4.4/8.2: a session closing must not leave
 * any of ITS OWN WT bidi/uni streams open -- reset every one with err_code.
 * wt_session_slot (set at offer time, srvrun_offer_wt_slot/_uni_slot) is what
 * tells these apart from a sibling session's own streams when
 * SRVRUN_MAX_WT_SESSIONS > 1 sessions are open at once on the same
 * connection. */
static void srvrun_reset_wt_streams_for_session(
    const srvrun_cfg* cfg, srvrun_conn* c, int session_slot, u64 err_code) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    srvrun_reset_wt_bidi_if_owned(
        cfg, c, &c->l.wt_streams[i], session_slot, err_code);
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    srvrun_reset_wt_uni_if_owned(
        cfg, c, &c->l.wt_uni_streams[i], session_slot, err_code);
}

/* Common body of "close WT session slot sidx, resetting every stream it owns
 * with err_code and freeing the slot" -- shared by srvrun_close_wt_on_stream_
 * close (WT_SESSION_GONE, triggered by the CONNECT stream itself closing),
 * srvrun_close_flow_violated_slot (WT_FLOW_CONTROL_ERROR, triggered by a
 * WT_MAX_STREAMS/WT_MAX_DATA violation, WTH3-058/WTH3-061), and
 * srvrun_send_wt_close (WT_CLOSE_SESSION, WTH3-067). Split out so no caller
 * repeats the free-slot bookkeeping. */
/* App-facing session-ended delivery (wired_wt_on_session_close): every path
 * that ends a WT session server-side funnels through here, BEFORE the
 * session's storage can be reused by a later connection -- an app keying
 * per-session state on the session pointer frees it in this callback. */
static void srvrun_notify_wt_close(const srvrun_cfg* cfg, wired_wt_session* s) {
  if (cfg->wt_on_session_close == 0) return;
  cfg->wt_on_session_close(cfg->wt_session_close_ctx, s);
}

static void srvrun_close_wt_session_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, u64 err_code) {
  srvrun_notify_wt_close(cfg, srvrun_wt_slot(c, sidx));
  wired_wt_session_close(srvrun_wt_slot(c, sidx));
  srvrun_reset_wt_streams_for_session(cfg, c, sidx, err_code);
  /* Closing frees the slot -- a later Extended CONNECT may reuse it
   * (srvrun_wt_free_slot's own check is the active flag, not session state,
   * since WIRED_WT_UNESTABLISHED's enum value 0 is indistinguishable from
   * "never initialized" by state alone). */
  *srvrun_wt_active_slot(c, sidx) = 0;
}

static void srvrun_close_wt_on_stream_close(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  int sidx = wt_connect_stream_slot(c);
  if (sidx >= 0)
    srvrun_close_wt_session_slot(cfg, c, sidx, srvrun_wt_session_gone_code());
  c->l.closed_stream_seen = 0;
}

/* draft-ietf-webtrans-http3-15 SS4.2/SS4.4/8.2 (WTH3-067): drain a
 * wired_server_wt_close_session call latched at slot sidx (wt_close_pending's
 * own doc) -- send the WT_CLOSE_SESSION capsule with FIN on the CONNECT
 * stream, then reset every OTHER WT stream this session owns with WT_SESSION_
 * GONE (srvrun_close_wt_session_slot, which never touches the CONNECT stream
 * itself) and close the session. A capsule-encode failure (message too long
 * -- cannot happen, wired_server_wt_close_session already truncated it to
 * QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX -- or out overflow) still closes the
 * session: a peer that never received the capsule finds out via the CONNECT
 * stream's own FIN/reset either way, and leaving the session open forever on
 * a local encode failure would be worse. */
static void srvrun_send_wt_close(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, wired_obuf* out) {
  /* +4: WT_CLOSE_SESSION's fixed 32-bit Application Error Code field
   * (wtcapsule.h). +16: worst-case Capsule Type + Capsule Length varint
   * overhead (RFC 9000 SS16: a varint is at most 8 bytes each,
   * quic_capsule_encode's own envelope) ahead of the 4-byte code and message
   * wired_wtcapsule_encode_close writes into this same buffer. */
  u8         body[16 + 4 + QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX];
  wired_obuf bob = obuf_of(body, sizeof body);
  if (wired_wtcapsule_encode_close(
          &bob, c->wt_close_code[sidx],
          wired_span_of(c->wt_close_msg[sidx], c->wt_close_msg_len[sidx])))
    srvrun_send_wt_capsule(cfg, c, sidx, wired_span_of(body, bob.len), 1, out);
  srvrun_close_wt_session_slot(cfg, c, sidx, srvrun_wt_session_gone_code());
}

static void srvrun_drain_wt_close_one(
    const srvrun_cfg* cfg, srvrun_conn* c, int i, wired_obuf* out) {
  if (!c->wt_close_pending[i]) return;
  c->wt_close_pending[i] = 0;
  if (srvrun_wt_is_active(c, i)) srvrun_send_wt_close(cfg, c, i, out);
}

/* Drain every session slot's pending wired_server_wt_close_session
 * (wt_close_pending, latched from an app callback), same per-step shape as
 * srvrun_close_wt_flow_violations. */
static void srvrun_drain_wt_close_pending(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  u8 out[1500]; /* worst case: WT_CLOSE_SESSION's 1024-byte message
                 * cap (srvrun_send_wt_close's own body[] doc) */
  wired_obuf ob = obuf_of(out, sizeof out);
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    srvrun_drain_wt_close_one(cfg, c, i, &ob);
}

/* Seal latch entry i's standard RESET_STREAM (RFC 9000 19.4) into out as
 * its own 1-RTT packet: the app code mapped into HTTP/3's WebTransport
 * range (draft-ietf-webtrans-http3-15 SS4.4/8.2) plus the final size
 * captured at latch time -- NOT looked up now (srvrun_wt_abort_reset's
 * live lookup would read 0, the send slot was already freed at latch
 * time), and no STOP_SENDING (the latch targets server-initiated uni
 * streams; see the wt_stream_reset_* latch fields' own doc). */
static int srvrun_seal_wt_stream_reset(srvrun_conn* c, usz i, wired_obuf* out) {
  u8                      pl[32];
  quic_reset_stream_frame rs = {
      c->wt_stream_reset_id[i],
      wired_wterrmap_to_http3(c->wt_stream_reset_app_code[i]),
      c->wt_stream_reset_final[i]};
  usz                   pln = quic_reset_stream_encode(pl, sizeof pl, &rs);
  wired_srvloop_send_in sin;
  if (!pln) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal and send latch entry i's RESET_STREAM as its own 1-RTT packet. */
static void srvrun_send_wt_stream_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, usz i) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_seal_wt_stream_reset(c, i, &ob)) return;
  srvrun_send(cfg, c, wired_span_of(out, ob.len), "WT stream RESET sent\n");
}

/* Drain the wired_server_wt_stream_reset latch (the wt_stream_reset_*
 * fields' own doc): every entry gets its own RESET_STREAM packet. The send
 * slots were already freed at latch time (wired_server_wt_stream_reset),
 * so only the wire bytes remain to send. */
static void srvrun_drain_wt_stream_reset(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < c->wt_stream_reset_n; i++)
    srvrun_send_wt_stream_reset(cfg, c, i);
  c->wt_stream_reset_n = 0;
}

/* 1 if slot is in-use and its stream id is this step's latched
 * wt_reset_stream_id -- the same "is this the reset target" test
 * wt_reset_bidi_session/wt_reset_uni_session each apply to their own table,
 * pulled into one predicate so neither loop's own `if` carries the `||`
 * (CCN). */
static int wt_reset_bidi_matches(
    const wired_srvloop_wt_stream_slot* slot, u64 reset_stream_id) {
  return slot->in_use && slot->stream_id == reset_stream_id;
}

/* Same as wt_reset_bidi_matches, for one WT uni stream slot. */
static int wt_reset_uni_matches(
    const wired_srvloop_wt_uni_stream_slot* slot, u64 reset_stream_id) {
  return slot->in_use && slot->stream_id == reset_stream_id;
}

/* This step's wt_reset_stream_id/gather_one_wt_reset latch (dispatch.c)
 * belongs to session slot sidx's own WT bidi stream: free that ONE stream
 * slot (WTH3-036: a reset ends the stream, not its session) and return the
 * session slot it belonged to, or -1 if it names no in-use bidi slot at all
 * -- split out of wt_reset_session_slot so its own branch count stays at
 * the CCN gate. */
static int wt_reset_bidi_session(srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++) {
    wired_srvloop_wt_stream_slot* slot = &c->l.wt_streams[i];
    if (!wt_reset_bidi_matches(slot, c->l.wt_reset_stream_id)) continue;
    slot->in_use = 0;
    return slot->wt_session_slot;
  }
  return -1;
}

/* Same as wt_reset_bidi_session, over the uni table. */
static int wt_reset_uni_session(srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++) {
    wired_srvloop_wt_uni_stream_slot* slot = &c->l.wt_uni_streams[i];
    if (!wt_reset_uni_matches(slot, c->l.wt_reset_stream_id)) continue;
    slot->in_use = 0;
    return slot->wt_session_slot;
  }
  return -1;
}

/* draft-ietf-webtrans-http3-15 4.4 (WTH3-039/WTH3-040): the session slot
 * this step's latched RESET_STREAM/STOP_SENDING belongs to -- the bidi
 * table first, then the uni table (the two id spaces are disjoint, RFC
 * 9000 2.1, so at most one ever matches), or -1 if the stream id names
 * neither a live WT bidi nor uni slot on this connection at all (e.g. a
 * plain HTTP/3 request stream's own reset, out of WebTransport's scope). */
static int wt_reset_session_slot(srvrun_conn* c) {
  int sidx = wt_reset_bidi_session(c);
  if (sidx >= 0) return sidx;
  return wt_reset_uni_session(c);
}

/* draft-ietf-webtrans-http3-15 4.4 (WTH3-040): "If a RESET_STREAM or
 * STOP_SENDING frame is received with an error code outside the
 * WT_APPLICATION_ERROR range, then the implementation should deliver this
 * to the application as a stream reset with no application error code."
 * wired_wterrmap_from_http3 (errmap.h) recovers the WebTransport application
 * error code when the wire code falls inside that range; mapped is left 0
 * (app_error_code meaningless) otherwise -- this is the SDK-side half of
 * WTH3-040, deciding what to hand the app; wired_wt_on_stream_reset's own
 * doc covers the same split from the app's point of view. */
static void srvrun_deliver_wt_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx) {
  u32 app_code = 0;
  int mapped   = wired_wterrmap_from_http3(c->l.wt_reset_error_code, &app_code);
  if (!cfg->wt_on_stream_reset) return;
  cfg->wt_on_stream_reset(
      cfg->wt_stream_reset_ctx, srvrun_wt_slot(c, sidx),
      c->l.wt_reset_stream_id, mapped, app_code);
}

/* draft-ietf-webtrans-http3-15 4.4 (WTH3-039/WTH3-040): once a step's
 * gather_one_wt_reset (dispatch.c) latched a RESET_STREAM/STOP_SENDING on a
 * stream id that resolves to one of THIS connection's own live WT bidi/uni
 * slots, deliver it to the app (srvrun_deliver_wt_reset) and free that one
 * stream's slot -- narrower than srvrun_close_wt_session_slot, which tears
 * down a whole SESSION; this tears down only the ONE stream the peer reset,
 * leaving the rest of its session untouched (WTH3-036: a reset is a per-
 * stream event, not a session-ending one). c->l.wt_reset_seen is consumed
 * every step regardless of whether it matched, mirroring closed_stream_
 * seen's own per-step latch-and-clear shape (wt_connect_stream_slot's doc). */
static void srvrun_deliver_wt_reset_if_owned(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  int sidx;
  if (!c->l.wt_reset_seen) return;
  sidx = wt_reset_session_slot(c);
  if (sidx >= 0) srvrun_deliver_wt_reset(cfg, c, sidx);
  c->l.wt_reset_seen = 0;
}

/* draft-ietf-webtrans-http3-15 SS5.3/SS5.4/8.2 (WTH3-058/WTH3-061): close one
 * session slot that wt_open_flow_ok/wt_reply_flow_ok latched
 * (wt_flow_violation[i]) for exceeding a peer-advertised WT_MAX_STREAMS/
 * WT_MAX_DATA limit, resetting every WT stream it owns with WT_FLOW_CONTROL_
 * ERROR (srvrun_close_wt_session_slot) -- run every step so a violation
 * latched from an app callback between steps is always closed on the very
 * next one, mirroring srvrun_close_wt_on_stream_close's own per-step shape. */
static void srvrun_close_flow_violated_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int i) {
  if (!c->wt_flow_violation[i]) return;
  c->wt_flow_violation[i] = 0;
  if (srvrun_wt_is_active(c, i))
    srvrun_close_wt_session_slot(cfg, c, i, srvrun_wt_flow_control_code());
}

static void srvrun_close_wt_flow_violations(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    srvrun_close_flow_violated_slot(cfg, c, i);
}

/* RFC 9221 3: this step's DATAGRAM gathering (dispatch.c) latched a violation
 * -- close the connection with a transport-level PROTOCOL_VIOLATION. Split out
 * of srvrun_on_step to keep its own branch count at the CCN gate. */
static void srvrun_close_on_datagram_violation(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "DATAGRAM exceeds advertised limit";
  srvrun_send_transport_close(
      cfg, c, QUIC_ERR_PROTOCOL_VIOLATION,
      wired_span_of(reason, sizeof reason - 1));
}

/* draft-ietf-webtrans-http3-15 4.3: this step's WT bidi gathering
 * (dispatch.c's gather_one_wt_signal_violation) latched the WT_STREAM signal
 * (0x41) arriving as a STREAM frame's own leading bytes at a non-zero stream
 * offset -- "Receiving this frame type in any other circumstances MUST be
 * treated as a connection error of type H3_FRAME_ERROR." An H3-level error
 * on an HTTP/3 connection is an application-level CONNECTION_CLOSE (RFC 9114
 * 8.1), the same shape srvrun_close_on_bad_qsid already uses for a different
 * H3-level violation -- NOT srvrun_close_on_datagram_violation's transport-
 * level PROTOCOL_VIOLATION, which is RFC 9221's own (different-layer) rule. */
static void srvrun_close_on_wt_signal_violation(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "WT_STREAM signal outside stream's leading bytes";
  srvrun_send_app_close(
      cfg, c, QUIC_H3_FRAME_ERROR, wired_span_of(reason, sizeof reason - 1));
}

/* 1 if this step's own gathering (dispatch.c) latched a connection-ending
 * violation and closed c over it -- datagram_violation (RFC 9221 3) or
 * wt_signal_mid_stream_violation (draft-ietf-webtrans-http3-15 4.3), checked
 * and cleared together so srvrun_on_step itself carries only one guard for
 * both (CCN). Datagram is checked first only because it was the original,
 * single violation; a step latching both simply chooses the datagram close
 * (RFC 9000 10.2: any CONNECTION_CLOSE ends the connection, so it does not
 * matter which of two same-step violations sends it). */
static int srvrun_close_on_step_violation(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  if (c->l.datagram_violation) {
    srvrun_close_on_datagram_violation(cfg, c);
    return 1;
  }
  if (c->l.wt_signal_mid_stream_violation) {
    c->l.wt_signal_mid_stream_violation = 0;
    srvrun_close_on_wt_signal_violation(cfg, c);
    return 1;
  }
  return 0;
}

/* Send this step's sealed reply, if any and if the connection is not
 * draining after a peer CONNECTION_CLOSE (RFC 9000 10.2.2). */
static void srvrun_send_step_reply(
    const srvrun_cfg* cfg, srvrun_conn* c, int produced, wired_span out) {
  if (c->l.peer_closed) return;
  if (produced) srvrun_send(cfg, c, out, "1-RTT reply sealed and sent\n");
}

/* RFC 9001 6.3: a rotation just confirmed (ku.generation advanced past what
 * this step last observed) -- record when, so the retained old key's
 * 3x-PTO retention floor (srvrun_ku_discard_stale) has a start line. */
static void srvrun_ku_note_rotation(srvrun_conn* c, u64 now_ms) {
  if (c->s.ku.generation == c->ku_seen_gen) return;
  c->ku_seen_gen      = c->s.ku.generation;
  c->ku_rotated_at_ms = now_ms;
}

/* A later datagram on a live slot: one real-wire step, send any sealed
 * reply — unless this step's own gathering found a connection-ending
 * violation (RFC 9221 3 DATAGRAM, or draft-ietf-webtrans-http3-15 4.3's
 * mid-stream WT_STREAM signal), in which case the connection closes itself
 * instead (srvrun_close_on_step_violation), or the step observed a peer
 * CONNECTION_CLOSE (srvrun_send_step_reply's own gate). */
static void srvrun_on_step(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg) {
  u8                 out[1500];
  wired_obuf         ob   = obuf_of(out, sizeof out);
  wired_srvloop_conn conn = {&c->l, &c->s};
  srvrun_rxmark      mark = srvrun_rx_mark(&c->l);
  int                produced;
  c->l.now_ms = ctx->now_ms; /* share srvrun's own PTO/RTT clock with
                              * quic_ackpolicy's delayed-ACK timer, not a
                              * second one. */
  c->l.ack_defer = 1;        /* RFC 9000 13.2.1: suppress the bare-ACK packet
                              * this step; the pump piggybacks the pending ACK
                              * onto a slice, or srvrun_flush_deferred_ack
                              * sends it at step end. */
  produced = wired_srvloop_step(&conn, dg, &ob);
  srvrun_ku_note_rotation(c, ctx->now_ms);
  srvrun_note_recv(ctx, &mark, c, dg.n);
  srvrun_offer_wt_streams(ctx->cfg, c);
  srvrun_offer_wt_uni_streams(ctx->cfg, c);
  srvrun_grant_wt_credit(ctx->cfg, c);
  srvrun_drain_rx_datagrams(ctx->cfg, c);
  srvrun_close_wt_on_stream_close(ctx->cfg, c);
  srvrun_deliver_wt_reset_if_owned(ctx->cfg, c);
  srvrun_close_wt_flow_violations(ctx->cfg, c);
  srvrun_drain_wt_close_pending(ctx->cfg, c);
  srvrun_drain_wt_stream_reset(ctx->cfg, c);
  if (srvrun_close_on_step_violation(ctx->cfg, c)) return;
  srvrun_send_step_reply(ctx->cfg, c, produced, wired_span_of(out, ob.len));
}

/* RFC 9114 6.2.1: first server unidirectional (control) stream id, same value
 * respond.c's build_settings_frame uses. */
#define SRVRUN_CTRL_STREAM 3

/* RFC 9114 5.2: the id a server GOAWAY carries is the lowest client-initiated
 * bidi stream the server will no longer accept. This SDK serves at most one
 * request stream per connection (id 0, srvloop.h), so there is no live
 * request id to preserve — id 4 (the next bidi stream after 0) simply says
 * "nothing further accepted", the simplest correct value for this server's
 * one-request-per-connection model.
 * ponytail: a real multi-stream server would track the highest in-flight
 * request id and GOAWAY one past it instead. */
#define SRVRUN_GOAWAY_ID 4

/* Byte length of the control stream's leading type+SETTINGS (RFC 9114 6.2.1),
 * recomputed via the same pure encoder respond.c's build_settings_frame uses.
 * A GOAWAY sent after confirmation is appended right after it, at this fixed
 * offset — this server sends control-stream data exactly twice (SETTINGS at
 * confirmation, GOAWAY at most once at shutdown), so no general offset
 * tracker is needed. */
static usz srvrun_ctrl_settings_len(int advertise_wt) {
  u8  tmp[64];
  usz n = 0;
  quic_h3conn_open_control(advertise_wt, tmp, sizeof tmp, &n);
  return n;
}

/* Build the 1-RTT payload for a GOAWAY (RFC 9114 5.2): the H3 GOAWAY frame
 * wrapped in a STREAM frame at the control stream's fixed post-SETTINGS
 * offset. Returns 1 with plb->len set, 0 on overflow. */
static int srvrun_goaway_payload(int advertise_wt, wired_obuf* plb) {
  u8                h3[16];
  usz               h3n = quic_h3_goaway_put(h3, sizeof h3, SRVRUN_GOAWAY_ID);
  quic_stream_frame f;
  if (h3n == 0) return 0;
  f = (quic_stream_frame){
      SRVRUN_CTRL_STREAM, srvrun_ctrl_settings_len(advertise_wt), h3n, h3, 0};
  return quic_appdata_stream_frame(&f, plb);
}

/* Seal a GOAWAY (RFC 9114 5.2) on the control stream into one 1-RTT packet for
 * c, whose confirmation (SETTINGS) has already been sent at offset 0. Returns
 * 1 with out->len set, 0 if the payload cannot be built or c has no 1-RTT key
 * yet. */
static int srvrun_send_goaway(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out) {
  u8                    pl[64];
  wired_obuf            plb = obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  if (!srvrun_goaway_payload(c->l.we_advertised_max_datagram > 0, &plb))
    return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, plb.len), 0};
  if (!wired_srvloop_send_onertt(&c->s, &sin, out)) return 0;
  srvrun_send(cfg, c, wired_span_of(out->p, out->len), "GOAWAY sent\n");
  c->goaway_sent = 1;
  return 1;
}

/* draft-ietf-webtrans-http3-15 SS4.2 (WTH3-048): send session slot sidx's own
 * WT_DRAIN_SESSION capsule (empty body, wired_wt_session_drain's own
 * advisory-only doc) and apply the matching local state transition. A no-op
 * if the session was not ESTABLISHED (wired_wt_session_drain's own 0 return,
 * e.g. already draining/closed) -- nothing to drain twice. */
static void srvrun_send_wt_drain(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, wired_obuf* out) {
  u8         body[8];
  wired_obuf bob = obuf_of(body, sizeof body);
  if (!wired_wt_session_drain(srvrun_wt_slot(c, sidx))) return;
  if (!quic_wtcapsule_encode_drain(&bob)) return;
  srvrun_send_wt_capsule(cfg, c, sidx, wired_span_of(body, bob.len), 0, out);
}

/* Fan WT_DRAIN_SESSION out to every active WT session slot on c -- run right
 * after c's own GOAWAY (srvrun_send_goaway), the trigger draft-ietf-webtrans-
 * http3-15 SS4.7 ties this capsule to ("a server sends WT_DRAIN_SESSION [...]
 * when [...] the connection is going away, for example, [...] GOAWAY"). */
static void srvrun_send_wt_drain_all(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (srvrun_wt_is_active(c, i)) srvrun_send_wt_drain(cfg, c, i, out);
}

/* GOAWAY is owed to c once: the connection is up, confirmed (a 1-RTT key
 * exists to seal with), and no GOAWAY has gone out yet. */
static int srvrun_owes_goaway(const srvrun_conn* c) {
  return c->up && c->l.hs_done_sent && !c->goaway_sent;
}

/* Queue data as c's one pending outbound QUIC DATAGRAM (RFC 9221), to be sent
 * on the connection's next step (srvrun_send_pending_datagram). Copies data
 * into c->dg_pending_buf, so the caller's span need not outlive this call.
 *
 * srvrun-internal for now rather than a wired_wt_session API: the
 * pending-datagram slot lives on srvrun_conn (not wired_wt_session), since
 * QUIC DATAGRAM sending is generic transport, not WebTransport-specific.
 * A future WT-specific wrapper (e.g. wired_wt_send_datagram) can call this
 * once srvrun exposes a stable per-connection handle to WT sessions; adding
 * that bridge now would be speculative (no second caller yet), and no
 * production code decides to send a datagram yet either (that needs an
 * app-facing callback hook, also not built) -- hence still test-only, same
 * situation as srvrun_test_set_shutdown above.
 *
 * Queuing itself is bounded only by the local dg_pending_buf capacity, same
 * as other frame types in this file (SRVRUN_CHUNK et al.); the peer's
 * advertised max_datagram_frame_size (RFC 9221 3) is enforced later, at send
 * time, by srvrun_send_pending_datagram.
 *
 * RFC 9297 2.1: an endpoint MUST NOT send a QUIC DATAGRAM frame before it has
 * sent its own SETTINGS_H3_DATAGRAM=1 (SETTINGS are never acked in HTTP/3, so
 * "sent" -- not "peer-observed" -- is the enforceable half of the ordering).
 * c->l.h3.settings_sent is that exact flag (set by wired_h3srv_open_control,
 * called at handshake confirmation before any response); silently drop the
 * queue request rather than invent a new error path, matching this being a
 * self-imposed ordering constraint, not a peer-facing fault.
 * ponytail: unused in the freestanding build (only tests/run.c calls this),
 * so it needs the attribute to avoid -Wunused-function under -Werror there.
 * @return 1 if queued, 0 if data.n exceeds dg_pending_buf's capacity or our
 * own SETTINGS have not been sent yet (RFC 9297 2.1) */
static int srvrun_queue_datagram(srvrun_conn* c, wired_span data) {
  if (!c->l.h3.settings_sent) return 0;
  if (data.n > sizeof c->dg_pending_buf) return 0;
  bytes_memcpy(c->dg_pending_buf, data.p, data.n);
  c->dg_pending_len = data.n;
  c->dg_pending     = 1;
  return 1;
}

/* Seal one QUIC DATAGRAM (RFC 9221 5) carrying data into a 1-RTT packet and
 * send it. Unlike srvrun_send_slice/srvrun_send_goaway, there is no
 * wired_sendsess/ACK-loss bookkeeping: RFC 9221 1 DATAGRAM frames are never
 * retransmitted. max_frame_size is the peer's advertised
 * max_datagram_frame_size (sdrv_recv_client_hello populated it from the
 * real ClientHello transport parameters): quic_dgdeliver_frame's internal
 * quic_datagram_allowed check rejects the send outright when the
 * peer never advertised support (value 0) or when the encoded frame would
 * exceed the peer's advertised limit. Shared by the single-slot pending
 * queue below and the session-addressed ring (srvrun_dgring_drain).
 * Returns 1 if sent, 0 if the frame could not be built (too large for the
 * peer's limit, or it would not fit the local buffer). */
static int srvrun_send_datagram_now(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_span data, wired_obuf* out) {
  u8                    pl[1400];
  wired_obuf            plb        = obuf_of(pl, sizeof pl);
  u64                   peer_limit = c->s.sdrv.peer_max_datagram_frame_size;
  quic_dgdeliver_opts   o = {.with_length = 1, .max_frame_size = peer_limit};
  wired_srvloop_send_in sin;
  if (!quic_dgdeliver_frame(data, &o, &plb)) return 0;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      wired_span_of(pl, plb.len), 0};
  if (!wired_srvloop_send_onertt(&c->s, &sin, out)) return 0;
  srvrun_send(cfg, c, wired_span_of(out->p, out->len), "DATAGRAM sent\n");
  return 1;
}

/* RFC 9297 2.1: on the wire every HTTP Datagram carries the quarter-stream-
 * id prefix of the session it belongs to. The pending slot stores the bare
 * payload (one slot serves every session on the connection), so the prefix
 * is applied here, per target session, at send time -- the exact mirror of
 * srvrun_deliver_rx_datagram stripping it on receive. A real browser peer
 * decodes the first payload byte as that prefix and silently drops the
 * datagram when it names no session it knows. */
static int srvrun_send_dg_prefixed(
    const srvrun_cfg*       cfg,
    srvrun_conn*            c,
    const wired_wt_session* s,
    wired_span              payload,
    wired_obuf*             out) {
  u8  buf[8 + sizeof c->dg_pending_buf];
  usz qn = quic_wtwire_qsid_put(buf, sizeof buf, s->connect_stream_id);
  if (!qn) return 0;
  bytes_memcpy(buf + qn, payload.p, payload.n);
  out->len = 0;
  return srvrun_send_datagram_now(
      cfg, c, wired_span_of(buf, qn + payload.n), out);
}

/* One session slot's share of srvrun_send_pending_datagram: an inactive or
 * send-side-closed slot is skipped (1 -- best-effort, mirroring
 * srvrun_broadcast_to_all), an eligible one reports its send result. */
static int srvrun_send_pending_dg_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int i, wired_obuf* out) {
  wired_wt_session* s;
  if (!srvrun_wt_is_active(c, i)) return 1;
  s = srvrun_wt_slot(c, i);
  if (!wt_session_send_side_open(s)) return 1;
  return srvrun_send_dg_prefixed(
      cfg, c, s, wired_span_of(c->dg_pending_buf, c->dg_pending_len), out);
}

/* Seal c's one pending broadcast DATAGRAM (srvrun_queue_datagram's single
 * last-writer-wins slot) once per active WT session, each with its own
 * session's qsid prefix; clears c->dg_pending when every eligible session
 * was sent to, keeps it pending on failure so a later step may retry
 * against a raised peer limit. */
static int srvrun_send_pending_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* out) {
  int ok = 1;
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    ok &= srvrun_send_pending_dg_slot(cfg, c, i, out);
  if (ok) c->dg_pending = 0;
  return ok;
}

/* 1 if c has any active WT session (any slot), regardless of which one. */
static int wt_any_active(const srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (srvrun_wt_is_active(c, i)) return 1;
  return 0;
}

/* c is a live connection with at least one active WT session -- a broadcast
 * target. Split out of srvrun_broadcast_to_all to keep its own branch count
 * at the CCN gate (mirrors srvrun_owes_goaway's own role for
 * srvrun_goaway_all). */
static int srvrun_is_broadcast_target(const srvrun_conn* c) {
  return c->up && wt_any_active(c);
}

/* Queue data into every connection with an active WT session's own single-
 * slot DATAGRAM queue (srvrun_queue_datagram) -- mirrors srvrun_goaway_all's
 * fan-out shape, swapping the goaway-owed guard for wt_active. Each
 * connection still drains through its own srvrun_send_pending_datagram on
 * its own next step, same as any other queued datagram; this only makes
 * every eligible connection's slot hold the same payload at once. */
static void srvrun_broadcast_to_all(srvrun_state* st, wired_span data) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_is_broadcast_target(&st->conns[i]))
      srvrun_queue_datagram(&st->conns[i], data);
}

/* Multi-worker broadcast fan-out. One registry entry per srvthreads
 * worker, keyed by the registering thread's
 * own tid (wired_thread_tid) -- srvrun.c never touches srvthreads' or
 * srvinbox's internals beyond wired_srvinbox_ring itself (the include in
 * srvrun.h), keeping the dependency direction srvrun -> srvinbox only. A
 * capacity of 16 mirrors srvthreads.h's WIRED_SRVTHREADS_MAX without srvrun.c
 * including that header (it would invert the intended dependency direction:
 * srvthreads depends on srvrun, not the reverse). */
#define SRVRUN_BCAST_MAX 16

typedef struct {
  i64                  tid;       /**< registering thread's tid, 0 = free */
  int                  index;     /**< this worker's 0-based mesh index */
  int                  n_total;   /**< total worker count in the mesh */
  wired_srvinbox_ring* inbox_row; /**< row[j] = ring fed by worker j */
  wired_srvrun_env*    env; /**< this worker's own env (its connection table) */
} srvrun_bcast_entry;

static srvrun_bcast_entry g_srvrun_bcast[SRVRUN_BCAST_MAX];
static int                g_srvrun_bcast_n; /* registered entry count */

/* Registry slot index for tid, or -1 if tid is not registered. */
static int srvrun_bcast_find(i64 tid) {
  for (int i = 0; i < SRVRUN_BCAST_MAX; i++)
    if (g_srvrun_bcast[i].tid == tid) return i;
  return -1;
}

void wired_srvrun_broadcast_register(
    int                  index,
    int                  n_total,
    wired_srvinbox_ring* inbox_row,
    wired_srvrun_env*    env) {
  i64 tid = wired_thread_tid();
  int slot;
  if (srvrun_bcast_find(tid) >= 0) return; /* already registered */
  slot = srvrun_bcast_find(0);
  if (slot < 0) return; /* registry full, drop the registration */
  g_srvrun_bcast[slot] =
      (srvrun_bcast_entry){tid, index, n_total, inbox_row, env};
  g_srvrun_bcast_n++;
}

void wired_srvrun_broadcast_unregister(void) {
  int slot = srvrun_bcast_find(wired_thread_tid());
  if (slot < 0) return;
  g_srvrun_bcast[slot] = (srvrun_bcast_entry){0};
  g_srvrun_bcast_n--;
}

/* t is a mesh push target: a registered slot other than the caller's own. */
static int srvrun_bcast_mesh_target(int t, int my_slot) {
  return g_srvrun_bcast[t].tid != 0 && t != my_slot;
}

/* Push data into every OTHER registered worker t's inbox row at column
 * my_index (the caller's own mesh index) -- best-effort per target, mirroring
 * srvrun_broadcast_to_all's own best-effort per-connection queuing. The
 * caller's own connections are reached directly by srvrun_broadcast_registered
 * instead (its own env's table), not through this mesh push -- pushing into
 * its own row here too would double-deliver: once now via the direct
 * fan-out, once more next step when it drains its own inbox row. my_slot
 * lets the loop skip exactly the caller's own registry entry. */
static void srvrun_bcast_mesh_push(int my_slot, int my_index, wired_span data) {
  for (int t = 0; t < SRVRUN_BCAST_MAX; t++) {
    if (!srvrun_bcast_mesh_target(t, my_slot)) continue;
    wired_srvinbox_push(&g_srvrun_bcast[t].inbox_row[my_index], data.p, data.n);
  }
}

/* Single-process fallback path: the calling thread is not registered (no
 * srvthreads worker ever called wired_srvrun_broadcast_register), so this is
 * either wired_server_run(_opt) or the one-and-only wired_srvrun_serve_env
 * instance -- both drive the single process-wide g_srvrun_env. */
static int srvrun_broadcast_direct(wired_span data) {
  srvrun_broadcast_to_all(
      &(srvrun_state){g_srvrun_table, g_srvrun_state.conns}, data);
  return 1;
}

/* A registered srvthreads worker (any n_total, including 1): fan out to the
 * calling worker's OWN env (its own connection table) first -- the env a
 * plain g_srvrun_env-based fan-out would completely miss, since srvthreads
 * gives every worker its own mmap'd env instead of the single global one.
 * With 2+ workers also push into every OTHER registered worker's inbox row
 * so their own next step delivers it to their own sessions. */
static int srvrun_broadcast_registered(int slot, wired_span data) {
  srvrun_bcast_entry* e = &g_srvrun_bcast[slot];
  srvrun_broadcast_to_all(&(srvrun_state){e->env->table, e->env->conns}, data);
  if (e->n_total > 1) srvrun_bcast_mesh_push(slot, e->index, data);
  return 1;
}

/* data.n fits every fan-out target's payload capacity (dg_pending_buf and
 * every wired_srvinbox_ring slot share the same 1200-byte cap by
 * construction, WIRED_SRVINBOX_SLOT_MAX). */
static int srvrun_broadcast_fits(wired_span data) {
  return data.n <= sizeof g_srvrun_state.conns[0].dg_pending_buf;
}

int wired_server_broadcast_datagram(wired_span data) {
  int slot;
  if (!srvrun_broadcast_fits(data)) return 0;
  slot = srvrun_bcast_find(wired_thread_tid());
  if (slot < 0) return srvrun_broadcast_direct(data);
  return srvrun_broadcast_registered(slot, data);
}

/* Pop at most one message from row[j] and, if there was one, fan it out to
 * st's local WT connections -- the loop body of srvrun_bcast_drain_self,
 * split out so the loop itself stays at the CCN gate. */
static void srvrun_bcast_drain_one(
    srvrun_state* st, wired_srvinbox_ring* row, int j) {
  u8  buf[WIRED_SRVINBOX_SLOT_MAX];
  usz n = wired_srvinbox_pop(&row[j], buf, sizeof buf);
  if (n) srvrun_broadcast_to_all(st, wired_span_of(buf, n));
}

/* This thread's own registry slot, or -1 if there is nothing to drain: fewer
 * than 2 workers registered (single-worker/default behavior is untouched,
 * mirroring wired_server_broadcast_datagram's own <= 1 guard) or the calling
 * thread never registered at all. */
static int srvrun_bcast_drain_slot(void) {
  if (g_srvrun_bcast_n <= 1) return -1;
  return srvrun_bcast_find(wired_thread_tid());
}

/* Drain every ring in this worker's own inbox row into its local WT
 * connections -- one pop per source ring per call, matching the depth-4
 * ring's best-effort/bounded-catch-up shape (a source that published more
 * than one message since the last drain catches up over a few steps rather
 * than blocking this one). */
static void srvrun_bcast_drain_self(srvrun_state* st) {
  int slot = srvrun_bcast_drain_slot();
  if (slot < 0) return;
  for (int j = 0; j < g_srvrun_bcast[slot].n_total; j++)
    srvrun_bcast_drain_one(st, g_srvrun_bcast[slot].inbox_row, j);
}

/* The env the calling thread's loop drives: a registered srvthreads worker's
 * own env (wired_srvrun_broadcast_register), else the process-wide
 * g_srvrun_env -- the same env-selection rule wired_server_broadcast_datagram
 * applies, reused by every session-addressed send API below (their session
 * pointer can only point into the caller's own loop's connection table). */
static wired_srvrun_env* srvrun_caller_env(void) {
  int slot = srvrun_bcast_find(wired_thread_tid());
  return slot < 0 ? &g_srvrun_env : g_srvrun_bcast[slot].env;
}

/* Session slot i of c is active and IS s (pointer identity: every session
 * pointer this SDK hands to a callback points into a srvrun_conn's own
 * wt/wt1 storage, so identity is the exact reverse of srvrun_wt_slot). */
static int wt_slot_holds_session(srvrun_conn* c, int i, wired_wt_session* s) {
  return srvrun_wt_is_active(c, i) && srvrun_wt_slot(c, i) == s;
}

static int srvrun_conn_owns_session(srvrun_conn* c, wired_wt_session* s) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (wt_slot_holds_session(c, i, s)) return 1;
  return 0;
}

/* s's own slot index on c (0 or 1), or -1 if c does not own s -- the index
 * form of wt_slot_holds_session's search, needed wherever a caller must name
 * WHICH slot (wt_flow_violation[sidx], srvrun_reset_wt_streams_for_session's
 * own session_slot param) rather than just whether c owns s at all. */
static int srvrun_conn_session_slot(srvrun_conn* c, wired_wt_session* s) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    if (wt_slot_holds_session(c, i, s)) return i;
  return -1;
}

static int conn_is_session_owner(srvrun_conn* c, wired_wt_session* s) {
  return c->up && srvrun_conn_owns_session(c, s);
}

/* The connection slot in env whose active WT session storage is s, or -1
 * when no live connection owns it (a stale or foreign session pointer). */
static int srvrun_session_conn_slot(
    wired_srvrun_env* env, wired_wt_session* s) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (conn_is_session_owner(&env->conns[i], s)) return (int)i;
  return -1;
}

/* Resolve s to its owning connection in the caller's env, also handing the
 * env and slot index back for the callers that need them (the datagram ring
 * keys entries by slot index). 0 when s is owned by no live connection. */
static srvrun_conn* srvrun_session_conn_env(
    wired_wt_session* s, wired_srvrun_env** env_out, int* slot_out) {
  *env_out  = srvrun_caller_env();
  *slot_out = srvrun_session_conn_slot(*env_out, s);
  return *slot_out < 0 ? 0 : &(*env_out)->conns[*slot_out];
}

static srvrun_conn* srvrun_session_conn(wired_wt_session* s) {
  wired_srvrun_env* env;
  int               slot;
  return srvrun_session_conn_env(s, &env, &slot);
}

/* Claim the first free WT send slot on c with the given stream credit seed
 * (RFC 9000 18.2/19.10; MAX_STREAM_DATA later raises it via
 * srvrun_apply_stream_credit_update). 0 when every slot is busy. */
static srvrun_wtsend* srvrun_wtsend_claim(srvrun_conn* c, u64 credit) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (c->wtsend[i].in_use) continue;
    c->wtsend[i].in_use           = 1;
    c->wtsend[i].stream_credit    = credit;
    c->wtsend[i].fin_only_pending = 0; /* a reused slot may still carry a
                                           stale 1 from its prior stream */
    c->wtsend[i].fin_requested = 0;
    return &c->wtsend[i];
  }
  return 0;
}

/* RFC 9000 2.1: allocate the next server-initiated stream id. Called only
 * after a send slot has been claimed, so a failed open never burns an id. */
static u64 srvrun_next_uni_id(srvrun_conn* c) {
  return 7 + 4 * c->wt_uni_opened++; /* the H3 control stream took id 3 */
}

/* RFC 9000 4.6: the peer's current uni-stream grant for server-initiated
 * streams -- the highest runtime MAX_STREAMS(uni) raise, or the
 * ClientHello's initial_max_streams_uni before any raise. Counts every uni
 * stream this server opened, H3 plumbing included (wt_uni_opened's id
 * arithmetic starts past control/QPACK: those three always count). */
static u64 srvrun_peer_uni_limit(const srvrun_conn* c) {
  return c->peer_uni_stream_limit ? c->peer_uni_stream_limit
                                  : c->s.sdrv.peer_initial_max_streams_uni;
}

/* RFC 9000 19.11: fold this step's gathered MAX_STREAMS(uni) high-water
 * mark into the connection's limit -- monotone, a stale lower raise never
 * lowers it (mirrors srvrun_apply_conn_credit_update's shape). */
static void srvrun_apply_uni_limit_update(srvrun_conn* c) {
  if (!c->l.max_streams_uni_seen_flag) return;
  c->l.max_streams_uni_seen_flag = 0;
  if (c->l.max_streams_uni_seen > c->peer_uni_stream_limit)
    c->peer_uni_stream_limit = c->l.max_streams_uni_seen;
}

/* 1 iff the peer's uni-stream limit admits one more server-initiated open:
 * wt_uni_opened counts opens past the H3 control stream (id 3, the one
 * fixed plumbing stream this server opens), which consumed the first
 * grant. */
static int srvrun_uni_open_allowed(const srvrun_conn* c) {
  return quic_maxstreams_can_open(
      c->wt_uni_opened + 1, srvrun_peer_uni_limit(c));
}

static u64 srvrun_next_bidi_id(srvrun_conn* c) {
  return 1 + 4 * c->wt_bidi_opened++;
}

/* Arm w over payload on stream id: a payload that fits w's own round
 * buffer is COPIED (the caller's storage may be reused the moment this
 * returns), a larger one is held as a view under srvrun.h's keep-alive
 * contract. The pump takes it from the connection's next step/tick under
 * the shared cwnd/credit/pacing gates. */
static i64 srvrun_wtsend_arm_id(
    const srvrun_conn* c, srvrun_wtsend* w, u64 id, wired_span payload) {
  const u8* src = payload.p;
  w->view_round = payload.n > SRVRUN_WTSEND_BUF;
  if (!w->view_round) {
    bytes_memcpy(w->roundbuf, payload.p, payload.n);
    src = w->roundbuf;
  }
  w->stream_id  = id;
  w->stream_off = payload.n;
  wired_sendsess_arm(&w->sess, src, payload.n, srvrun_mps(c));
  /* roundbuf epochs are rings (see srvrun_wtsend_stage_round); a view round
   * stays linear -- its bytes live in the app's storage, not roundbuf. */
  if (!w->view_round) wired_sendq_set_ring(&w->sess.q, SRVRUN_WTSEND_BUF);
  return (i64)id;
}

static srvrun_wtsend* srvrun_wtsend_find(srvrun_conn* c, u64 stream_id);

/* 1 iff opening one more stream of the given direction AND sending
 * payload.n bytes of Stream Body on it both stay within the session's
 * own limits (wired_wt_session_stream_open_allowed/data_send_allowed,
 * session.h). Folded into one predicate so every caller's own branch count
 * stays at the CCN gate. */
static int wt_flow_allows_open(
    const wired_wt_session* s, int bidi, wired_span payload) {
  return wired_wt_session_stream_open_allowed(s, bidi) &&
         wired_wt_session_data_send_allowed(s, payload.n);
}

/* s's own slot index on c, or -1 for a not-yet-resolved connection (c == 0)
 * as well as an unowned session -- lets every wt_open_flow_ok caller pass
 * srvrun_session_conn's possibly-null result straight through without its
 * own null guard. */
static int wt_session_slot_or_absent(srvrun_conn* c, wired_wt_session* s) {
  return c ? srvrun_conn_session_slot(c, s) : -1;
}

/* draft-ietf-webtrans-http3-15 SS5.3/SS5.4/8.2 (WTH3-058/WTH3-061): 1 iff
 * sidx names a real slot (c is live and owns s) AND opening one more stream
 * of the given direction with payload.n bytes of Stream Body stays within
 * whichever peer-advertised WT_MAX_STREAMS/WT_MAX_DATA limits are currently
 * in force (wt_flow_allows_open -- a limit of 0 means "no capsule received
 * yet", which both predicates already treat as "allowed", so a session that
 * never opted into flow control is never gated here). On a limit violation,
 * c's session slot sidx is latched for closing with WT_FLOW_CONTROL_ERROR on
 * the next srvrun_on_step (wt_flow_violation's own doc) instead of opening
 * the stream. @param sidx wt_session_slot_or_absent's result */
static int wt_open_flow_ok(
    srvrun_conn*      c,
    int               sidx,
    wired_wt_session* s,
    int               bidi,
    wired_span        payload) {
  if (sidx < 0) return 0;
  if (wt_flow_allows_open(s, bidi, payload)) return 1;
  c->wt_flow_violation[sidx] = 1;
  return 0;
}

/* 1 iff c's own server-initiated uni-stream grant (peer_uni_stream_limit)
 * admits one more open; latches uni_blocked_seen on refusal so the next
 * srvrun_pump_sess pass sends a STREAMS_BLOCKED(uni) (srvrun_notify_uni_
 * blocked's own doc -- this call site has no srvrun_cfg to send through). */
static int srvrun_wt_uni_grant_ok(srvrun_conn* c) {
  if (srvrun_uni_open_allowed(c)) return 1;
  c->uni_blocked_seen = 1;
  return 0;
}

/* Shared body of the one-shot and keep-open uni opens: flow gates, slot
 * claim, id allocation. keep_open sets append_open (srvrun_wtsend's own
 * doc), the only difference between the two entry points. */
/* WT-session flow gates plus the peer's QUIC uni-stream limit (RFC 9000
 * 4.6) -- an open past the latter is refused HERE, because the peer may
 * answer it with a connection-fatal STREAM_LIMIT_ERROR or silently discard
 * the stream and everything sent on it. */
static int srvrun_wt_uni_open_ok(
    srvrun_conn* c, int sidx, wired_wt_session* s, wired_span payload) {
  if (!wt_open_flow_ok(c, sidx, s, 0, payload)) return 0;
  return srvrun_wt_uni_grant_ok(c);
}

static i64 srvrun_wt_open_uni_common(
    wired_wt_session* s, wired_span payload, int keep_open) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  if (!srvrun_wt_uni_open_ok(c, sidx, s, payload)) return -1;
  w = srvrun_wtsend_claim(c, c->s.sdrv.peer_initial_max_stream_data_uni);
  if (!w) return -1;
  w->append_open = keep_open;
  wired_wt_session_note_stream_opened(s, 0);
  wired_wt_session_note_data_sent(s, payload.n);
  return srvrun_wtsend_arm_id(c, w, srvrun_next_uni_id(c), payload);
}

i64 wired_server_wt_open_uni(wired_wt_session* s, wired_span payload) {
  return srvrun_wt_open_uni_common(s, payload, 0);
}

i64 wired_server_wt_open_uni_stream(wired_wt_session* s, wired_span payload) {
  return srvrun_wt_open_uni_common(s, payload, 1);
}

/* RFC 9000 2.1 / draft-ietf-webtrans-http3-15 4.3: pre-register id's receive
 * side as a WT bidi slot with no signal prefix (server-initiated bidi carries
 * none, unlike a client-signalled stream) and associate it with s directly --
 * this endpoint already knows which session owns id (it just opened it), so
 * there is no offer/accept race to resolve the way an incoming client-
 * signalled stream has (srvrun_offer_wt_slot's own srvrun_wt_slot_for_new_
 * stream lookup). A full wt_streams[] table silently leaves the reply
 * unreceivable, same fixed-capacity drop policy as every other WT slot table
 * here. */
static void srvrun_wt_preclaim_bidi_recv(
    srvrun_conn* c, wired_wt_session* s, u64 id) {
  int i = wired_srvloop_wt_slot_claim_local(&c->l, id);
  if (i < 0) return;
  c->l.wt_streams[i].offered = 1;
  wired_wt_session_offer_stream(s, id);
}

/* Shared body of the one-shot and keep-open bidi opens -- the bidi twin of
 * srvrun_wt_open_uni_common, plus the receive-side preclaim. */
static i64 srvrun_wt_open_bidi_common(
    wired_wt_session* s, wired_span payload, int keep_open) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  u64            id;
  if (!wt_open_flow_ok(c, sidx, s, 1, payload)) return -1;
  w = srvrun_wtsend_claim(
      c, c->s.sdrv.peer_initial_max_stream_data_bidi_remote);
  if (!w) return -1;
  w->append_open = keep_open;
  wired_wt_session_note_stream_opened(s, 1);
  wired_wt_session_note_data_sent(s, payload.n);
  id = srvrun_next_bidi_id(c);
  srvrun_wt_preclaim_bidi_recv(c, s, id);
  return srvrun_wtsend_arm_id(c, w, id, payload);
}

i64 wired_server_wt_open_bidi(wired_wt_session* s, wired_span payload) {
  return srvrun_wt_open_bidi_common(s, payload, 0);
}

i64 wired_server_wt_open_bidi_stream(wired_wt_session* s, wired_span payload) {
  return srvrun_wt_open_bidi_common(s, payload, 1);
}

/* draft-ietf-webtrans-http3-15 SS5.4/8.2 (WTH3-061): same WT_MAX_DATA gate as
 * wt_open_flow_ok, minus the stream-count half -- a reply on an already-open
 * client-initiated stream opens no new stream, so only wired_wt_session_data_
 * send_allowed applies. On a violation, c's session slot sidx is latched the
 * same way wt_open_flow_ok does. */
static int wt_reply_flow_ok(
    srvrun_conn* c, int sidx, wired_wt_session* s, usz len) {
  if (sidx < 0) return 0;
  if (wired_wt_session_data_send_allowed(s, len)) return 1;
  c->wt_flow_violation[sidx] = 1;
  return 0;
}

/* Shared body of the one-shot and keep-open replies on a client-initiated
 * bidi stream. */
static int srvrun_wt_stream_reply_common(
    wired_wt_session* s, u64 stream_id, wired_span payload, int keep_open) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  if (!wt_reply_flow_ok(c, sidx, s, payload.n)) return 0;
  /* RFC 9000 18.2: the peer's bidi_local TP governs what we may send on a
   * stream the peer itself initiated -- same seed resp[] claiming uses. */
  w = srvrun_wtsend_claim(c, c->s.sdrv.peer_initial_max_stream_data_bidi_local);
  if (!w) return 0;
  w->append_open = keep_open;
  wired_wt_session_note_data_sent(s, payload.n);
  srvrun_wtsend_arm_id(c, w, stream_id, payload);
  return 1;
}

int wired_server_wt_stream_reply(
    wired_wt_session* s, u64 stream_id, wired_span payload) {
  return srvrun_wt_stream_reply_common(s, stream_id, payload, 0);
}

int wired_server_wt_stream_reply_open(
    wired_wt_session* s, u64 stream_id, wired_span payload) {
  return srvrun_wt_stream_reply_common(s, stream_id, payload, 1);
}

/* 1 iff w names a claimed slot still open for appending. */
static int srvrun_wtsend_open_slot(const srvrun_wtsend* w) {
  return w && w->append_open;
}

/* 1 iff every byte staged in w's sendsess has been sent and ACKed -- the
 * idempotent twin of wired_sendsess_done (which consumes the session's
 * active flag), so the append path can test-and-recycle the epoch buffer
 * without stealing the reap's own done() edge. */
static int srvrun_wtsend_epoch_acked(const srvrun_wtsend* w) {
  return wired_sendq_all_sent(&w->sess.q) && w->sess.requeue_n == 0 &&
         wired_sendsess_inflight(&w->sess) == 0;
}

/* 1 iff w's stream is already closing: a bare FIN was requested or armed,
 * so no further data round may be staged behind it. */
static int srvrun_wtsend_closing(const srvrun_wtsend* w) {
  return w->fin_requested || w->fin_only_pending;
}

/* 1 while an oversized view round is still in flight -- its bytes live in
 * the APP's storage (srvrun.h's keep-alive contract), so nothing can be
 * staged behind them in roundbuf until they fully ACK. */
static int srvrun_wtsend_blocked_by_view(const srvrun_wtsend* w) {
  return w->view_round && !srvrun_wtsend_epoch_acked(w);
}

static int srvrun_wtsend_accepting(const srvrun_wtsend* w) {
  return !srvrun_wtsend_closing(w) && !srvrun_wtsend_blocked_by_view(w);
}

/* 1 iff a new round may be staged on w at all: the slot is open for
 * appending, the round is non-empty (a FIN needs a final slice to ride on
 * -- wired_sendq_next never yields an empty slice), and nothing blocks
 * acceptance (srvrun_wtsend_accepting). Room in the epoch buffer is the
 * one remaining condition, checked by srvrun_wtsend_stage_round itself. */
static int srvrun_wtsend_appendable(const srvrun_wtsend* w, usz len) {
  return srvrun_wtsend_open_slot(w) && len != 0 && srvrun_wtsend_accepting(w);
}

/* Recycle w's fully-ACKed staging: fresh arm over roundbuf at the
 * cumulative stream offset. Safe exactly because everything staged so far
 * is ACKed (srvrun_wtsend_epoch_acked) -- no logged or requeued slice
 * still resolves into the old bytes. */
static void srvrun_wtsend_epoch_reset(const srvrun_conn* c, srvrun_wtsend* w) {
  wired_sendsess_arm(&w->sess, w->roundbuf, 0, srvrun_mps(c));
  wired_sendsess_set_base_offset(&w->sess, w->stream_off);
  wired_sendq_set_ring(&w->sess.q, SRVRUN_WTSEND_BUF);
  w->view_round = 0;
}

/* Ring occupancy: bytes of roundbuf still pinned by an unsent, in-flight,
 * or requeued slice. Everything below the floor is ACKed and reusable
 * (wired_sendsess_unacked_floor's contract). */
static usz srvrun_wtsend_ring_live(const srvrun_wtsend* w) {
  return w->sess.q.len - wired_sendsess_unacked_floor(&w->sess);
}

/* Copy one round into the ring at its logical end. A SLICE never crosses
 * the wrap (sendq clamps there), but a staged round may -- split the copy. */
static void srvrun_wtsend_ring_write(srvrun_wtsend* w, wired_span payload) {
  usz at    = w->sess.q.len % SRVRUN_WTSEND_BUF;
  usz tail  = SRVRUN_WTSEND_BUF - at;
  usz first = payload.n < tail ? payload.n : tail;
  bytes_memcpy(w->roundbuf + at, payload.p, first);
  bytes_memcpy(w->roundbuf, payload.p + first, payload.n - first);
}

/* Stage one accepted round: copy payload into the ring behind the bytes
 * already staged and extend the live sendsess over it -- the round starts
 * reaching the wire on the next pump pass, WITHOUT waiting for any earlier
 * round's ACK. Space reclaims continuously as the oldest bytes ACK
 * (srvrun_wtsend_ring_live), so bounded retention means "one buffer of
 * UNACKED bytes", not "one buffer per full-epoch ACK" -- a single straggler
 * packet no longer turns a loss spike into a burst of dropped rounds. 0
 * when the round does not fit the live window (the caller decides whether
 * to drop). fin ends the app's rounds: append_open drops, so the stream's
 * true last slice carries the wire FIN (srvrun_wt_slice_fin) and the slot
 * reaps once fully ACKed. */
static int srvrun_wtsend_stage_round(
    const srvrun_conn* c, srvrun_wtsend* w, wired_span payload, int fin) {
  if (srvrun_wtsend_epoch_acked(w)) srvrun_wtsend_epoch_reset(c, w);
  if (srvrun_wtsend_ring_live(w) + payload.n > SRVRUN_WTSEND_BUF) return 0;
  srvrun_wtsend_ring_write(w, payload);
  wired_sendsess_extend(&w->sess, payload.n);
  w->stream_off += payload.n;
  w->append_open = fin == 0;
  return 1;
}

/* 1 iff the round was accepted and staged; folds the two-step check so
 * wired_server_wt_stream_send stays inside the CCN gate. */
static int srvrun_wtsend_accept_round(
    const srvrun_conn* c, srvrun_wtsend* w, wired_span payload, int fin) {
  return srvrun_wtsend_appendable(w, payload.n) &&
         srvrun_wtsend_stage_round(c, w, payload, fin);
}

/* 1 iff this rejected append was a live round refused only because the
 * pipeline is full (epoch buffer exhausted, or an oversized view round
 * still in flight) -- as opposed to a misuse rejection (unknown/closed
 * slot, empty round), so stat_wtsend_busy counts real drops only. */
static int srvrun_wtsend_busy_reject(const srvrun_wtsend* w, usz len) {
  return srvrun_wtsend_open_slot(w) && len != 0;
}

int wired_server_wt_stream_send(
    wired_wt_session* s, u64 stream_id, wired_span payload, int fin) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  if (!wt_reply_flow_ok(c, sidx, s, payload.n)) {
    c->stat_wtsend_flow++;
    return -1;
  }
  w = srvrun_wtsend_find(c, stream_id);
  if (!srvrun_wtsend_accept_round(c, w, payload, fin)) {
    c->stat_wtsend_busy += (u64)srvrun_wtsend_busy_reject(w, payload.n);
    return -1;
  }
  c->stat_wtsend_ok++;
  wired_wt_session_note_data_sent(s, payload.n);
  return 1;
}

/* Arms w's sess for a bare-FIN round: no bytes, but wired_sendsess_arm is
 * still the only place that sets sess.active -- without it,
 * wired_sendsess_done keeps reading active=0 as "not done" forever (its own
 * early return), so the slot would never reap even after the bare-FIN
 * slice is ACKed. Mirrors srvrun_wtsend_append_round's arm+set_base_offset
 * pair, just with a NULL/0 payload. */
static void srvrun_wtsend_arm_fin_only(const srvrun_conn* c, srvrun_wtsend* w) {
  wired_sendsess_arm(&w->sess, 0, 0, srvrun_mps(c));
  wired_sendsess_set_base_offset(&w->sess, w->stream_off);
}

static void srvrun_wtsend_start_fin_now(
    const srvrun_conn* c, srvrun_wtsend* w) {
  srvrun_wtsend_arm_fin_only(c, w);
  w->fin_only_pending = 1;
}

/* Arms the bare-FIN round right away if w's previous round has already
 * finished (wired_sendsess_done), else defers it: fin_requested is
 * promoted to fin_only_pending by srvrun_pump_one_wt the moment that round
 * finishes, so a FIN requested while a data round is still in flight (the
 * common case -- a WebTransport writer's close() often follows its last
 * write() before that write's round has even been ACKed) is deferred, not
 * dropped. */
static void srvrun_wtsend_request_fin(const srvrun_conn* c, srvrun_wtsend* w) {
  if (wired_sendsess_done(&w->sess))
    srvrun_wtsend_start_fin_now(c, w);
  else
    w->fin_requested = 1;
}

int wired_server_wt_stream_fin(wired_wt_session* s, u64 stream_id) {
  srvrun_conn*   c    = srvrun_session_conn(s);
  int            sidx = wt_session_slot_or_absent(c, s);
  srvrun_wtsend* w;
  if (sidx < 0) return -1;
  w = srvrun_wtsend_find(c, stream_id);
  if (!srvrun_wtsend_open_slot(w)) return -1;
  srvrun_wtsend_request_fin(c, w);
  return 1;
}

/* Free the WT send slot armed on stream_id, if any: abandoning delivery
 * (RFC 9000 19.4 RESET_STREAM) releases the app's payload view and stops
 * the pump from sending further slices. */
static void srvrun_wtsend_release(srvrun_conn* c, u64 stream_id) {
  srvrun_wtsend* w = srvrun_wtsend_find(c, stream_id);
  if (w) w->in_use = 0;
}

/* Cumulative armed bytes on stream_id's send slot, 0 when no slot holds the
 * id. RFC 9000 4.5: a RESET_STREAM's Final Size must not undercut bytes
 * already sent on the stream -- stream_off is >= the largest sent offset
 * (bytes are armed before they are sent), so it is a safe final size. */
static u64 srvrun_wtsend_final_size(srvrun_conn* c, u64 stream_id) {
  const srvrun_wtsend* w = srvrun_wtsend_find(c, stream_id);
  return w ? w->stream_off : 0;
}

int wired_server_wt_stream_reset(
    wired_wt_session* s, u64 stream_id, u32 error_code) {
  srvrun_conn* c = srvrun_session_conn(s);
  usz          i;
  if (!c) return 0;
  /* Latch full: refuse WITHOUT touching the send slot. Freeing it here
   * would abandon delivery with no wire notification ever queued -- the
   * peer would wait on the stream forever. */
  if (c->wt_stream_reset_n >= SRVRUN_WT_RESET_LATCH) return 0;
  i                              = c->wt_stream_reset_n++;
  c->wt_stream_reset_id[i]       = stream_id;
  c->wt_stream_reset_app_code[i] = error_code;
  c->wt_stream_reset_final[i]    = srvrun_wtsend_final_size(c, stream_id);
  srvrun_wtsend_release(c, stream_id);
  return 1;
}

/* RFC 9297 2 (9297-001): "HTTP Datagrams MUST only be sent with an
 * association to an HTTP request that explicitly supports them." The only
 * request type this SDK associates HTTP Datagrams with is a WebTransport
 * CONNECT (draft-ietf-webtrans-http3-15 SS4.2/SS4.3): wired_server_wt_
 * send_datagram_to's own parameter type (wired_wt_session*) already makes
 * that request-type association a compile-time constraint -- a GET/POST
 * response (srvrun_resp) has no wired_wt_session to pass, so no caller can
 * even attempt to send an HTTP Datagram for a request type that does not
 * support them. This predicate names that gate explicitly (rather than
 * leaving it implicit in the parameter type alone) and adds the one runtime
 * half the type system cannot express: the session's own state must have
 * actually reached ESTABLISHED/DRAINING (the server sent its 2xx, so the
 * association is live), not merely UNESTABLISHED/CLOSED. */
static int srvrun_wt_datagram_request_type_ok(const wired_wt_session* s) {
  return wt_session_send_side_open(s);
}

/* slot names a live connection whose own SETTINGS have been sent (RFC 9297
 * 2.1's ordering rule, same gate as srvrun_queue_datagram), AND s passes
 * the RFC 9297 2 / 9297-001 request-type gate above (which also folds in
 * 9297-007's send-side-open check, ESTABLISHED or DRAINING only). */
static int srvrun_dgring_target_ok(
    const wired_srvrun_env* env, int slot, const wired_wt_session* s) {
  return slot >= 0 && env->conns[slot].l.h3.settings_sent &&
         srvrun_wt_datagram_request_type_ok(s);
}

/* The next free ring entry (FIFO tail), or 0 when the ring is full. */
static srvrun_dgring_entry* srvrun_dgring_tail(wired_srvrun_env* env) {
  if (env->dgring_n >= SRVRUN_DGRING_CAP) return 0;
  return &env->dgring[(env->dgring_head + env->dgring_n) % SRVRUN_DGRING_CAP];
}

/* Fill e with the RFC 9297 2.1 quarter-stream-id prefix (connect_id / 4,
 * quic_wtwire_qsid_put) followed by the payload copy. 0 when the prefixed
 * payload does not fit a ring slot. */
static int srvrun_dgring_fill(
    srvrun_dgring_entry* e, int conn_slot, u64 connect_id, wired_span payload) {
  usz qn = quic_wtwire_qsid_put(e->buf, sizeof e->buf, connect_id);
  if (!qn || payload.n > sizeof e->buf - qn) return 0;
  bytes_memcpy(e->buf + qn, payload.p, payload.n);
  e->len       = qn + payload.n;
  e->conn_slot = conn_slot;
  return 1;
}

static int srvrun_dgring_push(
    wired_srvrun_env* env, int slot, u64 connect_id, wired_span payload) {
  srvrun_dgring_entry* e = srvrun_dgring_tail(env);
  if (!e) return 0;
  if (!srvrun_dgring_fill(e, slot, connect_id, payload)) return 0;
  env->dgring_n++;
  return 1;
}

int wired_server_wt_send_datagram_to(wired_wt_session* s, wired_span payload) {
  wired_srvrun_env* env;
  int               slot;
  srvrun_session_conn_env(s, &env, &slot);
  if (!srvrun_dgring_target_ok(env, slot, s)) return 0;
  return srvrun_dgring_push(env, slot, s->connect_stream_id, payload);
}

/* Connection slot cslot's session slot i is an eligible ring-broadcast
 * target: the connection is up, the slot holds a session, and it passes the
 * same RFC 9297 gates a session-addressed send applies (SETTINGS sent,
 * association established, CONNECT send side open --
 * srvrun_dgring_target_ok). */
static int srvrun_bcast_ring_target(wired_srvrun_env* env, int cslot, int i) {
  srvrun_conn* c = &env->conns[cslot];
  return c->up && srvrun_wt_is_active(c, i) &&
         srvrun_dgring_target_ok(env, cslot, srvrun_wt_slot(c, i));
}

/* Queue data for one (connection, session) pair: an ineligible pair is
 * skipped (1 -- not a failure, mirroring srvrun_broadcast_to_all's own
 * best-effort skip), an eligible one that cannot be queued (ring full, or
 * the qsid-prefixed payload exceeds a ring slot) reports 0. */
static int srvrun_bcast_ring_sess(
    wired_srvrun_env* env, int cslot, int i, wired_span data) {
  if (!srvrun_bcast_ring_target(env, cslot, i)) return 1;
  return srvrun_dgring_push(
      env, cslot, srvrun_wt_slot(&env->conns[cslot], i)->connect_stream_id,
      data);
}

/* All of one connection's session slots, ANDing per-target success -- split
 * out of wired_server_broadcast_datagram_ring so each loop stays at the CCN
 * gate. */
static int srvrun_bcast_ring_conn(
    wired_srvrun_env* env, int cslot, wired_span data) {
  int ok = 1;
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++)
    ok &= srvrun_bcast_ring_sess(env, cslot, i, data);
  return ok;
}

int wired_server_broadcast_datagram_ring(wired_span data) {
  wired_srvrun_env* env = srvrun_caller_env();
  int               ok  = 1;
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    ok &= srvrun_bcast_ring_conn(env, (int)i, data);
  return ok;
}

/* Copy message into c's own wt_close_msg[sidx] scratch, capped at
 * QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX (wired_wtcapsule_encode_close's own limit,
 * wtcapsule.h) -- a longer message is truncated rather than rejected, same
 * ponytail policy as this file's other fixed-capacity copies (e.g. wt_path).
 */
static void srvrun_wt_close_record_message(
    srvrun_conn* c, int sidx, wired_span message) {
  usz n = u64_min(message.n, QUIC_WTCAPSULE_CLOSE_MESSAGE_MAX);
  bytes_memcpy(c->wt_close_msg[sidx], message.p, n);
  c->wt_close_msg_len[sidx] = n;
}

int wired_server_wt_close_session(
    wired_wt_session* s, u32 app_error_code, wired_span message) {
  srvrun_conn* c    = srvrun_session_conn(s);
  int          sidx = wt_session_slot_or_absent(c, s);
  if (sidx < 0) return 0;
  c->wt_close_code[sidx] = app_error_code;
  srvrun_wt_close_record_message(c, sidx, message);
  c->wt_close_pending[sidx] = 1;
  return 1;
}

/* Seal and send one ring entry to its target connection; a connection gone
 * down since queue time is skipped, and a frame the peer's advertised
 * max_datagram_frame_size rejects is dropped (RFC 9221 1: DATAGRAM delivery
 * is best-effort by design, so no retry/retention). */
static void srvrun_dgring_send_one(
    const srvrun_cfg* cfg, srvrun_state* st, const srvrun_dgring_entry* e) {
  u8           out[1500];
  wired_obuf   ob = obuf_of(out, sizeof out);
  srvrun_conn* c  = &st->conns[e->conn_slot];
  if (c->up)
    srvrun_send_datagram_now(cfg, c, wired_span_of(e->buf, e->len), &ob);
}

/* Drain the whole session-addressed datagram ring, oldest first -- run once
 * per loop step (srvrun_step), so a burst queued inside one step's callbacks
 * goes out before the loop waits for input again. */
static void srvrun_dgring_drain(const srvrun_cfg* cfg, srvrun_state* st) {
  wired_srvrun_env* env = cfg->env;
  while (env->dgring_n) {
    srvrun_dgring_send_one(cfg, st, &env->dgring[env->dgring_head]);
    env->dgring_head = (env->dgring_head + 1) % SRVRUN_DGRING_CAP;
    env->dgring_n--;
  }
}

/* Send GOAWAY to every live connection that still owes one (RFC 9114 5.2), the
 * first step of graceful shutdown. Connections not yet confirmed simply have
 * no 1-RTT key to receive it and are left to time out normally. */
/* GOAWAY plus this connection's own WT_DRAIN_SESSION fan-out
 * (srvrun_send_wt_drain_all, WTH3-048) -- split out of srvrun_goaway_all so
 * its own loop stays at the CCN gate. */
static void srvrun_goaway_one(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_obuf* ob) {
  if (!srvrun_send_goaway(cfg, c, ob)) return;
  srvrun_send_wt_drain_all(cfg, c, ob);
}

static void srvrun_goaway_all(const srvrun_cfg* cfg, srvrun_state* st) {
  u8         out[256];
  wired_obuf ob = obuf_of(out, sizeof out);
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_owes_goaway(&st->conns[i]))
      srvrun_goaway_one(cfg, &st->conns[i], &ob);
}

/* 1 once every slot has drained (gone down) or never came up — the condition
 * that lets the shutdown grace period end early instead of waiting out the
 * whole budget. */
static int srvrun_all_drained(const srvrun_state* st) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (st->conns[i].up) return 0;
  return 1;
}

/* Graceful shutdown: set by srvrun_sigterm_handler (async-signal-safe: it
 * only stores to this word), read by the main loop to stop accepting new
 * connections and start winding down live ones. A process-wide word, not an
 * env member: SIGTERM is process-wide, so every srvrun loop in the process
 * shares one shutdown state, whether serving through the single g_srvrun_env
 * or a caller-supplied one via wired_srvrun_serve_env. 0->1 monotonic only
 * (never reset back to 0 outside test teardown) so a concurrent reader never
 * observes it going backward; __atomic_store_n/__atomic_load_n (same
 * idiom as xskring.c) make the cross-thread handoff well-defined without a
 * lock. */
static int g_srvrun_shutdown;

/* SIGTERM handler: the ONLY thing safe to do here is set a flag (async-signal-
 * safe rule) — no syscalls, no allocation, nothing the interrupted code might
 * itself have been mid-way through. Registration (wired_sigterm_install) uses
 * the real rt_sigaction(2) syscall and is not exercised by unit tests; the
 * behavior driven off the flag below is. */
static void srvrun_sigterm_handler(int sig) {
  (void)sig;
  __atomic_store_n(&g_srvrun_shutdown, 1, __ATOMIC_RELEASE);
}

/* 1 once a graceful shutdown has been requested (SIGTERM, or a test forcing
 * the flag directly). */
static int srvrun_shutdown_requested(void) {
  return __atomic_load_n(&g_srvrun_shutdown, __ATOMIC_RELAXED);
}

/* Test-only hook: force the shutdown flag without going through a real
 * SIGTERM delivery (rt_sigaction registration is not unit-testable — see
 * sigterm.c — so tests drive the flag directly and assert on the behavior
 * that follows: new-Initial rejection, GOAWAY fan-out, drain). Also resets
 * it, so tests do not leak shutdown state into one another.
 * ponytail: unused in the freestanding build (only tests/run.c calls this),
 * so it needs the attribute to avoid -Wunused-function under -Werror there. */
__attribute__((unused)) static void srvrun_test_set_shutdown(int v) {
  __atomic_store_n(&g_srvrun_shutdown, v, __ATOMIC_RELEASE);
}

int* wired_srvrun_shutdown_word(void) { return &g_srvrun_shutdown; }

/* Certificate hot reload: a monotonically increasing generation counter, bumped
 * by srvrun_sighup_handler (async-signal-safe: __atomic_fetch_add is a single
 * lock xadd on x86, nothing else). Process-wide like g_srvrun_shutdown above
 * (SIGHUP is process-wide too) -- each env tracks its own reload_seen_gen so
 * "was this generation already applied by THIS env" is answered per-instance
 * even though the generation itself is shared. */
static u32 g_srvrun_reload_gen;

/* SIGHUP handler: same async-signal-safety rule as srvrun_sigterm_handler —
 * bump the generation and nothing else. Registration (wired_sighup_install)
 * is not exercised by unit tests; the behavior driven off the counter below
 * is. */
static void srvrun_sighup_handler(int sig) {
  (void)sig;
  __atomic_fetch_add(&g_srvrun_reload_gen, 1, __ATOMIC_RELEASE);
}

/* 1 once a certificate reload is pending for env: its own reload_seen_gen has
 * not caught up to the current generation yet (SIGHUP, or a test forcing the
 * generation directly). */
static int srvrun_reload_requested(const wired_srvrun_env* env) {
  u32 gen = __atomic_load_n(&g_srvrun_reload_gen, __ATOMIC_ACQUIRE);
  return gen != env->reload_seen_gen;
}

/* Test-only hook: force a reload to be (or not be) pending for g_srvrun_env
 * without a real SIGHUP delivery (same rationale as srvrun_test_set_shutdown).
 * v=1 makes one generation pending; v=0 marks the current generation already
 * seen, so tests do not leak reload state into one another.
 * ponytail: unused in the freestanding build, needs the attribute to avoid
 * -Wunused-function under -Werror there. */
__attribute__((unused)) static void srvrun_test_set_reload(int v) {
  if (v) {
    __atomic_fetch_add(&g_srvrun_reload_gen, 1, __ATOMIC_RELEASE);
    return;
  }
  g_srvrun_env.reload_seen_gen =
      __atomic_load_n(&g_srvrun_reload_gen, __ATOMIC_ACQUIRE);
}

/* Re-decode cfg->cert_path/key_path into cfg->id in place (wired_certreload_
 * load overwrites only chain/chain_count/cert_seed, RFC 9114 5.2-adjacent
 * operational note: no live connection is affected, see the srvrun_cfg
 * comment above). A failed reload (bad path or malformed PEM/DER) leaves the
 * previous identity untouched — wired_certreload_load does not partially
 * mutate *id on failure. No-op when reload is disabled (cert_path unset). */
static void srvrun_reload_cert(
    const srvrun_cfg* cfg, wired_certreload_store* store) {
  if (!cfg->cert_path) return;
  if (!wired_certreload_load(cfg->cert_path, cfg->key_path, store, cfg->id))
    WIRED_LOG("cert reload failed, keeping previous identity\n");
}

/* Consume a pending reload request once: mark this generation seen first so a
 * SIGHUP arriving mid-reload is not lost (it bumps the generation again),
 * then (re)load if one was pending. */
static void srvrun_reload_if_requested(
    const srvrun_cfg* cfg, wired_srvrun_env* env) {
  if (!srvrun_reload_requested(env)) return;
  env->reload_seen_gen =
      __atomic_load_n(&g_srvrun_reload_gen, __ATOMIC_ACQUIRE);
  srvrun_reload_cert(cfg, &env->certstore);
}

/* RFC 9000 7: a long-header Initial on a slot already up only (re)cold-starts
 * it once that connection is confirmed (its DCID legitimately changes after
 * ServerHello, so gate on confirmation, not the DCID). */
static int srvrun_reinit_ok(const srvrun_conn* c) {
  if (!c->up) return 1;
  return wired_server_is_confirmed(&c->s);
}

/* Whether dg may (re)open c: a long-header Initial, not during graceful
 * shutdown (no new Initial is accepted, fresh slot or existing one alike),
 * and only on a slot eligible to (re)cold-start. */
static int srvrun_is_new(const srvrun_conn* c, wired_mspan dg) {
  if (!wired_srvboot_is_initial(dg.p, dg.n)) return 0;
  if (srvrun_shutdown_requested()) return 0;
  return srvrun_reinit_ok(c);
}

/* c is up but its handshake is not confirmed yet -- still within the window
 * where an Initial retransmit means "resend the same flight", not "start a
 * fresh connection" (RFC 9000 13.3). */
static int srvrun_awaiting_confirm(const srvrun_conn* c) {
  return c->up && !wired_server_is_confirmed(&c->s);
}

/* 1 if the packet at dg.p[off] wears a long header of the Initial type
 * (RFC 9000 17.2.2 for v1, RFC 9369 3.2 for v2 -- the type-bit layout is
 * version-dependent, so this reads the packet's own Version field rather
 * than assuming v1's). */
static int srvrun_pkt_is_initial(wired_mspan dg, usz off) {
  if (off + 5 > dg.n) return 0;
  return quic_packet_long_type(dg.p[off], be_get_be32(dg.p + off + 1)) ==
         QUIC_PT_INITIAL;
}

/* 1 if every packet at offs[0..n) within dg is an Initial. */
static int srvrun_pkts_all_initial(wired_mspan dg, const usz* offs, usz n) {
  for (usz i = 0; i < n; i++)
    if (!srvrun_pkt_is_initial(dg, offs[i])) return 0;
  return 1;
}

/* RFC 9000 12.2: 1 if dg parses as coalesced packets that are ALL Initials.
 * A client's second flight coalesces an Initial (ACK) with a Handshake
 * packet carrying its Finished -- such a datagram is handshake progress, not
 * a bare first-flight retransmit, and must never be swallowed by the cached
 * boot-flight resend (that discards the Finished and wedges the handshake
 * unconfirmed; curl connects and then stalls on its request). */
static int srvrun_dgram_all_initial(wired_mspan dg) {
  const u8*    pkts[4];
  usz          offs[4], lens[4], n;
  quic_pktlist pl = {pkts, offs, lens, 4};
  n               = quic_udploop_split(wired_span_of(dg.p, dg.n), &pl);
  return n != 0 && srvrun_pkts_all_initial(dg, offs, n);
}

/* RFC 9000 13.3: an all-Initial datagram on a slot already up, not yet
 * confirmed, and not eligible to (re)cold-start (srvrun_is_new said no) is
 * the client retransmitting its first flight because the server's reply
 * hasn't reached it yet -- not a new connection attempt. A datagram that
 * coalesces anything beyond Initials (srvrun_dgram_all_initial says no)
 * carries handshake progress and takes the step path instead. */
static int srvrun_is_boot_retransmit(const srvrun_conn* c, wired_mspan dg) {
  if (!srvrun_awaiting_confirm(c)) return 0;
  if (c->boot_ini_len == 0) return 0;
  return srvrun_dgram_all_initial(dg);
}

static void srvrun_resp_release_bigbuf(wired_srvrun_env* env, srvrun_resp* r);

/* Free slot i: drop its table entry and clear its connection's up flag (the
 * shutdown drain accounting then counts it as drained).
 *
 * ponytail: connection teardown (peer CONNECTION_CLOSE, boot failure, or
 * idle sweep -- the 3 call sites below) is treated as WebTransport session
 * termination. This is a deliberate approximation, not the spec-accurate
 * trigger: the real rule cares about the CONNECT stream's own FIN/RESET
 * independent of whether the rest of the connection stays alive, and there
 * is no mechanism yet to detect a per-stream RESET_STREAM on just that
 * stream. Revisit once stream-level RESET_STREAM dispatch reaches
 * srvrun/srvloop. */
/* Release every resp[] slot's bigbuf pool row: a streaming response
 * mid-flight when its connection tears down (idle timeout, boot failure,
 * CONNECTION_CLOSE) would otherwise leave its claimed row permanently
 * marked in_use -- srvrun_open_slot only zeroes the conn struct on reuse, it
 * never touches wired_srvbigbuf's own in_use[] bookkeeping. */
static void srvrun_free_bigbuf_rows(wired_srvrun_env* env, srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    srvrun_resp_release_bigbuf(env, &c->resp[i]);
}

/* Close every open WT session slot on c, not just one -- whole-connection
 * teardown must never leave a session behind. */
static void srvrun_close_all_wt(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (int i = 0; i < SRVRUN_MAX_WT_SESSIONS; i++) {
    if (!(*srvrun_wt_active_slot(c, i))) continue;
    srvrun_notify_wt_close(cfg, srvrun_wt_slot(c, i));
    wired_wt_session_close(srvrun_wt_slot(c, i));
    (*srvrun_wt_active_slot(c, i)) = 0;
  }
}

static void srvrun_free_slot(const srvrun_cfg* cfg, srvrun_state* st, int i) {
  srvrun_conn* c = &st->conns[i];
  srvrun_close_all_wt(cfg, c);
  srvrun_free_bigbuf_rows(cfg->env, c);
  quic_conntable_remove(st->table, QUIC_CONNTABLE_CAP, i);
  c->up = 0;
  wired_srvboot_acc_reset(&c->boot);
  /* RFC 9000 8.1 antiamp state is per-attempt -- a slot reused for a fresh
   * boot must not inherit a stale budget from the connection it replaces.
   * srvrun_boot_finish re-seeds boot_dgram_count/sent on the next
   * accept; this covers the window before that. */
  c->boot_rx_bytes   = 0;
  c->boot_tx_bytes   = 0;
  c->boot_dgram_sent = 0;
}

/* Advertised max_idle_timeout in ms — keep in sync with the value
 * QUIC_TP_MAX_IDLE_TIMEOUT carries in tls/ext/stp/server_tp.c. Evicting at
 * (or after) the advertised value is always legitimate: the effective idle
 * timeout is the min of both endpoints' advertisements (RFC 9000 10.1). */
#define WIRED_SRVRUN_IDLE_MS 30000

/* 1 if the slot holds anything reclaimable: a live connection, or a boot
 * still reassembling its ClientHello (a stalled one would otherwise pin its
 * table entry forever). */
static int srvrun_slot_busy(const srvrun_conn* c) {
  return c->up || c->boot.any;
}

/* 1 if c has been silent at least the advertised idle timeout. */
static int srvrun_idle_due(const srvrun_conn* c, u64 now_ms) {
  return srvrun_slot_busy(c) && now_ms - c->last_ms >= WIRED_SRVRUN_IDLE_MS;
}

/* RFC 9000 10.1: silently discard every connection idle past the advertised
 * max_idle_timeout, freeing its slot for a new client. */
static void srvrun_sweep_idle(
    const srvrun_cfg* cfg, srvrun_state* st, u64 now_ms) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_idle_due(&st->conns[i], now_ms))
      srvrun_free_slot(cfg, st, (int)i);
}

/* Cold-start outcome for a slot: on success, rekey its table entry to the
 * slot's own SCID — the DCID the client addresses from its second flight on
 * (RFC 9000 7.2) — on failure, roll the whole claim back so the slot is not
 * leaked. */
static void srvrun_open_done(const srvrun_step_ctx* ctx, int slot, int ok) {
  srvrun_conn* c = &ctx->st->conns[slot];
  c->up          = ok;
  if (!ok) {
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  quic_conntable_rekey(
      ctx->st->table, QUIC_CONNTABLE_CAP, slot, c->scid,
      ctx->cfg->id->scid_len);
}

/* Fill one round of the response body from the app handler (empty without
 * one, or when it declines), starting at offset (0 on a response's first
 * round). more and total_size are the handler's streaming out-params (see
 * wired_srvloop_handler): left at their caller-zeroed defaults by every
 * ordinary (single-round) handler. */
static void srvrun_call_handler(
    const srvrun_step_ctx*      ctx,
    const wired_h3reqdrive_req* req,
    u64                         offset,
    wired_obuf*                 body,
    const char**                ct,
    int*                        more,
    u64*                        total_size) {
  if (!ctx->cfg->handler) return;
  if (!ctx->cfg->handler(
          ctx->cfg->ctx, req, offset, body, ct, more, total_size))
    body->len = 0;
}

/* All len octets of m equal want (draft-ietf-webtrans-http3-15 SS3: the
 * :protocol value is matched byte for byte, same idiom as connect.c's own
 * method_is_connect). */
static int wt_bytes_eq(const u8* m, const u8* want, usz len) {
  for (usz i = 0; i < len; i++)
    if (m[i] != want[i]) return 0;
  return 1;
}

/* r's :protocol equals the n-octet token want. */
static int wt_protocol_token_eq(
    const wired_h3reqdrive_req* r, const u8* want, usz n) {
  if (!r->protocol || r->protocol_len != n) return 0;
  return wt_bytes_eq(r->protocol, want, n);
}

/* r's :protocol is a WebTransport token: "webtransport" (what every deployed
 * browser generation -- Chrome 149 included, a draft-07 implementation --
 * actually sends) or "webtransport-h3" (draft-ietf-webtrans-http3-15 SS3's
 * renamed token). Accepting only the draft-15 spelling turned away every
 * real browser. */
static int wt_protocol_is_webtransport(const wired_h3reqdrive_req* r) {
  static const u8 d7[]  = {'w', 'e', 'b', 't', 'r', 'a',
                           'n', 's', 'p', 'o', 'r', 't'};
  static const u8 d15[] = {'w', 'e', 'b', 't', 'r', 'a', 'n', 's',
                           'p', 'o', 'r', 't', '-', 'h', '3'};
  if (wt_protocol_token_eq(r, d7, sizeof d7)) return 1;
  return wt_protocol_token_eq(r, d15, sizeof d15);
}

/* :method value equals the 7 octets "CONNECT" (same idiom as connect.c's own
 * method_is_connect, duplicated here because that one is private to
 * connect.c and connect_forbidden's shape does not fit Extended CONNECT
 * below). */
static int wt_method_is_connect(const wired_h3reqdrive_req* r) {
  static const u8 want[] = {'C', 'O', 'N', 'N', 'E', 'C', 'T'};
  if (!r->method || r->method_len != sizeof want) return 0;
  return wt_bytes_eq(r->method, want, sizeof want);
}

/* r carries :scheme, :authority and :path, all required (non-forbidden) for
 * Extended CONNECT unlike plain CONNECT (RFC 9220 3 / RFC 9114 4.4 contrast:
 * quic_h3_connect_req_ok enforces the opposite, plain-CONNECT shape, so it
 * cannot be reused here). */
static int wt_ext_fields_present(const wired_h3reqdrive_req* r) {
  return r->scheme != 0 && r->authority != 0 && r->path != 0;
}

/* r's request line is CONNECT with :scheme/:authority/:path all present:
 * the Extended CONNECT shape, checked before :protocol. */
static int wt_ext_connect_shape_ok(const wired_h3reqdrive_req* r) {
  if (!wt_method_is_connect(r)) return 0;
  return wt_ext_fields_present(r);
}

/* r is a well-formed Extended CONNECT (RFC 9220 3) for WebTransport:
 * :method=CONNECT, :scheme/:authority/:path all present, :protocol
 * negotiated (settings always advertised, Step 1 above) and a WebTransport
 * token (see wt_protocol_is_webtransport). */
static int srvrun_is_wt_connect(const wired_h3reqdrive_req* r) {
  if (!wt_ext_connect_shape_ok(r)) return 0;
  if (!wt_protocol_is_webtransport(r)) return 0;
  return quic_h3_connect_protocol_ok(r, 1);
}

/* RFC 9220 3: "If a server advertises support for Extended CONNECT but
 * receives an Extended CONNECT request with a :protocol value that is
 * unknown or is not supported, the server SHOULD respond ... with a 501
 * (Not Implemented) status code." r is exactly that case: the Extended
 * CONNECT shape (:method=CONNECT, :scheme/:authority/:path all present) with
 * a :protocol field present that names something other than a recognized
 * WebTransport token. srvrun_is_wt_connect already rejects this same r (its
 * wt_protocol_is_webtransport check fails), so without this check r would
 * fall through to srvrun_method_status/srvrun_start_app_resp and be treated
 * as an ordinary CONNECT request -- wrong, since RFC 9220's 501 applies the
 * moment :protocol names something this server does not support, before any
 * plain-CONNECT handling. A CONNECT with no :protocol at all (plain CONNECT,
 * RFC 9114 4.4) is unaffected: r->protocol is 0 there, so this returns 0 and
 * the normal method-status/app-handler path still runs. */
static int srvrun_is_wt_connect_unsupported_protocol(
    const wired_h3reqdrive_req* r) {
  if (!wt_ext_connect_shape_ok(r)) return 0;
  if (!r->protocol) return 0;
  return !wt_protocol_is_webtransport(r);
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.6: when Origin is present it
 * must be a non-empty value for the server to validate; this SDK has no
 * origin-allowlist configuration surface yet (YAGNI -- no in-tree consumer
 * needs one), so "well-formed and non-empty" is the whole check today.
 * Absent Origin is not itself a rejection reason: it only applies to
 * browser clients, which this SDK cannot detect server-side. */
static int wt_origin_ok(const wired_h3reqdrive_req* r) {
  if (!r->origin) return 1; /* absent: not a browser client, or none sent */
  return r->origin_len != 0;
}

/* 1 if r is claimed and answering stream_id. */
static int srvrun_resp_matches(const srvrun_resp* r, u64 stream_id) {
  return r->in_use && r->stream_id == stream_id;
}

/* The in-use resp[] slot answering stream_id, or 0 if none (RFC 9000 2.2:
 * at most one response per request stream at a time). */
static srvrun_resp* srvrun_resp_find(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (srvrun_resp_matches(&c->resp[i], stream_id)) return &c->resp[i];
  return 0;
}

/* Claim and reset a free resp[] slot for stream_id (caller has already
 * confirmed via srvrun_resp_find that stream_id has none). 0 if every slot
 * is busy -- the request is dropped, same bound as the old single-response-
 * per-connection behavior but per stream instead of per connection. */
static srvrun_resp* srvrun_resp_claim(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (c->resp[i].in_use) continue;
    c->resp[i].in_use     = 1;
    c->resp[i].stream_id  = stream_id;
    c->resp[i].bigbuf_row = -1;
    c->resp[i].streaming  = 0;
    c->resp[i].ring_cap   = 0;
    /* RFC 9000 18.2/19.10: seed this stream's send credit from the peer's
     * ClientHello TP (initial_max_stream_data_bidi_local, RFC 9000 18.2:
     * the TP sender's own locally-initiated streams' credit -- this
     * client-initiated request stream). MAX_STREAM_DATA naming stream_id
     * only ever raises it (srvrun_sess_on_step applies those each step). */
    c->resp[i].stream_credit =
        c->s.sdrv.peer_initial_max_stream_data_bidi_local;
    return &c->resp[i];
  }
  return 0;
}

/* r's index within c->resp[], for locating its respstore row
 * (env->respstore[slot][index]). */
static usz srvrun_resp_index(const srvrun_conn* c, const srvrun_resp* r) {
  return (usz)(r - c->resp);
}

/* Seal a bare status-only response (no body, no content-type, plus one
 * optional extra field line) into r's own storage row and arm r's session
 * over it — the same low-level prefix+arm mechanism srvrun_start_app_resp
 * uses for a normal 200, minus the app handler: this is protocol-level
 * WebTransport response building (draft-ietf-webtrans-http3-15 SS3.2), not
 * an application response. Used for both the 2xx that establishes a session
 * (extra = the wt-protocol header when a subprotocol was negotiated, SS3.4)
 * and the 403 that rejects one (extra = 0). The
 * response is bodyless, so it is written at the row's start rather than
 * right-aligned into the body path's SRVRUN_RESP_HDR_ROOM prefix area. */
static void srvrun_start_wt_status(
    wired_srvrun_env*       env,
    int                     slot,
    srvrun_conn*            c,
    srvrun_resp*            r,
    u16                     status,
    const quic_qpack_field* extra) {
  u8*        st  = env->respstore[slot][srvrun_resp_index(c, r)];
  wired_obuf pob = obuf_of(st, WIRED_SRVRUN_RESP_MAX);
  if (!quic_h3resp_prefix_field(status, 0, 0, extra, &pob)) return;
  wired_sendsess_arm(&r->sess, st, pob.len, srvrun_mps(c));
}

/* draft-ietf-webtrans-http3-15 SS3.2 (WTH3-018): "The server may reply with
 * a 3xx response, indicating a redirection (Section 15.4 of [HTTP])." RFC
 * 9110 15.4 ties every 3xx redirect status to a Location response header
 * field naming the target; encoded here as one Literal Field Line With
 * Literal Name (RFC 9204 4.5.6), the same mechanism srvrun_start_wt's own
 * wt-protocol header already uses via srvrun_start_wt_status's extra param. */
static void srvrun_reject_wt_redirect(
    wired_srvrun_env* env,
    int               slot,
    srvrun_conn*      c,
    srvrun_resp*      r,
    u16               status,
    wired_span        location) {
  static const u8  name[] = {'l', 'o', 'c', 'a', 't', 'i', 'o', 'n'};
  quic_qpack_field f      = {wired_span_of(name, sizeof name), location};
  srvrun_start_wt_status(env, slot, c, r, status, &f);
}

/* draft-ietf-webtrans-http3-15 SS3.2: run the app's registered resource
 * check (if any) for this Extended CONNECT's :authority/:path, filling
 * *out. A callback that leaves *out's status at 0 (its caller-zeroed
 * default) accepts the resource -- same as no callback registered at all
 * (cfg->wt_resource_check == 0), which never runs the callback and leaves
 * *out zeroed by this function's own memset-equivalent init. */
static void srvrun_wt_resource_decide(
    const srvrun_cfg*           cfg,
    const srvrun_conn*          c,
    wired_wt_resource_decision* out) {
  *out = (wired_wt_resource_decision){0, 0, 0};
  if (!cfg->wt_resource_check) return;
  cfg->wt_resource_check(
      cfg->wt_resource_ctx,
      wired_span_of(c->l.req.authority, c->l.req.authority_len),
      wired_span_of(c->l.req.path, c->l.req.path_len), out);
}

/* 1 if status is in the 3xx range (RFC 9110 15.4), the only range
 * wired_wt_resource_decision.location applies to. */
static int wt_status_is_3xx(u16 status) {
  return status >= 300 && status < 400;
}

/* Seal the app's non-zero resource-check verdict: a 3xx carries the
 * decision's Location value, anything else (404, or an app-chosen status
 * such as 403) is sent bare -- split out of srvrun_dispatch_wt_resource so
 * its own branch count stays at the CCN gate. */
static void srvrun_start_wt_resource_status(
    wired_srvrun_env*                 env,
    int                               slot,
    srvrun_conn*                      c,
    srvrun_resp*                      r,
    const wired_wt_resource_decision* d) {
  if (wt_status_is_3xx(d->status)) {
    srvrun_reject_wt_redirect(
        env, slot, c, r, d->status,
        wired_span_of(d->location, d->location_len));
    return;
  }
  srvrun_start_wt_status(env, slot, c, r, d->status, 0);
}

/* Record this Extended CONNECT's own :path value into session slot sidx:
 * copied, not viewed, since c->l.req's storage does not outlive this step.
 * Overflow past SRVRUN_WT_PATH_CAP is truncated (see its own doc). */
static void srvrun_wt_record_path(srvrun_conn* c, int sidx) {
  usz n = u64_min(c->l.req.path_len, SRVRUN_WT_PATH_CAP);
  bytes_memcpy(c->wt_path[sidx], c->l.req.path, n);
  c->wt_path_len[sidx] = n;
}

/* The n octets at s (up to the next ' ' or NUL) equal item byte for byte. */
static int srvrun_tok_eq(const char* s, usz n, wired_span item) {
  return n == item.n && wt_bytes_eq((const u8*)s, item.p, n);
}

/* Octets at s before the next ' ' or NUL: one entry of the space-separated
 * server subprotocol list (wired_srvrun_opt.wt_protocols). */
static usz srvrun_tok_len(const char* s) {
  usz n = 0;
  while (s[n] && s[n] != ' ') n++;
  return n;
}

static const char* srvrun_skip_spaces(const char* s) {
  while (*s == ' ') s++;
  return s;
}

/* item is one of the entries of the space-separated server subprotocol
 * list. */
static int srvrun_wt_server_has(const char* list, wired_span item) {
  const char* s = list;
  while (*s) {
    usz n = srvrun_tok_len(s);
    if (srvrun_tok_eq(s, n, item)) return 1;
    s = srvrun_skip_spaces(s + n);
  }
  return 0;
}

/* Decode the offer's next member into out and test server membership.
 * Returns -1 on end-of-list or a syntax error (stop, nothing selected), 0 on
 * a member the server does not support (continue), or the member's decoded
 * length (selected). */
static int srvrun_wt_try_next(
    const char* list, quic_sfield_iter* it, u8* out, usz cap) {
  wired_obuf ob = obuf_of(out, cap);
  int        rc = quic_sfield_next_string(it, &ob);
  if (rc <= 0) return -1;
  return srvrun_wt_server_has(list, wired_span_of(out, ob.len)) ? (int)ob.len
                                                                : 0;
}

/* draft-ietf-webtrans-http3-15 SS3.4: pick the first member of the client's
 * wt-available-protocols offer (an RFC 8941 sf-list of sf-strings, client
 * preference order) that the server's own space-separated list contains.
 * Returns the selected token's length in out, or 0 when there is no common
 * subprotocol or the offer is not a valid sf-list (RFC 8941 4.2: a list that
 * fails to parse is discarded entirely). */
static usz srvrun_wt_select(
    const char* list, wired_span avail, u8* out, usz cap) {
  quic_sfield_iter it;
  int              r = 0;
  quic_sfield_iter_init(&it, avail);
  while (r == 0) r = srvrun_wt_try_next(list, &it, out, cap);
  return r < 0 ? 0 : (usz)r;
}

/* The negotiated subprotocol for one Extended CONNECT: the raw token and its
 * sf-string encoding (the wt-protocol header's value, DQUOTE-wrapped per RFC
 * 8941 4.1.6 -- the reference peer rejects an unquoted value). Both lengths
 * are 0 when negotiation is disabled, no offer was sent, or nothing
 * matched. */
typedef struct {
  u8  tok[64];
  usz tok_len;
  u8  sfv[66];
  usz sfv_len;
} srvrun_wt_proto;

/* The raw selected token for this Extended CONNECT, or 0 octets when
 * negotiation is disabled (cfg->wt_protocols == 0) or no offer was sent. */
static usz srvrun_wt_negotiate(
    const srvrun_cfg* cfg, const srvrun_conn* c, u8* out, usz cap) {
  const wired_h3reqdrive_req* req = &c->l.req;
  if (!cfg->wt_protocols || !req->wt_avail_len) return 0;
  return srvrun_wt_select(
      cfg->wt_protocols, wired_span_of(req->wt_avail, req->wt_avail_len), out,
      cap);
}

/* Fill p for this Extended CONNECT: select the token, then sf-string-encode
 * it for the wt-protocol header; an encoding failure drops the selection
 * entirely (no header, empty notification). */
static void srvrun_wt_proto_pick(
    const srvrun_cfg* cfg, const srvrun_conn* c, srvrun_wt_proto* p) {
  p->tok_len = srvrun_wt_negotiate(cfg, c, p->tok, sizeof p->tok);
  p->sfv_len = 0;
  if (p->tok_len)
    p->sfv_len = quic_sfield_string_encode(
        p->sfv, sizeof p->sfv, wired_span_of(p->tok, p->tok_len));
  if (!p->sfv_len) p->tok_len = 0;
}

/* Notify the app that session slot sidx was established (its 2xx has been
 * built), with the recorded :path and the negotiated subprotocol (empty when
 * none). No-op without a registered callback. */
static void srvrun_wt_notify(
    const srvrun_cfg* cfg, srvrun_conn* c, int sidx, wired_span protocol) {
  if (!cfg->wt_on_session) return;
  cfg->wt_on_session(
      cfg->wt_session_ctx, srvrun_wt_slot(c, sidx),
      wired_span_of(c->wt_path[sidx], c->wt_path_len[sidx]), protocol);
}

/* Establish a WebTransport session for this Extended CONNECT (draft-ietf-
 * webtrans-http3-15 SS3.2/SS4) in the first free session slot: the session id
 * is the CONNECT stream's own id. The 200 carries a wt-protocol header when
 * a subprotocol was negotiated (SS3.4), and the app's wt_on_session callback
 * (if any) fires once after it is built. Skips the normal app-handler
 * response path entirely. Caller (srvrun_dispatch_wt_free_slot) already
 * confirmed a free slot exists. */
static void srvrun_start_wt(
    const srvrun_cfg* cfg, int slot, srvrun_conn* c, srvrun_resp* r) {
  static const u8  name[] = {'w', 't', '-', 'p', 'r', 'o',
                             't', 'o', 'c', 'o', 'l'};
  srvrun_wt_proto  p;
  quic_qpack_field f;
  int              sidx = srvrun_wt_free_slot(c);
  /* Caller (srvrun_dispatch_wt) already confirmed a free slot exists right
   * before reaching here with nothing in between that could claim one, so
   * this never actually fires -- guarding it anyway keeps wt_path/wt_path_len
   * (SRVRUN_MAX_WT_SESSIONS-sized) indexed only by a value in range. */
  if (sidx < 0) return;
  srvrun_wt_proto_pick(cfg, c, &p);
  f = (quic_qpack_field){
      wired_span_of(name, sizeof name), wired_span_of(p.sfv, p.sfv_len)};
  wired_wt_session_init(srvrun_wt_slot(c, sidx), c->l.req_stream_id);
  wired_wt_session_establish(srvrun_wt_slot(c, sidx));
  (*srvrun_wt_active_slot(c, sidx)) = 1;
  srvrun_wt_record_path(c, sidx);
  srvrun_start_wt_status(cfg->env, slot, c, r, 200, p.sfv_len ? &f : 0);
  /* wt_connect_sent_len's own doc: the 2xx HEADERS frame's byte length is
   * where a later capsule append (srvrun_send_wt_capsule) must continue. */
  c->wt_connect_sent_len[sidx] = r->sess.q.len;
  srvrun_wt_notify(cfg, c, sidx, wired_span_of(p.tok, p.tok_len));
}

/* Reject this Extended CONNECT with 403 (a present but malformed Origin)
 * without establishing a session. */
static void srvrun_reject_wt(
    wired_srvrun_env* env, int slot, srvrun_conn* c, srvrun_resp* r) {
  srvrun_start_wt_status(env, slot, c, r, 403, 0);
}

/* r's storage row for this response: the fixed per-(conn,stream) respstore
 * row (WIRED_SRVRUN_RESP_MAX = 16KB, SRVRUN_RESP_HDR_ROOM reserved at the
 * front for the framed HEADERS prefix), or -- when the app handler needs
 * more room than that -- a claimed wired_srvbigbuf row (srvbigbuf.h),
 * reserving the same HDR_ROOM prefix at its own front. Pool exhaustion
 * falls back to the fixed row (its cap simply bounds the handler's write,
 * same as before this pool existed): a body that then overflows the fixed
 * row is truncated by the handler's own wired_obuf cap, not a new failure
 * mode. r->bigbuf_row records which storage was used, -1 for the fixed row,
 * so srvrun_resp_reap knows whether to release a pool row later. A
 * streaming response's later rounds (r->bigbuf_row already >= 0) reuse that
 * SAME row instead of re-claiming -- a second claim here would either grab
 * a different pool row (silently orphaning round 0's, since only one index
 * is tracked) or, if the pool is momentarily full, hand back 0 and corrupt
 * an otherwise-fine ongoing stream. */
static u8* srvrun_resp_storage(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, srvrun_resp* r) {
  u8* fixed = ctx->cfg->env->respstore[slot][srvrun_resp_index(c, r)];
  u8* big;
  if (r->bigbuf_row >= 0)
    return wired_srvbigbuf_row(&ctx->cfg->env->bigbuf, r->bigbuf_row);
  big = wired_srvbigbuf_claim(&ctx->cfg->env->bigbuf, &r->bigbuf_row);
  return big ? big : fixed;
}

/* Bytes available in st for body_out (past the HDR_ROOM prefix), matching
 * whichever storage srvrun_resp_storage chose. */
static usz srvrun_resp_storage_cap(const srvrun_resp* r) {
  return (r->bigbuf_row >= 0 ? WIRED_SRVBIGBUF_ROW_CAP
                             : WIRED_SRVRUN_RESP_MAX) -
         SRVRUN_RESP_HDR_ROOM;
}

/* The storage row r is armed over, WITHOUT the claim side effect
 * (srvrun_resp_storage claims a pool row for bigbuf_row < 0) -- the
 * read-only companion for callers that only need the existing base. */
static u8* srvrun_resp_storage_ro(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, srvrun_resp* r) {
  if (r->bigbuf_row >= 0)
    return wired_srvbigbuf_row(&ctx->cfg->env->bigbuf, r->bigbuf_row);
  return ctx->cfg->env->respstore[slot][srvrun_resp_index(c, r)];
}

/* Full byte size of the row srvrun_resp_storage chose. */
static usz srvrun_resp_row_size(const srvrun_resp* r) {
  return r->bigbuf_row >= 0 ? WIRED_SRVBIGBUF_ROW_CAP : WIRED_SRVRUN_RESP_MAX;
}

/* If r's body ended up small enough for the fixed respstore row after all
 * (the common case: most responses are far under 16KB), copy it there and
 * release the pool row immediately -- pool rows are scarce (2 total) and a
 * response that never needed one should not hold one for its whole
 * lifetime. body/pre are already-framed bytes at st (HDR_ROOM prefix +
 * body); total is their combined length. */
static u8* srvrun_resp_shrink_to_fixed(
    const srvrun_step_ctx* ctx,
    int                    slot,
    srvrun_conn*           c,
    srvrun_resp*           r,
    u8*                    st,
    usz                    total) {
  u8* fixed;
  if (r->bigbuf_row < 0 || total > WIRED_SRVRUN_RESP_MAX) return st;
  fixed = ctx->cfg->env->respstore[slot][srvrun_resp_index(c, r)];
  bytes_memcpy(fixed, st, total);
  wired_srvbigbuf_release(&ctx->cfg->env->bigbuf, r->bigbuf_row);
  r->bigbuf_row = -1;
  return fixed;
}

/* quic-interop-runner's hq-interop (HTTP/0.9 over QUIC, see hq09.h): the
 * response is the handler's body bytes verbatim, no HEADERS/DATA framing
 * (RFC 9114 4.1 doesn't apply -- there is no HTTP/3 on this connection).
 * Arms directly over the body already written at st + HDR_ROOM, skipping
 * the H3 prefix build/shrink-to-fixed dance that assumes a framed
 * response. Every round (streaming or not) takes this same path: hq-interop
 * never frames, so there is no first-round-only prefix to skip on later
 * rounds. */
static void srvrun_arm_hq09_resp(
    const srvrun_conn* c, srvrun_resp* r, u8* st, const wired_obuf* body) {
  wired_sendsess_arm(
      &r->sess, st + SRVRUN_RESP_HDR_ROOM, body->len, srvrun_mps(c));
}

/* RFC 9114 4.1: frame the handler's body as HEADERS+DATA (quic_h3resp_prefix)
 * ahead of it, then arm over prefix+body. total_len is the DATA frame's
 * declared length (the full streaming response's total size,
 * not just this round's body -- HTTP/3 commits to one length upfront and
 * every later round's bytes are additional payload of that same frame, so
 * only round 0 ever calls this). Split out of srvrun_start_app_resp so
 * hq-interop's un-framed sibling can skip this whole shape (CCN). */
static void srvrun_arm_h3_resp_framed(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    int                    slot,
    srvrun_resp*           r,
    u8*                    st,
    const wired_obuf*      body,
    const char*            ct,
    u64                    total_len) {
  u8         pre[SRVRUN_RESP_HDR_ROOM];
  wired_obuf pob = obuf_of(pre, sizeof pre);
  usz        off;
  if (!quic_h3resp_prefix(200, ct, total_len, &pob)) return;
  off = SRVRUN_RESP_HDR_ROOM - pob.len;
  bytes_put(
      wired_mspan_of(st, SRVRUN_RESP_HDR_ROOM), &off,
      wired_span_of(pre, pob.len));
  st = srvrun_resp_shrink_to_fixed(
      ctx, slot, c, r, st + SRVRUN_RESP_HDR_ROOM - pob.len,
      pob.len + body->len);
  wired_sendsess_arm(&r->sess, st, pob.len + body->len, srvrun_mps(c));
}

/* RFC 9114 4.1: frame+arm round 0 (the only arm a response ever gets now
 * -- a streaming response's later bytes continue the same DATA frame via
 * the ring refill's extend, srvrun_resp_refill, never a re-arm). */
static void srvrun_arm_h3_resp(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    int                    slot,
    srvrun_resp*           r,
    u8*                    st,
    const wired_obuf*      body,
    const char*            ct,
    u64                    total_len) {
  r->stream_h3_framed = 1;
  srvrun_arm_h3_resp_framed(ctx, c, slot, r, st, body, ct, total_len);
}

/* Copy up to n bytes of src into dst, capped at n -- the shared byte-copy
 * loop for both fields srvrun_copy_stream_req scratches out. */
static void srvrun_scratch_copy(u8* dst, const u8* src, usz n) {
  for (usz i = 0; i < n; i++) dst[i] = src[i];
}

/* Copy req's method/path into r's own scratch (see stream_req's doc): later
 * rounds must call the handler with THIS copy, never c->l.req directly,
 * since c->l.req is a per-connection mirror any sibling stream's completion
 * overwrites between rounds. method+path share one scratch buffer, method
 * first (it is always short: "GET"/"POST"/...). */
static void srvrun_copy_stream_req(
    srvrun_resp* r, const wired_h3reqdrive_req* req) {
  usz cap  = sizeof r->stream_req_scratch;
  usz mlen = req->method_len < 8 ? req->method_len : 8;
  usz plen = req->path_len < cap - mlen ? req->path_len : cap - mlen;
  srvrun_scratch_copy(r->stream_req_scratch, req->method, mlen);
  srvrun_scratch_copy(r->stream_req_scratch + mlen, req->path, plen);
  r->stream_req            = *req;
  r->stream_req.method     = r->stream_req_scratch;
  r->stream_req.method_len = mlen;
  r->stream_req.path       = r->stream_req_scratch + mlen;
  r->stream_req.path_len   = plen;
  r->stream_req.body       = 0; /* not valid past round 0, streaming is GET */
  r->stream_req.body_len   = 0;
}

/* Prime r's streaming state after round 0: stays 0 for an
 * ordinary single-round response. base_shift is round 0's own base offset
 * (0, or a preceding 100-continue HEADERS frame's byte length, RFC 9110
 * 10.1.1) that round 1's own offset must keep counting up from. */
static void srvrun_prime_streaming(
    srvrun_resp*                r,
    const wired_h3reqdrive_req* req,
    int                         more,
    usz                         round_len,
    u64                         base_shift) {
  r->streaming = more != 0;
  if (!more) return;
  wired_sendsess_set_base_offset(&r->sess, base_shift);
  r->stream_off = base_shift + round_len;
  srvrun_copy_stream_req(r, req);
}

/* Arm r's round-0 body over st, hq-interop-raw or H3-framed depending on
 * what this connection negotiated, and prime the streaming state when the
 * handler asked for another round. base_shift shifts round 0's own STREAM
 * frame offset past a preceding 100-continue interim response (0 for the
 * ordinary case, see srvrun_send_continue). */
/* round 0's DATA frame length: the streaming total when the handler asked
 * for more rounds, else just this (only) round's own body. Split out so
 * srvrun_arm_round0's own branch count stays at the CCN gate. */
static u64 srvrun_round0_total_len(int more, u64 total_size, usz body_len) {
  if (more) return total_size;
  return body_len;
}

/* Turn a freshly-armed streaming response's queue into a ring over the
 * remainder of its storage row -- from wherever round 0's arm placed q.p
 * (the H3 prefix start, or st + HDR_ROOM for hq-interop) to the row's end.
 * The refill loop (srvrun_resp_refill) then cycles through it for the whole
 * response instead of draining and re-arming per round. */
static void srvrun_resp_ring_init(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  u8* base    = srvrun_resp_storage_ro(ctx, slot, c, r);
  r->ring_cap = srvrun_resp_row_size(r) - (usz)(r->sess.q.p - base);
  wired_sendq_set_ring(&r->sess.q, r->ring_cap);
}

static void srvrun_arm_round0(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    int                    slot,
    srvrun_resp*           r,
    u8*                    st,
    const wired_obuf*      body,
    const char*            ct,
    int                    more,
    u64                    total_size,
    u64                    base_shift) {
  u64 total_len = srvrun_round0_total_len(more, total_size, body->len);
  if (c->s.sdrv.alpn == QUIC_SALPN_HQ)
    srvrun_arm_hq09_resp(c, r, st, body);
  else
    srvrun_arm_h3_resp(ctx, c, slot, r, st, body, ct, total_len);
  wired_sendsess_set_base_offset(&r->sess, base_shift);
  srvrun_prime_streaming(r, &c->l.req, more, body->len, base_shift);
  if (r->streaming) srvrun_resp_ring_init(ctx, c, slot, r);
}

/* Run the app handler's round 0 into body/ct/more/total_size (out params). */
static void srvrun_call_round0(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    wired_obuf*            body,
    const char**           ct,
    int*                   more,
    u64*                   total_size) {
  srvrun_call_handler(ctx, &c->l.req, 0, body, ct, more, total_size);
}

/* RFC 9110 10.1.1: send the 100-continue interim ahead of round 0 when the
 * request asked for it (c->l.req.expect_continue), returning the base offset
 * shift srvrun_arm_round0 must apply so the final response's STREAM frame
 * continues the same QUIC stream right after it. 0 (no interim, no shift)
 * when the request did not ask, or c has no confirmed 1-RTT key yet to seal
 * one with (srvrun_send_continue's underlying seal simply fails and this
 * still returns 0 -- the final response then starts at offset 0 as usual). */
static u64 srvrun_maybe_send_continue(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (!c->l.req.expect_continue) return 0;
  return srvrun_send_continue(cfg, c, c->l.req_stream_id);
}

/* Body of srvrun_start_resp for a normal (non-WT) request: run the app
 * handler's first round, then frame+arm the response -- H3-framed or
 * hq-interop-raw depending on what this connection negotiated. Split out so
 * srvrun_start_resp itself stays at its gate/dispatch decision (CCN). */
static void srvrun_start_app_resp(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  u8*        st = srvrun_resp_storage(ctx, slot, c, r);
  wired_obuf body =
      obuf_of(st + SRVRUN_RESP_HDR_ROOM, srvrun_resp_storage_cap(r));
  const char* ct         = 0;
  int         more       = 0;
  u64         total_size = 0;
  u64         base_shift = srvrun_maybe_send_continue(ctx->cfg, c);
  r->stream_h3_framed    = 0;
  srvrun_call_round0(ctx, c, &body, &ct, &more, &total_size);
  srvrun_arm_round0(
      ctx, c, slot, r, st, &body, ct, more, total_size, base_shift);
}

/* Reject this Extended CONNECT with 429 (a new Extended CONNECT arriving
 * while every session slot is already occupied, SRVRUN_MAX_WT_SESSIONS
 * reached) without disturbing any existing session -- srvrun_start_wt
 * only ever claims a FREE slot (srvrun_wt_free_slot), so an existing
 * ESTABLISHED session's own slot is never re-initialized by this path. Also
 * aborts the rejected stream with H3_REQUEST_REJECTED (RFC 9114 4.1.1/8.1),
 * independent of and in addition to the 429 above. */
static void srvrun_reject_wt_busy(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  srvrun_start_wt_status(cfg->env, slot, c, r, 429, 0);
  srvrun_send_wt_busy_reset(
      cfg, c, c->l.req_stream_id, QUIC_H3_REQUEST_REJECTED);
}

/* RFC 9000 2.1: bit 0x01 of a stream id is the initiator role (0 = client),
 * bit 0x02 is the directionality (0 = bidi) -- so a client-initiated bidi
 * stream id is exactly the ones with both low bits clear. Same check as
 * srvloop/dispatch.c's is_request_stream, duplicated here because that one is
 * file-static and srvrun.c has no visibility into it. */
static int srvrun_stream_id_is_client_bidi(u64 stream_id) {
  return (stream_id & 0x03) == 0;
}

/* draft-ietf-webtrans-http3-15 SS3.2/SS4: the WT session id is the CONNECT
 * stream's own id, so it must be a client-initiated bidi stream
 * id (RFC 9000 2.1) or the session would be keyed by an id that cannot
 * possibly be the client's request stream. RFC 9114 8.1 lists H3_ID_ERROR for
 * exactly this "stream id used incorrectly" case; it is a stream-level abort
 * reason, so this mirrors srvrun_reject_wt_busy's RESET_STREAM+STOP_SENDING
 * shape rather than a CONNECTION_CLOSE. */
static void srvrun_reject_wt_bad_id(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  srvrun_start_wt_status(cfg->env, slot, c, r, 403, 0);
  srvrun_send_wt_busy_reset(cfg, c, c->l.req_stream_id, QUIC_H3_ID_ERROR);
}

/* Body of srvrun_dispatch_wt once Origin has passed and no session is
 * already active: reject a non-client-bidi session id or establish the
 * session. Split out so srvrun_dispatch_wt itself stays at one
 * gate (CCN). */
static void srvrun_dispatch_wt_free_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (!srvrun_stream_id_is_client_bidi(c->l.req_stream_id)) {
    srvrun_reject_wt_bad_id(cfg, c, slot, r);
    return;
  }
  srvrun_start_wt(cfg, slot, c, r);
}

/* A well-formed Extended CONNECT for WebTransport either establishes a
 * session (Origin absent, or present and well-formed, and no session
 * already active on this connection), or is rejected: 403 for a malformed
 * Origin, 429 if a session is already active, or H3_ID_ERROR if the
 * CONNECT stream's own id is not a client-initiated bidi stream id. */
static void srvrun_dispatch_wt(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (!wt_origin_ok(&c->l.req)) {
    srvrun_reject_wt(cfg->env, slot, c, r);
    return;
  }
  if (srvrun_wt_free_slot(c) < 0) {
    srvrun_reject_wt_busy(cfg, c, slot, r);
    return;
  }
  srvrun_dispatch_wt_free_slot(cfg, c, slot, r);
}

/* draft-ietf-webtrans-http3-15 SS3.2 (WTH3-016/WTH3-018): the app's resource
 * check runs before Origin verification (the RFC lists it first: "the HTTP/3
 * server can check if it has a WebTransport server associated with the
 * specified :authority and :path values ... When the request contains the
 * Origin header, the WebTransport server MUST verify" second) -- a status of
 * 0 (accept, including the no-callback-registered default) falls through to
 * srvrun_dispatch_wt unchanged; any other status seals and sends the app's
 * verdict verbatim instead. Split out of srvrun_dispatch_wt_gated so its own
 * branch count stays at the CCN gate. */
static void srvrun_dispatch_wt_resource(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  wired_wt_resource_decision d;
  srvrun_wt_resource_decide(cfg, c, &d);
  if (d.status) {
    srvrun_start_wt_resource_status(cfg->env, slot, c, r, &d);
    return;
  }
  srvrun_dispatch_wt(cfg, c, slot, r);
}

/* draft-ietf-webtrans-http3-15 SS3.1 (WTH3-009/042): "for draft versions of
 * WebTransport, the server shall not process any incoming WebTransport
 * requests until the client's SETTINGS have been received." c->l.peer_ctrl
 * (priority_ctrl.c's ctrl_note_generic) latches settings_seen the moment the
 * client's control-stream SETTINGS frame is actually walked -- 0 here means
 * either no control stream has been reassembled yet, or one has but its
 * SETTINGS has not yet arrived. */
static int srvrun_wt_settings_ready(const srvrun_conn* c) {
  return c->l.peer_ctrl.settings_seen != 0;
}

/* draft-ietf-webtrans-http3-15 SS3.1 (WTH3-007): "If the server receives ...
 * transport parameters that do not have correct values for every required
 * WebTransport ... parameter, then the server shall treat ... newly incoming
 * WebTransport sessions as malformed." RFC 9297 2.1.1 requires a peer that
 * wants HTTP Datagrams (which every WebTransport session rides on, SS4.5) to
 * advertise a non-zero max_datagram_frame_size transport parameter (0 is
 * this repo's existing "not advertised" sentinel, c->s.sdrv's own doc) -- a
 * WT CONNECT from a peer that never advertised it is exactly this "incorrect
 * value for a required parameter" case, so newly incoming sessions are
 * rejected rather than established malformed. */
static int srvrun_wt_tp_ok(const srvrun_conn* c) {
  return c->s.sdrv.peer_max_datagram_frame_size != 0;
}

/* srvrun_dispatch_wt gated on the client's own SETTINGS having arrived first
 * (WTH3-009/042) and its transport parameters carrying every value
 * WebTransport requires (WTH3-007) -- split out so srvrun_dispatch_resp's
 * own dispatch decision stays a single branch (CCN). A CONNECT failing
 * either gate is rejected the same way a malformed Origin is (403), since
 * draft-ietf-webtrans-http3-15 does not name a specific status for either
 * case. */
static void srvrun_dispatch_wt_gated(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (!srvrun_wt_settings_ready(c) || !srvrun_wt_tp_ok(c)) {
    srvrun_reject_wt(cfg->env, slot, c, r);
    return;
  }
  srvrun_dispatch_wt_resource(cfg, c, slot, r);
}

/* RFC 9110 9.1 (9110-017/9110-018): the status this request's method earns
 * before it ever reaches the application handler -- 0 once it passes both
 * gates, 501 for a method this server does not even recognize, 405 for one
 * it recognizes but does not allow through (see method.h's doc for the
 * allow set). Checked ahead of the WT Extended CONNECT dispatch in
 * srvrun_start_resp so a malformed/unsupported method never reaches either
 * path. */
static u16 srvrun_method_status(const wired_h3reqdrive_req* r) {
  wired_span method = wired_span_of(r->method, r->method_len);
  if (!quic_h3_method_is_known(method)) return 501;
  if (!quic_h3_method_is_allowed(method)) return 405;
  return 0;
}

/* Seal the bare status-only response srvrun_method_status asked for into r's
 * own storage row, reusing srvrun_start_wt_status's low-level prefix+arm
 * primitive (it is protocol-level response building, not WT-specific despite
 * the name). */
static void srvrun_start_method_status(
    wired_srvrun_env* env,
    int               slot,
    srvrun_conn*      c,
    srvrun_resp*      r,
    u16               status) {
  srvrun_start_wt_status(env, slot, c, r, status, 0);
}

/* Build the decoded request's response into a freshly claimed resp[] slot
 * and arm its session over the whole stream. A request stream that already
 * has an in-flight response is dropped rather than claiming a second slot
 * for it (its existing response keeps flowing); a request with no free slot
 * anywhere is also dropped (bounded, same policy as the old single-response-
 * per-connection table). An Extended CONNECT for WebTransport (RFC 9220 3,
 * draft-ietf-webtrans-http3-15 SS3) establishes a WT session or is rejected
 * with 403, and never reaches the app handler. */
/* Claim a fresh resp[] slot for c->l.req_stream_id, or 0 when the stream
 * already has one in flight (guard 1) or every slot is busy. */
static srvrun_resp* srvrun_start_resp_claim(srvrun_conn* c) {
  if (srvrun_resp_find(c, c->l.req_stream_id)) return 0;
  return srvrun_resp_claim(c, c->l.req_stream_id);
}

/* RFC 9110 9.1 / RFC 9220 3: the status a non-WT request earns before it
 * reaches the app handler -- srvrun_method_status's own 501/405, or 501 for
 * an Extended CONNECT naming an unsupported :protocol
 * (srvrun_is_wt_connect_unsupported_protocol, checked first since that
 * predicate only matches a shape srvrun_method_status would otherwise wave
 * through as a plain CONNECT). 0 once neither applies. Split out of
 * srvrun_dispatch_resp so its own branch count stays at the CCN gate. */
static u16 srvrun_non_wt_status(const wired_h3reqdrive_req* r) {
  if (srvrun_is_wt_connect_unsupported_protocol(r)) return 501;
  return srvrun_method_status(r);
}

/* Route a claimed slot to WT dispatch, a method/protocol-status response
 * (501/405), or the application handler -- split out of srvrun_start_resp so
 * its own `!r` guard stays a single branch at the CCN gate. */
static void srvrun_dispatch_resp(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  u16 status;
  if (srvrun_is_wt_connect(&c->l.req)) {
    srvrun_dispatch_wt_gated(ctx->cfg, c, slot, r);
    return;
  }
  status = srvrun_non_wt_status(&c->l.req);
  if (status) {
    srvrun_start_method_status(ctx->cfg->env, slot, c, r, status);
    return;
  }
  srvrun_start_app_resp(ctx, c, slot, r);
}

static void srvrun_start_resp(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_resp* r = srvrun_start_resp_claim(c);
  if (!r) return;
  srvrun_dispatch_resp(ctx, c, slot, r);
}

/* The wire FIN belongs on exactly the slice that ends the whole response:
 * computed fresh at send time as "ends at the queue's current logical end,
 * with no more refills coming" -- never from sl->fin, which is frozen at
 * take time and goes stale the moment a later refill extends the queue (a
 * requeued end-of-buffer slice would otherwise retransmit with FIN at a
 * mid-stream offset, RFC 9000 4.5 FINAL_SIZE_ERROR). The Extended CONNECT
 * stream never gets FIN at all: it IS the WebTransport session
 * (draft-ietf-webtrans-http3 4) -- a FIN on the session-accept 200 reads
 * as "session over" and Chrome closes with code 0 the moment it arrives.
 * Scoped to r's own stream_id: sibling normal responses still get theirs.
 */
static u8 srvrun_slice_fin(
    const srvrun_conn* c, const srvrun_resp* r, const wired_sendq_slice* sl) {
  if (srvrun_wt_slot_by_connect_id(c, r->stream_id) >= 0) return 0;
  if (r->streaming) return 0; /* the handler still owes bytes */
  return (u8)(sl->offset + sl->len == r->sess.q.len);
}

/* Seal one slice of sess as its own 1-RTT packet (a STREAM frame on
 * stream_id, RFC 9000 19.8) and send it -- the shared body under both a
 * resp[] slot's send (srvrun_send_slice) and a WT send slot's
 * (srvrun_pump_one_wt). Returns 1 once logged in flight. */
/* RFC 9000 13.2.1: piggyback the step's deferred pending ACK ahead of a
 * slice when the combined plaintext still fits this connection's validated
 * packet size. The ACK length is fixed by encoding it BEFORE committing
 * (wired_srvloop_ack_peek leaves the pending state untouched), so an ACK
 * that does not fit simply stays pending and the slice goes out bare -- no
 * take-then-fail hole: the policy is only cleared (mark_sent) after the
 * carrying packet went out. Returns the ACK bytes written at pl[0]. */
static usz srvrun_slice_ack_peek(
    srvrun_conn* c, const wired_sendq_slice* sl, u8* pl) {
  usz al;
  if (!c->l.ack_defer) return 0;
  al = wired_srvloop_ack_peek(&c->l, pl, SRVRUN_ACK_ROOM);
  return sl->len + al <= srvrun_mps(c) ? al : 0;
}

/* Seal pl as one 1-RTT packet under pn, send it, and -- once it is on the
 * wire -- consume the piggybacked pending ACK when the payload carried one
 * (al != 0). Returns 1 on success, 0 if sealing failed (nothing sent, the
 * pending ACK untouched). */
static int srvrun_seal_send_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_span pl, u64 pn, usz al) {
  u8                    out[1500];
  wired_obuf            ob  = obuf_of(out, sizeof out);
  wired_srvloop_send_in sin = {
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), pn, -1, pl, 0};
  if (!wired_srvloop_send_onertt(&c->s, &sin, &ob)) return 0;
  srvrun_send_staged(
      ctx->cfg, c, wired_span_of(out, ob.len), "1-RTT payload sent\n");
  if (al) wired_srvloop_ack_mark_sent(&c->l);
  return 1;
}

static int srvrun_send_stream_slice(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    wired_sendsess*          sess,
    u64                      stream_id,
    const wired_sendq_slice* sl,
    u8                       fin) {
  u8                pl[SRVRUN_ACK_ROOM + SRVRUN_SLICE_PL];
  usz               al  = srvrun_slice_ack_peek(c, sl, pl);
  wired_obuf        plb = obuf_of(pl + al, sizeof pl - al);
  quic_stream_frame f   = {
      stream_id, wired_sendsess_stream_offset(sess, sl), sl->len,
      wired_sendq_slice_data(&sess->q, sl), fin};
  u64 pn;
  if (!quic_appdata_stream_frame(&f, &plb)) return 0;
  pn = c->l.tx_pn++;
  srvrun_qlog_stream_sent(ctx->cfg, c, ctx->now_ms, pn, &f);
  if (!srvrun_seal_send_slice(ctx, c, wired_span_of(pl, al + plb.len), pn, al))
    return 0;
  return wired_sendsess_sent(sess, sl, pn, ctx->now_ms);
}

/* Send a just-taken slice; on failure return it to sess via
 * wired_sendsess_untake so the next take offers it again. The take already
 * advanced the sendq cursor (the slice's bytes count as consumed for flow
 * control), so a slice dropped here would be a permanent hole -- in no log
 * or requeue, invisible to loss detection, never resent. */
static int srvrun_send_taken(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    wired_sendsess*          sess,
    u64                      stream_id,
    const wired_sendq_slice* sl,
    u8                       fin) {
  if (srvrun_send_stream_slice(ctx, c, sess, stream_id, sl, fin)) return 1;
  wired_sendsess_untake(sess, sl);
  return 0;
}

/* One resp[] slot's slice, with the response path's own FIN suppression
 * (WT CONNECT stream / streaming rounds, srvrun_slice_fin above). */
static int srvrun_send_slice(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    srvrun_resp*             r,
    const wired_sendq_slice* sl) {
  return srvrun_send_taken(
      ctx, c, &r->sess, r->stream_id, sl, srvrun_slice_fin(c, r, sl));
}

static int  srvrun_pace_ok(const srvrun_step_ctx* ctx, const srvrun_conn* c);
static void srvrun_pace_next(const srvrun_step_ctx* ctx, srvrun_conn* c);
static void srvrun_pace_refill(const srvrun_step_ctx* ctx, srvrun_conn* c);
static void srvrun_pace_charge(srvrun_conn* c, usz bytes);
static void srvrun_ku_discard_stale(srvrun_conn* c, u64 now_ms);

/* Sum of in-flight stream bytes across every WT send slot -- the wtsend
 * side of srvrun_inflight_bytes_all's fan-out (its own function so both
 * loops stay at the CCN gate). */
static usz srvrun_wtsend_inflight_bytes(const srvrun_conn* c) {
  usz total = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (c->wtsend[i].in_use)
      total += wired_sendsess_inflight_bytes(&c->wtsend[i].sess);
  return total;
}

/* Sum of in-flight stream bytes across every resp[] AND wtsend slot -- the
 * congestion window (RFC 9002 7) gates the connection's TOTAL in-flight,
 * not any one stream's. */
static usz srvrun_inflight_bytes_all(const srvrun_conn* c) {
  usz total = srvrun_wtsend_inflight_bytes(c);
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (c->resp[i].in_use)
      total += wired_sendsess_inflight_bytes(&c->resp[i].sess);
  return total;
}

/* 1 when sess's send log has a free entry. The log gate applies to every
 * send regardless of cwnd: a slice taken and sent while the log is full can
 * be recorded in neither log nor requeue -- if that packet then drops, the
 * stream has a permanent hole the peer waits on forever. */
static int srvrun_sess_log_room(const wired_sendsess* sess) {
  return wired_sendsess_inflight(sess) < WIRED_SENDSESS_LOG;
}

/* 1 when the connection's congestion window (RFC 9002 7) has room for one
 * more chunk across every slot combined. Pacing (RFC 9002 7.7) is NOT
 * checked here -- it gates whole round-robin passes
 * (srvrun_pump_round_gated), not individual slots. Reads the cached total
 * (srvrun_conn.acct_inflight) rather than re-walking every slot per slice. */
static int srvrun_cwnd_has_room(const srvrun_conn* c) {
  return c->acct_inflight + srvrun_mps(c) <= c->cc.cwnd;
}

/* Sum of consumed (taken-from-sendq) stream bytes across every WT send
 * slot -- the wtsend side of srvrun_conn_consumed_bytes' fan-out. */
static usz srvrun_wtsend_consumed_bytes(const srvrun_conn* c) {
  usz total = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (c->wtsend[i].in_use)
      total += c->wtsend[i].sess.stream_base_offset + c->wtsend[i].sess.q.cur;
  return total;
}

/* RFC 9000 4.1: sum of stream bytes already handed to wired_sendsess_take
 * (stream_base_offset + q.cur, the ABSOLUTE next-unsent offset -- q.cur
 * alone restarts on every streaming re-arm / epoch recycle) across every
 * resp[] AND wtsend slot -- the cumulative total the connection's ONE
 * conn_credit (initial_max_data + any MAX_DATA raises) bounds. A
 * retransmit reuses an offset range already counted here, so PTO/loss
 * resends never double-count (mirrors srvrun_inflight_bytes_all's per-slot
 * fan-out, but this quantity only grows -- it is not cleared by an ACK the
 * way in-flight bytes are). */
static usz srvrun_conn_consumed_bytes(const srvrun_conn* c) {
  usz total = srvrun_wtsend_consumed_bytes(c);
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (c->resp[i].in_use)
      total += c->resp[i].sess.stream_base_offset + c->resp[i].sess.q.cur;
  return total;
}

/* One sess's contribution to acct_consumed: the absolute next-unsent stream
 * offset (see srvrun_conn_consumed_bytes on why base + cur, not cur alone).
 */
static usz srvrun_sess_consumed(const wired_sendsess* sess) {
  return sess->stream_base_offset + sess->q.cur;
}

/* Resync the cached totals from the full scans -- once per step (and per
 * pump pass), so ACK/requeue/reap/re-arm effects are picked up wholesale
 * instead of being tracked per event; see srvrun_conn.acct_inflight's doc.
 */
static void srvrun_acct_resync(srvrun_conn* c) {
  c->acct_inflight = srvrun_inflight_bytes_all(c);
  c->acct_consumed = srvrun_conn_consumed_bytes(c);
}

/* 1 when the connection's send credit (RFC 9000 18.2/19.9) has room for one
 * more chunk, summed across every slot the same way cwnd is (cached total,
 * see srvrun_acct_resync). */
static int srvrun_conn_credit_has_room(const srvrun_conn* c) {
  return c->acct_consumed + srvrun_mps(c) <= c->conn_credit;
}

/* 1 when RFC 9000 4.1's two flow-control credits (connection-wide, and
 * sess's own stream-level ceiling `credit`, RFC 9000 18.2/19.10) both have
 * room for one more chunk. Consumed bytes for one stream are exactly its
 * own sendq cursor (no cross-slot fan-out needed at this level). */
static int srvrun_sess_credit_room(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  /* stream_base_offset + q.cur is the ABSOLUTE next-unsent stream offset
   * (RFC 9000 19.10's limit is absolute): q.cur alone restarts at 0 on
   * every streaming re-arm / epoch recycle and would under-count. */
  return srvrun_conn_credit_has_room(c) &&
         sess->stream_base_offset + sess->q.cur + srvrun_mps(c) <= credit;
}

/* 1 when a brand-new slice (from sess's sendq, not its requeue) may go out:
 * the log, cwnd, and both flow-control credit gates all apply. */
static int srvrun_can_send_new(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  return srvrun_sess_log_room(sess) && srvrun_cwnd_has_room(c) &&
         srvrun_sess_credit_room(c, sess, credit);
}

/* RFC 9000 4.1/19.9: apply this step's highest-seen MAX_DATA (srvloop's
 * gather_max_data) to the connection's running send credit -- raise only,
 * per RFC 9000 4.1 ("MUST NOT reduce"), and always consume the step's
 * latch so a later step's absence of a new MAX_DATA is not mistaken for
 * this one's value persisting (srvloop.h's l->max_data_seen is this step's
 * observation only, not a running value itself). */
static void srvrun_apply_conn_credit_update(srvrun_conn* c) {
  if (!c->l.max_data_seen_flag) return;
  if (c->l.max_data_seen > c->conn_credit) c->conn_credit = c->l.max_data_seen;
  c->l.max_data_seen_flag = 0;
}

/* Raise a stream credit ceiling to value if that is higher, RFC 9000 4.1's
 * raise-only rule -- split out so srvrun_apply_stream_credit_update's own
 * CCN stays at the gate. */
static void srvrun_stream_credit_raise(u64* credit, u64 value) {
  if (value > *credit) *credit = value;
}

/* 1 if this step's gathered PATH_RESPONSE (srvloop's gather_path_response)
 * is worth comparing at all: a connection that never issued a PATH_CHALLENGE
 * (migrate.challenged == 0) cannot have a real one to match against --
 * quic_migrate_validate itself already refuses without challenged, but
 * checking here first avoids running the (cheap, but still pointless)
 * compare and lets srvrun_apply_path_response's own CCN stay at the gate. */
static int srvrun_path_response_pending(const srvrun_conn* c) {
  return c->l.path_response_seen_flag && c->migrate.challenged;
}

/* 1 if this step's gathered PATH_RESPONSE data (ct_diff8
 * constant-time compare) matches the challenge c last sent -- split out so
 * srvrun_apply_path_response's own CCN stays at the gate (the compound
 * pending && diff==0 that would otherwise inline here each cost +1). */
static int srvrun_path_response_matches(const srvrun_conn* c) {
  if (!srvrun_path_response_pending(c)) return 0;
  return ct_diff8(c->l.path_response_data, c->path_challenge_data) == 0;
}

/* RFC 9000 8.2.2: apply this step's gathered PATH_RESPONSE (if any) against
 * the challenge this connection last sent (c->path_challenge_data). A match
 * validates the path (quic_migrate_validate); a mismatch or an unchallenged
 * connection leaves migrate untouched. Always consumes the step's latch,
 * same convention as srvrun_apply_conn_credit_update. See
 * srvrun_rebind_peer's doc comment for why the response's own source
 * address is deliberately never checked here. */
static void srvrun_apply_path_response(srvrun_conn* c) {
  if (!c->l.path_response_seen_flag) return;
  if (srvrun_path_response_matches(c)) quic_migrate_validate(&c->migrate);
  c->l.path_response_seen_flag = 0;
}

/* w is claimed and sending on stream_id. */
static int srvrun_wtsend_matches(const srvrun_wtsend* w, u64 stream_id) {
  return w->in_use && w->stream_id == stream_id;
}

/* The in-use WT send slot on stream_id, or 0 if none. */
static srvrun_wtsend* srvrun_wtsend_find(srvrun_conn* c, u64 stream_id) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (srvrun_wtsend_matches(&c->wtsend[i], stream_id)) return &c->wtsend[i];
  return 0;
}

/* Apply one this-step MAX_STREAM_DATA slot to its named resp[] or wtsend
 * slot's running stream credit. A stream_id naming no in-use slot (already
 * reaped, or never claimed) is a no-op -- srvloop has no notion of send
 * slots and cannot itself validate the id. */
static void srvrun_apply_one_stream_credit_update(srvrun_conn* c, usz i) {
  srvrun_resp*   r = srvrun_resp_find(c, c->l.max_stream_data_stream_id[i]);
  srvrun_wtsend* w = srvrun_wtsend_find(c, c->l.max_stream_data_stream_id[i]);
  if (r)
    srvrun_stream_credit_raise(
        &r->stream_credit, c->l.max_stream_data_value[i]);
  if (w)
    srvrun_stream_credit_raise(
        &w->stream_credit, c->l.max_stream_data_value[i]);
}

/* RFC 9000 4.1/19.10: apply EVERY distinct MAX_STREAM_DATA slot this step
 * latched (dispatch.c's gather_one_max_stream_data) -- several parallel
 * streamed responses can each be raised in the same step, and applying only
 * one would leave the rest stuck at their prior credit ceiling forever. */
static void srvrun_apply_stream_credit_update(srvrun_conn* c) {
  usz n                  = c->l.max_stream_data_n;
  c->l.max_stream_data_n = 0;
  for (usz i = 0; i < n; i++) srvrun_apply_one_stream_credit_update(c, i);
}

/* RFC 9002 7.5: "Probe packets MUST NOT be blocked by the congestion
 * controller." A PTO probe is a retransmit of an already-in-flight slice
 * that wired_sendsess_pto_fire moved to r->sess's requeue (sendsess.c) --
 * gating it on cwnd re-creates the exact deadlock RFC 9002 7.5 forbids: cwnd
 * can only grow from new ACKs, new ACKs need new sends, and a probe stuck
 * behind a full cwnd is the one send that would produce that ACK. */
static int srvrun_has_requeued(const wired_sendsess* sess) {
  return sess->requeue_n != 0;
}

/* RFC 9000 4.1/19.12: tell the peer THIS connection ran out of send credit,
 * once per distinct ceiling (data_blocked_sent_at != c->conn_credit -- a
 * later MAX_DATA raise makes a stale sent-at send again if blocked a second
 * time). Without this, a peer whose own autotuning lags a fast multi-stream
 * transfer never learns the SERVER is blocked and has no signal to raise
 * MAX_DATA sooner -- the connection stalls until the peer's own heuristics
 * eventually catch up, or the idle timeout fires first (RFC 9000 10.1).
 * A no-op while conn_credit still has room: only the connection-wide ceiling
 * blocking (not a per-stream credit or cwnd/log gate) warrants this signal,
 * same scope DATA_BLOCKED itself carries (STREAM_DATA_BLOCKED would be the
 * per-stream counterpart, not needed here since srvloop already raises
 * stream credit independently via MAX_STREAM_DATA). */
static void srvrun_notify_conn_blocked(const srvrun_cfg* cfg, srvrun_conn* c) {
  if (srvrun_conn_credit_has_room(c)) return;
  if (c->data_blocked_sent_at == c->conn_credit) return;
  srvrun_send_data_blocked(cfg, c, c->conn_credit);
  c->data_blocked_sent_at = c->conn_credit;
}

/* RFC 9000 4.6/19.14: srvrun_notify_conn_blocked's uni-stream mirror. A
 * server-initiated uni open (moqtrun's relay streams) refused by peer_uni_
 * stream_limit latches uni_blocked_seen at the call site (srvrun_wt_uni_
 * grant_ok, which has no srvrun_cfg); this drains that latch once per pump
 * pass and sends STREAMS_BLOCKED(uni) at most once per distinct ceiling
 * (uni_blocked_sent_at), the same one-signal-per-raise shape as the bidi/
 * DATA_BLOCKED siblings. Without this, a peer that only re-grants MAX_
 * STREAMS(uni) on seeing this signal never learns the relay is stuck, and
 * every relay open keeps failing until the connection ends. */
static void srvrun_notify_uni_blocked(const srvrun_cfg* cfg, srvrun_conn* c) {
  u64 limit = srvrun_peer_uni_limit(c);
  if (!c->uni_blocked_seen) return;
  c->uni_blocked_seen = 0;
  if (c->uni_blocked_sent_at == limit) return;
  srvrun_send_streams_blocked(cfg, c, 1, limit);
  c->uni_blocked_sent_at = limit;
}

/* 1 when sess may send right now: a queued probe retransmit only needs the
 * log gate (RFC 9002 7.5 bypasses cwnd for it); brand-new data needs both
 * gates. The log gate is checked for a probe too, even though
 * sendsess_requeue (sendsess.c) already cleared its log entry's inflight
 * flag the moment it moved to requeue -- so requeue_n != 0 always implies
 * at least that many free log entries, and this check can never actually
 * fail for a probe. It stays as an explicit invariant, not dead code: it
 * documents that a probe's cwnd exemption is deliberately narrower than a
 * blanket "requeue bypasses everything". */
static int srvrun_pump_gate_ok(
    const srvrun_conn* c, const wired_sendsess* sess, u64 credit) {
  if (srvrun_has_requeued(sess)) return srvrun_sess_log_room(sess);
  return srvrun_can_send_new(c, sess, credit);
}

/* Send one slice from r if the gates allow and one is ready. Pacing's
 * next-send time is scheduled once per whole pass by the caller
 * (srvrun_pump_round_gated), not per slice. */
static int srvrun_pump_one_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r) {
  wired_sendq_slice sl;
  if (!srvrun_pump_gate_ok(c, &r->sess, r->stream_credit)) {
    srvrun_notify_conn_blocked(ctx->cfg, c);
    return 0;
  }
  if (!wired_sendsess_take(&r->sess, &sl)) return 0;
  return srvrun_send_slice(ctx, c, r, &sl);
}

/* Delta-adjust the cached totals around one slice attempt: only this sess's
 * contribution can change inside it (take/untake/sent), so the before/after
 * difference is exact -- and unsigned wraparound adds a negative delta
 * correctly. */
static int srvrun_pump_one(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r) {
  usz inf0 = wired_sendsess_inflight_bytes(&r->sess);
  usz con0 = srvrun_sess_consumed(&r->sess);
  int sent = srvrun_pump_one_slice(ctx, c, r);
  usz inf1 = wired_sendsess_inflight_bytes(&r->sess);
  c->acct_inflight += inf1 - inf0;
  c->acct_consumed += srvrun_sess_consumed(&r->sess) - con0;
  if (sent) srvrun_pace_charge(c, inf1 - inf0);
  return sent;
}

/* The wire FIN belongs on exactly the slice that ends the stream: the
 * slot is past its final append (append_open 0) and sl ends at the
 * cumulative stream offset. sl->fin (end of the CURRENT epoch buffer) is
 * deliberately ignored: rounds can be staged behind an already-logged
 * slice (wired_sendsess_extend), so a retransmit of a stale
 * end-of-buffer slice must not carry FIN at what is by then a mid-stream
 * offset (RFC 9000 4.5: a final size that moves is FINAL_SIZE_ERROR). */
static u8 srvrun_wt_slice_fin(
    const srvrun_wtsend* w, const wired_sendq_slice* sl) {
  return (u8)(!w->append_open &&
              wired_sendsess_stream_offset(&w->sess, sl) + sl->len ==
                  w->stream_off);
}

/* Sends w's pending bare-FIN round (srvrun_wtsend.fin_only_pending's own
 * doc): a synthetic 0-byte/fin=1 slice, since wired_sendsess_take never
 * yields one for w's 0-byte arm. Clears fin_only_pending and append_open
 * (the stream really is over now) once the slice is on the wire; the slot
 * itself reaps later, same as any other final round, once this one's ACK
 * lands (srvrun_wtsend_finished). */
static int srvrun_pump_wt_fin_only(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w) {
  wired_sendq_slice sl = {0, 0, 1};
  if (!w->fin_only_pending) return 0;
  if (!srvrun_send_stream_slice(ctx, c, &w->sess, w->stream_id, &sl, 1))
    return 0;
  w->fin_only_pending = 0;
  w->append_open      = 0;
  return 1;
}

/* Promotes a deferred wired_server_wt_stream_fin request to fin_only_pending
 * the moment w's previous round finishes (srvrun_wtsend_request_fin's own
 * doc on why the request could not be armed immediately). No-op once
 * already promoted or if nothing was ever requested. */
static void srvrun_wtsend_promote_fin_if_ready(
    const srvrun_conn* c, srvrun_wtsend* w) {
  if (!w->fin_requested) return;
  if (!wired_sendsess_done(&w->sess)) return;
  w->fin_requested = 0;
  srvrun_wtsend_start_fin_now(c, w);
}

/* Send one slice from WT send slot w under the same gates -- or, once its
 * own sess has nothing left to give (wired_sendsess_take), a bare-FIN
 * round if one is pending (promoting a deferred request first). */
static int srvrun_pump_one_wt_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w) {
  wired_sendq_slice sl;
  srvrun_wtsend_promote_fin_if_ready(c, w);
  if (!srvrun_pump_gate_ok(c, &w->sess, w->stream_credit)) {
    srvrun_notify_conn_blocked(ctx->cfg, c);
    return 0;
  }
  if (wired_sendsess_take(&w->sess, &sl))
    return srvrun_send_taken(
        ctx, c, &w->sess, w->stream_id, &sl, srvrun_wt_slice_fin(w, &sl));
  return srvrun_pump_wt_fin_only(ctx, c, w);
}

/* srvrun_pump_one's cached-total delta wrapper, WT-slot flavor. */
static int srvrun_pump_one_wt(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_wtsend* w) {
  usz inf0 = wired_sendsess_inflight_bytes(&w->sess);
  usz con0 = srvrun_sess_consumed(&w->sess);
  int sent = srvrun_pump_one_wt_slice(ctx, c, w);
  usz inf1 = wired_sendsess_inflight_bytes(&w->sess);
  c->acct_inflight += inf1 - inf0;
  c->acct_consumed += srvrun_sess_consumed(&w->sess) - con0;
  if (sent) srvrun_pace_charge(c, inf1 - inf0);
  return sent;
}

/* One arrival-order pass over every in-use wtsend slot matching keep_open
 * (append_open's own value, not just "is it set right now" -- a slot mid-
 * closing still counts as the keep-open pass so its final slice/FIN is not
 * pushed a whole extra pass behind fresh one-shot arrivals). */
static int srvrun_pump_wt_round_matching(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int keep_open) {
  int sent = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if ((c->wtsend[i].append_open != 0) == keep_open)
      sent |= srvrun_pump_one_wt(ctx, c, &c->wtsend[i]);
  return sent;
}

/* The WT-send half of one round-robin pass. RFC 9218 has no urgency signal
 * for WebTransport streams (Extended CONNECT carries no Priority parameters
 * of its own), so this can't read a real priority -- but moqtrun's own two
 * stream shapes (moqtrun.h) give a usable proxy: a long-lived append_open
 * relay stream carries one MOQT Object per round (audio, paced ~50/s and
 * loss-tolerant-but-latency-sensitive), while a one-shot stream carries a
 * whole chat message. Draining every append_open slot's one slice before any
 * one-shot slot's at least keeps audio's OWN pass-order position ahead of a
 * chat burst's tail-half slots within a single pass; it does not, by itself,
 * bound how often a pass runs at all -- a live 4-way call with chat every
 * 150ms still showed audio inter-arrival p99 climbing past 500ms with zero
 * relay drops (frames queued, not lost), and this reordering alone did not
 * measurably change that on a CPU-starved test host, so the pass-frequency
 * side of the problem (pacing/poll cadence under contention) remains open. */
static int srvrun_pump_wt_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = srvrun_pump_wt_round_matching(ctx, c, 1);
  return sent | srvrun_pump_wt_round_matching(ctx, c, 0);
}

/* resp[] slot i's current RFC 9218 priority, read from the receive-side
 * streams[] table (wired_srvloop_priority_of) rather than stored on
 * srvrun_resp itself -- streams[] is the one place a PRIORITY_UPDATE lands
 * (priority_ctrl.c), so reading it here keeps a single source of truth
 * instead of a second copy that could drift. An in_use resp[] slot with no
 * matching streams[] slot (already released, e.g. mid-teardown) reads as
 * the RFC 9218 4.1 default -- it still sends, just without a live urgency
 * signal, matching the pre-scheduling behavior for that edge case. */
static quic_h3prio_candidate srvrun_resp_candidate(
    const srvrun_conn* c, usz i) {
  quic_h3prio_candidate cand = {
      QUIC_H3_URGENCY_DEFAULT, 0, c->resp[i].stream_id, c->resp[i].in_use};
  quic_h3_priority p;
  if (c->resp[i].in_use &&
      wired_srvloop_priority_of(&c->l, c->resp[i].stream_id, &p)) {
    cand.urgency     = p.urgency;
    cand.incremental = p.incremental;
  }
  return cand;
}

/* RFC 9218 10: one pacing-unrelated pass over resp[] in priority order
 * (ascending urgency, ascending stream id within a tie -- see
 * quic_h3prio_order's own doc for why this ordering also covers
 * incremental bandwidth sharing and same-urgency starvation avoidance
 * without extra machinery: every slot still gets exactly one slice per
 * pass, only the visiting order within a pass changed). */
/* (Re)build c->prio_order for the coming pump pass. Claims, releases, and
 * PRIORITY_UPDATEs all land between passes (reap/start/receive run before
 * srvrun_pump_sess in the step), so one build per pass sees exactly what a
 * per-round build used to. */
static void srvrun_prio_refresh(srvrun_conn* c) {
  quic_h3prio_candidate cand[SRVRUN_RESP_SLOTS];
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    cand[i] = srvrun_resp_candidate(c, i);
  quic_h3prio_order(cand, SRVRUN_RESP_SLOTS, c->prio_order);
}

static int srvrun_pump_resp_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = 0;
  for (usz k = 0; k < SRVRUN_RESP_SLOTS; k++)
    sent |= srvrun_pump_one(ctx, c, &c->resp[c->prio_order[k]]);
  return sent;
}

/* One round-robin pass: try exactly one slice from every in-use wtsend and
 * resp[] slot. @return 1 if any slot actually sent one. */
static int srvrun_pump_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = srvrun_pump_wt_round(ctx, c);
  return sent | srvrun_pump_resp_round(ctx, c);
}

/* 1 if any resp[] slot has a PTO probe queued. */
static int srvrun_any_resp_requeued(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (srvrun_has_requeued(&c->resp[i].sess)) return 1;
  return 0;
}

/* 1 if any WT send slot has a PTO probe queued. */
static int srvrun_any_wtsend_requeued(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (srvrun_has_requeued(&c->wtsend[i].sess)) return 1;
  return 0;
}

/* 1 if any resp[]/wtsend slot has a PTO probe queued (srvrun_has_requeued)
 * -- the round-level trigger for bypassing the pacing gate below. */
static int srvrun_any_requeued(const srvrun_conn* c) {
  return srvrun_any_resp_requeued(c) || srvrun_any_wtsend_requeued(c);
}

/* RFC 9002 7.5: a PTO probe must not be blocked by the congestion
 * controller, and that includes pacing (RFC 9002 7.7) -- not just cwnd. A
 * probe was already exempted from cwnd (srvrun_pump_gate_ok), but the
 * pacing check ahead of it in srvrun_pump_round_gated still gated on
 * c->srtt_ms/next_send_ms, so an RTT spike (a real blackhole off-period's
 * delayed ACK) could push next_send_ms far into the future and silently
 * swallow the one send that would recover the connection -- observed live:
 * a real interop blackhole run stalls mid-transfer and never resumes once
 * the link comes back. */
static int srvrun_pace_or_probe_ok(
    const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  return srvrun_pace_ok(ctx, c) || srvrun_any_requeued(c);
}

/* One pacing-gated round-robin pass: the whole pass (up to SRVRUN_RESP_SLOTS
 * slices, one per slot) counts as a single paced send, so pacing limits how
 * often a PASS may run, not how often each SLOT within it may run -- pacing
 * and round-robin fairness would otherwise fight (a 1ms pacing floor made
 * slot 0's first slice push next_send_ms a full ms into the future before
 * slots 4/8 ever got a turn in the same step, starving them completely). */
static int srvrun_pump_round_gated(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (!srvrun_pace_or_probe_ok(ctx, c)) return 0;
  int sent = srvrun_pump_round(ctx, c);
  if (sent) srvrun_pace_next(ctx, c);
  return sent;
}

/* 1 if c already has a DPLPMTUD probe outstanding (srvrun_pmtu_try_probe
 * below has not yet been reconciled by an ACK/LOSS/timer for it) -- RFC 8899
 * 5.1.3 PROBED_SIZE is a single value, so at most one probe is ever
 * outstanding at a time (mirrors connrunner's own pmtu_probe_held, see
 * pmtudrive.c). */
static int srvrun_pmtu_probe_outstanding(const srvrun_conn* c) {
  return c->pmtu_probe_pn != SRVRUN_PMTU_NO_PROBE;
}

/* RFC 8899 3.2/5: a PING frame (1 byte, ack-eliciting) followed by PADDING
 * (0x00) filling the rest of len bytes -- carries no application data that
 * would need retransmission if the probe is lost (RFC 8899 3.4). Returns
 * len, or 0 if it does not fit cap. */
static usz srvrun_pmtu_probe_payload(u8* buf, usz cap, usz len) {
  if (len == 0 || len > cap) return 0;
  buf[0] = QUIC_FRAME_PING;
  bytes_memset(buf + 1, QUIC_FRAME_PADDING, len - 1);
  return len;
}

/* RFC 8899 4.4/DPLPMTUD: `size` is the target WIRE size -- the UDP datagram
 * byte count DPLPMTUD is asking the path to carry -- not a plaintext frame
 * length. Sealing adds the short header (1 flags + dcid + 4-byte pn) and the
 * AEAD tag on top of the payload, so the plaintext PING+PADDING built below
 * must be shorter than `size` by that overhead or the sealed packet would
 * overshoot the probe's own target. QUIC_PMTU_OVERHEAD already is this SDK's
 * one worst-case figure for that overhead (max 20-byte dcid + 16-byte tag,
 * see pmtu.h), the same constant quic_pmtu_mps subtracts for the same
 * reason -- reused here instead of a second hand-derived margin. Returns 0
 * if size is at or below the overhead (no room for even a 1-byte PING). */
static usz srvrun_pmtu_probe_len(usz size) {
  if (size <= QUIC_PMTU_OVERHEAD) return 0;
  return size - QUIC_PMTU_OVERHEAD;
}

/* Seal the PING+PADDING payload above into out as its own 1-RTT packet,
 * under a fresh pn from this connection's own tx_pn sequence (the same
 * counter every other srvrun_seal_* caller advances). Returns 1 with
 * out->len and *pn set, 0 on payload-build or seal failure (pn left
 * unassigned). */
static int srvrun_seal_pmtu_probe(
    srvrun_conn* c, usz size, wired_obuf* out, u64* pn) {
  u8                    pl[QUIC_PMTU_MAX];
  wired_srvloop_send_in sin;
  usz                   len = srvrun_pmtu_probe_len(size);
  usz                   pln = srvrun_pmtu_probe_payload(pl, sizeof pl, len);
  if (!pln) return 0;
  *pn = c->l.tx_pn++;
  sin = (wired_srvloop_send_in){
      wired_span_of(c->l.cli_scid, c->l.cli_scid_len), *pn, -1,
      wired_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Clear c's outstanding-probe tracking, letting the next opportunity
 * (srvrun_pmtu_probe_candidate) start a fresh probe -- shared by the ACK
 * (srvrun_pmtu_reap_ack) and PROBE_TIMER (srvrun_pmtu_reap_timeout)
 * resolution paths, both of which must leave at most one probe outstanding
 * (RFC 8899 5.1.3 PROBED_SIZE is a single value). */
static void srvrun_pmtu_probe_clear(srvrun_conn* c) {
  c->pmtu_probe_pn      = SRVRUN_PMTU_NO_PROBE;
  c->pmtu_probe_size    = 0;
  c->pmtu_probe_sent_ms = 0;
}

/* RFC 8899 5.1.1 PROBE_TIMER: an outstanding probe that has not been
 * acked/lost within QUIC_PMTU_PROBE_TIMER_US is itself treated as a loss --
 * without this, an unanswered probe leaves pmtu_probe_pn outstanding
 * forever and srvrun_pmtu_probe_candidate never starts another (found by
 * TLA+ model-checking: the ACK path alone has no fairness toward a probe
 * the peer never acknowledges at all). Polled once per send opportunity
 * (srvrun_pmtu_try_probe), matching how this connection has no dedicated
 * timer thread -- only per-step polling (see srvrun_pto_deadline_ms's own
 * doc on the same style of poll-driven deadline). */
static void srvrun_pmtu_reap_timeout(srvrun_conn* c, u64 now_us) {
  if (!quic_pmtu_probe_timer_due(&c->pmtu, now_us)) return;
  quic_pmtu_on_loss(&c->pmtu, c->pmtu_probe_size);
  srvrun_pmtu_probe_clear(c);
}

/* The next candidate size to probe on c, or 0 if none: a probe already
 * outstanding or a concluded search (quic_pmtu_next_probe's own gate) both
 * read as "nothing to do this opportunity". now_us converts srvrun's ms
 * clock into pmtu.c's us unit (matching QUIC_RTT_INITIAL_US and the other
 * RFC 9002 RTT state already on this us clock). */
static usz srvrun_pmtu_probe_candidate(srvrun_conn* c, u64 now_us) {
  srvrun_pmtu_reap_timeout(c, now_us);
  if (srvrun_pmtu_probe_outstanding(c)) return 0;
  return quic_pmtu_next_probe(&c->pmtu, now_us);
}

/* Seal and send a `size`-byte probe, then record its pn/size/send-time for
 * the later ACK/LOSS reconciliation step to consume. Returns 1 once a
 * packet actually went out, 0 if this opportunity built nothing (seal
 * failure -- e.g. an unexpected suite/dcid combination this call site did
 * not anticipate). The 0 return matters: srvrun_pmtu_try_probe's caller
 * treats "1 = sent, stop trying other sends this opportunity" as a per-
 * opportunity contract, and quic_pmtu_next_probe (via probe_candidate) keeps
 * re-offering the same candidate size until it is acked/lost/timed out --
 * without this 0, a seal failure at one size would starve every other send
 * on the connection in a tight retry loop, opportunity after opportunity,
 * for as long as that size keeps failing to seal (this is the defensive
 * half of the QUIC_PMTU_OVERHEAD fix above: with that fix in place this
 * path should not be reachable in practice, but srvrun_pmtu_send_probe must
 * not itself become a hang if it ever is). */
static int srvrun_pmtu_send_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, usz size) {
  u8         buf[QUIC_PMTU_MAX];
  wired_obuf out = obuf_of(buf, sizeof buf);
  u64        pn;
  if (!srvrun_seal_pmtu_probe(c, size, &out, &pn)) return 0;
  c->pmtu_probe_pn      = pn;
  c->pmtu_probe_size    = size;
  c->pmtu_probe_sent_ms = ctx->now_ms;
  srvrun_send(ctx->cfg, c, wired_span_of(buf, out.len), "PMTU probe sent\n");
  return 1;
}

/* RFC 8899 DPLPMTUD probe send opportunity: try the next candidate size
 * (srvrun_pmtu_probe_candidate) and, if there is one, seal and send it
 * (srvrun_pmtu_send_probe). Returns 1 if a probe was sent this opportunity,
 * 0 if there was nothing to send. */
static int srvrun_pmtu_try_probe(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u64 now_us = ctx->now_ms * 1000;
  usz size   = srvrun_pmtu_probe_candidate(c, now_us);
  if (!size) return 0;
  return srvrun_pmtu_send_probe(ctx, c, size);
}

/* Transmit while the window has room and slices are ready, across every
 * in-flight response on this connection (RFC 9000 2.2: several requests may
 * be in flight at once) -- round-robin one slice per slot per pass, so a
 * single stream with a full send log never starves its siblings of the
 * connection's one shared cwnd (a strict per-slot drain-then-next order let
 * slot 0 claim the whole window every step; slot 2 fell far enough behind on
 * real send time that its own in-flight slices tripped RFC 9002 6.1.1's
 * packet threshold, not because they were actually lost).
 *
 * RFC 8899 DPLPMTUD probe fairness: each iteration of the loop below is one
 * send opportunity, and a probe attempt is given first refusal on EVERY
 * iteration -- not only once normal sends run dry. An "only after the loop"
 * placement lets a connection with a steady stream of normal sends starve
 * the probe forever -- a design mistake TLA+ model-checking caught: weak
 * fairness on the merge point was not enough, since a continuously busy
 * normal-send path never leaves a window where the probe is the only thing
 * enabled. Trying the probe first, every iteration, gives it the standing
 * to always take its turn the moment it has one (srvrun_pmtu_try_probe
 * itself is a no-op whenever a probe is already outstanding or the search
 * has nothing left to try, so this costs nothing on the common case), while
 * still keeping one send opportunity exclusive to either a probe or a
 * normal pass -- never both (the short-circuit below skips the normal pass
 * on the same opportunity a probe went out). */
static int srvrun_pump_opportunity(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (srvrun_pmtu_try_probe(ctx, c)) return 1;
  return srvrun_pump_round_gated(ctx, c);
}

static void srvrun_pump_sess(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  /* RFC 9001 4.1.2 / RFC 9000 12.3: 1-RTT packet-protection keys (the SDK's
   * own send_onertt_keys fallback, srvloop/send.c) do not exist until the
   * server's own Finished-inclusive transcript confirms
   * (keysched_advance_master, srvfin/complete.c) -- a response started
   * from a 0-RTT-carried request (srvrun_boot_flush_zerortt, or the live
   * 0-RTT path before the client's Finished lands) can be CLAIMED and armed
   * before that point, but sending its slices this early always fails
   * closed at the key layer. Deferring the whole pump until confirmed costs
   * nothing: the next post-confirm step (the client's own Finished, which
   * confirms) drains every slot's already-armed sendq exactly as if it had
   * started then. */
  if (!wired_server_is_confirmed(&c->s)) return;
  srvrun_acct_resync(c); /* pick up ACK/requeue/reap/re-arm effects wholesale
                          * before any gate reads the cached totals */
  srvrun_prio_refresh(c);
  srvrun_pace_refill(ctx, c);
  while (srvrun_pump_opportunity(ctx, c)) {
  }
  srvrun_notify_uni_blocked(ctx->cfg, c);
  srvrun_stage_flush(ctx->cfg); /* the pass's staged slices leave as one
                                 * GSO batch (srvrun_send_staged) */
}

/* After a live step: feed the step's ACK ranges to the session, start a
 * response for a freshly decoded request, and send what the window allows.
 * A finished session simply goes idle. */
/* qlog packet_lost (connection-level trend) for one lost pn. No-op without a
 * qlog path -- callers only reach here after their own gate already
 * confirmed one. */
static void srvrun_qlog_lost_packet(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 now_ms, u64 pn) {
  char rec[128];
  usz  w =
      wired_qlogevent_packet_lost(rec, sizeof rec, now_ms, c->qlog_slot, pn);
  if (w) wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, w));
}

/* qlog stream_frame_lost (frame-level forensics: moqt-voice-stability
 * addendum 4/5's "did the server see loss, did it resend" question) for one
 * declared-lost slice. */
static void srvrun_qlog_lost_stream_frame(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* l) {
  char                            rec[192];
  wired_qlogevent_stream_frame_in in = {
      stream_id, l->offset, l->length, l->fin, l->pn};
  usz w = wired_qlogevent_stream_frame(
      rec, sizeof rec, now_ms, c->qlog_slot, "stream_frame_lost", &in);
  if (w) wired_qlog_append(cfg->qlog_path, wired_span_of((const u8*)rec, w));
}

/* Both qlog records for one declared-lost slice -- packet_lost stays for
 * existing connection-trend tooling, stream_frame_lost is the new
 * frame-level forensic record; both fire, they serve different uses. No-op
 * without a qlog path. */
static void srvrun_qlog_lost_one(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* l) {
  if (!cfg->qlog_path) return;
  srvrun_qlog_lost_packet(cfg, c, now_ms, l->pn);
  srvrun_qlog_lost_stream_frame(cfg, c, now_ms, stream_id, l);
}

static void srvrun_qlog_lost(
    const srvrun_cfg*                cfg,
    const srvrun_conn*               c,
    u64                              now_ms,
    u64                              stream_id,
    const wired_sendsess_lost_slice* lost,
    usz                              n) {
  for (usz i = 0; i < n; i++)
    srvrun_qlog_lost_one(cfg, c, now_ms, stream_id, &lost[i]);
}

/* Consume this step's ACK ranges, then declare packet-threshold losses so
 * their slices requeue ahead of new data (RFC 9002 6.1.1), logging each
 * lost packet to the qlog when one is configured. */
/* RFC 9002 5.3 (shape): seed on the first sample, then 7/8 old + 1/8 new.
 * Also feeds the full RFC 9002 5 estimator (rtt, us) that
 * srvrun_pto_deadline_ms needs for rttvar -- srtt_ms above stays the simpler
 * ms-only EWMA pacing already relies on, unchanged. */
static void srvrun_rtt_note(srvrun_conn* c, u64 sample_ms) {
  c->srtt_ms = c->srtt_ms ? (7 * c->srtt_ms + sample_ms) / 8 : sample_ms;
  quic_rtt_sample(
      &c->rtt, sample_ms * 1000, 0, SRVRUN_MAX_ACK_DELAY_US,
      wired_server_is_confirmed(&c->s));
}

/* 1 if confirmation landed on the datagram just processed: c was still
 * awaiting confirm before it (was_booting) and is confirmed now. */
static int srvrun_confirm_edge(const srvrun_conn* c, int was_booting) {
  return was_booting && wired_server_is_confirmed(&c->s);
}

/* 1 while no RTT sample exists yet and a boot send timestamp is there to
 * measure against. */
static int srvrun_boot_rtt_unseeded(const srvrun_conn* c) {
  return !c->srtt_ms && c->boot_pto_sent_ms != 0;
}

/* RFC 9002 6.2.2: before the first 1-RTT ACK the PTO deadline falls back to
 * the kInitialRtt-based ~1s default -- but the handshake itself already
 * measured the path once: the client's confirming flight answers the boot
 * flight last sent at boot_pto_sent_ms. Seed both estimators with that one
 * sample at the confirm transition, so a first post-confirm loss probes on
 * the real path RTT instead of waiting out the ~1s floor (the dominant
 * cost per connection under the interop runner's handshakeloss profile). */
static void srvrun_seed_boot_rtt(srvrun_conn* c, int was_booting, u64 now_ms) {
  if (!srvrun_confirm_edge(c, was_booting)) return;
  if (!srvrun_boot_rtt_unseeded(c)) return;
  srvrun_rtt_note(c, now_ms - c->boot_pto_sent_ms);
}

static int srvrun_pace_within_poll_tick(const srvrun_conn* c);

/* Bytes per ms the pacer refills at: BBR paces at its own model's
 * pacing_gain% x btl_bw (falling back to the generic formula until the
 * first bandwidth sample); Reno/Cubic at RFC 9002 7.7's 1.25 * cwnd /
 * srtt. Callers guarantee srtt_ms != 0. */
static u64 srvrun_pace_rate_raw(const srvrun_conn* c) {
  if (c->cc.algo == QUIC_CC_ALGO_BBR && c->cc.bbr.btl_bw)
    return quic_bbr_pacing_gain_pct(&c->cc.bbr) * c->cc.bbr.btl_bw / 100;
  return 5 * c->cc.cwnd / (4 * c->srtt_ms);
}

/* Floored at 1 B/ms so a degenerate estimate can never stall the refill
 * entirely (the tokens would otherwise never accumulate again). */
static u64 srvrun_pace_rate(const srvrun_conn* c) {
  return u64_max(srvrun_pace_rate_raw(c), 1);
}

/* The uncapped balance after refilling for the wall time since the last
 * refill. pace_refill_ms == 0 means "never refilled": a full bucket, so the
 * very first paced pass is not stalled (real monotonic now_ms is never 0 --
 * only a fresh connection carries the 0 stamp). */
static u64 srvrun_pace_new_tokens(const srvrun_conn* c, u64 now_ms) {
  if (!c->pace_refill_ms) return SRVRUN_PACE_BURST;
  return c->pace_tokens + (now_ms - c->pace_refill_ms) * srvrun_pace_rate(c);
}

/* Advance the token bucket by the wall time since the last refill, capped
 * at the burst ceiling. Once per pump pass (srvrun_pump_sess) -- within a
 * pass now_ms is frozen, so the pass can never send more than one bucket.
 */
static void srvrun_pace_refill(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u64 t;
  if (!c->srtt_ms) return; /* unpaced until the first RTT sample */
  t                 = srvrun_pace_new_tokens(c, ctx->now_ms);
  c->pace_tokens    = t > SRVRUN_PACE_BURST ? SRVRUN_PACE_BURST : t;
  c->pace_refill_ms = ctx->now_ms;
}

/* Spend bytes from the bucket (clamped at zero -- srvrun_pace_ok's > 0
 * gate deliberately allows a one-slice overdraft). */
static void srvrun_pace_charge(srvrun_conn* c, usz bytes) {
  c->pace_tokens = c->pace_tokens > bytes ? c->pace_tokens - bytes : 0;
}

/* 1 when pacing allows a send now: unpaced until the first RTT sample; in
 * the sub-poll-tick regime (srvrun_pace_within_poll_tick) the token bucket
 * decides -- the ACK-clocked steps refill it, so throughput follows the
 * pacing rate instead of the 25ms poll cadence, while a burst stays under
 * the bucket and cannot overflow a shallow bottleneck queue; past one poll
 * tick, the absolute next_send_ms deadline as before. */
static int srvrun_pace_ok(const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  if (!c->srtt_ms) return 1;
  if (srvrun_pace_within_poll_tick(c)) return c->pace_tokens > 0;
  return ctx->now_ms >= c->next_send_ms;
}

/* 1 if NewReno's pacing interval is under one poll-loop tick (RFC 9002 7.7
 * intends smoothing bursts, not capping throughput): srvrun has no timer-
 * driven send loop -- srvrun_pump_sess only ever runs from srvrun_sess_
 * on_step (a received datagram) or srvrun_pto_slot (the SRVRUN_PTO_MS=25ms
 * poll tick), so a real send opportunity is at best SRVRUN_PTO_MS away.
 * Deferring a send to next_send_ms when the theoretical gap is already
 * shorter than that just pins the whole connection to the poll cadence
 * instead of the pacing rate -- observed pinning "response slice sent" to
 * a ~25-30ms cadence against a real quic-go client even with cwnd grown
 * past 4MB and zero loss, an effective throughput far under the link's real
 * capacity (interop goodput timing out at 60s). Once the interval grows
 * past SRVRUN_PTO_MS, deferring is real: a later poll tick or the next ACK
 * will still be there to pick the send back up, and pacing spreads it
 * genuinely. BBR is ALWAYS token-gated: pacing at pacing_gain x btl_bw is
 * its core mechanism (srvrun_pace_rate_raw), and the next_send_ms deferral
 * would pin it to the poll cadence exactly like the pre-token-bucket
 * regression this comment records. */
static int srvrun_pace_within_poll_tick(const srvrun_conn* c) {
  return c->cc.algo == QUIC_CC_ALGO_BBR ||
         quic_pacing_interval(c->srtt_ms, c->cc.cwnd, QUIC_MAX_DATAGRAM) <
             SRVRUN_PTO_MS;
}

/* Schedule the next paced send (RFC 9002 7.7: ~1.25x cwnd/srtt rate) --
 * a no-op (send stays due now) while the real interval already fits inside
 * one poll tick, see srvrun_pace_within_poll_tick. */
static void srvrun_pace_next(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (srvrun_pace_within_poll_tick(c)) return;
  c->next_send_ms =
      ctx->now_ms + quic_cc_pacing_ms(&c->cc, c->srtt_ms, QUIC_MAX_DATAGRAM);
}

/* 1 while the controller is still in slow start (no loss, no exit yet). */
static int srvrun_in_slow_start(const srvrun_conn* c) {
  return c->cc.cwnd < c->cc.ssthresh && !c->cc.in_recovery;
}

/* Feed one acked packet's sample to the slow-start exit detector (RFC 9406,
 * which explicitly samples every ACKed packet in a round, not just the
 * newest); on the verdict, end slow start by dropping ssthresh to the
 * current window. Round boundary: the next pn to be sent. Does NOT touch
 * the RTT estimator -- see srvrun_hystart_range's comment for why. */
static void srvrun_hystart_ack(srvrun_conn* c, u64 pn, u64 sent_ms, u64 now) {
  if (!srvrun_in_slow_start(c)) return;
  if (quic_hystart_sample(&c->hs, now - sent_ms, pn, c->l.tx_pn))
    c->cc.ssthresh = c->cc.cwnd;
}

/* Feed every in-flight packet an ACK range covers to the hystart detector
 * (RFC 9406 intends every sample in the round, unlike RTT estimation) --
 * the RTT estimator itself is fed separately, once, from the range's newest
 * send time (RFC 9002 5.1: "an endpoint... SHOULD generate an RTT sample
 * using only the largest acknowledged packet in the received ACK frame").
 * Feeding every hit here fed the SAME range's older, already-in-flight-a-
 * while slices as separate samples too -- under round-robin pumping
 * (srvrun_pump_round) a slot's own slices spread further apart in real send
 * time than under the old drain-then-next order, so those older samples'
 * inflated (now - sent_ms) dragged smoothed_rtt further from the true RTT
 * every ACK, observed as srtt climbing from ~36ms to ~55ms over a run whose
 * simulated RTT never changed. */
static void srvrun_hystart_range(
    srvrun_conn* c, const wired_sendsess* sess, u64 lo, u64 hi, u64 now) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    const wired_sent_slice* e = &sess->log[i];
    if (wired_sendsess_covered(e, lo, hi))
      srvrun_hystart_ack(c, e->pn, e->sent_ms, now);
  }
}

/* Credit one ACK range against r's log to the congestion controller before
 * consuming it (RFC 9002 7.3.2: growth per acked bytes; the newest send
 * time among the hits drives recovery exit). A range is broadcast to every
 * resp[] slot, and wired_sendsess_ack only clears the log entries that hit
 * ITS OWN log (sendsess.c) -- but it also unconditionally raises
 * largest_acked to the range's hi, even when hi belongs to another slot's
 * pn (pn is a single monotonic per-connection space, so a broadcast range
 * routinely names pns this slot never sent). That falsely advances this
 * slot's packet-loss threshold (RFC 9002 6.1.1) and requeues in-flight
 * slices that were never actually lost. Only forward the range when it
 * actually hits something in r's own log. */
/* 1 if [lo, hi] covers at least one of sess's own in-flight log entries,
 * regardless of byte length -- wired_sendsess_peek_ack's own bytes==0
 * return (a bare-FIN round's synthetic 0-byte slice, srvrun_pump_wt_fin_
 * only) must not be mistaken for "nothing of ours was hit" the way it
 * legitimately is for a resp[]/wtsend slot with no in-flight data at all:
 * a 0-byte slice still needs its own wired_sendsess_ack, or its log entry
 * never clears and the slot never reaps (wired_sendsess_done keeps seeing
 * it as pending forever). */
static int srvrun_cc_range_has_hit(const wired_sendsess* sess, u64 lo, u64 hi) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++)
    if (wired_sendsess_covered(&sess->log[i], lo, hi)) return 1;
  return 0;
}

static void srvrun_cc_range(
    srvrun_conn* c, wired_sendsess* sess, u64 lo, u64 hi, u64 now_ms) {
  u64 newest = 0;
  usz bytes  = wired_sendsess_peek_ack(sess, lo, hi, &newest);
  if (bytes) {
    srvrun_rtt_note(c, now_ms - newest);
    srvrun_hystart_range(c, sess, lo, hi, now_ms);
    quic_cc_on_ack(&c->cc, bytes, newest, now_ms);
  } else if (!srvrun_cc_range_has_hit(sess, lo, hi)) {
    return;
  }
  wired_sendsess_ack(sess, lo, hi);
}

/* Threshold pass over sess's log: requeue losses, log each lost packet. The
 * congestion-window shrink (quic_cc_on_loss) is applied once per step by
 * the caller (srvrun_feed_acks), not here, so a loss on several concurrent
 * responses in the same step still only shrinks the connection's one
 * window once. */
static usz srvrun_reap_losses(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    wired_sendsess*    sess,
    u64                stream_id,
    u64                now_ms) {
  wired_sendsess_lost_slice lost[WIRED_SENDSESS_LOG];
  usz                       n = wired_sendsess_detect_lost(
      sess, c->largest_acked, now_ms, c->rtt.smoothed_rtt, lost,
      WIRED_SENDSESS_LOG);
  srvrun_qlog_lost(cfg, c, now_ms, stream_id, lost, n);
  return n;
}

/* Ack/cc accounting for one range on every in-use wtsend session. Loss
 * reaping deliberately does NOT happen here -- see srvrun_feed_acks. */
static void srvrun_ack_range_wt(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (c->wtsend[i].in_use)
      srvrun_cc_range(c, &c->wtsend[i].sess, lo, hi, now_ms);
}

/* The resp[] half of the ACK-range broadcast, mirroring the wtsend loop. */
static void srvrun_ack_range_resps(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (c->resp[i].in_use) srvrun_cc_range(c, &c->resp[i].sess, lo, hi, now_ms);
}

/* One loss pass over every in-use wtsend session against the connection's
 * ONE largest_acked (RFC 9002 6.1.1); the slot's stream_id is only for the
 * loss records' qlog attribution (RFC 9000 19.8). */
static usz srvrun_reap_losses_wt(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms) {
  usz lost = 0;
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (c->wtsend[i].in_use)
      lost += srvrun_reap_losses(
          cfg, c, &c->wtsend[i].sess, c->wtsend[i].stream_id, now_ms);
  return lost;
}

/* The resp[] half of the loss pass. */
static usz srvrun_reap_losses_resps(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms) {
  usz lost = 0;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (c->resp[i].in_use)
      lost += srvrun_reap_losses(
          cfg, c, &c->resp[i].sess, c->resp[i].stream_id, now_ms);
  return lost;
}

/* The whole-connection loss pass: every in-use send session, wtsend and
 * resp[] alike. Runs once per srvrun_feed_acks batch, never per range. */
static usz srvrun_reap_losses_all(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 now_ms) {
  return srvrun_reap_losses_wt(cfg, c, now_ms) +
         srvrun_reap_losses_resps(cfg, c, now_ms);
}

/* 1 if [lo,hi] covers c's one outstanding DPLPMTUD probe pn -- the probe
 * lives outside every resp[]/wtsend[] send-session log (srvrun_conn's own
 * pmtu_probe_pn doc), so this is a separate branch from the range-based
 * loss detection above, not a change to it. */
static int srvrun_pmtu_probe_in_range(const srvrun_conn* c, u64 lo, u64 hi) {
  return srvrun_pmtu_probe_outstanding(c) && c->pmtu_probe_pn >= lo &&
         c->pmtu_probe_pn <= hi;
}

/* RFC 8899 5.1.3: an acked probe raises the validated PMTU (quic_pmtu_on_ack)
 * and resolves the outstanding tracking, letting the next opportunity start
 * a new probe. Entirely independent of the resp[]/wtsend[] ACK accounting
 * above -- a probe's pn belongs to neither log. */
static void srvrun_pmtu_reap_ack(srvrun_conn* c, u64 lo, u64 hi) {
  if (!srvrun_pmtu_probe_in_range(c, lo, hi)) return;
  quic_pmtu_on_ack(&c->pmtu, c->pmtu_probe_size);
  srvrun_pmtu_probe_clear(c);
}

/* Broadcast one ACK range's accounting to every in-flight send session
 * (resp[] and wtsend alike), after raising the connection's shared
 * largest_acked (RFC 9002 6.1.1: one packet number space, one
 * largest_acked -- never regresses). Accounting only -- no loss pass. */
static void srvrun_feed_ack_range(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  if (hi > c->largest_acked) c->largest_acked = hi;
  srvrun_ack_range_wt(c, lo, hi, now_ms);
  srvrun_ack_range_resps(c, lo, hi, now_ms);
  srvrun_pmtu_reap_ack(c, lo, hi);
}

/* Consume a step's ACK ranges, THEN run one loss pass over the whole
 * connection. The two-phase order is load-bearing in both directions:
 * (a) reaping per range mis-fires -- an ACK frame's ranges arrive
 * largest-first, so a reap right after range 0 sees the lower ranges'
 * packets as unacked-behind-largest and spuriously requeues them (a real
 * quic-go client's ACKs for streams 4/8 once re-sent ~35KB of stream 0's
 * already-delivered body this way); (b) reaping only sessions the peer
 * has acked leaves a one-shot round whose only packet was dropped -- so
 * no session-local ACK can ever arrive -- undeclared for tens of seconds
 * (RFC 9002 6.1's "sent prior to an acknowledged packet" is about the
 * connection's packet number space, not one session's own ACK history;
 * the s3-voice-loss qlog caught exactly this on chat relay streams). */
static void srvrun_feed_acks(
    const srvrun_step_ctx* ctx, const srvrun_cfg* cfg, srvrun_conn* c) {
  usz lost;
  for (usz i = 0; i < c->l.ack_n; i++)
    srvrun_feed_ack_range(c, c->l.ack_lo[i], c->l.ack_hi[i], ctx->now_ms);
  lost = srvrun_reap_losses_all(cfg, c, ctx->now_ms);
  if (lost) quic_cc_on_loss(&c->cc, ctx->now_ms, ctx->now_ms);
}

/* Send c's pending DATAGRAM (if any) using a scratch wired_obuf on the stack,
 * the same shape srvrun_send_pending_datagram expects. */
static void srvrun_pump_datagram(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8         out[1500];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!c->dg_pending) return;
  srvrun_send_pending_datagram(ctx->cfg, c, &ob);
}

/* Mirror one completed request into l->req/req_stream_id and start its
 * response -- the mirror is the single-request interface srvrun_start_resp
 * reads, re-pointed here per completion so each of a step's requests is
 * answered with ITS OWN decode, not just the last one dispatch mirrored. */
static void srvrun_start_done_resp(
    const srvrun_step_ctx* ctx, int slot, u8 done_i) {
  srvrun_conn*                     c  = &ctx->st->conns[slot];
  const wired_srvloop_stream_slot* sl = &c->l.streams[done_i];
  c->l.req                            = sl->req;
  c->l.req_stream_id                  = sl->stream_id;
  srvrun_start_resp(ctx, slot);
}

/* Start a response for every request that completed this step (RFC 9000
 * 2.2: a datagram may complete several request streams at once). */
static void srvrun_start_done_resps(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  for (usz i = 0; i < c->l.done_n; i++)
    srvrun_start_done_resp(ctx, slot, c->l.done_slots[i]);
}

/* RFC 9114 4.1.1: "if the request stream ends without enough of the HTTP
 * message to provide a complete response, the server SHOULD abort its
 * response stream with the error code H3_REQUEST_INCOMPLETE" -- srvloop's
 * dispatch (route_note_incomplete) already detected the case and latched the
 * slot index in incomplete_slots this step; abort it here with the same
 * RESET_STREAM + STOP_SENDING pair srvrun_reject_wt_busy uses, just
 * keyed by the stream's own id instead of req_stream_id. */
static void srvrun_abort_incomplete_req(
    const srvrun_step_ctx* ctx, int slot, u8 incomplete_i) {
  srvrun_conn* c  = &ctx->st->conns[slot];
  u64          id = c->l.streams[incomplete_i].stream_id;
  srvrun_send_wt_busy_reset(ctx->cfg, c, id, QUIC_H3_REQUEST_INCOMPLETE);
}

/* Abort every request stream that ended incomplete this step (RFC 9000 2.2:
 * a datagram may close several streams at once, same fan-out as
 * srvrun_start_done_resps). */
static void srvrun_abort_incomplete_reqs(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  for (usz i = 0; i < c->l.incomplete_n; i++)
    srvrun_abort_incomplete_req(ctx, slot, c->l.incomplete_slots[i]);
}

/* RFC 9114 7.2.5/7.2.8 (9114-067/9114-073): a request stream carried
 * PUSH_PROMISE or an HTTP/2-only reserved frame type -- srvloop's dispatch
 * (route_note_frame_unexpected) already detected it and latched the slot in
 * frame_unexpected_slots this step; abort it with H3_FRAME_UNEXPECTED, same
 * RESET_STREAM + STOP_SENDING pair as srvrun_abort_incomplete_req. */
static void srvrun_abort_frame_unexpected_req(
    const srvrun_step_ctx* ctx, int slot, u8 unexpected_i) {
  srvrun_conn* c  = &ctx->st->conns[slot];
  u64          id = c->l.streams[unexpected_i].stream_id;
  srvrun_send_wt_busy_reset(ctx->cfg, c, id, QUIC_H3_FRAME_UNEXPECTED);
}

/* Abort every request stream rejected outright this step, same fan-out as
 * srvrun_abort_incomplete_reqs. */
static void srvrun_abort_frame_unexpected_reqs(
    const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  for (usz i = 0; i < c->l.frame_unexpected_n; i++)
    srvrun_abort_frame_unexpected_req(
        ctx, slot, c->l.frame_unexpected_slots[i]);
}

/* Return r's borrowed wired_srvbigbuf row to the pool, if it holds one. */
static void srvrun_resp_release_bigbuf(wired_srvrun_env* env, srvrun_resp* r) {
  if (r->bigbuf_row >= 0) wired_srvbigbuf_release(&env->bigbuf, r->bigbuf_row);
}

/* 1 while r is a live streaming response the refill loop must keep fed. */
static int srvrun_resp_streaming_live(const srvrun_resp* r) {
  return r->in_use && r->streaming;
}

/* Bytes the next refill may write: the reclaimed room, capped at the ring
 * wrap so one handler write stays contiguous in storage. */
static usz srvrun_resp_refill_take(const srvrun_resp* r, usz room) {
  usz take = r->ring_cap - r->sess.q.len % r->ring_cap;
  return take < room ? take : room;
}

/* Feed r's ring: whenever enough acknowledged space has been reclaimed
 * (wired_sendsess_ring_room), run the handler for the next body chunk
 * directly into the ring and extend the live sendsess over it -- earlier
 * bytes can still be in flight, so the stream never waits out a full-buffer
 * ACK drain the way the old fixed rounds did (the round boundary idled the
 * link ~1 RTT every 640KB, an ~8% goodput loss on the interop link). The
 * quarter-capacity threshold keeps handler calls chunky without ever
 * exceeding what a small fixed-row ring can reclaim. A handler that
 * declines mid-stream (body.len 0, more 0) simply ends the stream exactly
 * as the old round flow did. Uses r->stream_req (the round-0 copy), never
 * c->l.req -- see stream_req's own doc. */
static void srvrun_resp_refill(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  usz         room, take;
  u8*         base;
  wired_obuf  body;
  const char* ct         = 0;
  int         more       = 0;
  u64         total_size = 0;
  if (!srvrun_resp_streaming_live(r)) return;
  room = wired_sendsess_ring_room(&r->sess, r->ring_cap);
  if (room < r->ring_cap / 4) return;
  take = srvrun_resp_refill_take(r, room);
  base = srvrun_resp_storage_ro(ctx, slot, c, r);
  body = obuf_of(
      base + (usz)(r->sess.q.p - base) + r->sess.q.len % r->ring_cap, take);
  srvrun_call_handler(
      ctx, &r->stream_req, r->stream_off, &body, &ct, &more, &total_size);
  wired_sendsess_extend(&r->sess, body.len);
  r->stream_off += body.len;
  r->streaming = more != 0;
}

/* Once r's session goes idle (wired_sendsess_done: every slice sent and
 * acked), either advance a streaming response to its next round or
 * free r's slot and the matching srvloop receive-side slot -- HTTP/3 never
 * reuses a stream id, so without releasing the receive slot too,
 * WIRED_SRVLOOP_MAX_STREAMS sequential requests on distinct streams would
 * permanently exhaust it. A body that borrowed a wired_srvbigbuf row returns
 * it to the pool here too (only once streaming is actually done, not
 * between rounds). */
static int srvrun_resp_not_yet_idle(srvrun_resp* r) {
  return !r->in_use || !wired_sendsess_done(&r->sess);
}

/* This connection's transport-parameter bidi stream limit (the value
 * srvrun_grant_streams raises from the first time it fires) -- 0
 * (unset), including when the test harness's own cfg carries no id at all,
 * falls back to the same built-in default the transport parameter itself
 * uses (stp_build_server_lim, server_tp.c). */
static u64 srvrun_stream_limit_base(const srvrun_step_ctx* ctx) {
  u64 configured = ctx->cfg->id ? ctx->cfg->id->max_streams_bidi : 0;
  return wired_srvloop_stream_limit(configured);
}

/* Returns 1 when the slot was released (its stream-limit grant is owed),
 * 0 otherwise. A streaming slot is refilled (never released) until the
 * handler's last bytes are queued AND fully acknowledged; a momentarily
 * drained streaming sess just re-activates on the next refill's extend. */
static usz srvrun_resp_reap(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  srvrun_resp_refill(ctx, c, slot, r);
  if (srvrun_resp_not_yet_idle(r)) return 0;
  if (r->streaming) return 0;
  wired_srvloop_slot_release(&c->l, r->stream_id);
  srvrun_resp_release_bigbuf(ctx->cfg->env, r);
  r->in_use = 0;
  return 1;
}

static void srvrun_reap_resps(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot) {
  usz freed = 0;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    freed += srvrun_resp_reap(ctx, c, slot, &c->resp[i]);
  srvrun_grant_streams(ctx->cfg, c, srvrun_stream_limit_base(ctx), freed);
}

/* w has delivered every byte (sent and acknowledged) AND the app has
 * written the stream's end -- the same fully-drained guard srvrun_resp_reap
 * applies, minus the response-only streaming/bigbuf concerns a WT send
 * never has. An append-open slot is never finished: its fully-ACKed round
 * is just the pause before the app's next wired_server_wt_stream_send
 * (whose busy check consumes wired_sendsess_done instead), the same way a
 * streaming resp[] slot survives its round boundary. */
static int srvrun_wtsend_finished(srvrun_wtsend* w) {
  return w->in_use && !w->append_open && wired_sendsess_done(&w->sess);
}

/* Free every fully-ACKed WT send slot; the app's payload view is released
 * (nothing SDK-side to return -- the sendsess only ever borrowed it). */
static void srvrun_reap_wtsends(srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (srvrun_wtsend_finished(&c->wtsend[i])) c->wtsend[i].in_use = 0;
}

/* Sum of receive-window overflow drops across this connection's WT stream
 * reassembly slots (bidi + uni), for the metrics snapshot below. Counts the
 * slots currently claimed -- a released slot's count leaves the sum. */
static u64 srvrun_wtwin_dropped(const srvrun_conn* c) {
  u64 total = 0;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    total += c->l.wt_streams[i].win.dropped_bytes;
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    total += c->l.wt_uni_streams[i].win.dropped_bytes;
  return total;
}

/* Snapshot for the qlog recovery:metrics_updated record: RFC 9002 recovery
 * state (quic_stats) plus this connection's WT diagnostic counters. */
static void srvrun_metrics_fill(
    const srvrun_conn* c, wired_qlogevent_metrics_in* m) {
  quic_stats_rtt rtt;
  quic_stats_cc  cc;
  quic_stats_rtt_get(&c->rtt, &rtt);
  quic_stats_cc_get(&c->cc, &cc);
  m->smoothed_rtt    = rtt.smoothed_rtt;
  m->cwnd            = cc.cwnd;
  m->bytes_in_flight = srvrun_inflight_bytes_all(c);
  m->wtsend_ok       = c->stat_wtsend_ok;
  m->wtsend_busy     = c->stat_wtsend_busy;
  m->wtsend_flow     = c->stat_wtsend_flow;
  m->wtwin_drop      = srvrun_wtwin_dropped(c);
  m->streams_blocked = c->stat_streams_blocked;
}

/* 1 once per SRVRUN_METRICS_INTERVAL_MS per connection, arming the next
 * window as a side effect. */
static int srvrun_metrics_due(srvrun_conn* c, u64 now_ms) {
  if (now_ms - c->metrics_emit_ms < SRVRUN_METRICS_INTERVAL_MS) return 0;
  c->metrics_emit_ms = now_ms;
  return 1;
}

/* 1 iff a metrics record should be written this step: a qlog path is
 * configured and this connection's interval has elapsed (arming the next
 * window as a side effect). */
static int srvrun_metrics_emit_due(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  return ctx->cfg->qlog_path && srvrun_metrics_due(c, ctx->now_ms);
}

/* qlog recovery:metrics_updated for one connection, ~1/s (time is srvrun's
 * own monotonic now_ms, the same clock the PTO deadlines run on). No-op
 * without a qlog path. */
static void srvrun_qlog_metrics(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  char                       rec[256];
  usz                        n;
  wired_qlogevent_metrics_in m;
  if (!srvrun_metrics_emit_due(ctx, c)) return;
  srvrun_metrics_fill(c, &m);
  n = wired_qlogevent_metrics(rec, sizeof rec, ctx->now_ms, c->qlog_slot, &m);
  if (n)
    wired_qlog_append(ctx->cfg->qlog_path, wired_span_of((const u8*)rec, n));
}

/* 1 iff this step deferred a bare ACK that is due right now; closes the
 * defer window either way (it spans exactly one step). Down connections
 * flush nothing. */
static int srvrun_deferred_ack_due(srvrun_conn* c) {
  if (!c->up || !c->l.ack_defer) return 0;
  c->l.ack_defer = 0;
  return quic_ackpolicy_should_ack(
      &c->l.app_ack_policy, c->l.now_ms, WIRED_SRVLOOP_MAX_ACK_DELAY_MS);
}

/* RFC 9000 13.2.1/13.2.2: a step whose deferred ACK found no slice to ride
 * flushes it as the traditional bare-ACK datagram, so deferral never delays
 * an ACK past the pre-existing upper bound (the delay window still gates
 * this packet, exactly like respond.c's emit_ack_only did). */
static void srvrun_flush_deferred_ack(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8  pl[SRVRUN_ACK_ROOM];
  usz al;
  if (!srvrun_deferred_ack_due(c)) return;
  al = wired_srvloop_ack_peek(&c->l, pl, sizeof pl);
  if (al)
    srvrun_seal_send_slice(ctx, c, wired_span_of(pl, al), c->l.tx_pn++, al);
  srvrun_stage_flush(ctx->cfg); /* the bare ACK stages like a slice; nothing
                                 * later this step would flush it */
}

static void srvrun_sess_on_step(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_feed_acks(ctx, ctx->cfg, c);
  srvrun_acct_resync(c);
  quic_cc_bbr_tick(&c->cc, c->acct_inflight, ctx->now_ms);
  srvrun_apply_conn_credit_update(c);
  srvrun_apply_stream_credit_update(c);
  srvrun_apply_path_response(c);
  srvrun_apply_uni_limit_update(c);
  srvrun_reap_resps(ctx, c, slot);
  srvrun_reap_wtsends(c);
  srvrun_reannounce_stream_limit(ctx->cfg, c, srvrun_stream_limit_base(ctx));
  srvrun_reannounce_uni_stream_limit(ctx->cfg, c);
  srvrun_abort_incomplete_reqs(ctx, slot);
  srvrun_abort_frame_unexpected_reqs(ctx, slot);
  srvrun_start_done_resps(ctx, slot);
  srvrun_pump_sess(ctx, slot);
  srvrun_pump_datagram(ctx, c);
  srvrun_flush_deferred_ack(ctx, c);
  srvrun_ku_discard_stale(c, ctx->now_ms);
  srvrun_qlog_metrics(ctx, c);
}

/* 1 if any resp[] slot is in use -- a connection with at least one response
 * still being built or in flight. */
static int srvrun_any_resp_active(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (c->resp[i].in_use) return 1;
  return 0;
}

/* 1 if any WT send slot is in use -- the wtsend side of the same check. */
static int srvrun_any_wtsend_active(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++)
    if (c->wtsend[i].in_use) return 1;
  return 0;
}

/* 1 if any send session (resp[] or wtsend) is still in flight. */
static int srvrun_any_send_active(const srvrun_conn* c) {
  return srvrun_any_resp_active(c) || srvrun_any_wtsend_active(c);
}

/* 1 while this slot still owes stream bytes (in flight, paced, or window
 * blocked) — the loop must keep ticking for it. */
static int srvrun_sess_waiting(const srvrun_conn* c) {
  return c->up && srvrun_any_send_active(c);
}

/* 1 while this slot has anything outbound that only a poll-loop tick (not
 * this connection's own next receive) will flush: an in-flight HTTP
 * response (srvrun_sess_waiting) or a broadcast DATAGRAM (dg_pending, RFC
 * 9221 5 -- queued by srvrun_broadcast_to_all/srvrun_bcast_drain_self but
 * only ever flushed from srvrun_pump_datagram, which srvrun_sess_on_step
 * reaches only when THIS connection itself next receives something). Used
 * only to decide whether the loop must keep ticking (srvrun_any_waiting);
 * NOT for the PTO probe/teardown decision below, which is specifically
 * about wired_sendsess retransmission and must not fire for a connection
 * that merely has a queued DATAGRAM and no HTTP response in flight. */
static int srvrun_has_outbound(const srvrun_conn* c) {
  return c->up && (srvrun_any_send_active(c) || c->dg_pending);
}

/* 1 if c has a boot flight outstanding, awaiting confirm -- true regardless
 * of resp[]/wtsend[] activity (none is possible before confirm anyway).
 * srvrun_boot_pto_slot only ever runs from the same poll-timeout tick this
 * gates below, so without counting it here, a boot-only connection makes
 * srvrun_may_block_unbounded block in recvmmsg forever and the boot PTO
 * timer never gets a chance to fire (RFC 9002 6.2, handshakeloss/
 * handshakecorruption interop). */
static int srvrun_has_boot_outbound(const srvrun_conn* c) {
  return srvrun_awaiting_confirm(c) && c->boot_ini_len != 0;
}

/* RFC 9002 6.2: this connection's current PTO duration in ms, scaled by
 * 2^pto_count backoff. Before any RTT sample exists, fall back to the RFC
 * 9002 6.2.2 kInitialRtt-based default (quic_rtt_init seeds exactly that),
 * so an idle-but-just-opened connection still gets a sane (not zero)
 * deadline. */
static u64 srvrun_pto_deadline_ms(const srvrun_conn* c, int pto_count) {
  quic_pto_rtt rtt = {c->rtt.smoothed_rtt, c->rtt.rttvar};
  u64 us = quic_pto_duration(rtt, SRVRUN_MAX_ACK_DELAY_US, (u32)pto_count);
  return us / 1000;
}

/* RFC 9001 6.5: "SHOULD retain old read keys for no more than three times
 * the PTO" -- once that floor (measured from the rotation this connection's
 * own 1x-PTO deadline calc already knows how to size) has elapsed, drop the
 * retained old generation. A no-op before any rotation (ku_rotated_at_ms
 * stays 0 until the first one, and have_old is 0 until then too). */
static void srvrun_ku_discard_stale(srvrun_conn* c, u64 now_ms) {
  u64 floor_ms;
  if (!c->s.ku.have_old) return;
  floor_ms = 3u * srvrun_pto_deadline_ms(c, 0);
  if (now_ms >= c->ku_rotated_at_ms + floor_ms) kuswitch_discard_old(&c->s.ku);
}

/* 1 if sess's oldest in-flight slice is still within its PTO window (RFC
 * 9002 6.2: probe only once send_time + PTO has elapsed) -- nothing in
 * flight counts as "not due" too, since wired_sendsess_pto_fire's own
 * nothing-in-flight case is a no-op anyway. */
static int srvrun_sess_pto_due(
    const srvrun_conn* c, const wired_sendsess* sess, u64 now_ms) {
  u64 sent_ms;
  if (!wired_sendsess_oldest_sent_ms(sess, &sent_ms)) return 0;
  return now_ms >= sent_ms + srvrun_pto_deadline_ms(c, sess->pto_count);
}

/* Fire sess's probe if its slot is claimed and the deadline elapsed; 1 while
 * the probe budget survives, 0 once it is spent (the caller tears the whole
 * connection slot down -- shared by resp[] and wtsend slots alike). */
static int srvrun_sess_pto_ok(
    const srvrun_conn* c, wired_sendsess* sess, int in_use, u64 now_ms) {
  if (!in_use || !srvrun_sess_pto_due(c, sess, now_ms)) return 1;
  return wired_sendsess_pto_fire(sess, SRVRUN_PTO_MAX);
}

/* Probe every in-flight response on this connection slot whose own
 * RTT-derived PTO deadline has actually elapsed (RFC 9002 6.2) -- not on
 * every poll tick regardless of RTT, which fired probes against packets
 * that were merely slow rather than lost on any link faster than the old
 * fixed SRVRUN_PTO_MS. The probe budget (SRVRUN_PTO_MAX) is a
 * connection-wide policy, not per-stream: the peer going silent means it
 * likely stopped acknowledging the whole connection, not just one stream,
 * so the first resp[] slot to exhaust its budget tears down the entire
 * connection slot rather than leaving the others to probe alone against a
 * dead peer.
 * @return 1 if every in-flight response still has probe budget, 0 if any
 *   slot's budget is spent (caller tears the connection slot down). */
static int srvrun_pto_resps(srvrun_conn* c, u64 now_ms) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++) {
    if (!srvrun_sess_pto_ok(c, &c->resp[i].sess, c->resp[i].in_use, now_ms))
      return 0;
  }
  return 1;
}

/* The wtsend half of the probe pass, same budget policy. */
static int srvrun_pto_wtsends(srvrun_conn* c, u64 now_ms) {
  for (usz i = 0; i < SRVRUN_WT_SEND_SLOTS; i++) {
    if (!srvrun_sess_pto_ok(c, &c->wtsend[i].sess, c->wtsend[i].in_use, now_ms))
      return 0;
  }
  return 1;
}

/* 1 while every in-flight send session (resp[] and wtsend) still has probe
 * budget; 0 tears the connection slot down (the peer went silent on the
 * whole connection, not one stream -- see srvrun_pto_resps' doc above). */
static int srvrun_pto_all(srvrun_conn* c, u64 now_ms) {
  return srvrun_pto_resps(c, now_ms) && srvrun_pto_wtsends(c, now_ms);
}

static void srvrun_pto_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!srvrun_sess_waiting(c)) return;
  if (!srvrun_pto_all(c, ctx->now_ms)) {
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  srvrun_pump_sess(ctx, slot);
}

/* Flush one slot's queued broadcast DATAGRAM (if any) on a poll-loop tick --
 * the counterpart to srvrun_pto_slot for dg_pending, since a receive-only
 * peer (e.g. a WebTransport client that only listens) never runs
 * srvrun_sess_on_step's own srvrun_pump_datagram call on its own. */
static void srvrun_dg_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (c->up) srvrun_pump_datagram(ctx, c);
}

/* One live step; a peer CONNECTION_CLOSE observed by the loop frees the slot
 * afterward (RFC 9000 10.2.2: the connection is done, its state discarded). */
static void srvrun_step_and_reap(
    const srvrun_step_ctx* ctx, int slot, wired_mspan dg) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_on_step(ctx, c, dg);
  if (c->l.peer_closed) {
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  srvrun_sess_on_step(ctx, slot);
}

/* Drive one received datagram against its resolved slot: a new Initial
 * (re)opens the connection, any other datagram steps the live loop. */
/* Drive one cold-start feeding: a pending boot keeps its claim (and its
 * accumulator) for the next datagram; success or failure settles the slot. */
/* RFC 9000 13.2.1 while the ClientHello is still incomplete: ack the
 * Initial packets that did arrive, so a client whose missing piece keeps
 * getting dropped hears the server is alive instead of dying on its own
 * handshake idle timer. That ack is the slot's first packet, which makes
 * the client switch its DCID to our scid (RFC 9000 7.2) -- rekey the
 * routing entry and admit the new DCID into the accumulator before the
 * switched retransmits arrive. The antiamp gate still bounds the send. */
static void srvrun_boot_partial_ack(const srvrun_step_ctx* ctx, int slot) {
  u8           out[1400];
  srvrun_conn* c    = &ctx->st->conns[slot];
  wired_span   scid = wired_span_of(c->scid, ctx->cfg->id->scid_len);
  usz          n = wired_srvboot_partial_ack(&c->boot, scid, out, sizeof out);
  if (n == 0) return;
  if (srvrun_boot_gate_blocks(c, 0, n)) return;
  /* The routing entry stays keyed on the ODCID: pre-switch retransmits
   * still arrive under it, and rekeying here let them claim a COMPETING
   * slot whose flight carried a different initial_source_connection_id
   * (observed live: quic-go closed with TRANSPORT_PARAMETER_ERROR).
   * Post-switch datagrams route via srvrun_find_boot_scid instead. */
  wired_srvboot_acc_allow(&c->boot, scid);
  srvrun_boot_send(
      ctx->cfg, c, wired_span_of(out, n), "partial ClientHello acked\n");
}

static void srvrun_cold_start(
    const srvrun_step_ctx* ctx, int slot, wired_mspan dg) {
  int r = srvrun_on_initial(ctx, slot, &ctx->st->conns[slot], dg);
  if (r != SRVRUN_BOOT_PENDING) {
    srvrun_open_done(ctx, slot, r);
    return;
  }
  srvrun_boot_partial_ack(ctx, slot);
}

/* RFC 9000 13.3: resend c's cached accept flight verbatim -- same Initial,
 * same Handshake datagrams -- instead of stepping dg through the confirmed-
 * connection path, where an Initial-keyed retransmit would just fail to
 * decrypt and get silently dropped. */
static void srvrun_resend_boot_flight(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  srvrun_boot_send_initial(ctx->cfg, c, "server Initial resent\n");
  /* RFC 9002 6.2: a resend means the client is still waiting. Once the
   * WHOLE flight has gone out, any of its datagrams may be sitting in a
   * dropped packet, so rewind and replay from the start (without this a
   * single lost Handshake datagram deadlocked the handshake: the client
   * held the ServerHello and retransmitted its Initial forever, answered
   * only by verbatim Initial replays). While a tail is still withheld by
   * the antiamp budget, though, keep continuing FROM the tail -- an
   * unconditional rewind burned each budget grant re-sending datagrams
   * the client already had, and the amplificationlimit flight's tail
   * never went out at all (observed live: the client dropped the same
   * Handshake datagram 0 as a duplicate until its idle timeout). */
  if (c->boot_dgram_sent == c->boot_dgram_count) c->boot_dgram_sent = 0;
  srvrun_boot_send_hs_gated(ctx->cfg, c, wired_server_is_confirmed(&c->s));
  /* boot PTO: the client itself just proved it's reachable (this is
   * its own retransmit reaching us) -- push the boot PTO deadline out so the
   * timer-driven probe below does not also fire for the same round. */
  c->boot_pto_sent_ms = ctx->now_ms;
  c->boot_pto_count   = 0;
}

/* c is in the boot PTO's window at all -- up (accepted) but not
 * yet confirmed (srvrun_awaiting_confirm), and has actually sent a flight to
 * probe (boot_ini_len == 0 means nothing was ever cached, e.g. a slot still
 * mid-ClientHello-reassembly or a slot that failed to boot). */
static int srvrun_boot_pto_waiting(const srvrun_conn* c) {
  return srvrun_awaiting_confirm(c) && c->boot_ini_len != 0;
}

/* RFC 9002 6.2: 1 once c is in the boot PTO's window AND now_ms has crossed
 * its deadline (scaled by boot_pto_count's backoff, same formula
 * srvrun_sess_pto_due uses for an in-flight response, applied to the boot
 * flight's own single sent timestamp instead of a wired_sendsess log). */
static int srvrun_boot_pto_due(const srvrun_conn* c, u64 now_ms) {
  if (!srvrun_boot_pto_waiting(c)) return 0;
  return now_ms >=
         c->boot_pto_sent_ms + srvrun_pto_deadline_ms(c, c->boot_pto_count);
}

/* Resend the boot flight for a fired probe and restore its post-resend probe
 * count: srvrun_resend_boot_flight itself resets boot_pto_count to 0 (any
 * real send re-arms the deadline), which would erase this probe's own
 * budget spend -- put it back to `fired` right after so consecutive timer
 * probes keep climbing instead of resetting every single one. */
static void srvrun_boot_pto_resend(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int fired) {
  srvrun_resend_boot_flight(ctx, c);
  c->boot_pto_count = fired;
}

/* RFC 9002 6.2 boot-stage PTO: while awaiting confirm with a flight already
 * sent, resend the cached boot_ini/boot_hs verbatim once the deadline
 * elapses -- quic-interop-runner's handshakeloss/handshakecorruption drop the
 * server's first flight often enough that waiting on a client-triggered
 * retransmit alone (srvrun_resend_boot_flight) leaves the handshake to time
 * out. Tears the slot down once the probe budget is spent, the same policy
 * srvrun_pto_slot applies to an in-flight response (SRVRUN_PTO_MAX shared:
 * boot and post-confirm PTO are never both active for the same slot, RFC
 * 9002 6.2's budget is a per-connection policy either way). */
static void srvrun_boot_pto_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c     = &ctx->st->conns[slot];
  int          fired = c->boot_pto_count + 1;
  if (!srvrun_boot_pto_due(c, ctx->now_ms)) return;
  if (fired >= SRVRUN_PTO_MAX) {
    srvrun_free_slot(ctx->cfg, ctx->st, slot);
    return;
  }
  srvrun_boot_pto_resend(ctx, c, fired);
}

/* One slot's tick work on a poll timeout: post-confirm PTO probe/teardown,
 * boot-stage PTO probe/teardown (mutually exclusive -- srvrun_sess_waiting
 * requires c->up with no in-flight send session possible before confirm, and
 * srvrun_boot_pto_waiting requires !confirmed), then flush any queued
 * broadcast DATAGRAM -- split out so the loop below stays flat. */
static void srvrun_tick_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_pto_slot(ctx, slot);
  srvrun_boot_pto_slot(ctx, slot);
  srvrun_dg_slot(ctx, slot);
}

/* A poll timeout with responses or broadcast DATAGRAMs in flight: fire the
 * probe/flush pass over every waiting slot. */
static void srvrun_fire_ptos(const srvrun_cfg* cfg, srvrun_state* st) {
  srvrun_step_ctx ctx = {cfg, 0, st, clock_mono_ms(), 0};
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++) srvrun_tick_slot(&ctx, (int)i);
}

/* RFC 9001 4.6.1: dg is a 0-RTT datagram arriving on a slot still mid-boot
 * (not up yet) -- this boot's early keys do not exist yet to open it with,
 * so it goes straight into the boot accumulator's own 0-RTT buffer
 * (wired_srvboot_acc_feed's own dispatch) for srvrun_boot_flush_zerortt to
 * replay once the accumulator's Initial reassembly completes and keys are
 * derived. A slot already up (c->up) instead takes the live 1-RTT/0-RTT
 * step path (srvrun_step_and_reap), which opens directly with the
 * connection's now-installed keys. */
static int srvrun_boot_zerortt(srvrun_conn* c, wired_mspan dg) {
  if (c->up || !wired_srvboot_is_zerortt(dg.p, dg.n)) return 0;
  wired_srvboot_acc_feed(&c->boot, dg);
  return 1;
}

/* dg is a fresh cold-start Initial (srvrun_cold_start), a retransmit of one
 * already accepted but not yet confirmed (srvrun_resend_boot_flight), or a
 * 0-RTT datagram arriving ahead of this boot's keys (srvrun_boot_zerortt) --
 * dispatched to whichever applies. Returns 1 if any handled dg. */
static int srvrun_serve_boot(
    const srvrun_step_ctx* ctx, int slot, wired_mspan dg) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (srvrun_is_new(c, dg)) {
    srvrun_cold_start(ctx, slot, dg);
    return 1;
  }
  if (srvrun_is_boot_retransmit(c, dg)) {
    srvrun_resend_boot_flight(ctx, c);
    return 1;
  }
  return srvrun_boot_zerortt(c, dg);
}

/* c is up, unconfirmed, and still has boot datagrams the antiamp gate held
 * back -- the condition srvrun_boot_release_pending gates its send on. */
static int srvrun_boot_has_pending_tail(const srvrun_conn* c) {
  if (!c->up || wired_server_is_confirmed(&c->s)) return 0;
  return c->boot_dgram_sent < c->boot_dgram_count;
}

/* RFC 9000 8.1: a slot with boot datagrams still held back by the antiamp
 * gate gets another release attempt on EVERY datagram it receives before
 * confirmation -- not just an all-Initial retransmit (srvrun_is_boot_
 * retransmit's narrower trigger). The real amplificationlimit trace shows
 * the client ACKing Handshake packets it already has (not resending its
 * Initial) while waiting for the still-held-back tail; without this, that
 * growing boot_rx_bytes budget never gets spent and the tail sits forever. */
static void srvrun_boot_release_pending(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (srvrun_boot_has_pending_tail(c))
    srvrun_boot_send_hs_gated(ctx->cfg, c, 0);
}

/* 1 if ctx->peer's address differs from c->peer's -- the trigger for the
 * naive rebind-tracking below. Split out so the caller's branch count stays
 * low (the &&/|| that would otherwise inline here each cost lizard +1). */
static int srvrun_peer_changed(
    const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  return ctx->peer->port_be != c->peer.port_be ||
         ct_diffn(ctx->peer->addr, c->peer.addr, 16) != 0;
}

/* Test-only override forcing challenge_generate to behave as if
 * the RNG failed, the same override-flag shape as srvrun_test_set_shutdown
 * above -- getrandom(2) failing is not practically triggerable from a test,
 * so this is the seam. Always reset to 0 after the owning test (see
 * srvrun_test_set_shutdown's own callers for the convention). */
static int                          g_srvrun_path_challenge_force_fail;
__attribute__((unused)) static void srvrun_test_force_challenge_rng_fail(
    int v) {
  g_srvrun_path_challenge_force_fail = v;
}

/* RFC 9000 8.2.2: generate this rebind's 8-byte PATH_CHALLENGE data. Returns
 * 0 (and writes nothing meaningful to data) on RNG failure, so the caller
 * never arms/sends an unpredictable-in-name-only (actually zero or stale)
 * challenge. */
static int srvrun_gen_path_challenge(u8 data[QUIC_PATH_DATA]) {
  if (g_srvrun_path_challenge_force_fail) return 0;
  return challenge_generate(data);
}

/* RFC 9000 8.2/9.3: a rebind just detected by srvrun_rebind_peer arms this
 * connection's migrate state machine and sends a PATH_CHALLENGE to the new
 * peer -- c->peer must already be updated to ctx->peer before this runs (the
 * challenge has to reach the path being validated). A generation failure
 * leaves migrate un-challenged and sends nothing: challenged==0 means
 * a later PATH_RESPONSE cannot spuriously validate (quic_migrate_validate's
 * own precondition), matching "no challenge was ever actually issued". */
static void srvrun_arm_path_challenge(const srvrun_cfg* cfg, srvrun_conn* c) {
  u8 data[QUIC_PATH_DATA];
  if (!srvrun_gen_path_challenge(data)) return;
  c->migrate.handshake_confirmed = 1; /* only reachable post-confirm */
  quic_migrate_detect(&c->migrate);
  quic_migrate_challenge(&c->migrate);
  bytes_memcpy(c->path_challenge_data, data, QUIC_PATH_DATA);
  srvrun_send_path_challenge(cfg, c, data);
}

/* RFC 9000 9 (naive subset, quic-interop-runner's rebind-port/rebind-addr):
 * once a connection is past the boot/handshake window, follow its source
 * address if a datagram arrives from a different one -- a NAT re-mapping a
 * client's port, or the client switching networks, must not orphan the
 * connection's reply path. c->peer is updated the moment the change is seen
 * (still NOT gated on path validation, see below), and a PATH_CHALLENGE
 * (RFC 9000 8.2) is issued to the new path so quic-interop-runner's rebind-
 * port/rebind-addr judge (which checks for a PATH_CHALLENGE on the first
 * server packet sent to the new path) is satisfied.
 *
 * Deliberately out of scope for this slice: RFC 9000 9.4's
 * congestion-control/RTT reset on a confirmed migration, 8.2.1's send-volume
 * limit on a not-yet-validated path, actually switching to a new connection
 * ID (quic_migrate_confirm is never called here), and tracking more than one
 * path at once (srvrun_conn holds a single quic_migrate + a single 8-byte
 * challenge, see their own doc comments) are all left undone -- this is
 * still the naive subset, now with a real PATH_CHALLENGE/PATH_RESPONSE round
 * trip layered on top rather than full RFC 9000 9 path validation.
 *
 * Deliberate scope decision, documented rather than fixed: a
 * PATH_RESPONSE's own source address is never checked against the path it is
 * validating (see srvrun_apply_path_response below) -- only its 8-byte data
 * is compared. This does not weaken the pre-existing hole one line up: c->
 * peer is *already* updated (and PATH_CHALLENGE already sent to the forged
 * address) the instant a spoofed source address arrives with a known DCID,
 * before any response round trip occurs at all, because this SDK's receive
 * routing is DCID-based, not address-based, by design (srvrun_find_slot).
 * Adding a source-address check on the PATH_RESPONSE side would not close
 * that hole -- an attacker able to forge the rebind in the first place can
 * equally forge (or simply relay) a matching PATH_RESPONSE from the same
 * spoofed address. The real fix is RFC 9000 9.5-style per-path validation
 * gating c->peer's update on success, not a response-side address check;
 * that is a separate task from this one (naive-rebind-plus-challenge). */
static void srvrun_rebind_peer(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (srvrun_awaiting_confirm(c)) return;
  if (!srvrun_peer_changed(ctx, c)) return;
  c->peer = *ctx->peer;
  srvrun_arm_path_challenge(ctx->cfg, c);
}

/* 1 if dg leads with a long-header Handshake packet (first byte 0b1110xxxx,
 * RFC 9000 17.2) -- readable without any keys. */
static int srvrun_leads_handshake(wired_mspan dg) {
  return dg.n != 0 && (dg.p[0] & 0xf0) == 0xe0;
}

/* RFC 9000 19.20: a confirmed connection receiving a Handshake-space probe
 * means the client never got the one-time confirmation datagram (it would
 * have dropped its Handshake keys otherwise) -- replay the cached
 * confirmation so HANDSHAKE_DONE still reaches it. Without this, one lost
 * confirmation datagram left the client PTO-retransmitting its Finished
 * until its own idle timeout (observed live under the interop runner's 30%
 * loss profile). */
static void srvrun_reconfirm(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8                 out[512];
  wired_obuf         ob   = obuf_of(out, sizeof out);
  wired_srvloop_conn conn = {&c->l, &c->s};
  if (!wired_srvloop_reconfirm(&conn, &ob)) return;
  srvrun_send(
      ctx->cfg, c, wired_span_of(ob.p, ob.len), "confirmation resent\n");
}

static void srvrun_reconfirm_on_hs_probe(
    const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg) {
  if (!wired_server_is_confirmed(&c->s)) return;
  if (!srvrun_leads_handshake(dg)) return;
  srvrun_reconfirm(ctx, c);
}

static void srvrun_serve_slot(
    const srvrun_step_ctx* ctx, int slot, wired_mspan dg) {
  srvrun_conn* c       = &ctx->st->conns[slot];
  int          booting = srvrun_awaiting_confirm(c);
  c->last_ms = ctx->now_ms; /* RFC 9000 10.1: activity resets idle age */
  /* RFC 9000 8.1: every physically received byte counts toward this path's
   * antiamp budget, whether or not dg turns out to parse. */
  c->boot_rx_bytes += dg.n;
  /* RFC 9000 13.4 / RFC 9002 19.3.2: every datagram's ECN codepoint counts
   * toward this connection's cumulative total, whether or not it parses --
   * same "every physically received byte/datagram counts" rule as
   * boot_rx_bytes above. */
  wired_srvloop_ecn_note(&c->l, ctx->ecn);
  int consumed = srvrun_serve_boot(ctx, slot, dg);
  /* confirm may have landed inside serve_boot: seed the RTT estimators
   * from the boot flight's round trip either way (no-op off the edge). */
  srvrun_seed_boot_rtt(c, booting, ctx->now_ms);
  if (consumed) return;
  if (c->up) {
    srvrun_rebind_peer(ctx, c);
    srvrun_reconfirm_on_hs_probe(ctx, c, dg);
    srvrun_step_and_reap(ctx, slot, dg);
  }
  srvrun_boot_release_pending(ctx, c);
}

/* dg's DCID as a span into dg, or a 0-length span if dg is too short to carry
 * the DCID length it claims (quic_dcidresolve_dcid can't tell that apart from
 * a legitimate zero-length CID on its own, so reject dcid_len < 0 first). */
static wired_span srvrun_dcid(wired_mspan dg, u8 short_hdr_len) {
  int dcid_len = quic_dcidresolve_len(dg, short_hdr_len);
  if (dcid_len < 0) return wired_span_of(0, 0);
  return quic_dcidresolve_dcid(dg, dcid_len);
}

/* Find the live slot this datagram's DCID matches. -1 if none does (the
 * datagram is malformed, or its DCID belongs to no connection this process
 * has open). */
static int srvrun_find_slot(const srvrun_step_ctx* ctx, wired_span dcid) {
  if (dcid.p == 0) return -1;
  return quic_conntable_find(
      ctx->st->table, QUIC_CONNTABLE_CAP, dcid.p, (u8)dcid.n);
}

/* Claim a free slot for a DCID no live connection matches. Only a fresh
 * Initial may open a new slot (RFC 9000 7) — a non-Initial datagram with an
 * unrecognized DCID (e.g. one arriving mid-migration, which this server does
 * not yet track, RFC 9000 9) is dropped instead of burning a slot per
 * datagram. Once graceful shutdown has been requested no new slot is claimed
 * either, so a brand-new client cannot start a connection during drain. -1 if
 * dcid is malformed, is_initial is false, shutdown is pending, or the table
 * is full. */
static int srvrun_claim_refused(wired_span dcid, int is_initial) {
  return dcid.p == 0 || !is_initial || srvrun_shutdown_requested();
}

static int srvrun_claim_slot(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial) {
  if (srvrun_claim_refused(dcid, is_initial)) return -1;
  return quic_conntable_insert(
      ctx->st->table, QUIC_CONNTABLE_CAP, dcid.p, (u8)dcid.n);
}

/* AF_XDP core-routing (see wired_srvrun_opt.core_id): only in XDP mode with a
 * non-negative core_id does a freshly generated CID get its leading byte
 * overwritten with this worker's own core/queue index, so the BPF filter can
 * key an XSKMAP lookup off the CID instead of the NIC's rx_queue_index.
 * Neither guard is a validating boundary -- quic_ncid_worker_encode itself
 * already no-ops (returns < 0) on a zero-length cid; there is simply nothing
 * to embed into. */
static int srvrun_xdp_core_routing(const srvrun_cfg* cfg) {
  return cfg->xdp != 0 && cfg->core_id >= 0;
}

/* One place both a fresh accept (srvrun_open_slot) and any future additional-
 * CID issuance route through, so both share the exact same core-id embedding
 * policy (see NEW_CONNECTION_ID note in srvrun.h's core_id doc). Returns 1 on
 * success matching cid_generate's own contract. */
static int srvrun_issue_cid(const srvrun_cfg* cfg, u8* cid, u8 cid_len) {
  if (!cid_generate(cid, cid_len)) return 0;
  if (srvrun_xdp_core_routing(cfg))
    quic_ncid_worker_encode(cid, cid_len, 8, (u32)cfg->core_id);
  return 1;
}

/* The congestion controller a fresh connection starts with (RFC 9002 7):
 * cfg->cc_algo == 0 means the build's default; a non-zero runtime choice
 * (--cc-algo) wins. Cubic by default, matching what the mainstream stacks
 * (quic-go, quiche) run out of the box, so untuned benchmark preconditions
 * are equal; a build wanting NewReno overrides -DWIRED_CC_ALGO_DEFAULT=0
 * (an explicit runtime NewReno request is indistinguishable from "unset"
 * because QUIC_CC_ALGO_NEWRENO is itself 0). */
#ifndef WIRED_CC_ALGO_DEFAULT
#define WIRED_CC_ALGO_DEFAULT QUIC_CC_ALGO_CUBIC
#endif
static int srvrun_cc_algo(const srvrun_cfg* cfg) {
  return cfg->cc_algo ? cfg->cc_algo : WIRED_CC_ALGO_DEFAULT;
}

/* Claim and initialize a fresh slot for dcid: record the peer, and generate
 * this slot's own scid (never cfg->id's fixed one — every slot sharing it
 * would collapse conntable's routing back to a single slot). Returns the slot
 * index, or -1 if claiming fails or scid generation fails (in which case the
 * claimed slot is freed again rather than run with an all-zero scid). */
static int srvrun_open_slot(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial) {
  int slot = srvrun_claim_slot(ctx, dcid, is_initial);
  if (slot < 0) return -1;
  ctx->st->conns[slot]              = (srvrun_conn){0};
  ctx->st->conns[slot].peer         = *ctx->peer;
  ctx->st->conns[slot].qlog_slot    = (u64)slot;
  ctx->st->conns[slot].l.qlog_path  = ctx->cfg->qlog_path;
  ctx->st->conns[slot].l.qlog_group = (u64)slot;
  quic_cc_init_algo(&ctx->st->conns[slot].cc, srvrun_cc_algo(ctx->cfg));
  quic_hystart_init(&ctx->st->conns[slot].hs);
  quic_rtt_init(&ctx->st->conns[slot].rtt);
  quic_pmtu_init(&ctx->st->conns[slot].pmtu);
  ctx->st->conns[slot].pmtu_probe_pn = SRVRUN_PMTU_NO_PROBE;
  if (srvrun_issue_cid(
          ctx->cfg, ctx->st->conns[slot].scid, ctx->cfg->id->scid_len))
    return slot;
  quic_conntable_remove(ctx->st->table, QUIC_CONNTABLE_CAP, slot);
  return -1;
}

/* Drive one received datagram: resolve it to a connection slot by DCID (a
 * fresh slot only for an unrecognized DCID on a new Initial, RFC 9000 5.1/7)
 * and serve it there. Silently drops a datagram that matches no slot and
 * cannot claim or initialize a new one. */
/* RFC 9000 8.1.2 forced address validation (the interop retry testcase):
 * a fixed process-lifetime HMAC key for Retry tokens.
 * ponytail: fixed key, no rotation -- same policy as the session-ticket key
 * (respond.c); a real deployment rotates both. */
static const u8 g_srvrun_retry_key[QUIC_RETRYTOKEN_KEY] = {
    0x77, 0x69, 0x72, 0x65, 0x64, 0x2d, 0x72, 0x74, 0x72, 0x79, 0x2d,
    0x6b, 0x65, 0x79, 0x2d, 0x30, 0x77, 0x69, 0x72, 0x65, 0x64, 0x2d,
    0x72, 0x74, 0x72, 0x79, 0x2d, 0x6b, 0x65, 0x79, 0x2d, 0x31};

/* Seal DCID=h->scid/SCID=scid/token into pkt with a garbage tag; the caller
 * patches the real RFC 9001 5.8 tag in afterward. Returns bytes written, or
 * 0 on overflow. */
static usz srvrun_retry_pkt_build(
    const quic_lhdr* h, const u8 scid[8], wired_span token, u8* pkt, usz cap) {
  quic_retry_desc d = {1, h->scid, wired_span_of(scid, 8), token, pkt};
  return quic_retry_build(pkt, cap, &d);
}

/* scid + wire token for the Retry answering h, or 0 tn on RNG/overflow
 * failure. */
static void srvrun_retry_prep(
    const srvrun_step_ctx* ctx,
    const quic_lhdr*       h,
    u8                     scid[8],
    u8                     token[QUIC_RETRYTOKEN_WIRE_MAX],
    usz*                   tn) {
  *tn = 0;
  if (!cid_generate(scid, 8)) return;
  *tn = quic_retrytoken_wire_make(
      g_srvrun_retry_key,
      wired_span_of((const u8*)ctx->peer, sizeof(*ctx->peer)), h->dcid, token);
}

/* Assemble the Retry with its real integrity tag and send it: pkt already
 * carries a garbage tag (srvrun_retry_pkt_build); patch in the RFC 9001 5.8
 * tag computed over everything before it. */
static void srvrun_retry_finish(
    const srvrun_step_ctx* ctx, const quic_lhdr* h, u8* pkt, usz n) {
  retry_tag(
      h->dcid, wired_span_of(pkt, n - QUIC_RETRY_TAG_LEN),
      pkt + n - QUIC_RETRY_TAG_LEN);
  srvrun_tx(ctx->cfg, ctx->peer, wired_span_of(pkt, n));
}

/* Build and send the stateless Retry answering h (an Initial without a
 * token): DCID = the client's SCID (RFC 9000 7.2), a fresh random SCID the
 * client will derive its next Initial keys from (RFC 9001 5.2), the wire
 * token binding the peer address to h's DCID (the true ODCID), and the
 * RFC 9001 5.8 integrity tag patched over the assembled packet. */
static void srvrun_send_retry(const srvrun_step_ctx* ctx, const quic_lhdr* h) {
  u8  scid[8], token[QUIC_RETRYTOKEN_WIRE_MAX], pkt[128];
  usz tn, n;
  srvrun_retry_prep(ctx, h, scid, token, &tn);
  if (tn == 0) return;
  n = srvrun_retry_pkt_build(
      h, scid, wired_span_of(token, tn), pkt, sizeof pkt);
  if (n == 0) return;
  srvrun_retry_finish(ctx, h, pkt, n);
}

/* Verify a presented token against the peer address; on success *odcid is
 * the embedded original DCID (a view into dg's token bytes). */
static int srvrun_retry_token_ok(
    const srvrun_step_ctx* ctx, wired_span token, wired_span* odcid) {
  return quic_retrytoken_wire_verify(
      g_srvrun_retry_key,
      wired_span_of((const u8*)ctx->peer, sizeof(*ctx->peer)), token, odcid);
}

/* h carries a token: consumed either way -- valid recovers *odcid and lets
 * the caller continue serving (0), invalid drops the datagram (1). */
static int srvrun_retry_gate_tokened(
    const srvrun_step_ctx* ctx, const quic_lhdr* h, wired_span* odcid) {
  return !srvrun_retry_token_ok(ctx, h->token, odcid);
}

/* dg is already known to be a fresh Initial the force_retry gate applies to
 * (srvrun_retry_applies): a valid token continues serving (0, *odcid set),
 * anything else is consumed here -- a malformed header, no token (a Retry
 * goes out), or an invalid token (dropped). */
static int srvrun_retry_gate(
    const srvrun_step_ctx* ctx, wired_mspan dg, wired_span* odcid) {
  quic_lhdr h;
  if (!quic_lhdr_parse(wired_span_of(dg.p, dg.n), 1, &h)) return 1;
  if (h.token.n != 0) return srvrun_retry_gate_tokened(ctx, &h, odcid);
  srvrun_send_retry(ctx, &h);
  return 1;
}

/* Stash the token-recovered ODCID on the freshly claimed slot so the accept
 * path advertises it (srvrun_slot_id -> srvboot_tp_odcid). */
static void srvrun_note_retry_odcid(srvrun_conn* c, wired_span odcid) {
  if (odcid.n == 0 || odcid.n > WIRED_MAX_CID_LEN) return;
  bytes_memcpy(c->retry_odcid, odcid.p, odcid.n);
  c->retry_odcid_len = (u8)odcid.n;
}

/* Answer an unsupported-version datagram with Version Negotiation, straight
 * to the sender — no connection slot is involved (RFC 9000 5.2.2). Returns 1
 * when the datagram was consumed this way. */
static int srvrun_vneg(const srvrun_step_ctx* ctx, wired_mspan dg) {
  u8  vn[64];
  usz n = wired_srvboot_vneg(wired_span_of(dg.p, dg.n), vn, sizeof vn);
  if (!n) return 0;
  srvrun_tx(ctx->cfg, ctx->peer, wired_span_of(vn, n));
  return 1;
}

/* 1 while slot i is a claimed boot that has absorbed something but is not
 * up yet -- the only state whose scid a switched client DCID may name. */
static int srvrun_boot_pending(const srvrun_conn* c) {
  return !c->up && c->boot.any;
}

/* 1 if slot i is a still-pending boot whose own scid equals dcid. */
static int srvrun_boot_scid_match(
    const srvrun_step_ctx* ctx, usz i, wired_span dcid) {
  const srvrun_conn* c = &ctx->st->conns[i];
  if (!srvrun_boot_pending(c)) return 0;
  if (dcid.n != ctx->cfg->id->scid_len) return 0;
  return ct_diffn(c->scid, dcid.p, dcid.n) == 0;
}

/* The pending boot slot whose own scid is dcid, or -1: after a
 * partial-ClientHello ack the client switches its DCID to that scid
 * (RFC 9000 7.2) while the routing entry still keys the ODCID -- without
 * this, the switched retransmits claimed a competing slot with a
 * different initial_source_connection_id. */
static int srvrun_find_boot_scid(const srvrun_step_ctx* ctx, wired_span dcid) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_boot_scid_match(ctx, i, dcid)) return (int)i;
  return -1;
}

/* The slot dg routes to: an existing DCID match, a pending boot the client
 * switched its DCID onto, else a fresh claim (only for a new Initial); -1
 * when none. */
static int srvrun_route(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  int slot = srvrun_find_slot(ctx, dcid);
  if (slot >= 0) return slot;
  slot = srvrun_find_boot_scid(ctx, dcid);
  if (slot >= 0) return slot;
  return srvrun_open_slot(ctx, dcid, wired_srvboot_is_initial(dg.p, dg.n));
}

/* RFC 9000 10.1: how long a slot must have been idle before a full table may
 * reclaim it for a new client. 1s keeps anything actually talking (voice
 * sends every 20ms, keep-alive scales are far above this) out of reach of an
 * Initial flood, while an abruptly-vanished client's slot is reusable within
 * a human "reconnect right away" window instead of the 30s idle sweep. */
#define WIRED_SRVRUN_EVICT_GRACE_MS 1000

/* 1 if every conntable entry is live -- eviction is strictly the full-table
 * fallback; with a free entry the normal claim path must be the one that
 * admits (a claim that failed for any other reason must not cost a live
 * connection its slot). */
static int srvrun_table_full(const srvrun_state* st) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (!st->table[i].live) return 0;
  return 1;
}

/* 1 if slot i beats the best-so-far eviction candidate: only a busy slot
 * competes at all (a freed slot's stale last_ms must never make it look
 * "oldest"), and among busy slots the smallest last_ms wins. */
static int srvrun_evict_prefer(const srvrun_state* st, usz i, int best) {
  if (!srvrun_slot_busy(&st->conns[i])) return 0;
  return best < 0 || st->conns[i].last_ms < st->conns[best].last_ms;
}

/* The oldest busy slot, -1 if none is busy. Whether it is idle enough to
 * actually evict is the caller's grace check -- the oldest busy slot being
 * under the grace floor means no slot at all is over it. */
static int srvrun_evict_candidate(const srvrun_state* st) {
  int best = -1;
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_evict_prefer(st, i, best)) best = (int)i;
  return best;
}

static int srvrun_evict_grace_ok(const srvrun_step_ctx* ctx, int cand) {
  return cand >= 0 && ctx->now_ms - ctx->st->conns[cand].last_ms >=
                          WIRED_SRVRUN_EVICT_GRACE_MS;
}

/* Eviction applies only when a datagram eligible to open a connection at
 * all (fresh Initial, sane DCID, no shutdown pending -- the same gate the
 * normal claim uses) found the table genuinely full. */
static int srvrun_evict_applies(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial) {
  return !srvrun_claim_refused(dcid, is_initial) && srvrun_table_full(ctx->st);
}

/* Full-table fallback for a new client's Initial: free the oldest slot idle
 * at least the grace floor and claim its place, all within this one
 * datagram's processing (no candidate is remembered across steps -- a slot
 * picked earlier could have been freed or sprung back to life by the time a
 * later step fired). Returns the freshly opened slot, or -1 (caller sends
 * the refusal) when no slot has been idle long enough. */
static int srvrun_evict_for_initial(
    const srvrun_step_ctx* ctx, wired_span dcid, int is_initial) {
  int cand;
  if (!srvrun_evict_applies(ctx, dcid, is_initial)) return -1;
  cand = srvrun_evict_candidate(ctx->st);
  if (!srvrun_evict_grace_ok(ctx, cand)) return -1;
  srvrun_free_slot(ctx->cfg, ctx->st, cand);
  return srvrun_open_slot(ctx, dcid, is_initial);
}

/* RFC 9000 10.3: a stateless reset answers a short-header datagram whose
 * DCID matches no live connection -- the client is talking to a server that
 * lost (or never had) its state, and without the reset it keeps
 * retransmitting into silence until its own idle timeout. Never for an
 * Initial (that path gets the CONNECTION_CLOSE refusal instead), and never
 * for a datagram too small to answer with something strictly smaller
 * (RFC 9000 10.3.3's loop-prevention rule: every reset sent must be smaller
 * than the packet that triggered it). */
static int srvrun_sreset_applies(wired_span dcid, wired_mspan dg) {
  return dcid.p != 0 && !wired_srvboot_is_initial(dg.p, dg.n) &&
         dg.n > QUIC_SRESET_MIN;
}

/* Build the reset for dcid: random-looking bytes ending in the token the
 * connection's handshake advertised (same quic_sreset_key_derive derivation
 * srvboot used, so the token survives a server restart -- the exact
 * situation this packet exists for). Capacity is clamped below the
 * triggering datagram's size (10.3.3). */
static int srvrun_seal_stateless_reset(
    const srvrun_cfg* cfg, wired_span dcid, usz trigger_len, wired_obuf* out) {
  u8  key[QUIC_SRESET_KEY];
  usz cap = u64_min(out->cap, trigger_len - 1);
  usz len;
  quic_sreset_key_derive(cfg->id->cert_seed, key);
  if (!quic_sreset_build(
          key, dcid.p, dcid.n, trigger_len, rng_bytes, out->p, cap, &len))
    return 0;
  out->len = len;
  return 1;
}

static void srvrun_send_stateless_reset(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  u8         out[128];
  wired_obuf ob = obuf_of(out, sizeof out);
  if (!srvrun_sreset_applies(dcid, dg)) return;
  if (!srvrun_seal_stateless_reset(ctx->cfg, dcid, dg.n, &ob)) return;
  srvrun_tx(ctx->cfg, ctx->peer, wired_span_of(out, ob.len));
}

/* srvrun_route plus the full-table eviction fallback (srvrun_evict_for_
 * initial). Routing to an existing slot always wins -- a retransmitted
 * Initial must reach its own connection, never trigger an eviction. */
static int srvrun_route_or_evict(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  int slot = srvrun_route(ctx, dcid, dg);
  if (slot >= 0) return slot;
  return srvrun_evict_for_initial(
      ctx, dcid, wired_srvboot_is_initial(dg.p, dg.n));
}

/* RFC 9000 5.2.2: whether a datagram that matched no slot and could not
 * claim a fresh one is a genuine new-connection attempt being turned away
 * (graceful shutdown or a full conntable) rather than something that was
 * never eligible to open one in the first place (a malformed/absent DCID or
 * a non-Initial packet) -- only the former deserves a refusal reply. */
static int srvrun_is_refusable_new_conn(wired_span dcid, wired_mspan dg) {
  return dcid.p != 0 && wired_srvboot_is_initial(dg.p, dg.n);
}

/* RFC 9000 5.2.2/19.19: build a transport CONNECTION_CLOSE(CONNECTION_REFUSED)
 * as an unpadded server Initial addressed to the client's own DCID/SCID, using
 * Initial keys derived from dcid (no live connection or session state is
 * needed -- Initial keys come from the DCID alone, RFC 9001 5.2). Returns 1
 * with out->len set, 0 on a malformed header or overflow. */
static int srvrun_seal_new_conn_refusal(
    wired_span dg, const u8 scid[8], wired_obuf* out) {
  quic_lhdr             h;
  u8                    fr[8];
  usz                   fn;
  quic_conn_close_frame cc = {0, QUIC_ERR_CONNECTION_REFUSED, 0, 0, 0};
  quic_srvwire_seal_in  wi;
  if (!quic_lhdr_parse(dg, 1, &h)) return 0;
  fn = quic_frame_put_conn_close(fr, sizeof fr, &cc);
  if (!fn) return 0;
  wi = (quic_srvwire_seal_in){
      h.dcid, h.scid, wired_span_of(scid, 8), 0, -1, wired_span_of(fr, fn), 0};
  return quic_srvwire_seal_initial_frames_lean(&wi, out);
}

/* Seal and send the refusal above, addressed to ctx->peer. A server-chosen
 * SCID of zero length is fine (RFC 9000 7.2 allows an empty CID); this
 * connection ends immediately after, so no routing table entry is needed
 * for it. */
static void srvrun_send_new_conn_refusal(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  u8         out[128];
  u8         scid[8] = {0};
  wired_obuf ob      = obuf_of(out, sizeof out);
  if (!srvrun_is_refusable_new_conn(dcid, dg)) return;
  if (!srvrun_seal_new_conn_refusal(wired_span_of(dg.p, dg.n), scid, &ob))
    return;
  srvrun_tx(ctx->cfg, ctx->peer, wired_span_of(out, ob.len));
}

/* 1 if force_retry is on and dg is a fresh Initial (the gate's precondition
 * before any slot lookup). */
static int srvrun_retry_wanted(const srvrun_step_ctx* ctx, wired_mspan dg) {
  return ctx->cfg->force_retry && wired_srvboot_is_initial(dg.p, dg.n);
}

/* The retry gate applies only to an Initial whose DCID matches no live
 * slot: a claimed slot's own retransmits already passed validation once,
 * and a post-Retry Initial routes by the token path instead. */
static int srvrun_retry_applies(
    const srvrun_step_ctx* ctx, wired_span dcid, wired_mspan dg) {
  if (!srvrun_retry_wanted(ctx, dg)) return 0;
  if (srvrun_find_slot(ctx, dcid) >= 0) return 0;
  return srvrun_find_boot_scid(ctx, dcid) < 0;
}

/* 1 if the force_retry gate consumed dg (a Retry went out, or an invalid
 * token was dropped) -- the caller stops here either way. */
static int srvrun_retry_consumed(
    const srvrun_step_ctx* ctx,
    wired_span             dcid,
    wired_mspan            dg,
    wired_span*            odcid) {
  if (!srvrun_retry_applies(ctx, dcid, dg)) return 0;
  return srvrun_retry_gate(ctx, dg, odcid);
}

/* Route dg to its slot and serve it there, threading a retry-recovered
 * ODCID (if any) onto the freshly claimed slot before the accept path
 * reads it (srvrun_slot_id -> srvboot_tp_odcid). */
static void srvrun_route_and_serve(
    const srvrun_step_ctx* ctx,
    wired_span             dcid,
    wired_mspan            dg,
    wired_span             odcid) {
  int slot = srvrun_route_or_evict(ctx, dcid, dg);
  if (slot < 0) {
    srvrun_send_new_conn_refusal(ctx, dcid, dg);
    srvrun_send_stateless_reset(ctx, dcid, dg);
    return;
  }
  if (odcid.n) srvrun_note_retry_odcid(&ctx->st->conns[slot], odcid);
  srvrun_serve_slot(ctx, slot, dg);
}

/* RFC 9000 14.1/14: a datagram carrying an Initial packet below the
 * 1200-byte floor violates the size constraint and is discarded outright --
 * never treated as a connection error, since a malicious or misbehaving
 * middlebox (not the peer) is the more likely cause (RFC 9000 14). */
static int srvrun_size_violation(wired_mspan dg) {
  return wired_srvboot_is_initial(dg.p, dg.n) &&
         !quic_middlebox_initial_ok(dg.n);
}

/* dg past the size-violation gate: version-negotiate, consume a retry, or
 * route it to its slot. Split from srvrun_serve so neither carries more than
 * one guard beyond its own entry check (CCN). */
static void srvrun_serve_sized(const srvrun_step_ctx* ctx, wired_mspan dg) {
  wired_span dcid  = srvrun_dcid(dg, ctx->cfg->id->scid_len);
  wired_span odcid = {0, 0};
  if (srvrun_vneg(ctx, dg)) return;
  if (srvrun_retry_consumed(ctx, dcid, dg, &odcid)) return;
  srvrun_route_and_serve(ctx, dcid, dg, odcid);
}

static void srvrun_serve(const srvrun_step_ctx* ctx, wired_mspan dg) {
  if (srvrun_size_violation(dg)) return;
  srvrun_serve_sized(ctx, dg);
}

/* so_busy_poll_us > 0 enables SO_BUSY_POLL on fd; best-effort like
 * SO_REUSEPORT, a no-op when <= 0 or unsupported by the kernel/driver. */
static void srvrun_maybe_busy_poll(i64 fd, int so_busy_poll_us) {
  if (so_busy_poll_us > 0) wired_udp_busy_poll_enable(fd, so_busy_poll_us);
}

/* SO_PREFER_BUSY_POLL only has kernel effect when SO_BUSY_POLL is also
 * enabled; hoisted so the caller's `if` stays a single condition (CCN). */
static int srvrun_prefer_busy_poll_wanted(const wired_srvrun_opt* opt) {
  return opt->so_busy_poll_us > 0 && opt->so_prefer_busy_poll;
}

/* so_prefer_busy_poll/so_busy_poll_budget: best-effort like SO_REUSEPORT and
 * srvrun_maybe_busy_poll above, each independently opt-in. */
static void srvrun_maybe_prefer_busy_poll(i64 fd, const wired_srvrun_opt* opt) {
  if (srvrun_prefer_busy_poll_wanted(opt))
    wired_udp_prefer_busy_poll_enable(fd, 1);
}

static void srvrun_maybe_busy_poll_budget(i64 fd, const wired_srvrun_opt* opt) {
  if (opt->so_busy_poll_budget > 0)
    wired_udp_busy_poll_budget_set(fd, opt->so_busy_poll_budget);
}

/* -1 = disabled (wired_srvrun_opt's own sentinel; see srvrun.h). */
static void srvrun_maybe_incoming_cpu(i64 fd, const wired_srvrun_opt* opt) {
  if (opt->incoming_cpu >= 0) wired_udp_incoming_cpu_set(fd, opt->incoming_cpu);
}

/* Bind a UDP socket on port. Returns the fd, or <0 on failure. */
static i64 srvrun_listen(u16 port, const wired_srvrun_opt* opt) {
  quic_sockaddr sa;
  i64           fd = wired_udp_socket();
  if (fd < 0) return fd;
  /* Best-effort: lets multiple srvworkers children share one port. A
   * single-worker run does not need it, so a failure here is not fatal --
   * fall through to bind unconditionally. */
  wired_udp_reuseport_enable(fd);
  /* RFC 9000 13.4 / RFC 9002 19.3.2: best-effort like reuseport above -- ECT(0)
   * marking on send and IP_TOS cmsg on receive are an optimization an ECN-
   * unaware kernel/NIC simply won't provide, never a bind blocker. */
  wired_udp_ect0_enable(fd);
  wired_udp_recvtos_enable(fd);
  /* RFC 8899 4.5: this connection runs its own DPLPMTUD search (quic_pmtu via
   * connrunner's probe drive), so the kernel's own PMTU enforcement/caching
   * must be suspended for this socket's flows -- best-effort like the ECN
   * options above, never a bind blocker. */
  wired_udp_pmtu_probe_enable(fd);
  srvrun_maybe_busy_poll(fd, opt->so_busy_poll_us);
  srvrun_maybe_prefer_busy_poll(fd, opt);
  srvrun_maybe_busy_poll_budget(fd, opt);
  srvrun_maybe_incoming_cpu(fd, opt);
  wired_udp_addr(&sa, port, (const u8[4]){0, 0, 0, 0});
  if (wired_udp_bind(fd, &sa) < 0) return -1;
  return fd;
}

/* RFC 9114 5.2 shutdown grace period: once GOAWAY has gone out, poll for at
 * most this many 200ms ticks (~5s total) before closing regardless of
 * whether any connection is still open.
 * ponytail: a fixed tick budget, not a real deadline/clock — simplest thing
 * that reliably terminates; swap for a monotonic deadline if 5s is ever
 * wrong for a real workload. */
#define SRVRUN_DRAIN_TICKS 25
#define SRVRUN_DRAIN_TICK_MS 200

/* Serve a recvmmsg batch message by message, in arrival order. One idle
 * sweep and one clock read cover the whole batch; each message's own source
 * address is the peer a fresh slot records (RFC 9000 5.1). */
static void srvrun_serve_batch(
    const srvrun_cfg* cfg, srvrun_state* st, const quic_mmsg_buf* bufs, i64 n) {
  u64 now = clock_mono_ms();
  srvrun_sweep_idle(cfg, st, now); /* lazy: swept on each arrival */
  for (i64 i = 0; i < n; i++) {
    srvrun_step_ctx ctx = {cfg, &bufs[i].src, st, now, bufs[i].ecn};
    srvrun_serve(&ctx, wired_mspan_of(bufs[i].buf.p, bufs[i].len));
  }
}

/* One receive+serve step: drain up to a batch of waiting datagrams in one
 * recvmmsg (it blocks for the first only, then returns what else is queued)
 * and serve each. Pending SIGHUP is consumed once per step (same granularity
 * as SIGTERM's shutdown flag): a reload lands before the batch is served, so
 * a fresh Initial arriving right after a reload already sees the new
 * identity. */
/* 1 if c needs the poll-timeout tick to keep making progress: a response
 * awaiting ACKs/a queued DATAGRAM (srvrun_has_outbound), or a boot flight
 * awaiting confirm (srvrun_has_boot_outbound). */
static int srvrun_slot_waiting(const srvrun_conn* c) {
  return srvrun_has_outbound(c) || srvrun_has_boot_outbound(c);
}

/* Wait for input: block in recvmmsg unless some slot needs the poll-timeout
 * tick (srvrun_slot_waiting), in which case poll with the probe tick so
 * silence still makes progress.
 * @return 1 to receive, 0 when the tick expired instead. */
static int srvrun_any_waiting(const srvrun_state* st) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_slot_waiting(&st->conns[i])) return 1;
  return 0;
}

/* Non-blocking receive path: the busy_poll spin loop and the AF_XDP driver
 * both drain without ever waiting in poll(2). */
static int srvrun_polling(const srvrun_cfg* cfg) {
  return cfg->busy_poll || cfg->xdp != 0;
}

/* env->pto_next_ms/pto_spin: the PTO probe deadline for every driver. The
 * polling drivers never sleep in poll(2), so the poll-timeout probe pass in
 * srvrun_step is unreachable for them -- and the blocking driver's timeout
 * branch is just as unreachable for as long as continuous inbound traffic
 * keeps the socket readable within every 25ms window (a live relay under
 * steady voice uploads starved it for 30+ seconds, RFC 9002 6.2's probe
 * never firing). So the clocked pass runs for all drivers; pto_spin paces
 * the clock read below (1 on every 1024th call) for the spin drivers only,
 * since a blocking step already pays at least one syscall per iteration. */
static int srvrun_pto_due(const srvrun_cfg* cfg, wired_srvrun_env* env) {
  if (!srvrun_polling(cfg)) return 1;
  env->pto_spin++;
  return (env->pto_spin & 1023u) == 0;
}

/* The clocked probe pass: fire the PTOs on the SRVRUN_PTO_MS cadence
 * regardless of whether poll(2) ever times out (srvrun_pto_due's doc). */
static void srvrun_polling_ptos(const srvrun_cfg* cfg, srvrun_state* st) {
  u64 now;
  if (!srvrun_pto_due(cfg, cfg->env)) return;
  now = clock_mono_ms();
  if (now < cfg->env->pto_next_ms) return;
  cfg->env->pto_next_ms = now + SRVRUN_PTO_MS;
  srvrun_fire_ptos(cfg, st);
}

/* busy_poll=1 or xdp!=0: the blocking poll(2) itself is replaced by a non-
 * blocking return (the srvrun_any_waiting branch above is kept as-is; only
 * this leaf call changes). The actual non-blocking receive happens at the
 * recv step (srvrun_recv), so there is nothing left to wait for here. */
/* 1 if nothing requires a bounded wait: no response is awaiting ACKs, and
 * this instance owns SIGTERM/SIGHUP so an unbounded blocking recv can still
 * be interrupted. A srvthreads worker keeps SIGTERM/SIGHUP blocked for its
 * whole lifetime (no_signal_handlers), so only a timeout -- never a signal
 * -- can break it out of the loop to observe shutdown; it always takes the
 * bounded path below even with nothing in flight. */
static int srvrun_may_block_unbounded(const srvrun_cfg* cfg, srvrun_state* st) {
  if (cfg->no_signal_handlers) return 0;
  return !srvrun_any_waiting(st);
}

static int srvrun_wait_input(const srvrun_cfg* cfg, srvrun_state* st) {
  if (srvrun_polling(cfg)) return 1;
  if (srvrun_may_block_unbounded(cfg, st)) return 1;
  return quic_poll_wait_readable(cfg->fd, SRVRUN_PTO_MS) > 0;
}

/* AF_XDP rx_burst step: pause once on an empty burst, same spin-step shape
 * as wired_srvpoll_spin_step (srvrun_recv below). */
static i64 srvrun_recv_xdp(
    const srvrun_cfg* cfg, quic_mmsg_buf* bufs, usz nbufs) {
  i64 n = wired_srvxdp_rx_burst(cfg->xdp, bufs, nbufs);
  if (!n) wired_arch_pause();
  return n;
}

/* The batch receive call itself: AF_XDP when cfg->xdp is set, MSG_DONTWAIT
 * spin-step in busy_poll mode, the existing blocking recvmmsg otherwise
 * (byte-identical default path). */
static i64 srvrun_recv(const srvrun_cfg* cfg, quic_mmsg_buf* bufs, usz nbufs) {
  if (cfg->xdp) return srvrun_recv_xdp(cfg, bufs, nbufs);
  if (cfg->busy_poll) return wired_srvpoll_spin_step(cfg->fd, bufs, nbufs);
  return wired_udp_recvmmsg(cfg->fd, bufs, nbufs);
}

static void srvrun_step(
    const srvrun_cfg* cfg, srvrun_state* st, quic_mmsg_buf* bufs, usz nbufs) {
  i64 r;
  srvrun_reload_if_requested(cfg, cfg->env);
  srvrun_bcast_drain_self(st); /* other workers' broadcasts */
  srvrun_polling_ptos(cfg, st);
  if (!srvrun_wait_input(cfg, st)) {
    srvrun_fire_ptos(cfg, st);
  } else {
    r = srvrun_recv(cfg, bufs, nbufs);
    if (r > 0) srvrun_serve_batch(cfg, st, bufs, r);
  }
  /* Session-addressed datagrams queued by this step's callbacks (or left
   * from an interrupted prior step) go out before the loop waits again. */
  srvrun_dgring_drain(cfg, st);
}

/* Drain phase (RFC 9114 5.2): GOAWAY already sent to every live connection:
 * poll with a timeout instead of blocking forever, so the loop keeps making
 * progress toward the tick budget even if the peer sends nothing more.
 * Returns 1 once every connection has drained or the tick budget is spent
 * (the caller should stop), 0 to keep draining. */
static int srvrun_drain_tick(
    const srvrun_cfg* cfg, srvrun_state* st, quic_mmsg_buf* bufs, int tick) {
  if (quic_poll_wait_readable(cfg->fd, SRVRUN_DRAIN_TICK_MS) > 0)
    srvrun_step(cfg, st, bufs, SRVRUN_RX_BATCH);
  return srvrun_all_drained(st) || tick >= SRVRUN_DRAIN_TICKS;
}

/* Point each batch slot at env's own storage. */
static void srvrun_rx_init(wired_srvrun_env* env, quic_mmsg_buf* bufs) {
  for (usz i = 0; i < SRVRUN_RX_BATCH; i++)
    bufs[i].buf = wired_mspan_of(env->rxstorage[i], sizeof env->rxstorage[i]);
}

/* RFC 9114 8.1 / 9114-077: when about to close with H3_NO_ERROR, occasionally
 * substitute a reserved (grease) error code instead, so a peer's handling of
 * an unrecognized-but-valid code (9114-075: treated as equivalent to
 * H3_NO_ERROR) gets exercised on the wire -- same one-random-byte shape as
 * control_settings_grease_id (control_settings.c), applied to the error-code
 * space instead of the SETTINGS-identifier space. A failed RNG read skips
 * greasing, same fallback. */
static u64 srvrun_close_grease_id(void) {
  u8 b;
  if (!rng_bytes(&b, 1)) return 0;
  if (b & 1) return 0;
  return quic_h3_grease_value(b);
}

/* RFC 9114 5.2: once the drain grace period ends, any connection still up
 * (the peer never finished on its own) is closed by the server with an
 * application-level CONNECTION_CLOSE carrying H3_NO_ERROR -- the graceful
 * shutdown's own completion, distinct from GOAWAY (which merely announces
 * the intent to stop accepting new requests on it). quic_h3_error_send_value
 * substitutes an occasional grease code per connection (9114-077, above). */
static void srvrun_close_drained(const srvrun_cfg* cfg, srvrun_state* st) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (st->conns[i].up)
      srvrun_send_app_close(
          cfg, &st->conns[i],
          quic_h3_error_send_value(QUIC_H3_NO_ERROR, srvrun_close_grease_id()),
          wired_span_of(0, 0));
}

/* Receive datagrams until told to stop: normal service while no shutdown has
 * been requested; once requested, send GOAWAY to every live connection once
 * and drain for a bounded grace period (RFC 9114 5.2) before returning. */
static void srvrun_loop(const srvrun_cfg* cfg) {
  srvrun_state  st = {cfg->env->table, cfg->env->conns};
  quic_mmsg_buf bufs[SRVRUN_RX_BATCH];
  int           tick = 0;
  quic_conntable_init(st.table, QUIC_CONNTABLE_CAP);
  srvrun_rx_init(cfg->env, bufs);
  while (!srvrun_shutdown_requested())
    srvrun_step(cfg, &st, bufs, SRVRUN_RX_BATCH);
  srvrun_goaway_all(cfg, &st);
  while (!srvrun_drain_tick(cfg, &st, bufs, tick)) tick++;
  srvrun_close_drained(cfg, &st);
}

/* Arm SIGHUP only when a cert path was given (cfg.cert_path unset means
 * reload is disabled, so there is nothing to reload into). */
static void srvrun_install_sighup(const srvrun_cfg* cfg) {
  if (!cfg->cert_path) return;
  if (!wired_sighup_install(srvrun_sighup_handler))
    WIRED_LOG("SIGHUP install failed, no cert reload\n");
}

/* Install the signal handlers wired_server_run needs: SIGTERM always,
 * SIGHUP conditionally (srvrun_install_sighup). Skipped entirely when
 * opt->no_signal_handlers is set -- e.g. a second wired_srvrun_serve_env
 * instance running alongside one that already owns the process-wide
 * handlers. */
static void srvrun_install_signals(
    const srvrun_cfg* cfg, const wired_srvrun_opt* opt) {
  if (opt->no_signal_handlers) return;
  if (!wired_sigterm_install(srvrun_sigterm_handler))
    WIRED_LOG("SIGTERM install failed, no graceful shutdown\n");
  srvrun_install_sighup(cfg);
}

/* Build the fixed run context from the app-facing port/id/handler/obs/opt
 * plus the mutable env this run drives -- the shared body of
 * wired_server_run_opt and wired_srvrun_serve_env. */
static srvrun_cfg srvrun_build_cfg(
    wired_srvrun_env*       env,
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt) {
  return (srvrun_cfg){
      srvrun_listen(port, opt),
      id,
      h.cb,
      h.ctx,
      obs.qlog_path,
      obs.keylog_path,
      obs.cert_path,
      obs.key_path,
      obs.cc_algo,
      opt->busy_poll,
      opt->wt_on_datagram,
      opt->wt_datagram_ctx,
      opt->wt_on_stream_data,
      opt->wt_stream_data_ctx,
      opt->xdp,
      env,
      opt->no_signal_handlers,
      opt->core_id,
      opt->wt_protocols,
      opt->wt_on_session,
      opt->wt_session_ctx,
      opt->force_retry,
      opt->wt_resource_check,
      opt->wt_resource_ctx,
      opt->wt_on_stream_reset,
      opt->wt_stream_reset_ctx,
      opt->wt_on_session_close,
      opt->wt_session_close_ctx};
}

usz wired_srvrun_env_size(void) { return sizeof(wired_srvrun_env); }

void wired_srvrun_env_init(wired_srvrun_env* env) {
  /* NOT `*env = (wired_srvrun_env){0}`: some compilers materialize that
   * compound literal as a stack temporary before copying it in, and this
   * struct is now well past a normal 8MB stack limit (QUIC_CONNTABLE_CAP
   * srvrun_conn's worth of wired_server/sdrv each) -- that pattern
   * segfaulted on overflow the moment sdrv grew past the threshold. memset
   * writes directly into *env, no intermediate stack copy. */
  bytes_memset(env, 0, sizeof(*env));
  wired_srvbigbuf_init(
      &env->bigbuf, &env->bigbuf_rows[0][0], WIRED_SRVBIGBUF_ROW_CAP);
}

int wired_srvrun_serve_env(
    wired_srvrun_env*       env,
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt) {
  srvrun_cfg cfg = srvrun_build_cfg(env, port, id, h, obs, opt);
  if (cfg.fd < 0) return 0;
  wired_certcache_prime(&env->certcache, id);
  srvrun_install_signals(&cfg, opt);
  WIRED_LOG("listening\n");
  srvrun_loop(&cfg);
  return 1;
}

int wired_server_run_opt(
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt) {
  /* g_srvrun_env is BSS-zeroed (static storage), which happens to already
   * match wired_srvrun_env_init's own zeroing -- except bigbuf, whose
   * wired_srvbigbuf_init call points it at this env's own row storage. */
  wired_srvbigbuf_init(
      &g_srvrun_env.bigbuf, &g_srvrun_env.bigbuf_rows[0][0],
      WIRED_SRVBIGBUF_ROW_CAP);
  return wired_srvrun_serve_env(&g_srvrun_env, port, id, h, obs, opt);
}

int wired_server_run(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs) {
  static const wired_srvrun_opt default_opt = {
      0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
  return wired_server_run_opt(port, id, h, obs, &default_opt);
}
