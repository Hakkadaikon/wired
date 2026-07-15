#include "app/http3/server/srvrun/srvrun.h"

#include "app/datagram/dgdeliver/dg_send.h"
#include "app/http3/core/h3/connect.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/establish.h"
#include "app/http3/request/h3resp/resp_build.h"
#include "app/http3/server/certreload/certreload.h"
#include "app/http3/server/sendsess/sendsess.h"
#include "app/http3/server/sigterm/sigterm.h"
#include "app/http3/server/srvbigbuf/srvbigbuf.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/server/srvpoll/srvpoll.h"
#include "app/http3/server/srvxdp/srvxdp.h"
#include "app/webtransport/errmap/errmap/errmap.h"
#include "app/webtransport/session/session/session.h"
#include "common/bytes/util/bytes.h"
#include "common/diag/error/error.h"
#include "common/platform/clock/mono.h"
#include "common/platform/debug/debug.h"
#include "common/platform/qlog/qlog.h"
#include "common/platform/qlog/qlogevent.h"
#include "common/platform/rng/cidgen.h"
#include "common/platform/thread/thread.h"
#include "tls/keys/kuswitch/twogen.h"
#include "transport/conn/lifecycle/conntable/conntable.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/poll/wait.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/frame/frame/frame.h"
#include "transport/packet/frame/frame/stream_ctl.h"
#include "transport/packet/header/dcidresolve/dcidresolve.h"
#include "transport/packet/header/packet/header.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "transport/recovery/congestion/cc/hystart.h"
#include "transport/recovery/congestion/cc/pacing.h"
#include "transport/recovery/detect/recovery/pto.h"
#include "transport/recovery/detect/recovery/rtt.h"
#include "transport/stream/data/appdata/stream_send.h"

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
} srvrun_cfg;

/* One live connection's mutable state: the orchestrator, the HTTP/3 loop,
 * whether it has completed its first (Initial) reply, the peer address to
 * send replies to (recorded from the datagram that opened the slot, RFC 9000
 * 5.1 — every reply on this slot targets this address, not whichever peer's
 * datagram was received most recently), and this slot's own server source
 * connection id. scid is generated per slot (quic_cid_generate): every slot
 * sharing cfg->id's fixed scid would make every connection answer to the same
 * DCID, collapsing quic_conntable's routing to a single slot. Indexed in
 * parallel with the conntable slot of the same index. */
/* One in-flight response answering one request stream. The connection's PN
 * space (l.tx_pn) and congestion controller (cc, below) stay per-connection
 * -- only the send session (unsent/in-flight/requeue bookkeeping) is
 * per-stream, so up to SRVRUN_RESP_SLOTS requests can be in flight
 * concurrently on one connection (RFC 9000 2.2). */
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
  /* 1 while the app handler has more response body to produce past this
   * round (wired_srvloop_handler's *more): srvrun_resp_reap must re-invoke
   * the handler for the next round instead of releasing this slot once its
   * sendsess goes idle. 0 for every ordinary (single-round) response. */
  int streaming;
  /* Response body bytes delivered to the handler/sendsess so far, across
   * every round of a streaming response (RFC 9000 19.8's absolute stream
   * offset for the NEXT round to arm at). Meaningless while !streaming. */
  u64 stream_off;
  /* 1 once the h3 HEADERS+DATA prefix has been written for this response
   * (only the first round writes it; every later round is raw body bytes
   * continuing the same DATA frame). Meaningless on the hq-interop path,
   * which never frames at all. */
  int stream_h3_framed;
} srvrun_resp;
/* Matches WIRED_SRVLOOP_MAX_STREAMS: the receive side's stream-slot table
 * bounds how many distinct request streams a connection reassembles at
 * once, so the response side never needs more slots than that. */
#define SRVRUN_RESP_SLOTS WIRED_SRVLOOP_MAX_STREAMS

typedef struct {
  wired_server     s;
  wired_srvloop    l;
  int              up;
  quic_sockaddr_in peer;
  u8               scid[WIRED_MAX_CID_LEN];
  int              goaway_sent; /**< 1 once graceful-shutdown GOAWAY sent */
  u64              last_ms;     /**< monotonic ms of the last routed datagram */
  srvrun_resp      resp[SRVRUN_RESP_SLOTS]; /**< in-flight responses, one per
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
  wired_wt_session  wt; /**< WebTransport session for this connection, if any
                         * (draft-ietf-webtrans-http3-15 SS4); valid only
                         * when wt_active is set. One session per connection
                         * for now (tasks/webtransport-plan.md scope). */
  int wt_active; /**< 1 once wired_wt_session_init has been called for this
                    slot */
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
  u8  boot_hs[4096];
  usz boot_dgram_len[WIRED_SRVBOOT_FLIGHT_MAX];
  usz boot_dgram_count;
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
#define SRVRUN_CHUNK 1100 /* stream bytes per packet (fits a 1500 MTU) */
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
/* RFC 9000 18.2's default when the peer's own transport parameter isn't
 * tracked (srvrun does not parse the client's max_ack_delay yet -- YAGNI
 * until a deployment needs a non-default value). */
#define SRVRUN_MAX_ACK_DELAY_US 25000
#define SRVRUN_PTO_MAX 5

/* Receive batch: srvrun drains up to this many datagrams per recvmmsg call.
 * ponytail: 16 x 2048B storage (32KB) per env; raise if a profile ever shows
 * the loop syscall-bound at higher fan-in. Hoisted here (from its former
 * point of use, next to g_srvrun_rxstorage) so wired_srvrun_env below can
 * size its rxstorage member. */
#define SRVRUN_RX_BATCH 16

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
  /* PTO probe deadline for the polling drivers (srvrun_polling_ptos). */
  u64 pto_next_ms;
  /* Spin-iteration counter pacing the clock read in srvrun_pto_due. */
  u32 pto_spin;
  /* Test-only: how many times srvrun_send has fired since the last
   * srvrun_test_reset_send_count (see its doc below). */
  usz send_count;
  /* The reload generation this env has already applied (srvrun_reload_
   * if_requested); a single-threaded run sees at most one pending generation
   * at a time, so "gen != seen" behaves exactly like the old boolean flag. */
  u32 reload_seen_gen;
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
  const srvrun_cfg*       cfg;
  const quic_sockaddr_in* peer;
  srvrun_state*           st;
  u64                     now_ms; /**< monotonic ms this step started at */
} srvrun_step_ctx;

/* qlog packet_sent (pn/time are not tracked at this layer, so both are logged
 * as 0 — the record still proves a packet of `bytes` size went out). No-op
 * when no qlog path is set. */
static void srvrun_qlog_sent(const srvrun_cfg* cfg, usz bytes) {
  char rec[128];
  usz  n;
  if (!cfg->qlog_path) return;
  n = wired_qlogevent_packet_sent(rec, sizeof rec, 0, 0, bytes);
  if (n) wired_qlog_append(cfg->qlog_path, quic_span_of((const u8*)rec, n));
}

/* qlog packet_received (time not tracked at this layer; bytes is the whole
 * datagram, matching packet_sent's granularity). No-op without a qlog path.
 */
static void srvrun_qlog_recv(const srvrun_cfg* cfg, u64 pn, usz bytes) {
  char rec[128];
  usz  n;
  if (!cfg->qlog_path) return;
  n = wired_qlogevent_packet_received(rec, sizeof rec, 0, pn, bytes);
  if (n) wired_qlog_append(cfg->qlog_path, quic_span_of((const u8*)rec, n));
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
    srvrun_qlog_recv(ctx->cfg, srvrun_rx_pn(m, &c->l), bytes);
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

/* The one TX seam: AF_XDP when cfg->xdp is set, the UDP socket otherwise
 * (tasks/xdp-driver-plan.md). Both srvrun_send and the direct Version
 * Negotiation send route through this. */
static void srvrun_tx(
    const srvrun_cfg* cfg, const quic_sockaddr_in* sa, quic_span pkt) {
  if (cfg->xdp)
    wired_srvxdp_send(cfg->xdp, sa, pkt);
  else
    wired_udp_send(cfg->fd, sa, pkt);
}

static void srvrun_send(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    quic_span          pkt,
    const char*        what) {
  (void)what; /* WIRED_LOG compiles out without -DQUIC_DEBUG */
  if (pkt.n) {
    srvrun_tx(cfg, &c->peer, pkt);
    srvrun_qlog_sent(cfg, pkt.n);
    WIRED_LOG(what);
    g_srvrun_send_count++;
  }
}

/* Send each sealed Handshake flight datagram in order (a flight split per
 * RFC 9000 19.6 arrives as dgram_count slices of the flight buffer). */
static void srvrun_send_flight_dgrams(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    const u8*          hs,
    const usz*         dgram_len,
    usz                dgram_count) {
  usz off = 0;
  for (usz i = 0; i < dgram_count; i++) {
    srvrun_send(
        cfg, c, quic_span_of(hs + off, dgram_len[i]),
        "server Handshake flight sent\n");
    off += dgram_len[i];
  }
}

static void srvrun_send_flight(
    const srvrun_cfg*        cfg,
    const srvrun_conn*       c,
    const u8*                hs,
    const wired_srvboot_out* out) {
  srvrun_send_flight_dgrams(cfg, c, hs, out->dgram_len, out->dgram_count);
}

/* Build this slot's own wired_srvboot_id: every field from cfg->id except
 * scid, which is c's own per-connection id — sharing cfg->id's fixed scid
 * across every slot would make every connection answer to the same DCID,
 * collapsing quic_conntable's routing to a single slot (RFC 9000 5.1). */
static wired_srvboot_id srvrun_slot_id(
    const wired_srvboot_id* base, const srvrun_conn* c) {
  wired_srvboot_id id = *base;
  id.scid             = c->scid;
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
  usz n = wired_srvboot_refusal(
      &c->boot, quic_span_of(c->scid, ctx->cfg->id->scid_len), pkt, sizeof pkt);
  WIRED_LOG("srvboot accept failed\n");
  if (n) srvrun_send(ctx->cfg, c, quic_span_of(pkt, n), "boot refused\n");
  return 0;
}

static int srvrun_boot_finish(
    const srvrun_step_ctx* ctx, srvrun_conn* c, quic_mspan dg) {
  quic_obuf          iob  = quic_obuf_of(c->boot_ini, sizeof c->boot_ini);
  quic_obuf          hob  = quic_obuf_of(c->boot_hs, sizeof c->boot_hs);
  wired_srvboot_conn conn = {&c->s, &c->l};
  wired_srvboot_id   sid  = srvrun_slot_id(ctx->cfg->id, c);
  wired_srvboot_out  out  = {&iob, &hob, {0}, 0, 0};
  if (!wired_srvboot_accept_acc(&conn, &sid, &c->boot, &out))
    return srvrun_refuse(ctx, c);
  srvrun_qlog_recv(ctx->cfg, out.client_pn, dg.n);
  wired_server_set_keylog_path(&c->s, ctx->cfg->keylog_path);
  wired_srvloop_set_handler(&c->l, ctx->cfg->handler, ctx->cfg->ctx);
  c->l.resp_external = 1; /* srvrun streams the response (multi-packet) */
  /* RFC 9221 3: this connection's own advertised max_datagram_frame_size,
   * threaded to dispatch.c's DATAGRAM-gathering size check (see
   * wired_srvloop.we_advertised_max_datagram's doc). Same sid/base value
   * quic_stp_build_server_lim already sends in the transport parameters
   * (WT-A-006) — sid is this slot's own copy of cfg->id, built above. */
  c->l.we_advertised_max_datagram = sid.max_datagram_frame_size;
  /* RFC 9000 18.2/19.9: seed this connection's send credit from the peer's
   * ClientHello TP now that quic_sdrv_recv_client_hello has run (inside
   * wired_srvboot_accept_acc above); MAX_DATA frames only ever raise it
   * from here (srvrun_ku_discard_stale's neighbors gather_max_data /
   * srvrun_sess_on_step apply those raises each step). */
  c->conn_credit  = c->s.sdrv.peer_initial_max_data;
  c->boot_ini_len = iob.len;
  for (usz i = 0; i < out.dgram_count; i++)
    c->boot_dgram_len[i] = out.dgram_len[i];
  c->boot_dgram_count = out.dgram_count;
  srvrun_send(
      ctx->cfg, c, quic_span_of(c->boot_ini, c->boot_ini_len),
      "server Initial sent\n");
  srvrun_send_flight(ctx->cfg, c, c->boot_hs, &out);
  wired_srvboot_acc_reset(&c->boot); /* the reassembly buffer is spent */
  return 1;
}

/* srvrun_on_initial: the datagram was absorbed but the ClientHello is not
 * whole yet — keep the slot claimed and wait for the next Initial. */
#define SRVRUN_BOOT_PENDING 2

/* Feed dg into c's boot accumulator, restarting it for a fresh attempt (a
 * just-claimed slot, or a confirmed connection re-cold-starting). */
static int srvrun_boot_feed(srvrun_conn* c, quic_mspan dg) {
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
    const srvrun_step_ctx* ctx, srvrun_conn* c, quic_mspan dg) {
  if (!srvrun_boot_feed(c, dg)) return srvrun_boot_salvage(c);
  if (!wired_srvboot_acc_complete(&c->boot)) return SRVRUN_BOOT_PENDING;
  return srvrun_boot_finish(ctx, c, dg);
}

/* RFC 9114 4.1.1/8.1, draft-ietf-quic-reliable-stream-reset: a server aborts
 * a stream with a RESET_STREAM_AT + STOP_SENDING pair carrying err_code on
 * both -- same shape as quic_h3cancel_request, which pairs a plain
 * RESET_STREAM with STOP_SENDING for H3_REQUEST_CANCELLED, but parameterized
 * over the error code so callers can carry either an HTTP/3-level code (e.g.
 * H3_REQUEST_REJECTED) or a WebTransport application code already mapped
 * through quic_wterrmap_to_http3. RESET_STREAM_AT (not a plain RESET_STREAM,
 * WT-F-007) since a WT session's stream aborts are draft-ietf-webtrans-
 * http3-15's own preference for reliable delivery up to a point; every
 * current caller aborts a stream that never carried any application bytes
 * (a buffer-full/busy/bad-id rejection at association time), so final_size
 * and reliable_size are both 0 -- there is nothing yet to guarantee
 * delivery of. */
static usz srvrun_wt_busy_reset_payload(
    u64 stream_id, u64 err_code, quic_obuf* plb) {
  quic_reset_stream_at_frame rs = {stream_id, err_code, 0, 0};
  quic_stop_sending_frame    ss = {stream_id, err_code};
  usz rn = quic_reset_stream_at_encode(plb->p, plb->cap, &rs);
  usz sn;
  if (!rn) return 0;
  sn = quic_stop_sending_encode(plb->p + rn, plb->cap - rn, &ss);
  if (!sn) return 0;
  return rn + sn;
}

/* Seal the RESET_STREAM+STOP_SENDING pair above into out as its own 1-RTT
 * packet on stream_id. Returns 1 with out->len set, 0 if the payload or the
 * seal failed. */
static int srvrun_seal_wt_busy_reset(
    srvrun_conn* c, u64 stream_id, u64 err_code, quic_obuf* out) {
  u8                    pl[64];
  quic_obuf             plb = quic_obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  usz pln = srvrun_wt_busy_reset_payload(stream_id, err_code, &plb);
  if (!pln) return 0;
  sin = (wired_srvloop_send_in){
      quic_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      quic_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal and send the RESET_STREAM+STOP_SENDING pair carrying err_code as its
 * own 1-RTT packet. */
static void srvrun_send_wt_busy_reset(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id, u64 err_code) {
  u8        out[128];
  quic_obuf ob = quic_obuf_of(out, sizeof out);
  if (!srvrun_seal_wt_busy_reset(c, stream_id, err_code, &ob)) return;
  srvrun_send(cfg, c, quic_span_of(out, ob.len), "WT busy RESET_STREAM sent\n");
}

/* RFC 9000 10.2.3: an application-level CONNECTION_CLOSE (type 0x1d,
 * is_app=1) carrying an HTTP/3 or WebTransport-level error code and reason.
 * Mirrors wired_srvboot_refusal's is_app=0 handshake-rejection pattern
 * (srvboot.c) but for use OUTSIDE handshake rejection -- an established
 * connection closing itself for an application-level protocol violation. */
static usz srvrun_app_close_payload(
    u64 error_code, quic_span reason, quic_obuf* plb) {
  quic_conn_close_frame cc = {1, error_code, 0, reason.n, reason.p};
  return quic_frame_put_conn_close(plb->p, plb->cap, &cc);
}

/* Seal the CONNECTION_CLOSE above into out as its own 1-RTT packet. Returns
 * 1 with out->len set, 0 if the payload or the seal failed. */
static int srvrun_seal_app_close(
    srvrun_conn* c, u64 error_code, quic_span reason, quic_obuf* out) {
  u8                    pl[64];
  quic_obuf             plb = quic_obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  usz pln = srvrun_app_close_payload(error_code, reason, &plb);
  if (!pln) return 0;
  sin = (wired_srvloop_send_in){
      quic_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      quic_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal and send an application-level CONNECTION_CLOSE as its own 1-RTT
 * packet.
 * ponytail: no live caller yet (the violation-detection trigger is a
 * separate follow-up, tasks/webtransport-plan.md WT-C-005 second half) -- only
 * tests/run.c calls this today, so it needs the attribute to avoid
 * -Wunused-function under -Werror in the freestanding build. */
__attribute__((unused)) static void srvrun_send_app_close(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 error_code, quic_span reason) {
  u8        out[128];
  quic_obuf ob = quic_obuf_of(out, sizeof out);
  if (!srvrun_seal_app_close(c, error_code, reason, &ob)) return;
  srvrun_send(cfg, c, quic_span_of(out, ob.len), "app CONNECTION_CLOSE sent\n");
}

/* RFC 9000 10.2.3: a transport-level CONNECTION_CLOSE (type 0x1c, is_app=0)
 * carrying a standard RFC 9000 20.1 error code -- the sibling of
 * srvrun_seal_app_close for a violation the transport itself detects (e.g.
 * RFC 9221 3's PROTOCOL_VIOLATION), rather than an HTTP/3/WebTransport
 * application error. frame_type 0 (unknown/unspecified) matches
 * wired_srvboot_refusal's own transport-close payload. */
static usz srvrun_transport_close_payload(
    u64 error_code, quic_span reason, quic_obuf* plb) {
  quic_conn_close_frame cc = {0, error_code, 0, reason.n, reason.p};
  return quic_frame_put_conn_close(plb->p, plb->cap, &cc);
}

/* Seal the CONNECTION_CLOSE above into out as its own 1-RTT packet. Returns
 * 1 with out->len set, 0 if the payload or the seal failed. */
static int srvrun_seal_transport_close(
    srvrun_conn* c, u64 error_code, quic_span reason, quic_obuf* out) {
  u8                    pl[64];
  quic_obuf             plb = quic_obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  usz pln = srvrun_transport_close_payload(error_code, reason, &plb);
  if (!pln) return 0;
  sin = (wired_srvloop_send_in){
      quic_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      quic_span_of(pl, pln), 0};
  return wired_srvloop_send_onertt(&c->s, &sin, out);
}

/* Seal and send a transport-level CONNECTION_CLOSE as its own 1-RTT packet
 * (RFC 9000 20.1 error code, e.g. QUIC_ERR_PROTOCOL_VIOLATION). */
static void srvrun_send_transport_close(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 error_code, quic_span reason) {
  u8        out[128];
  quic_obuf ob = quic_obuf_of(out, sizeof out);
  if (!srvrun_seal_transport_close(c, error_code, reason, &ob)) return;
  srvrun_send(
      cfg, c, quic_span_of(out, ob.len), "transport CONNECTION_CLOSE sent\n");
}

/* draft-ietf-webtrans-http3-15 4.3/8.2: a buffered-stream-capacity rejection
 * (wired_wt_session_offer_stream returned 0, i.e. WIRED_WT_MAX_BUFFERED_
 * STREAMS is full on an unestablished session) is the caller's own contract
 * to enforce (session.h's offer_stream doc): reset the stream with
 * WT_BUFFERED_STREAM_REJECTED, mapped through quic_wterrmap_to_http3 since
 * it is a WebTransport application error code, not an HTTP/3-level one. */
static void srvrun_reject_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 stream_id) {
  srvrun_send_wt_busy_reset(
      cfg, c, stream_id,
      quic_wterrmap_to_http3(QUIC_WTERR_BUFFERED_STREAM_REJECTED));
}

/* draft-ietf-webtrans-http3-15 4.3: associate one newly-reassembled WT bidi
 * stream slot with c's WebTransport session, exactly once (slot->offered
 * latches it) — the session only needs to know the stream id, not its bytes
 * (wired_wt_session_offer_stream's own signature, session.h). A stray WT bidi
 * stream on a connection with no active session (!c->wt_active) is a
 * protocol-level mismatch this slice leaves as accepted-and-ignored, matching
 * the pre-Slice-3 fallback: routing to a session that does not exist is not
 * meaningful, so nothing is offered and the slot is simply left reassembled
 * but unclaimed by any session. A 0 return (buffer full) is rejected on the
 * wire and the slot freed so a retry does not loop forever re-offering the
 * same doomed stream id. */
static void srvrun_offer_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  if (!c->wt_active) return;
  if (!wired_wt_session_offer_stream(&c->wt, slot->stream_id)) {
    srvrun_reject_wt_slot(cfg, c, slot->stream_id);
    slot->in_use = 0;
    return;
  }
  slot->offered = 1;
}

/* A reassembled-but-not-yet-associated slot: in_use (claimed by a WT-bidi
 * stream) and not already offered to the session this connection owns. */
static int wt_slot_needs_offer(const wired_srvloop_wt_stream_slot* slot) {
  return slot->in_use && !slot->offered;
}

/* A fresh, not-yet-delivered FIN — the one case wt_stream_delta_pending's
 * plain len > delivered_len check misses (a stream whose closing frame, or
 * whose only frame, carries no new bytes). fin_delivered (not delivered_len)
 * is the guard: delivered_len alone cannot tell "FIN already delivered" apart
 * from "nothing delivered yet" when both are 0. */
static int wt_stream_fin_only(u8 fin, int fin_delivered) {
  return fin && !fin_delivered;
}

/* Whether this step has anything new worth delivering for one WT stream slot:
 * either fresh bytes past the last delivery, or a fresh FIN (see
 * wt_stream_fin_only). */
static int wt_stream_delta_pending(
    usz len, u8 fin, usz delivered_len, int fin_delivered) {
  if (len > delivered_len) return 1;
  return wt_stream_fin_only(fin, fin_delivered);
}

/* Whether srvrun_deliver_wt_stream_delta has anything to do at all: an active
 * session, a registered callback, and a pending delta (wt_stream_delta_pending)
 * — folded into one predicate so the caller is a single guarded early return.
 */
static int wt_stream_delta_ready(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    usz                len,
    u8                 fin,
    usz                delivered_len,
    int                fin_delivered) {
  if (!c->wt_active || !cfg->wt_on_stream_data) return 0;
  return wt_stream_delta_pending(len, fin, delivered_len, fin_delivered);
}

/* draft-ietf-webtrans-http3-15 4.3 (Phase 7b Slice 4): deliver the bytes a WT
 * bidi/uni slot has accumulated since the last delivery to the app callback.
 * A slot's buf is a cumulative reassembly buffer (not a queue), so "new data
 * this step" is buf[delivered_len..len) — the caller passes pointers to the
 * slot's own delivered_len/fin_delivered so this can advance them in place.
 * Called every step for every in_use slot regardless of offered, so bytes
 * that arrive before the stream's session association still reach the app
 * once one exists, mirroring srvrun_offer_wt_slot's own no-active-session
 * fallback (silently skip rather than buffer growing unboundedly). */
static void srvrun_deliver_wt_stream_delta(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    u64               stream_id,
    const u8*         buf,
    usz               len,
    u8                fin,
    usz*              delivered_len,
    int*              fin_delivered) {
  if (!wt_stream_delta_ready(cfg, c, len, fin, *delivered_len, *fin_delivered))
    return;
  cfg->wt_on_stream_data(
      cfg->wt_stream_data_ctx, &c->wt, stream_id,
      quic_span_of(buf + *delivered_len, len - *delivered_len), fin);
  *delivered_len = len;
  if (fin) *fin_delivered = 1;
}

/* One wt_streams slot's per-step work: offer it to the session if this step
 * (or an earlier one) claimed it but has not yet offered it, then deliver any
 * new bytes to the app callback — split out of srvrun_offer_wt_streams so the
 * loop itself stays at the CCN gate. */
static void srvrun_offer_and_deliver_wt_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, wired_srvloop_wt_stream_slot* slot) {
  if (wt_slot_needs_offer(slot)) srvrun_offer_wt_slot(cfg, c, slot);
  if (!slot->in_use) return;
  srvrun_deliver_wt_stream_delta(
      cfg, c, slot->stream_id, slot->buf, slot->len, slot->fin,
      &slot->delivered_len, &slot->fin_delivered);
}

/* draft-ietf-webtrans-http3-15 4.3: after a step has reassembled this
 * datagram's frames into c->l.wt_streams[], run srvrun_offer_and_deliver_wt_
 * slot over every slot. */
static void srvrun_offer_wt_streams(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_STREAMS; i++)
    srvrun_offer_and_deliver_wt_slot(cfg, c, &c->l.wt_streams[i]);
}

/* RFC 9221 5 / draft-ietf-webtrans-http3-15 SS4 (Phase 7b Slice 2): deliver one
 * queued received DATAGRAM to the app callback, if a session is active and a
 * callback is registered. wired_wt_session_offer_datagram (session.h) is
 * purely internal buffering/association bookkeeping -- it has no path to an
 * app callback itself, so wt_on_datagram is invoked here directly rather than
 * threaded through it. Still calls offer_datagram first so the session's own
 * state (buffered-vs-associated) stays consistent regardless of whether an app
 * callback is registered. */
static void srvrun_deliver_rx_datagram(
    const srvrun_cfg*                cfg,
    srvrun_conn*                     c,
    const wired_srvloop_rx_datagram* dg) {
  quic_span data = quic_span_of(dg->buf, dg->len);
  if (!c->wt_active) return;
  wired_wt_session_offer_datagram(&c->wt, data);
  if (cfg->wt_on_datagram)
    cfg->wt_on_datagram(cfg->wt_datagram_ctx, &c->wt, data);
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
  if (!c->wt_active) return;
  if (!wired_wt_session_offer_stream(&c->wt, slot->stream_id)) {
    srvrun_reject_wt_slot(cfg, c, slot->stream_id);
    slot->in_use = 0;
    return;
  }
  slot->offered = 1;
}

/* A reassembled-but-not-yet-associated uni slot, mirroring wt_slot_needs_offer
 * for the separate uni table. */
static int wt_uni_slot_needs_offer(
    const wired_srvloop_wt_uni_stream_slot* slot) {
  return slot->in_use && !slot->offered;
}

/* One wt_uni_streams slot's per-step work, mirroring
 * srvrun_offer_and_deliver_wt_slot for the separate uni table. */
static void srvrun_offer_and_deliver_wt_uni_slot(
    const srvrun_cfg*                 cfg,
    srvrun_conn*                      c,
    wired_srvloop_wt_uni_stream_slot* slot) {
  if (wt_uni_slot_needs_offer(slot)) srvrun_offer_wt_uni_slot(cfg, c, slot);
  if (!slot->in_use) return;
  srvrun_deliver_wt_stream_delta(
      cfg, c, slot->stream_id, slot->buf, slot->len, slot->fin,
      &slot->delivered_len, &slot->fin_delivered);
}

/* draft-ietf-webtrans-http3-15 4.3: after a step has reassembled this
 * datagram's frames into c->l.wt_uni_streams[], run srvrun_offer_and_deliver_
 * wt_uni_slot over every slot, mirroring srvrun_offer_wt_streams for the
 * separate uni table. */
static void srvrun_offer_wt_uni_streams(const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < WIRED_SRVLOOP_MAX_WT_UNI_STREAMS; i++)
    srvrun_offer_and_deliver_wt_uni_slot(cfg, c, &c->l.wt_uni_streams[i]);
}

/* draft-ietf-webtrans-http3-15 SS4.4: this step's stream-close gathering
 * (dispatch.c's gather_stream_closes) latched a RESET_STREAM/STOP_SENDING/FIN
 * on the exact stream id that is this connection's active WT session's
 * CONNECT stream -- close the session now, independent of whether the rest
 * of the connection is still alive. This is the fourth, precise trigger the
 * TLA+ model (tasks/loopeng/webtransport/) found missing: the existing
 * srvrun_free_slot trigger only fires on whole-connection teardown, so a
 * CONNECT stream closing while the connection stays open previously left the
 * session established indefinitely. c->l.closed_stream_seen is consumed
 * (cleared) here every step regardless of whether it matched, mirroring
 * datagram_violation's own per-step latch-and-clear shape. */
/* 1 if the stream this step's gather_stream_closes latched is this
 * connection's active WT session's own CONNECT stream — split out of
 * srvrun_close_wt_on_stream_close to keep its own branch count at the CCN
 * gate. */
static int wt_connect_stream_closed(const srvrun_conn* c) {
  if (!c->wt_active || !c->l.closed_stream_seen) return 0;
  return c->l.closed_stream_id == c->wt.connect_stream_id;
}

static void srvrun_close_wt_on_stream_close(srvrun_conn* c) {
  if (wt_connect_stream_closed(c)) wired_wt_session_close(&c->wt);
  c->l.closed_stream_seen = 0;
}

/* RFC 9221 3: this step's DATAGRAM gathering (dispatch.c) latched a violation
 * -- close the connection with a transport-level PROTOCOL_VIOLATION. Split out
 * of srvrun_on_step to keep its own branch count at the CCN gate. */
static void srvrun_close_on_datagram_violation(
    const srvrun_cfg* cfg, srvrun_conn* c) {
  static const u8 reason[] = "DATAGRAM exceeds advertised limit";
  srvrun_send_transport_close(
      cfg, c, QUIC_ERR_PROTOCOL_VIOLATION,
      quic_span_of(reason, sizeof reason - 1));
}

/* Send this step's sealed reply, if any and if the connection is not
 * draining after a peer CONNECTION_CLOSE (RFC 9000 10.2.2). */
static void srvrun_send_step_reply(
    const srvrun_cfg* cfg, srvrun_conn* c, int produced, quic_span out) {
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
 * reply — unless this step's own DATAGRAM gathering found an RFC 9221 3
 * violation, in which case the connection closes itself instead (see
 * srvrun_close_on_datagram_violation), or the step observed a peer
 * CONNECTION_CLOSE (srvrun_send_step_reply's own gate). */
static void srvrun_on_step(
    const srvrun_step_ctx* ctx, srvrun_conn* c, quic_mspan dg) {
  u8                 out[1500];
  quic_obuf          ob       = quic_obuf_of(out, sizeof out);
  wired_srvloop_conn conn     = {&c->l, &c->s};
  srvrun_rxmark      mark     = srvrun_rx_mark(&c->l);
  int                produced = wired_srvloop_step(&conn, dg, &ob);
  srvrun_ku_note_rotation(c, ctx->now_ms);
  srvrun_note_recv(ctx, &mark, c, dg.n);
  srvrun_offer_wt_streams(ctx->cfg, c);
  srvrun_offer_wt_uni_streams(ctx->cfg, c);
  srvrun_drain_rx_datagrams(ctx->cfg, c);
  srvrun_close_wt_on_stream_close(c);
  if (c->l.datagram_violation) {
    srvrun_close_on_datagram_violation(ctx->cfg, c);
    return;
  }
  srvrun_send_step_reply(ctx->cfg, c, produced, quic_span_of(out, ob.len));
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
static int srvrun_goaway_payload(int advertise_wt, quic_obuf* plb) {
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
    const srvrun_cfg* cfg, srvrun_conn* c, quic_obuf* out) {
  u8                    pl[64];
  quic_obuf             plb = quic_obuf_of(pl, sizeof pl);
  wired_srvloop_send_in sin;
  if (!srvrun_goaway_payload(c->l.we_advertised_max_datagram > 0, &plb))
    return 0;
  sin = (wired_srvloop_send_in){
      quic_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      quic_span_of(pl, plb.len), 0};
  if (!wired_srvloop_send_onertt(&c->s, &sin, out)) return 0;
  srvrun_send(cfg, c, quic_span_of(out->p, out->len), "GOAWAY sent\n");
  c->goaway_sent = 1;
  return 1;
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
 * A future WT-specific wrapper (e.g. wired_wt_send_datagram, sketched in
 * tasks/webtransport-plan.md but not yet declared anywhere) can call this
 * once srvrun exposes a stable per-connection handle to WT sessions; adding
 * that bridge now would be speculative (no second caller yet), and no
 * production code decides to send a datagram yet either (that needs the
 * app-facing callback hook from the plan's API sketch, also not built) --
 * hence still test-only, same situation as srvrun_test_set_shutdown above.
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
static int srvrun_queue_datagram(srvrun_conn* c, quic_span data) {
  if (!c->l.h3.settings_sent) return 0;
  if (data.n > sizeof c->dg_pending_buf) return 0;
  quic_memcpy(c->dg_pending_buf, data.p, data.n);
  c->dg_pending_len = data.n;
  c->dg_pending     = 1;
  return 1;
}

/* Seal c's one pending QUIC DATAGRAM (RFC 9221 5) into a 1-RTT packet and send
 * it. Unlike srvrun_send_slice/srvrun_send_goaway, there is no
 * wired_sendsess/ACK-loss bookkeeping: RFC 9221 1 DATAGRAM frames are never
 * retransmitted. max_frame_size is the peer's advertised
 * max_datagram_frame_size (quic_sdrv_recv_client_hello populated it from the
 * real ClientHello transport parameters): quic_dgdeliver_frame's internal
 * quic_datagram_allowed check rejects the send outright when the
 * peer never advertised support (value 0) or when the encoded frame would
 * exceed the peer's advertised limit. Clears c->dg_pending on success.
 * Returns 1 if sent, 0 if the frame could not be built (too large for the
 * peer's limit, or it would not fit the local buffer). */
static int srvrun_send_pending_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, quic_obuf* out) {
  u8                    pl[1400];
  quic_obuf             plb        = quic_obuf_of(pl, sizeof pl);
  u64                   peer_limit = c->s.sdrv.peer_max_datagram_frame_size;
  quic_dgdeliver_opts   o = {.with_length = 1, .max_frame_size = peer_limit};
  wired_srvloop_send_in sin;
  if (!quic_dgdeliver_frame(
          quic_span_of(c->dg_pending_buf, c->dg_pending_len), &o, &plb))
    return 0;
  sin = (wired_srvloop_send_in){
      quic_span_of(c->l.cli_scid, c->l.cli_scid_len), c->l.tx_pn++, -1,
      quic_span_of(pl, plb.len), 0};
  if (!wired_srvloop_send_onertt(&c->s, &sin, out)) return 0;
  srvrun_send(cfg, c, quic_span_of(out->p, out->len), "DATAGRAM sent\n");
  c->dg_pending = 0;
  return 1;
}

/* c is a live connection with an active WT session -- a broadcast target.
 * Split out of srvrun_broadcast_to_all to keep its own branch count at the
 * CCN gate (mirrors srvrun_owes_goaway's own role for srvrun_goaway_all). */
static int srvrun_is_broadcast_target(const srvrun_conn* c) {
  return c->up && c->wt_active;
}

/* Queue data into every connection with an active WT session's own single-
 * slot DATAGRAM queue (srvrun_queue_datagram) -- mirrors srvrun_goaway_all's
 * fan-out shape, swapping the goaway-owed guard for wt_active. Each
 * connection still drains through its own srvrun_send_pending_datagram on
 * its own next step, same as any other queued datagram; this only makes
 * every eligible connection's slot hold the same payload at once. */
static void srvrun_broadcast_to_all(srvrun_state* st, quic_span data) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_is_broadcast_target(&st->conns[i]))
      srvrun_queue_datagram(&st->conns[i], data);
}

/* Phase E (tasks/loopeng/srvinbox-mesh): multi-worker broadcast fan-out. One
 * registry entry per srvthreads worker, keyed by the registering thread's
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
static void srvrun_bcast_mesh_push(int my_slot, int my_index, quic_span data) {
  for (int t = 0; t < SRVRUN_BCAST_MAX; t++) {
    if (!srvrun_bcast_mesh_target(t, my_slot)) continue;
    wired_srvinbox_push(&g_srvrun_bcast[t].inbox_row[my_index], data.p, data.n);
  }
}

/* Single-process fallback path: the calling thread is not registered (no
 * srvthreads worker ever called wired_srvrun_broadcast_register), so this is
 * either wired_server_run(_opt) or the one-and-only wired_srvrun_serve_env
 * instance -- both drive the single process-wide g_srvrun_env, byte-identical
 * to before Phase E. */
static int srvrun_broadcast_direct(quic_span data) {
  srvrun_broadcast_to_all(
      &(srvrun_state){g_srvrun_table, g_srvrun_state.conns}, data);
  return 1;
}

/* A registered srvthreads worker (any n_total, including 1): fan out to the
 * calling worker's OWN env (its own connection table) first -- the env a
 * plain g_srvrun_env-based fan-out would completely miss, since srvthreads
 * gives every worker its own mmap'd env instead of the single global one.
 * With 2+ workers also push into every OTHER registered worker's inbox row
 * (Phase E mesh) so their own next step delivers it to their own sessions. */
static int srvrun_broadcast_registered(int slot, quic_span data) {
  srvrun_bcast_entry* e = &g_srvrun_bcast[slot];
  srvrun_broadcast_to_all(&(srvrun_state){e->env->table, e->env->conns}, data);
  if (e->n_total > 1) srvrun_bcast_mesh_push(slot, e->index, data);
  return 1;
}

/* data.n fits every fan-out target's payload capacity (dg_pending_buf and
 * every wired_srvinbox_ring slot share the same 1200-byte cap by
 * construction, WIRED_SRVINBOX_SLOT_MAX). */
static int srvrun_broadcast_fits(quic_span data) {
  return data.n <= sizeof g_srvrun_state.conns[0].dg_pending_buf;
}

int wired_server_broadcast_datagram(quic_span data) {
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
  if (n) srvrun_broadcast_to_all(st, quic_span_of(buf, n));
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

/* Send GOAWAY to every live connection that still owes one (RFC 9114 5.2), the
 * first step of graceful shutdown. Connections not yet confirmed simply have
 * no 1-RTT key to receive it and are left to time out normally. */
static void srvrun_goaway_all(const srvrun_cfg* cfg, srvrun_state* st) {
  u8        out[256];
  quic_obuf ob = quic_obuf_of(out, sizeof out);
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_owes_goaway(&st->conns[i]))
      srvrun_send_goaway(cfg, &st->conns[i], &ob);
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
static int srvrun_is_new(const srvrun_conn* c, quic_mspan dg) {
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

/* 1 if b0 wears a long header of the Initial type (RFC 9000 17.2.2). */
static int srvrun_pkt_is_initial(u8 b0) {
  return (b0 & 0x80) != 0 && (b0 & 0x30) == 0;
}

/* 1 if every packet at offs[0..n) within dg is an Initial. */
static int srvrun_pkts_all_initial(quic_mspan dg, const usz* offs, usz n) {
  for (usz i = 0; i < n; i++)
    if (!srvrun_pkt_is_initial(dg.p[offs[i]])) return 0;
  return 1;
}

/* RFC 9000 12.2: 1 if dg parses as coalesced packets that are ALL Initials.
 * A client's second flight coalesces an Initial (ACK) with a Handshake
 * packet carrying its Finished -- such a datagram is handshake progress, not
 * a bare first-flight retransmit, and must never be swallowed by the cached
 * boot-flight resend (that discards the Finished and wedges the handshake
 * unconfirmed; curl connects and then stalls on its request). */
static int srvrun_dgram_all_initial(quic_mspan dg) {
  const u8*    pkts[4];
  usz          offs[4], lens[4], n;
  quic_pktlist pl = {pkts, offs, lens, 4};
  n               = quic_udploop_split(quic_span_of(dg.p, dg.n), &pl);
  return n != 0 && srvrun_pkts_all_initial(dg, offs, n);
}

/* RFC 9000 13.3: an all-Initial datagram on a slot already up, not yet
 * confirmed, and not eligible to (re)cold-start (srvrun_is_new said no) is
 * the client retransmitting its first flight because the server's reply
 * hasn't reached it yet -- not a new connection attempt. A datagram that
 * coalesces anything beyond Initials (srvrun_dgram_all_initial says no)
 * carries handshake progress and takes the step path instead. */
static int srvrun_is_boot_retransmit(const srvrun_conn* c, quic_mspan dg) {
  if (!srvrun_awaiting_confirm(c)) return 0;
  if (c->boot_ini_len == 0) return 0;
  return srvrun_dgram_all_initial(dg);
}

/* Free slot i: drop its table entry and clear its connection's up flag (the
 * shutdown drain accounting then counts it as drained).
 *
 * ponytail: connection teardown (peer CONNECTION_CLOSE, boot failure, or
 * idle sweep -- the 3 call sites below) is treated as WebTransport session
 * termination (tasks/webtransport-plan.md WT-F-001/002/003). This is a
 * deliberate approximation, not the spec-accurate trigger: the real rule
 * cares about the CONNECT stream's own FIN/RESET independent of whether the
 * rest of the connection stays alive, and there is no mechanism yet to
 * detect a per-stream RESET_STREAM on just that stream (this session's
 * investigation, see tasks/wt-pin-poll-progress.md). Revisit once
 * stream-level RESET_STREAM dispatch reaches srvrun/srvloop. */
static void srvrun_free_slot(srvrun_state* st, int i) {
  srvrun_conn* c = &st->conns[i];
  if (c->wt_active) {
    wired_wt_session_close(&c->wt);
    c->wt_active = 0;
  }
  quic_conntable_remove(st->table, QUIC_CONNTABLE_CAP, i);
  c->up = 0;
  wired_srvboot_acc_reset(&c->boot);
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
static void srvrun_sweep_idle(srvrun_state* st, u64 now_ms) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_idle_due(&st->conns[i], now_ms)) srvrun_free_slot(st, (int)i);
}

/* Cold-start outcome for a slot: on success, rekey its table entry to the
 * slot's own SCID — the DCID the client addresses from its second flight on
 * (RFC 9000 7.2) — on failure, roll the whole claim back so the slot is not
 * leaked. */
static void srvrun_open_done(const srvrun_step_ctx* ctx, int slot, int ok) {
  srvrun_conn* c = &ctx->st->conns[slot];
  c->up          = ok;
  if (!ok) {
    srvrun_free_slot(ctx->st, slot);
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
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    u64                    offset,
    quic_obuf*             body,
    const char**           ct,
    int*                   more,
    u64*                   total_size) {
  if (!ctx->cfg->handler) return;
  if (!ctx->cfg->handler(
          ctx->cfg->ctx, &c->l.req, offset, body, ct, more, total_size))
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

/* r's request line is CONNECT with :scheme/:authority/:path all present
 * (WT-B-003/004): the Extended CONNECT shape, checked before :protocol. */
static int wt_ext_connect_shape_ok(const wired_h3reqdrive_req* r) {
  if (!wt_method_is_connect(r)) return 0;
  return wt_ext_fields_present(r);
}

/* r is a well-formed Extended CONNECT (RFC 9220 3) for WebTransport:
 * :method=CONNECT, :scheme/:authority/:path all present (WT-B-003/004),
 * :protocol negotiated (settings always advertised, Step 1 above) and a
 * WebTransport token (see wt_protocol_is_webtransport). */
static int srvrun_is_wt_connect(const wired_h3reqdrive_req* r) {
  if (!wt_ext_connect_shape_ok(r)) return 0;
  if (!wt_protocol_is_webtransport(r)) return 0;
  return quic_h3_connect_protocol_ok(r, 1);
}

/* WebTransport draft-ietf-webtrans-http3-15 SS3.6: when Origin is present it
 * must be a non-empty value for the server to validate; this SDK has no
 * origin-allowlist configuration surface yet (YAGNI -- no in-tree consumer
 * needs one), so "well-formed and non-empty" is the whole check today.
 * Absent Origin is not itself a rejection reason (WT-B-005: only applies to
 * browser clients, which this SDK cannot detect server-side). */
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

/* Seal a bare status-only response (no body, no content-type) into r's own
 * storage row and arm r's session over it — the same low-level prefix+arm
 * mechanism srvrun_start_app_resp uses for a normal 200, minus the app
 * handler: this is protocol-level WebTransport response building
 * (draft-ietf-webtrans-http3-15 SS3.2), not an application response. Used for
 * both the 2xx that establishes a session and the 403 that rejects one
 * (WT-B-005/007/008). */
static void srvrun_start_wt_status(
    wired_srvrun_env* env,
    int               slot,
    srvrun_conn*      c,
    srvrun_resp*      r,
    u16               status) {
  u8*       st = env->respstore[slot][srvrun_resp_index(c, r)];
  u8        pre[SRVRUN_RESP_HDR_ROOM];
  quic_obuf pob = quic_obuf_of(pre, sizeof pre);
  usz       off;
  if (!quic_h3resp_prefix(status, 0, 0, &pob)) return;
  off = SRVRUN_RESP_HDR_ROOM - pob.len;
  quic_put_bytes(
      quic_mspan_of(st, SRVRUN_RESP_HDR_ROOM), &off,
      quic_span_of(pre, pob.len));
  wired_sendsess_arm(
      &r->sess, st + SRVRUN_RESP_HDR_ROOM - pob.len, pob.len, SRVRUN_CHUNK);
}

/* Establish a WebTransport session for this Extended CONNECT (draft-ietf-
 * webtrans-http3-15 SS3.2/SS4): the session id is the CONNECT stream's own
 * id. Skips the normal app-handler response path entirely. */
static void srvrun_start_wt(
    wired_srvrun_env* env, int slot, srvrun_conn* c, srvrun_resp* r) {
  wired_wt_session_init(&c->wt, c->l.req_stream_id);
  wired_wt_session_establish(&c->wt);
  c->wt_active = 1;
  srvrun_start_wt_status(env, slot, c, r, 200);
}

/* Reject this Extended CONNECT with 403 (WT-B-005/007/008: a present but
 * malformed Origin) without establishing a session. */
static void srvrun_reject_wt(
    wired_srvrun_env* env, int slot, srvrun_conn* c, srvrun_resp* r) {
  srvrun_start_wt_status(env, slot, c, r, 403);
}

/* r's storage row for this response: the fixed per-(conn,stream) respstore
 * row (WIRED_SRVRUN_RESP_MAX = 16KB, SRVRUN_RESP_HDR_ROOM reserved at the
 * front for the framed HEADERS prefix), or -- when the app handler needs
 * more room than that -- a claimed wired_srvbigbuf row (srvbigbuf.h),
 * reserving the same HDR_ROOM prefix at its own front. Pool exhaustion
 * falls back to the fixed row (its cap simply bounds the handler's write,
 * same as before this pool existed): a body that then overflows the fixed
 * row is truncated by the handler's own quic_obuf cap, not a new failure
 * mode. r->bigbuf_row records which storage was used, -1 for the fixed row,
 * so srvrun_resp_reap knows whether to release a pool row later. */
static u8* srvrun_resp_storage(
    const srvrun_step_ctx* ctx, int slot, srvrun_conn* c, srvrun_resp* r) {
  u8* fixed = ctx->cfg->env->respstore[slot][srvrun_resp_index(c, r)];
  u8* big   = wired_srvbigbuf_claim(&ctx->cfg->env->bigbuf, &r->bigbuf_row);
  return big ? big : fixed;
}

/* Bytes available in st for body_out (past the HDR_ROOM prefix), matching
 * whichever storage srvrun_resp_storage chose. */
static usz srvrun_resp_storage_cap(const srvrun_resp* r) {
  return (r->bigbuf_row >= 0 ? WIRED_SRVBIGBUF_ROW_CAP
                             : WIRED_SRVRUN_RESP_MAX) -
         SRVRUN_RESP_HDR_ROOM;
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
  quic_memcpy(fixed, st, total);
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
 * rounds (T-010). */
static void srvrun_arm_hq09_resp(
    srvrun_resp* r, u8* st, const quic_obuf* body) {
  wired_sendsess_arm(
      &r->sess, st + SRVRUN_RESP_HDR_ROOM, body->len, SRVRUN_CHUNK);
}

/* RFC 9114 4.1: frame the handler's body as HEADERS+DATA (quic_h3resp_prefix)
 * ahead of it, then arm over prefix+body. total_len is the DATA frame's
 * declared length (T-012/T-021: the full streaming response's total size,
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
    const quic_obuf*       body,
    const char*            ct,
    u64                    total_len) {
  u8        pre[SRVRUN_RESP_HDR_ROOM];
  quic_obuf pob = quic_obuf_of(pre, sizeof pre);
  usz       off;
  if (!quic_h3resp_prefix(200, ct, total_len, &pob)) return;
  off = SRVRUN_RESP_HDR_ROOM - pob.len;
  quic_put_bytes(
      quic_mspan_of(st, SRVRUN_RESP_HDR_ROOM), &off,
      quic_span_of(pre, pob.len));
  st = srvrun_resp_shrink_to_fixed(
      ctx, slot, c, r, st + SRVRUN_RESP_HDR_ROOM - pob.len,
      pob.len + body->len);
  wired_sendsess_arm(&r->sess, st, pob.len + body->len, SRVRUN_CHUNK);
}

/* RFC 9114 4.1: a streaming response's round 1+ is unframed body bytes
 * continuing the DATA frame round 0 already declared -- no HEADERS/DATA
 * prefix, unlike round 0's srvrun_arm_h3_resp_framed (T-011/T-013: the
 * bigbuf-to-fixed shrink is also skipped here, since a shrink would discard
 * the storage row round 0's bytes may still be in flight from). */
static void srvrun_arm_h3_resp_round(
    srvrun_resp* r, u8* st, const quic_obuf* body) {
  wired_sendsess_arm(
      &r->sess, st + SRVRUN_RESP_HDR_ROOM, body->len, SRVRUN_CHUNK);
}

/* RFC 9114 4.1: frame+arm round 0, or arm a later round's unframed
 * continuation -- whichever this call is (T-011). */
static void srvrun_arm_h3_resp(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    int                    slot,
    srvrun_resp*           r,
    u8*                    st,
    const quic_obuf*       body,
    const char*            ct,
    u64                    total_len) {
  if (r->stream_h3_framed) {
    srvrun_arm_h3_resp_round(r, st, body);
    return;
  }
  r->stream_h3_framed = 1;
  srvrun_arm_h3_resp_framed(ctx, c, slot, r, st, body, ct, total_len);
}

/* Prime r's streaming state after round 0 (T-004/T-006): stays 0 for an
 * ordinary single-round response. */
static void srvrun_prime_streaming(srvrun_resp* r, int more, usz round_len) {
  r->streaming = more != 0;
  if (!more) return;
  wired_sendsess_set_base_offset(&r->sess, 0);
  r->stream_off = round_len;
}

/* Arm r's round-0 body over st, hq-interop-raw or H3-framed depending on
 * what this connection negotiated (T-010/T-011), and prime the streaming
 * state (T-004/T-006) when the handler asked for another round. */
static void srvrun_arm_round0(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    int                    slot,
    srvrun_resp*           r,
    u8*                    st,
    const quic_obuf*       body,
    const char*            ct,
    int                    more,
    u64                    total_size) {
  u64 total_len = more ? total_size : body->len;
  if (c->s.sdrv.alpn == QUIC_SALPN_HQ)
    srvrun_arm_hq09_resp(r, st, body);
  else
    srvrun_arm_h3_resp(ctx, c, slot, r, st, body, ct, total_len);
  srvrun_prime_streaming(r, more, body->len);
}

/* Run the app handler's round 0 into body/ct/more/total_size (out params). */
static void srvrun_call_round0(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    quic_obuf*             body,
    const char**           ct,
    int*                   more,
    u64*                   total_size) {
  srvrun_call_handler(ctx, c, 0, body, ct, more, total_size);
}

/* Body of srvrun_start_resp for a normal (non-WT) request: run the app
 * handler's first round, then frame+arm the response -- H3-framed or
 * hq-interop-raw depending on what this connection negotiated. Split out so
 * srvrun_start_resp itself stays at its gate/dispatch decision (CCN). */
static void srvrun_start_app_resp(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  u8*       st = srvrun_resp_storage(ctx, slot, c, r);
  quic_obuf body =
      quic_obuf_of(st + SRVRUN_RESP_HDR_ROOM, srvrun_resp_storage_cap(r));
  const char* ct         = 0;
  int         more       = 0;
  u64         total_size = 0;
  r->stream_h3_framed    = 0;
  srvrun_call_round0(ctx, c, &body, &ct, &more, &total_size);
  srvrun_arm_round0(ctx, c, slot, r, st, &body, ct, more, total_size);
}

/* Reject this Extended CONNECT with 429 (WT-C-010/011: a second Extended
 * CONNECT arriving while a WT session is already active on this connection)
 * without disturbing the existing session. One session per connection for
 * now (tasks/webtransport-plan.md scope) -- srvrun_start_wt would otherwise
 * unconditionally re-init c->wt, silently resetting an ESTABLISHED session
 * back to UNESTABLISHED and dropping its buffered state. Also aborts the
 * rejected stream with H3_REQUEST_REJECTED (RFC 9114 4.1.1/8.1), independent
 * of and in addition to the 429 above. */
static void srvrun_reject_wt_busy(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  srvrun_start_wt_status(cfg->env, slot, c, r, 429);
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

/* draft-ietf-webtrans-http3-15 SS3.2/SS4 (WT-C-006/007): the WT session id is
 * the CONNECT stream's own id, so it must be a client-initiated bidi stream
 * id (RFC 9000 2.1) or the session would be keyed by an id that cannot
 * possibly be the client's request stream. RFC 9114 8.1 lists H3_ID_ERROR for
 * exactly this "stream id used incorrectly" case; it is a stream-level abort
 * reason, so this mirrors srvrun_reject_wt_busy's RESET_STREAM+STOP_SENDING
 * shape rather than a CONNECTION_CLOSE. */
static void srvrun_reject_wt_bad_id(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  srvrun_start_wt_status(cfg->env, slot, c, r, 403);
  srvrun_send_wt_busy_reset(cfg, c, c->l.req_stream_id, QUIC_H3_ID_ERROR);
}

/* Body of srvrun_dispatch_wt once Origin has passed and no session is
 * already active: reject a non-client-bidi session id (WT-C-006/007) or
 * establish the session. Split out so srvrun_dispatch_wt itself stays at one
 * gate (CCN). */
static void srvrun_dispatch_wt_free_slot(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (!srvrun_stream_id_is_client_bidi(c->l.req_stream_id)) {
    srvrun_reject_wt_bad_id(cfg, c, slot, r);
    return;
  }
  srvrun_start_wt(cfg->env, slot, c, r);
}

/* A well-formed Extended CONNECT for WebTransport either establishes a
 * session (Origin absent, or present and well-formed, and no session already
 * active on this connection -- WT-C-010/011), or is rejected: 403 for a
 * malformed Origin (WT-B-005/007/008), 429 if a session is already active,
 * or H3_ID_ERROR if the CONNECT stream's own id is not a client-initiated
 * bidi stream id (WT-C-006/007). */
static void srvrun_dispatch_wt(
    const srvrun_cfg* cfg, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (!wt_origin_ok(&c->l.req)) {
    srvrun_reject_wt(cfg->env, slot, c, r);
    return;
  }
  if (c->wt_active) {
    srvrun_reject_wt_busy(cfg, c, slot, r);
    return;
  }
  srvrun_dispatch_wt_free_slot(cfg, c, slot, r);
}

/* Build the decoded request's response into a freshly claimed resp[] slot
 * and arm its session over the whole stream. Guard 1 (TLA+ resp-multiplex,
 * tasks/loopeng/resp-multiplex/summary.md): a request stream that already
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

static void srvrun_start_resp(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_resp* r = srvrun_start_resp_claim(c);
  if (!r) return;
  if (srvrun_is_wt_connect(&c->l.req)) {
    srvrun_dispatch_wt(ctx->cfg, c, slot, r);
    return;
  }
  srvrun_start_app_resp(ctx, c, slot, r);
}

/* draft-ietf-webtrans-http3 4 / RFC 9114 4.1: a normal response ends its
 * stream with FIN, but the Extended CONNECT stream IS the WebTransport
 * session and stays open for its whole lifetime -- a FIN on the
 * session-accept 200 reads as "session over" and Chrome closes with code 0
 * the moment it arrives. Scoped to r's own stream_id (not the whole
 * connection): a wt_active connection may still have OTHER streams' normal
 * responses in flight (RFC 9000 2.2), and those must still get their FIN. */
static u8 srvrun_slice_fin(
    const srvrun_conn* c, const srvrun_resp* r, const wired_sendq_slice* sl) {
  int is_wt_connect_stream =
      c->wt_active && r->stream_id == c->wt.connect_stream_id;
  return (u8)(sl->fin && !is_wt_connect_stream);
}

/* Seal one slice as its own 1-RTT packet (a STREAM frame on r's request
 * stream, RFC 9000 19.8) and send it. Returns 1 once logged in flight. */
static int srvrun_send_slice(
    const srvrun_step_ctx*   ctx,
    srvrun_conn*             c,
    srvrun_resp*             r,
    const wired_sendq_slice* sl) {
  u8                pl[1400], out[1500];
  quic_obuf         plb = quic_obuf_of(pl, sizeof pl);
  quic_obuf         ob  = quic_obuf_of(out, sizeof out);
  quic_stream_frame f   = {
      r->stream_id, wired_sendsess_stream_offset(&r->sess, sl), sl->len,
      r->sess.q.p + sl->offset, srvrun_slice_fin(c, r, sl)};
  u64 pn;
  if (!quic_appdata_stream_frame(&f, &plb)) return 0;
  pn = c->l.tx_pn++;
  {
    wired_srvloop_send_in sin = {
        quic_span_of(c->l.cli_scid, c->l.cli_scid_len), pn, -1,
        quic_span_of(pl, plb.len), 0};
    if (!wired_srvloop_send_onertt(&c->s, &sin, &ob)) return 0;
  }
  srvrun_send(ctx->cfg, c, quic_span_of(out, ob.len), "response slice sent\n");
  return wired_sendsess_sent(&r->sess, sl, pn, ctx->now_ms);
}

static int  srvrun_pace_ok(const srvrun_step_ctx* ctx, const srvrun_conn* c);
static void srvrun_pace_next(const srvrun_step_ctx* ctx, srvrun_conn* c);
static void srvrun_ku_discard_stale(srvrun_conn* c, u64 now_ms);

/* Sum of in-flight stream bytes across every resp[] slot -- the congestion
 * window (RFC 9002 7) gates the connection's TOTAL in-flight, not any one
 * stream's. */
static usz srvrun_inflight_bytes_all(const srvrun_conn* c) {
  usz total = 0;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (c->resp[i].in_use)
      total += wired_sendsess_inflight_bytes(&c->resp[i].sess);
  return total;
}

/* 1 when r's send log has a free entry. The log gate applies to every send
 * regardless of cwnd: a slice taken and sent while the log is full can be
 * recorded in neither log nor requeue -- if that packet then drops, the
 * stream has a permanent hole the peer waits on forever. */
static int srvrun_log_has_room(const srvrun_resp* r) {
  return wired_sendsess_inflight(&r->sess) < WIRED_SENDSESS_LOG;
}

/* 1 when the connection's congestion window (RFC 9002 7) has room for one
 * more chunk across every slot combined. Pacing (RFC 9002 7.7) is NOT
 * checked here -- it gates whole round-robin passes
 * (srvrun_pump_round_gated), not individual slots. */
static int srvrun_cwnd_has_room(const srvrun_conn* c) {
  return srvrun_inflight_bytes_all(c) + SRVRUN_CHUNK <= c->cc.cwnd;
}

/* RFC 9000 4.1: sum of stream bytes already handed to wired_sendsess_take
 * (r->sess.q.cur, the sendq's next-unsent-offset cursor) across every
 * resp[] slot -- the cumulative total the connection's ONE conn_credit
 * (initial_max_data + any MAX_DATA raises) bounds. A retransmit reuses an
 * offset range already counted here, so PTO/loss resends never double-count
 * (mirrors srvrun_inflight_bytes_all's per-slot fan-out, but this quantity
 * only grows -- it is not cleared by an ACK the way in-flight bytes are). */
static usz srvrun_conn_consumed_bytes(const srvrun_conn* c) {
  usz total = 0;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (c->resp[i].in_use) total += c->resp[i].sess.q.cur;
  return total;
}

/* 1 when the connection's send credit (RFC 9000 18.2/19.9) has room for one
 * more chunk, summed across every resp[] slot the same way cwnd is. */
static int srvrun_conn_credit_has_room(const srvrun_conn* c) {
  return srvrun_conn_consumed_bytes(c) + SRVRUN_CHUNK <= c->conn_credit;
}

/* 1 when r's own stream-level send credit (RFC 9000 18.2/19.10) has room
 * for one more chunk. Consumed bytes for one stream are exactly its own
 * sendq cursor (no cross-slot fan-out needed at this level). */
static int srvrun_stream_credit_has_room(const srvrun_resp* r) {
  return r->sess.q.cur + SRVRUN_CHUNK <= r->stream_credit;
}

/* 1 when RFC 9000 4.1's two flow-control credits (connection and stream)
 * both have room for one more chunk -- split out so srvrun_can_send_new's
 * own CCN stays at the gate. */
static int srvrun_credit_has_room(const srvrun_conn* c, const srvrun_resp* r) {
  return srvrun_conn_credit_has_room(c) && srvrun_stream_credit_has_room(r);
}

/* 1 when a brand-new slice (from r's sendq, not its requeue) may go out:
 * the log, cwnd, and both flow-control credit gates all apply. */
static int srvrun_can_send_new(const srvrun_conn* c, const srvrun_resp* r) {
  return srvrun_log_has_room(r) && srvrun_cwnd_has_room(c) &&
         srvrun_credit_has_room(c, r);
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

/* Raise r's stream credit to value if that is higher, RFC 9000 4.1's
 * raise-only rule -- split out so srvrun_apply_stream_credit_update's own
 * CCN stays at the gate. */
static void srvrun_stream_credit_raise(srvrun_resp* r, u64 value) {
  if (value > r->stream_credit) r->stream_credit = value;
}

/* RFC 9000 4.1/19.10: apply this step's last-seen MAX_STREAM_DATA to the
 * named resp[] slot's running stream credit. A stream_id naming no in-use
 * slot (already reaped, or never claimed) is a no-op -- srvloop has no
 * notion of resp[] slots and cannot itself validate the id. */
static void srvrun_apply_stream_credit_update(srvrun_conn* c) {
  srvrun_resp* r;
  if (!c->l.max_stream_data_seen) return;
  c->l.max_stream_data_seen = 0;
  r = srvrun_resp_find(c, c->l.max_stream_data_stream_id);
  if (r) srvrun_stream_credit_raise(r, c->l.max_stream_data_value);
}

/* RFC 9002 7.5: "Probe packets MUST NOT be blocked by the congestion
 * controller." A PTO probe is a retransmit of an already-in-flight slice
 * that wired_sendsess_pto_fire moved to r->sess's requeue (sendsess.c) --
 * gating it on cwnd re-creates the exact deadlock RFC 9002 7.5 forbids: cwnd
 * can only grow from new ACKs, new ACKs need new sends, and a probe stuck
 * behind a full cwnd is the one send that would produce that ACK. */
static int srvrun_has_requeued(const srvrun_resp* r) {
  return r->sess.requeue_n != 0;
}

/* 1 when r may send right now: a queued probe retransmit only needs the log
 * gate (RFC 9002 7.5 bypasses cwnd for it); brand-new data needs both
 * gates. The log gate is checked for a probe too, even though
 * sendsess_requeue (sendsess.c) already cleared its log entry's inflight
 * flag the moment it moved to requeue -- so requeue_n != 0 always implies
 * at least that many free log entries, and this check can never actually
 * fail for a probe. It stays as an explicit invariant, not dead code: it
 * documents that a probe's cwnd exemption is deliberately narrower than a
 * blanket "requeue bypasses everything". */
static int srvrun_pump_gate_ok(const srvrun_conn* c, const srvrun_resp* r) {
  if (srvrun_has_requeued(r)) return srvrun_log_has_room(r);
  return srvrun_can_send_new(c, r);
}

/* Send one slice from r if the gates allow and one is ready. Pacing's
 * next-send time is scheduled once per whole pass by the caller
 * (srvrun_pump_round_gated), not per slice. */
static int srvrun_pump_one(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r) {
  wired_sendq_slice sl;
  if (!srvrun_pump_gate_ok(c, r)) return 0;
  if (!wired_sendsess_take(&r->sess, &sl)) return 0;
  return srvrun_send_slice(ctx, c, r, &sl);
}

/* One round-robin pass: try exactly one slice from every in-use resp[]
 * slot, in order. @return 1 if any slot actually sent one. */
static int srvrun_pump_round(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  int sent = 0;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    sent |= srvrun_pump_one(ctx, c, &c->resp[i]);
  return sent;
}

/* One pacing-gated round-robin pass: the whole pass (up to SRVRUN_RESP_SLOTS
 * slices, one per slot) counts as a single paced send, so pacing limits how
 * often a PASS may run, not how often each SLOT within it may run -- pacing
 * and round-robin fairness would otherwise fight (a 1ms pacing floor made
 * slot 0's first slice push next_send_ms a full ms into the future before
 * slots 4/8 ever got a turn in the same step, starving them completely). */
static int srvrun_pump_round_gated(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  if (!srvrun_pace_ok(ctx, c)) return 0;
  int sent = srvrun_pump_round(ctx, c);
  if (sent) srvrun_pace_next(ctx, c);
  return sent;
}

/* Transmit while the window has room and slices are ready, across every
 * in-flight response on this connection (RFC 9000 2.2: several requests may
 * be in flight at once) -- round-robin one slice per slot per pass, so a
 * single stream with a full send log never starves its siblings of the
 * connection's one shared cwnd (a strict per-slot drain-then-next order let
 * slot 0 claim the whole window every step; slot 2 fell far enough behind on
 * real send time that its own in-flight slices tripped RFC 9002 6.1.1's
 * packet threshold, not because they were actually lost). */
static void srvrun_pump_sess(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  while (srvrun_pump_round_gated(ctx, c)) {
  }
}

/* After a live step: feed the step's ACK ranges to the session, start a
 * response for a freshly decoded request, and send what the window allows.
 * A finished session simply goes idle. */
/* qlog packet_lost for one packet (time not tracked at this layer, logged
 * 0). No-op without a qlog path. */
static void srvrun_qlog_lost_one(const srvrun_cfg* cfg, u64 pn) {
  char rec[128];
  usz  w;
  if (!cfg->qlog_path) return;
  w = wired_qlogevent_packet_lost(rec, sizeof rec, 0, pn);
  if (w) wired_qlog_append(cfg->qlog_path, quic_span_of((const u8*)rec, w));
}

static void srvrun_qlog_lost(const srvrun_cfg* cfg, const u64* pns, usz n) {
  for (usz i = 0; i < n; i++) srvrun_qlog_lost_one(cfg, pns[i]);
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
  quic_rtt_sample(&c->rtt, sample_ms * 1000, 0);
}

/* 1 when pacing allows a send now: unpaced until the first RTT sample. */
static int srvrun_pace_ok(const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  return !c->srtt_ms || ctx->now_ms >= c->next_send_ms;
}

/* Schedule the next paced send (RFC 9002 7.7: ~1.25x cwnd/srtt rate). */
static void srvrun_pace_next(const srvrun_step_ctx* ctx, srvrun_conn* c) {
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
    srvrun_conn* c, const srvrun_resp* r, u64 lo, u64 hi, u64 now) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    const wired_sent_slice* e = &r->sess.log[i];
    if (wired_sendsess_covered(e, lo, hi))
      srvrun_hystart_ack(c, e->pn, e->sent_ms, now);
  }
}

/* Credit one ACK range against r's log to the congestion controller before
 * consuming it (RFC 9002 7.3.2: growth per acked bytes; the newest send
 * time among the hits drives recovery exit). Guard 5 (TLA+ resp-multiplex):
 * a range is broadcast to every resp[] slot, and wired_sendsess_ack only
 * clears the log entries that hit ITS OWN log (sendsess.c) -- but it also
 * unconditionally raises largest_acked to the range's hi, even when hi
 * belongs to another slot's pn (pn is a single monotonic per-connection
 * space, so a broadcast range routinely names pns this slot never sent).
 * That falsely advances this slot's packet-loss threshold (RFC 9002
 * 6.1.1) and requeues in-flight slices that were never actually lost --
 * observed against a real quic-go client on a 500KB body: offsets past
 * ~90KB were re-sent from ~55KB after an ACK for a sibling stream's pns.
 * Only forward the range when it actually hits something in r's own log. */
static void srvrun_cc_range(
    srvrun_conn* c, srvrun_resp* r, u64 lo, u64 hi, u64 now_ms) {
  u64 newest = 0;
  usz bytes  = wired_sendsess_peek_ack(&r->sess, lo, hi, &newest);
  if (!bytes) return;
  srvrun_rtt_note(c, now_ms - newest);
  srvrun_hystart_range(c, r, lo, hi, now_ms);
  quic_cc_on_ack(&c->cc, bytes, newest, now_ms);
  wired_sendsess_ack(&r->sess, lo, hi);
}

/* Threshold pass over r's log: requeue losses, log each lost packet. The
 * congestion-window shrink (quic_cc_on_loss) is applied once per step by
 * the caller (srvrun_feed_acks), not here, so a loss on several concurrent
 * responses in the same step still only shrinks the connection's one
 * window once. */
static usz srvrun_reap_losses_resp(
    const srvrun_cfg* cfg, const srvrun_conn* c, srvrun_resp* r, u64 now_ms) {
  u64 lost[WIRED_SENDSESS_LOG];
  usz n = wired_sendsess_detect_lost(
      &r->sess, c->largest_acked, now_ms, c->rtt.smoothed_rtt, lost,
      WIRED_SENDSESS_LOG);
  srvrun_qlog_lost(cfg, lost, n);
  return n;
}

/* Feed one ACK range to one in-flight resp[] slot's session and run its
 * loss-detection pass against the connection's ONE largest_acked (RFC 9002
 * 6.1.1 -- see the srvrun_conn field comment). A no-op for an unused slot. */
static usz srvrun_feed_ack_range_resp(
    const srvrun_cfg* cfg,
    srvrun_conn*      c,
    srvrun_resp*      r,
    u64               lo,
    u64               hi,
    u64               now_ms) {
  if (!r->in_use) return 0;
  srvrun_cc_range(c, r, lo, hi, now_ms);
  if (!r->sess.has_acked) return 0;
  return srvrun_reap_losses_resp(cfg, c, r, now_ms);
}

/* Broadcast one ACK range to every in-flight response's send session, after
 * raising the connection's shared largest_acked (RFC 9002 6.1.1: one packet
 * number space, one largest_acked -- never regresses). */
static usz srvrun_feed_ack_range(
    const srvrun_cfg* cfg, srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  usz lost = 0;
  if (hi > c->largest_acked) c->largest_acked = hi;
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    lost += srvrun_feed_ack_range_resp(cfg, c, &c->resp[i], lo, hi, now_ms);
  return lost;
}

static void srvrun_feed_acks(
    const srvrun_step_ctx* ctx, const srvrun_cfg* cfg, srvrun_conn* c) {
  usz lost = 0;
  for (usz i = 0; i < c->l.ack_n; i++)
    lost += srvrun_feed_ack_range(
        cfg, c, c->l.ack_lo[i], c->l.ack_hi[i], ctx->now_ms);
  if (lost) quic_cc_on_loss(&c->cc, ctx->now_ms, ctx->now_ms);
}

/* Send c's pending DATAGRAM (if any) using a scratch quic_obuf on the stack,
 * the same shape srvrun_send_pending_datagram expects. */
static void srvrun_pump_datagram(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8        out[1500];
  quic_obuf ob = quic_obuf_of(out, sizeof out);
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

/* Return r's borrowed wired_srvbigbuf row to the pool, if it holds one. */
static void srvrun_resp_release_bigbuf(wired_srvrun_env* env, srvrun_resp* r) {
  if (r->bigbuf_row >= 0) wired_srvbigbuf_release(&env->bigbuf, r->bigbuf_row);
}

/* Run r's next streaming round: call the handler at the cumulative offset
 * already delivered, then re-arm over the fresh round's bytes (T-004/T-006).
 * hq-interop never frames a length so it always continues; H3 already wrote
 * its DATA frame's total length in round 0 (stream_h3_framed), so its later
 * rounds are just more of that frame's payload (srvrun_arm_h3_resp_round via
 * srvrun_arm_h3_resp). Clears r->streaming once the handler stops asking for
 * more. */
static void srvrun_resp_next_round(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  u8*       st = srvrun_resp_storage(ctx, slot, c, r);
  quic_obuf body =
      quic_obuf_of(st + SRVRUN_RESP_HDR_ROOM, srvrun_resp_storage_cap(r));
  const char* ct         = 0;
  int         more       = 0;
  u64         total_size = 0;
  srvrun_call_handler(ctx, c, r->stream_off, &body, &ct, &more, &total_size);
  if (c->s.sdrv.alpn == QUIC_SALPN_HQ)
    srvrun_arm_hq09_resp(r, st, &body);
  else
    srvrun_arm_h3_resp(ctx, c, slot, r, st, &body, ct, 0);
  wired_sendsess_set_base_offset(&r->sess, r->stream_off);
  r->stream_off += body.len;
  r->streaming = more != 0;
}

/* Once r's session goes idle (wired_sendsess_done: every slice sent and
 * acked), either advance a streaming response to its next round (T-004) or
 * free r's slot and the matching srvloop receive-side slot -- HTTP/3 never
 * reuses a stream id, so without releasing the receive slot too,
 * WIRED_SRVLOOP_MAX_STREAMS sequential requests on distinct streams would
 * permanently exhaust it (guard: TLA+ resp-multiplex I4). A body that
 * borrowed a wired_srvbigbuf row returns it to the pool here too (T-005:
 * only once streaming is actually done, not between rounds). */
static int srvrun_resp_not_yet_idle(srvrun_resp* r) {
  return !r->in_use || !wired_sendsess_done(&r->sess);
}

static void srvrun_resp_reap(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot, srvrun_resp* r) {
  if (srvrun_resp_not_yet_idle(r)) return;
  if (r->streaming) {
    srvrun_resp_next_round(ctx, c, slot, r);
    return;
  }
  wired_srvloop_slot_release(&c->l, r->stream_id);
  srvrun_resp_release_bigbuf(ctx->cfg->env, r);
  r->in_use = 0;
}

static void srvrun_reap_resps(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    srvrun_resp_reap(ctx, c, slot, &c->resp[i]);
}

static void srvrun_sess_on_step(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_feed_acks(ctx, ctx->cfg, c);
  quic_cc_bbr_tick(&c->cc, srvrun_inflight_bytes_all(c), ctx->now_ms);
  srvrun_apply_conn_credit_update(c);
  srvrun_apply_stream_credit_update(c);
  srvrun_reap_resps(ctx, c, slot);
  srvrun_start_done_resps(ctx, slot);
  srvrun_pump_sess(ctx, slot);
  srvrun_pump_datagram(ctx, c);
  srvrun_ku_discard_stale(c, ctx->now_ms);
}

/* 1 if any resp[] slot is in use -- a connection with at least one response
 * still being built or in flight. */
static int srvrun_any_resp_active(const srvrun_conn* c) {
  for (usz i = 0; i < SRVRUN_RESP_SLOTS; i++)
    if (c->resp[i].in_use) return 1;
  return 0;
}

/* 1 while this slot still owes response bytes (in flight, paced, or window
 * blocked) — the loop must keep ticking for it. */
static int srvrun_sess_waiting(const srvrun_conn* c) {
  return c->up && srvrun_any_resp_active(c);
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
  return c->up && (srvrun_any_resp_active(c) || c->dg_pending);
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
  if (now_ms >= c->ku_rotated_at_ms + floor_ms)
    quic_kuswitch_discard_old(&c->s.ku);
}

/* 1 if r's oldest in-flight slice is still within its PTO window (RFC 9002
 * 6.2: probe only once send_time + PTO has elapsed) -- nothing in flight
 * counts as "not due" too, since wired_sendsess_pto_fire's own nothing-in-
 * flight case is a no-op anyway. */
static int srvrun_resp_pto_due(
    const srvrun_conn* c, const srvrun_resp* r, u64 now_ms) {
  u64 sent_ms;
  if (!wired_sendsess_oldest_sent_ms(&r->sess, &sent_ms)) return 0;
  return now_ms >= sent_ms + srvrun_pto_deadline_ms(c, r->sess.pto_count);
}

/* 1 if r has nothing to probe right now: unused, or its PTO deadline
 * hasn't elapsed yet. */
static int srvrun_resp_pto_not_due(
    const srvrun_conn* c, const srvrun_resp* r, u64 now_ms) {
  return !r->in_use || !srvrun_resp_pto_due(c, r, now_ms);
}

static int srvrun_resp_pto_ok(
    const srvrun_conn* c, srvrun_resp* r, u64 now_ms) {
  if (srvrun_resp_pto_not_due(c, r, now_ms)) return 1;
  return wired_sendsess_pto_fire(&r->sess, SRVRUN_PTO_MAX);
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
    if (!srvrun_resp_pto_ok(c, &c->resp[i], now_ms)) return 0;
  }
  return 1;
}

static void srvrun_pto_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!srvrun_sess_waiting(c)) return;
  if (!srvrun_pto_resps(c, ctx->now_ms)) {
    srvrun_free_slot(ctx->st, slot);
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

/* One slot's tick work on a poll timeout: PTO probe/teardown, then flush any
 * queued broadcast DATAGRAM -- split out so the loop below stays flat. */
static void srvrun_tick_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_pto_slot(ctx, slot);
  srvrun_dg_slot(ctx, slot);
}

/* A poll timeout with responses or broadcast DATAGRAMs in flight: fire the
 * probe/flush pass over every waiting slot. */
static void srvrun_fire_ptos(const srvrun_cfg* cfg, srvrun_state* st) {
  srvrun_step_ctx ctx = {cfg, 0, st, quic_clock_mono_ms()};
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++) srvrun_tick_slot(&ctx, (int)i);
}

/* One live step; a peer CONNECTION_CLOSE observed by the loop frees the slot
 * afterward (RFC 9000 10.2.2: the connection is done, its state discarded). */
static void srvrun_step_and_reap(
    const srvrun_step_ctx* ctx, int slot, quic_mspan dg) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_on_step(ctx, c, dg);
  if (c->l.peer_closed) {
    srvrun_free_slot(ctx->st, slot);
    return;
  }
  srvrun_sess_on_step(ctx, slot);
}

/* Drive one received datagram against its resolved slot: a new Initial
 * (re)opens the connection, any other datagram steps the live loop. */
/* Drive one cold-start feeding: a pending boot keeps its claim (and its
 * accumulator) for the next datagram; success or failure settles the slot. */
static void srvrun_cold_start(
    const srvrun_step_ctx* ctx, int slot, quic_mspan dg) {
  int r = srvrun_on_initial(ctx, &ctx->st->conns[slot], dg);
  if (r != SRVRUN_BOOT_PENDING) srvrun_open_done(ctx, slot, r);
}

/* RFC 9000 13.3: resend c's cached accept flight verbatim -- same Initial,
 * same Handshake datagrams -- instead of stepping dg through the confirmed-
 * connection path, where an Initial-keyed retransmit would just fail to
 * decrypt and get silently dropped. */
static void srvrun_resend_boot_flight(
    const srvrun_step_ctx* ctx, srvrun_conn* c) {
  srvrun_send(
      ctx->cfg, c, quic_span_of(c->boot_ini, c->boot_ini_len),
      "server Initial resent\n");
  srvrun_send_flight_dgrams(
      ctx->cfg, c, c->boot_hs, c->boot_dgram_len, c->boot_dgram_count);
}

/* dg is a fresh cold-start Initial (srvrun_cold_start) or a retransmit of
 * one already accepted but not yet confirmed (srvrun_resend_boot_flight),
 * dispatched to whichever applies. Returns 1 if either handled dg. */
static int srvrun_serve_boot(
    const srvrun_step_ctx* ctx, int slot, quic_mspan dg) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (srvrun_is_new(c, dg)) {
    srvrun_cold_start(ctx, slot, dg);
    return 1;
  }
  if (srvrun_is_boot_retransmit(c, dg)) {
    srvrun_resend_boot_flight(ctx, c);
    return 1;
  }
  return 0;
}

static void srvrun_serve_slot(
    const srvrun_step_ctx* ctx, int slot, quic_mspan dg) {
  srvrun_conn* c = &ctx->st->conns[slot];
  c->last_ms     = ctx->now_ms; /* RFC 9000 10.1: activity resets idle age */
  if (srvrun_serve_boot(ctx, slot, dg)) return;
  if (c->up) srvrun_step_and_reap(ctx, slot, dg);
}

/* dg's DCID as a span into dg, or a 0-length span if dg is too short to carry
 * the DCID length it claims (quic_dcidresolve_dcid can't tell that apart from
 * a legitimate zero-length CID on its own, so reject dcid_len < 0 first). */
static quic_span srvrun_dcid(quic_mspan dg, u8 short_hdr_len) {
  int dcid_len = quic_dcidresolve_len(dg, short_hdr_len);
  if (dcid_len < 0) return quic_span_of(0, 0);
  return quic_dcidresolve_dcid(dg, dcid_len);
}

/* Find the live slot this datagram's DCID matches. -1 if none does (the
 * datagram is malformed, or its DCID belongs to no connection this process
 * has open). */
static int srvrun_find_slot(const srvrun_step_ctx* ctx, quic_span dcid) {
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
static int srvrun_claim_refused(quic_span dcid, int is_initial) {
  return dcid.p == 0 || !is_initial || srvrun_shutdown_requested();
}

static int srvrun_claim_slot(
    const srvrun_step_ctx* ctx, quic_span dcid, int is_initial) {
  if (srvrun_claim_refused(dcid, is_initial)) return -1;
  return quic_conntable_insert(
      ctx->st->table, QUIC_CONNTABLE_CAP, dcid.p, (u8)dcid.n);
}

/* Claim and initialize a fresh slot for dcid: record the peer, and generate
 * this slot's own scid (never cfg->id's fixed one — every slot sharing it
 * would collapse conntable's routing back to a single slot). Returns the slot
 * index, or -1 if claiming fails or scid generation fails (in which case the
 * claimed slot is freed again rather than run with an all-zero scid). */
static int srvrun_open_slot(
    const srvrun_step_ctx* ctx, quic_span dcid, int is_initial) {
  int slot = srvrun_claim_slot(ctx, dcid, is_initial);
  if (slot < 0) return -1;
  ctx->st->conns[slot]      = (srvrun_conn){0};
  ctx->st->conns[slot].peer = *ctx->peer;
  quic_cc_init_algo(&ctx->st->conns[slot].cc, ctx->cfg->cc_algo);
  quic_hystart_init(&ctx->st->conns[slot].hs);
  quic_rtt_init(&ctx->st->conns[slot].rtt);
  if (quic_cid_generate(ctx->st->conns[slot].scid, ctx->cfg->id->scid_len))
    return slot;
  quic_conntable_remove(ctx->st->table, QUIC_CONNTABLE_CAP, slot);
  return -1;
}

/* Drive one received datagram: resolve it to a connection slot by DCID (a
 * fresh slot only for an unrecognized DCID on a new Initial, RFC 9000 5.1/7)
 * and serve it there. Silently drops a datagram that matches no slot and
 * cannot claim or initialize a new one. */
/* Answer an unsupported-version datagram with Version Negotiation, straight
 * to the sender — no connection slot is involved (RFC 9000 5.2.2). Returns 1
 * when the datagram was consumed this way. */
static int srvrun_vneg(const srvrun_step_ctx* ctx, quic_mspan dg) {
  u8  vn[64];
  usz n = wired_srvboot_vneg(quic_span_of(dg.p, dg.n), vn, sizeof vn);
  if (!n) return 0;
  srvrun_tx(ctx->cfg, ctx->peer, quic_span_of(vn, n));
  return 1;
}

/* The slot dg routes to: an existing DCID match, else a fresh claim (only
 * for a new Initial); -1 when neither. */
static int srvrun_route(
    const srvrun_step_ctx* ctx, quic_span dcid, quic_mspan dg) {
  int slot = srvrun_find_slot(ctx, dcid);
  if (slot >= 0) return slot;
  return srvrun_open_slot(ctx, dcid, wired_srvboot_is_initial(dg.p, dg.n));
}

static void srvrun_serve(const srvrun_step_ctx* ctx, quic_mspan dg) {
  int slot;
  if (srvrun_vneg(ctx, dg)) return;
  slot = srvrun_route(ctx, srvrun_dcid(dg, ctx->cfg->id->scid_len), dg);
  if (slot < 0) return;
  srvrun_serve_slot(ctx, slot, dg);
}

/* so_busy_poll_us > 0 enables SO_BUSY_POLL on fd (tasks/polling-driver-
 * plan.md POLL-003a); best-effort like SO_REUSEPORT, a no-op when <= 0 or
 * unsupported by the kernel/driver. */
static void srvrun_maybe_busy_poll(i64 fd, int so_busy_poll_us) {
  if (so_busy_poll_us > 0) wired_udp_busy_poll_enable(fd, so_busy_poll_us);
}

/* SO_PREFER_BUSY_POLL only has kernel effect when SO_BUSY_POLL is also
 * enabled (tasks/polling-driver-plan.md POLL-003b); hoisted so the caller's
 * `if` stays a single condition (CCN). */
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
  quic_sockaddr_in sa;
  i64              fd = wired_udp_socket();
  if (fd < 0) return fd;
  /* Best-effort: lets multiple srvworkers children share one port (tasks/
   * core-pinning-plan.md PIN-004). A single-worker run does not need it, so a
   * failure here is not fatal -- fall through to bind unconditionally. */
  wired_udp_reuseport_enable(fd);
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
  u64 now = quic_clock_mono_ms();
  srvrun_sweep_idle(st, now); /* lazy: swept on each arrival */
  for (i64 i = 0; i < n; i++) {
    srvrun_step_ctx ctx = {cfg, &bufs[i].src, st, now};
    srvrun_serve(&ctx, quic_mspan_of(bufs[i].buf.p, bufs[i].len));
  }
}

/* One receive+serve step: drain up to a batch of waiting datagrams in one
 * recvmmsg (it blocks for the first only, then returns what else is queued)
 * and serve each. Pending SIGHUP is consumed once per step (same granularity
 * as SIGTERM's shutdown flag): a reload lands before the batch is served, so
 * a fresh Initial arriving right after a reload already sees the new
 * identity. */
/* Wait for input: block in recvmmsg unless a response is awaiting ACKs, in
 * which case poll with the probe tick so silence still makes progress.
 * @return 1 to receive, 0 when the tick expired instead. */
static int srvrun_any_waiting(const srvrun_state* st) {
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_has_outbound(&st->conns[i])) return 1;
  return 0;
}

/* Non-blocking receive path: the busy_poll spin loop and the AF_XDP driver
 * both drain without ever waiting in poll(2) (tasks/xdp-driver-plan.md). */
static int srvrun_polling(const srvrun_cfg* cfg) {
  return cfg->busy_poll || cfg->xdp != 0;
}

/* env->pto_next_ms/pto_spin: the PTO probe deadline for the polling drivers.
 * They never sleep in poll(2), so the poll-timeout probe pass in srvrun_step
 * is unreachable for them and a lost reply would otherwise never be
 * retransmitted (RFC 9002 6.2). pto_spin paces the clock read below (1 on
 * every 1024th call). */

/* 1 on every 1024th call in a polling driver: the mono-clock read is a real
 * syscall, too costly to pay per spin iteration for a 300ms deadline. */
static int srvrun_pto_due(const srvrun_cfg* cfg, wired_srvrun_env* env) {
  if (!srvrun_polling(cfg)) return 0;
  env->pto_spin++;
  return (env->pto_spin & 1023u) == 0;
}

/* Clocked stand-in for the poll-timeout probe pass: fire the PTOs on the
 * same SRVRUN_PTO_MS cadence the blocking driver gets from poll(2). */
static void srvrun_polling_ptos(const srvrun_cfg* cfg, srvrun_state* st) {
  u64 now;
  if (!srvrun_pto_due(cfg, cfg->env)) return;
  now = quic_clock_mono_ms();
  if (now < cfg->env->pto_next_ms) return;
  cfg->env->pto_next_ms = now + SRVRUN_PTO_MS;
  srvrun_fire_ptos(cfg, st);
}

/* busy_poll=1 or xdp!=0: the blocking poll(2) itself is replaced by a non-
 * blocking return (tasks/polling-driver-plan.md — the srvrun_any_waiting
 * branch above is kept as-is; only this leaf call changes). The actual non-
 * blocking receive happens at the recv step (srvrun_recv), so there is
 * nothing left to wait for here. */
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
  if (!n) __builtin_ia32_pause();
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
  srvrun_bcast_drain_self(st); /* Phase E: other workers' broadcasts */
  srvrun_polling_ptos(cfg, st);
  if (!srvrun_wait_input(cfg, st)) {
    srvrun_fire_ptos(cfg, st);
    return;
  }
  r = srvrun_recv(cfg, bufs, nbufs);
  if (r > 0) srvrun_serve_batch(cfg, st, bufs, r);
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
    bufs[i].buf = quic_mspan_of(env->rxstorage[i], sizeof env->rxstorage[i]);
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
      opt->no_signal_handlers};
}

usz wired_srvrun_env_size(void) { return sizeof(wired_srvrun_env); }

void wired_srvrun_env_init(wired_srvrun_env* env) {
  *env = (wired_srvrun_env){0};
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
  static const wired_srvrun_opt default_opt = {0, 0, 0,  0, 0, 0,
                                               0, 0, -1, 0, 0};
  return wired_server_run_opt(port, id, h, obs, &default_opt);
}
