#ifndef APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_VOID_H
#define APP_HTTP3_SERVER_SRVRUN_SRVRUN_IMPL_VOID_H

#include "app/http3/server/srvrun/srvrun_impl_srvrun.h"

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
#define g_srvrun_tx_max_len (g_srvrun_env.tx_max_len)

typedef struct {
  conntable*   table;
  srvrun_conn* conns;
} srvrun_state;

/* Everything one datagram-serving step needs besides the datagram itself and
 * the resolved slot: the fixed run config, the peer address the datagram
 * arrived from, and the mutable server state. Folded into one parameter so
 * srvrun_send/on_initial/on_step/serve stay <=3 args. */
typedef struct {
  const srvrun_cfg* cfg;
  const sockaddr*   peer;
  srvrun_state*     st;
  u64               now_ms; /**< monotonic ms this step started at */
  /** RFC 9000 13.4 / RFC 9002 19.3.2: the ECN codepoint (RFC 3168, 0..3) this
   * datagram's UDP layer read off its IP_TOS cmsg (mmsg_buf.ecn in
   * udp.h), carried through so srvrun_serve_slot can hand it to the routed
   * slot's wired_srvloop_ecn_note. 0 (Not-ECT) for any caller that does not
   * set it explicitly. */
  u8 ecn;
} srvrun_step_ctx;

/* Snapshot of the loop's per-space receive marks, taken before a step; a
 * post-step difference proves the datagram carried at least one packet that
 * actually opened (an undecryptable datagram advances nothing). */
typedef struct {
  int app_seen;
  u64 app_pn;
  int hs_seen;
  u64 hs_pn;
} srvrun_rxmark;

/* srvrun_on_initial: the datagram was absorbed but the ClientHello is not
 * whole yet — keep the slot claimed and wait for the next Initial. */
#define SRVRUN_BOOT_PENDING 2

/* draft-ietf-moq-transport-19 3.3.4 / -22 12.5: MoQT's EXCESSIVE_LOAD
 * stream error code, what a raw-QUIC connection resets a client stream it
 * cannot take with (srvrun_refuse_code). */
#define SRVRUN_RAW_REFUSE_CODE 0x9

/* One WT bidi or uni slot's receive state, as the delivery below reads
 * and advances it (the two slot types share these fields, not a type). */
typedef struct {
  u64                            stream_id;
  const u8*                      buf;
  const wired_srvloop_wt_window* win;
  u8                             fin;
  u64                            fin_off;
  u64*                           delivered_len;
  int*                           fin_delivered;
} srvrun_wt_rx;

typedef void (*srvrun_rx_dg_fn)(
    const srvrun_cfg*, srvrun_conn*, const wired_srvloop_rx_datagram*);

/* One CONNECT stream capsule pass: the app env, the session, its
 * wt_drain_rcvd latch, and the code a rejected pass closes the session with
 * (WT_SESSION_GONE unless a capsule handler latched a more specific one). */
typedef struct {
  const wired_srvrun_env* env;
  wired_wt_session*       s;
  int*                    drain_rcvd;
  u64                     violation_code;
} srvrun_wt_caprx;

/* Reason-phrase room in a SRVRUN_CLOSE_PL_MAX close frame (RFC 9000 19.19):
 * 1159 - type (1) - Error Code varint (<= 8) - Reason Phrase Length varint
 * (2, the reason is < 16384) = 1148. */
#define SRVRUN_RAW_CLOSE_REASON_MAX (SRVRUN_CLOSE_PL_MAX - 1 - 8 - 2)

_Static_assert(
    WTCAPSULE_CLOSE_MESSAGE_MAX <= SRVRUN_RAW_CLOSE_REASON_MAX,
    "a kept WT close message fits the raw CONNECTION_CLOSE reason whole");

typedef void (*srvrun_sess_close_fn)(const srvrun_cfg*, srvrun_conn*, int);

/* RFC 9114 6.2.1: first server unidirectional (control) stream id, same value
 * respond.c's build_settings_frame uses. */
#define SRVRUN_CTRL_STREAM 3

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
  /** registering thread's tid (> 0), 0 = free, SRVRUN_BCAST_CLAIMING while
   * its registrant is still writing the fields below. Atomic: a slot is
   * claimed by a CAS 0 -> CLAIMING and published by a release store of the
   * tid, so a reader that acquire-loads a tid > 0 sees the fields whole. */
  i64                  tid;
  int                  index;     /**< this worker's 0-based mesh index */
  int                  n_total;   /**< total worker count in the mesh */
  wired_srvinbox_ring* inbox_row; /**< row[j] = ring fed by worker j */
  wired_srvrun_env*    env; /**< this worker's own env (its connection table) */
} srvrun_bcast_entry;

#define SRVRUN_BCAST_CLAIMING (-1)

/* RFC 9204 4.2: this connection's fixed QPACK encoder stream id -- the
 * second server-initiated uni stream, right after the H3 control stream. */
#define SRVRUN_QENC_STREAM 7

/* RFC 9204 4.2: this connection's fixed QPACK decoder stream id -- the
 * third server-initiated uni stream, after the control and encoder ones. */
#define SRVRUN_QDEC_STREAM 11

/* --- draft-ietf-webtrans-http3-15 4: a session's stream API never reaches
 * a stream something else owns. A send slot records its owner at open or
 * reply (wt_session_slot; -1 for connection plumbing: the H3 control and
 * QPACK streams, a CONNECT stream's capsule sender); a receive slot records
 * it once offered (-1 before). A stream neither tracks (already reaped, or
 * never seen) has no owner left to check. */
#define SRVRUN_WT_UNTRACKED (-2)

/* RFC 9221 5: DATAGRAM frames are congestion-controlled and never
 * retransmitted, so a ring drained at line rate is a burst a bottleneck
 * queue simply discards, and every dropped datagram is gone for good. A
 * per-step cap alone is not enough: every arriving ACK triggers a step, so
 * ack-clocking amplifies "16 per step" back into a line-rate burst (the
 * interop simulator's 25-packet queue saw 160 packets in 10ms and dropped
 * ~90 of a 200-datagram transfer). Pace by TIME: at most one
 * SRVRUN_DGRING_DRAIN_MAX slice per SRVRUN_DGRING_DRAIN_MS, sized so a
 * slice never overruns a small bottleneck queue (16 < 25) and the rate
 * (16/5ms = 3200 pkt/s) stays far under a 10Mbps path's small-packet
 * capacity. The count cap alone is calibrated for SMALL datagrams: 16
 * near-MTU entries per 5ms is ~23Mbps, which the same 10Mbps queue steadily
 * discarded (45 of 200 ~900B transfer replies lost) -- so a slice is ALSO
 * bounded by bytes (3000B/5ms = 4.8Mbps sustained, leaving stream-traffic
 * headroom under 10Mbps). ponytail: fixed slice/interval, not real cc
 * pacing -- wire the drain into the connection's cc budget if a lossy path
 * still overruns this. */
#define SRVRUN_DGRING_DRAIN_MAX 16
#define SRVRUN_DGRING_DRAIN_MS 5
#define SRVRUN_DGRING_DRAIN_BYTES 3000

/* The default advertised max_idle_timeout in ms (STP_DEFAULT_IDLE_TIMEOUT_MS
 * in tls/ext/stp/server_tp.h). The idle sweep itself uses each
 * connection's negotiated period (srvrun_idle_ms, RFC 9000 10.1). */
#define WIRED_SRVRUN_IDLE_MS 30000

/* SRVRUN_BOOT_DEADLINE_MS's own comment (its definition, above) relies on
 * clearing before the idle sweep's cadence would otherwise reap a boot
 * first -- that ordering only holds if the boot deadline is strictly
 * shorter than the idle timeout. */
_Static_assert(
    SRVRUN_BOOT_DEADLINE_MS < WIRED_SRVRUN_IDLE_MS,
    "a boot must be reaped before the idle sweep would catch it instead");

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

/* Above every real key (urgency <= 7): a slot that cannot send. */
#define SRVRUN_WT_KEY_IDLE 0xffffffffu

/* One loss batch's extent: the newest lost send time (cc_on_loss's
 * recovery-period key, RFC 9002 7.3.1) and the oldest/newest lost packet
 * (RFC 9002 7.6.2's persistent congestion period). pn order is send order,
 * so lo_pn is the oldest_ms packet and hi_pn the newest_ms one. */
typedef struct {
  u64 newest_ms, oldest_ms, lo_pn, hi_pn;
} srvrun_loss_span;

#define SRVRUN_LOSS_SPAN0 ((srvrun_loss_span){0, ~(u64)0, ~(u64)0, 0})

/* The congestion controller a fresh connection starts with (RFC 9002 7):
 * cfg->cc_algo == 0 means the build's default; a non-zero runtime choice
 * (--cc-algo) wins. Cubic by default, matching what the mainstream stacks
 * (quic-go, quiche) run out of the box, so untuned benchmark preconditions
 * are equal; a build wanting NewReno overrides -DWIRED_CC_ALGO_DEFAULT=0
 * (an explicit runtime NewReno request is indistinguishable from "unset"
 * because CC_ALGO_NEWRENO is itself 0). */
#ifndef WIRED_CC_ALGO_DEFAULT
#define WIRED_CC_ALGO_DEFAULT CC_ALGO_CUBIC
#endif

/* RFC 9000 10.1: how long a slot must have been idle before a full table may
 * reclaim it for a new client. 1s keeps anything actually talking (voice
 * sends every 20ms, keep-alive scales are far above this) out of reach of an
 * Initial flood, while an abruptly-vanished client's slot is reusable within
 * a human "reconnect right away" window instead of the 30s idle sweep. */
#define WIRED_SRVRUN_EVICT_GRACE_MS 1000

/* RFC 9114 5.2 shutdown grace period: once GOAWAY has gone out, poll for at
 * most this many 200ms ticks (~5s total) before closing regardless of
 * whether any connection is still open.
 * ponytail: a fixed tick budget, not a real deadline/clock — simplest thing
 * that reliably terminates; swap for a monotonic deadline if 5s is ever
 * wrong for a real workload. */
#define SRVRUN_DRAIN_TICKS 25
#define SRVRUN_DRAIN_TICK_MS 200

void srvrun_on_step(const srvrun_step_ctx* ctx, srvrun_conn* c, wired_mspan dg);
void srvrun_sess_on_step(const srvrun_step_ctx* ctx, int slot);
void srvrun_open_qpack_streams(srvrun_conn* c);
void srvrun_flush_qdec(srvrun_conn* c);
void srvrun_flush_wt_drain(srvrun_conn* c);
u64  srvrun_wtsend_final_size(srvrun_conn* c, u64 stream_id);
int  srvrun_wt_send_ended(srvrun_conn* c, u64 stream_id);
void srvrun_wtsend_release(srvrun_conn* c, u64 stream_id);
void srvrun_rst_keep(srvrun_conn* c, const u8* pl, usz pln);
u64  srvrun_pto_deadline_ms(const srvrun_conn* c, int pto_count);
u64  srvrun_idle_ms(const srvrun_conn* c);
int  srvrun_initial_live(const srvrun_conn* c);
void srvrun_close_all_wt(const srvrun_cfg* cfg, srvrun_conn* c);
void srvrun_grant_uni_streams(const srvrun_cfg* cfg, srvrun_conn* c, usz n);
wired_srvloop_stream_slot* srvrun_wt_rx_slot(srvrun_conn* c, int sidx);
int                        srvrun_send_wt_capsule(
    srvrun_conn* c, int sidx, wired_span capsule_bytes, u8 fin);
void srvrun_wt_connect_sender_drop(srvrun_conn* c, int sidx);
void srvrun_wt_connect_fin(srvrun_conn* c, int sidx);
u64  srvrun_wtwin_dropped(const srvrun_conn* c);
u64  srvrun_stream_limit_base(const srvrun_step_ctx* ctx);
void srvrun_answer_peer_stops(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_free_reset_reqs(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_drop_held_resets(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_path_reverts(const srvrun_step_ctx* ctx, const srvrun_conn* c);
void srvrun_path_step(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    wired_mspan            dg,
    const srvrun_rxmark*   mark);
void srvrun_path_tick(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_wtsend_stage_round(
    const srvrun_conn* c, srvrun_wtsend* w, wired_span payload, int fin);
int            srvrun_wtsend_matches(const srvrun_wtsend* w, u64 stream_id);
srvrun_wtsend* srvrun_wtsend_find(srvrun_conn* c, u64 stream_id);
void           srvrun_wt_send_done_mark(srvrun_conn* c, u64 stream_id);
void srvrun_resp_release_bigbuf(wired_srvrun_env* env, srvrun_resp* r);
int  srvrun_pace_ok(const srvrun_step_ctx* ctx, const srvrun_conn* c);
void srvrun_pace_next(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_pace_refill(const srvrun_step_ctx* ctx, srvrun_conn* c);
void srvrun_pace_charge(srvrun_conn* c, usz bytes);
void srvrun_ku_discard_stale(srvrun_conn* c, u64 now_ms);
int  srvrun_pace_within_poll_tick(const srvrun_conn* c);
usz  srvrun_resp_stop(
    const srvrun_step_ctx* ctx, srvrun_conn* c, srvrun_resp* r, u64 code);
void srvrun_note_ghost(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_resend_boot_flight(const srvrun_step_ctx* ctx, srvrun_conn* c);
int  srvrun_boot_probe_or_replay(const srvrun_step_ctx* ctx, srvrun_conn* c);
wired_span srvrun_dcid(wired_mspan dg, u8 short_hdr_len);

int  srvrun_conn_is_raw(const srvrun_conn* c);
usz  srvrun_mps(const srvrun_conn* c);
void srvrun_qlog_sent(const srvrun_cfg* cfg, const srvrun_conn* c, usz bytes);
void srvrun_qlog_recv(
    const srvrun_cfg* cfg, const srvrun_conn* c, u64 pn, usz bytes);
void srvrun_qlog_stream_sent(
    const srvrun_cfg*   cfg,
    const srvrun_conn*  c,
    u64                 now_ms,
    u64                 pn,
    const stream_frame* f);
srvrun_rxmark srvrun_rx_mark(const wired_srvloop* l);
int           srvrun_rx_app_adv(const srvrun_rxmark* m, const wired_srvloop* l);
void          srvrun_note_recv(
    const srvrun_step_ctx* ctx,
    const srvrun_rxmark*   m,
    const srvrun_conn*     c,
    usz                    bytes);
__attribute__((unused)) static void srvrun_test_reset_send_count(void);
__attribute__((unused)) static void srvrun_test_reset_flush_count(
    const srvrun_cfg* cfg);
i64 srvrun_rx_fd(const srvrun_cfg* cfg);
i64 srvrun_conn_fd(const srvrun_cfg* cfg, const srvrun_conn* c);
i64 srvrun_stage_fd(const srvrun_cfg* cfg, const wired_srvrun_env* e);

#endif
