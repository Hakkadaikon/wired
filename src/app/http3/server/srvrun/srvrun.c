#include "app/http3/server/srvrun/srvrun.h"

#include "app/datagram/dgdeliver/dg_send.h"
#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/establish.h"
#include "app/http3/request/h3resp/resp_build.h"
#include "app/http3/server/certreload/certreload.h"
#include "app/http3/server/sendsess/sendsess.h"
#include "app/http3/server/sigterm/sigterm.h"
#include "app/http3/server/srvloop/send.h"
#include "app/http3/core/h3/connect.h"
#include "app/http3/server/srvpoll/srvpoll.h"
#include "app/webtransport/session/session/session.h"
#include "common/bytes/util/bytes.h"
#include "common/platform/clock/mono.h"
#include "common/platform/debug/debug.h"
#include "common/platform/qlog/qlog.h"
#include "common/platform/qlog/qlogevent.h"
#include "common/platform/rng/cidgen.h"
#include "transport/conn/lifecycle/conntable/conntable.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/poll/wait.h"
#include "transport/packet/header/dcidresolve/dcidresolve.h"
#include "transport/packet/header/packet/header.h"
#include "transport/recovery/congestion/cc/cc.h"
#include "transport/recovery/congestion/cc/hystart.h"
#include "transport/recovery/congestion/cc/pacing.h"
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
} srvrun_cfg;

/* Storage a SIGHUP reload decodes into — must outlive the identity built from
 * it, so static (same lifetime rule as g_srvrun_table/g_srvrun_state below).
 */
static wired_certreload_store g_srvrun_certstore;

/* One live connection's mutable state: the orchestrator, the HTTP/3 loop,
 * whether it has completed its first (Initial) reply, the peer address to
 * send replies to (recorded from the datagram that opened the slot, RFC 9000
 * 5.1 — every reply on this slot targets this address, not whichever peer's
 * datagram was received most recently), and this slot's own server source
 * connection id. scid is generated per slot (quic_cid_generate): every slot
 * sharing cfg->id's fixed scid would make every connection answer to the same
 * DCID, collapsing quic_conntable's routing to a single slot. Indexed in
 * parallel with the conntable slot of the same index. */
typedef struct {
  wired_server     s;
  wired_srvloop    l;
  int              up;
  quic_sockaddr_in peer;
  u8               scid[WIRED_MAX_CID_LEN];
  int              goaway_sent; /**< 1 once graceful-shutdown GOAWAY sent */
  u64              last_ms;     /**< monotonic ms of the last routed datagram */
  wired_sendsess   sess;        /**< in-flight multi-packet response */
  quic_cc          cc;          /**< congestion window gating sess's pump */
  quic_hystart     hs;          /**< slow-start exit detector (RFC 9406) */
  u64              srtt_ms;     /**< smoothed RTT of this connection's acks */
  u64              next_send_ms; /**< pacing: earliest time to send again */
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
} srvrun_conn;

/* The running server's mutable state: a fixed pool of connection slots keyed
 * by DCID (RFC 9000 5.1) so one socket serves several clients at once.
 * ponytail: static storage, not a local — QUIC_CONNTABLE_CAP slots of
 * wired_server+wired_srvloop run into the hundreds of KB, too large for a
 * thread stack. A single-threaded server needs exactly one instance. */
static quic_conntable g_srvrun_table[QUIC_CONNTABLE_CAP];
static struct {
  srvrun_conn conns[QUIC_CONNTABLE_CAP];
} g_srvrun_state;

typedef struct {
  quic_conntable* table;
  srvrun_conn*    conns;
} srvrun_state;

/* Response storage, one stream per slot: 64-byte prefix room (HEADERS + DATA
 * header framed in place, quic_h3resp_prefix) followed by the handler's body.
 * ponytail: 16KB per response, 64 slots = 1MB BSS; raise WIRED_SRVRUN_RESP_MAX
 * when a deployment needs bigger bodies. */
#define WIRED_SRVRUN_RESP_MAX 16384
#define SRVRUN_RESP_HDR_ROOM 64
#define SRVRUN_CHUNK 1100 /* stream bytes per packet (fits a 1500 MTU) */
/* ponytail: fixed 300ms probe tick with a 5-probe budget, not an RTT-derived
 * PTO (the server tracks no RTT for its own sends yet); refine when the
 * send path grows RTT sampling. */
#define SRVRUN_PTO_MS 300
#define SRVRUN_PTO_MAX 5
static u8 g_srvrun_respstore[QUIC_CONNTABLE_CAP][WIRED_SRVRUN_RESP_MAX];

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
static void srvrun_send(
    const srvrun_cfg*  cfg,
    const srvrun_conn* c,
    quic_span          pkt,
    const char*        what) {
  (void)what; /* WIRED_LOG compiles out without -DQUIC_DEBUG */
  if (pkt.n) {
    wired_udp_send(cfg->fd, &c->peer, pkt);
    srvrun_qlog_sent(cfg, pkt.n);
    WIRED_LOG(what);
  }
}

/* Send each sealed Handshake flight datagram in order (a flight split per
 * RFC 9000 19.6 arrives as dgram_count slices of the flight buffer). */
static void srvrun_send_flight(
    const srvrun_cfg*        cfg,
    const srvrun_conn*       c,
    const u8*                hs,
    const wired_srvboot_out* out) {
  usz off = 0;
  for (usz i = 0; i < out->dgram_count; i++) {
    srvrun_send(
        cfg, c, quic_span_of(hs + off, out->dgram_len[i]),
        "server Handshake flight sent\n");
    off += out->dgram_len[i];
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
  u8                 ini[1500], hs[4096];
  quic_obuf          iob  = quic_obuf_of(ini, sizeof ini);
  quic_obuf          hob  = quic_obuf_of(hs, sizeof hs);
  wired_srvboot_conn conn = {&c->s, &c->l};
  wired_srvboot_id   sid  = srvrun_slot_id(ctx->cfg->id, c);
  wired_srvboot_out  out  = {&iob, &hob, {0}, 0, 0};
  if (!wired_srvboot_accept_acc(&conn, &sid, &c->boot, &out))
    return srvrun_refuse(ctx, c);
  srvrun_qlog_recv(ctx->cfg, out.client_pn, dg.n);
  wired_server_set_keylog_path(&c->s, ctx->cfg->keylog_path);
  wired_srvloop_set_handler(&c->l, ctx->cfg->handler, ctx->cfg->ctx);
  c->l.resp_external = 1; /* srvrun streams the response (multi-packet) */
  srvrun_send(ctx->cfg, c, quic_span_of(ini, iob.len), "server Initial sent\n");
  srvrun_send_flight(ctx->cfg, c, hs, &out);
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

/* A later datagram on a live slot: one real-wire step, send any sealed
 * reply — unless the step observed a peer CONNECTION_CLOSE, in which case
 * the connection is draining and nothing further is sent (RFC 9000 10.2.2).
 */
static void srvrun_on_step(
    const srvrun_step_ctx* ctx, srvrun_conn* c, quic_mspan dg) {
  u8                 out[1500];
  quic_obuf          ob       = quic_obuf_of(out, sizeof out);
  wired_srvloop_conn conn     = {&c->l, &c->s};
  srvrun_rxmark      mark     = srvrun_rx_mark(&c->l);
  int                produced = wired_srvloop_step(&conn, dg, &ob);
  srvrun_note_recv(ctx, &mark, c, dg.n);
  if (c->l.peer_closed) return;
  if (produced)
    srvrun_send(
        ctx->cfg, c, quic_span_of(out, ob.len),
        "1-RTT reply sealed and sent\n");
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
static usz srvrun_ctrl_settings_len(void) {
  u8  tmp[64];
  usz n = 0;
  quic_h3conn_open_control(tmp, sizeof tmp, &n);
  return n;
}

/* Build the 1-RTT payload for a GOAWAY (RFC 9114 5.2): the H3 GOAWAY frame
 * wrapped in a STREAM frame at the control stream's fixed post-SETTINGS
 * offset. Returns 1 with plb->len set, 0 on overflow. */
static int srvrun_goaway_payload(quic_obuf* plb) {
  u8                h3[16];
  usz               h3n = quic_h3_goaway_put(h3, sizeof h3, SRVRUN_GOAWAY_ID);
  quic_stream_frame f;
  if (h3n == 0) return 0;
  f = (quic_stream_frame){
      SRVRUN_CTRL_STREAM, srvrun_ctrl_settings_len(), h3n, h3, 0};
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
  if (!srvrun_goaway_payload(&plb)) return 0;
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
 * Does not check the peer's advertised max_datagram_frame_size, since this
 * SDK does not yet retain peer transport parameters (see
 * tasks/webtransport-plan.md WT-A-007/008). Bounded only by the local
 * dg_pending_buf capacity, consistent with how other frame types in this file
 * are already bounded by a local packet-size budget (SRVRUN_CHUNK et al.)
 * rather than a peer-advertised limit.
 * ponytail: unused in the freestanding build (only tests/run.c calls this),
 * so it needs the attribute to avoid -Wunused-function under -Werror there.
 * @return 1 if queued, 0 if data.n exceeds dg_pending_buf's capacity */
__attribute__((unused)) static int srvrun_queue_datagram(
    srvrun_conn* c, quic_span data) {
  if (data.n > sizeof c->dg_pending_buf) return 0;
  quic_memcpy(c->dg_pending_buf, data.p, data.n);
  c->dg_pending_len = data.n;
  c->dg_pending     = 1;
  return 1;
}

/* Seal c's one pending QUIC DATAGRAM (RFC 9221 5) into a 1-RTT packet and send
 * it. Unlike srvrun_send_slice/srvrun_send_goaway, there is no
 * wired_sendsess/ACK-loss bookkeeping: RFC 9221 1 DATAGRAM frames are never
 * retransmitted. max_frame_size is passed as the local plaintext buffer's own
 * capacity, so quic_dgdeliver_frame's internal size check bounds against
 * local capacity, not a (nonexistent) peer-advertised limit. Clears
 * c->dg_pending on success. Returns 1 if sent, 0 if the frame could not be
 * built (e.g. it would not fit). */
static int srvrun_send_pending_datagram(
    const srvrun_cfg* cfg, srvrun_conn* c, quic_obuf* out) {
  u8                  pl[1400];
  quic_obuf           plb = quic_obuf_of(pl, sizeof pl);
  quic_dgdeliver_opts o   = {.with_length = 1, .max_frame_size = sizeof pl};
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

/* Graceful shutdown: set by srvrun_sigterm_handler (async-signal-safe: it only
 * stores to this flag), read by the main loop to stop accepting new
 * connections and start winding down live ones. volatile because a signal
 * handler writes it asynchronously to the loop reading it. */
static volatile int g_srvrun_shutdown;

/* SIGTERM handler: the ONLY thing safe to do here is set a flag (async-signal-
 * safe rule) — no syscalls, no allocation, nothing the interrupted code might
 * itself have been mid-way through. Registration (wired_sigterm_install) uses
 * the real rt_sigaction(2) syscall and is not exercised by unit tests; the
 * behavior driven off the flag below is. */
static void srvrun_sigterm_handler(int sig) {
  (void)sig;
  g_srvrun_shutdown = 1;
}

/* 1 once a graceful shutdown has been requested (SIGTERM, or a test forcing
 * the flag directly). */
static int srvrun_shutdown_requested(void) { return g_srvrun_shutdown; }

/* Test-only hook: force the shutdown flag without going through a real
 * SIGTERM delivery (rt_sigaction registration is not unit-testable — see
 * sigterm.c — so tests drive the flag directly and assert on the behavior
 * that follows: new-Initial rejection, GOAWAY fan-out, drain). Also resets
 * it, so tests do not leak shutdown state into one another.
 * ponytail: unused in the freestanding build (only tests/run.c calls this),
 * so it needs the attribute to avoid -Wunused-function under -Werror there. */
__attribute__((unused)) static void srvrun_test_set_shutdown(int v) {
  g_srvrun_shutdown = v;
}

/* Certificate hot reload: set by srvrun_sighup_handler (async-signal-safe:
 * only stores to this flag), read by the main loop to trigger a reload of
 * cfg->id's certificate chain and signing key from cfg->cert_path/key_path.
 * volatile for the same reason as g_srvrun_shutdown above. */
static volatile int g_srvrun_reload;

/* SIGHUP handler: same async-signal-safety rule as srvrun_sigterm_handler —
 * set the flag and nothing else. Registration (wired_sighup_install) is not
 * exercised by unit tests; the behavior driven off the flag below is. */
static void srvrun_sighup_handler(int sig) {
  (void)sig;
  g_srvrun_reload = 1;
}

/* 1 once a certificate reload has been requested (SIGHUP, or a test forcing
 * the flag directly). */
static int srvrun_reload_requested(void) { return g_srvrun_reload; }

/* Test-only hook: force the reload flag without a real SIGHUP delivery (same
 * rationale as srvrun_test_set_shutdown). Also resets it, so tests do not
 * leak reload state into one another.
 * ponytail: unused in the freestanding build, needs the attribute to avoid
 * -Wunused-function under -Werror there. */
__attribute__((unused)) static void srvrun_test_set_reload(int v) {
  g_srvrun_reload = v;
}

/* Re-decode cfg->cert_path/key_path into cfg->id in place (wired_certreload_
 * load overwrites only chain/chain_count/cert_seed, RFC 9114 5.2-adjacent
 * operational note: no live connection is affected, see the srvrun_cfg
 * comment above). A failed reload (bad path or malformed PEM/DER) leaves the
 * previous identity untouched — wired_certreload_load does not partially
 * mutate *id on failure. No-op when reload is disabled (cert_path unset). */
static void srvrun_reload_cert(const srvrun_cfg* cfg) {
  if (!cfg->cert_path) return;
  if (!wired_certreload_load(
          cfg->cert_path, cfg->key_path, &g_srvrun_certstore, cfg->id))
    WIRED_LOG("cert reload failed, keeping previous identity\n");
}

/* Consume a pending reload request once: clear the flag first so a SIGHUP
 * arriving mid-reload is not lost, then (re)load if one was pending. */
static void srvrun_reload_if_requested(const srvrun_cfg* cfg) {
  if (!srvrun_reload_requested()) return;
  g_srvrun_reload = 0;
  srvrun_reload_cert(cfg);
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

/* Fill the response body from the app handler (empty without one, or when
 * it declines). */
static void srvrun_call_handler(
    const srvrun_step_ctx* ctx,
    srvrun_conn*           c,
    quic_obuf*             body,
    const char**           ct) {
  if (!ctx->cfg->handler) return;
  if (!ctx->cfg->handler(ctx->cfg->ctx, &c->l.req, body, ct)) body->len = 0;
}

/* All len octets of m equal want (draft-ietf-webtrans-http3-15 SS3: the
 * :protocol value is matched byte for byte, same idiom as connect.c's own
 * method_is_connect). */
static int wt_bytes_eq(const u8* m, const u8* want, usz len) {
  for (usz i = 0; i < len; i++)
    if (m[i] != want[i]) return 0;
  return 1;
}

/* r's :protocol value is exactly "webtransport-h3"
 * (draft-ietf-webtrans-http3-15 SS3, not the older draft's "webtransport"). */
static int wt_protocol_is_webtransport_h3(const wired_h3reqdrive_req* r) {
  static const u8 want[] = {
      'w', 'e', 'b', 't', 'r', 'a', 'n', 's', 'p', 'o', 'r', 't',
      '-', 'h', '3'};
  if (!r->protocol || r->protocol_len != sizeof want) return 0;
  return wt_bytes_eq(r->protocol, want, sizeof want);
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
 * :protocol negotiated (settings always advertised, Step 1 above) and equal
 * to "webtransport-h3". */
static int srvrun_is_wt_connect(const wired_h3reqdrive_req* r) {
  if (!wt_ext_connect_shape_ok(r)) return 0;
  if (!wt_protocol_is_webtransport_h3(r)) return 0;
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

/* Seal a bare status-only response (no body, no content-type) into the
 * slot's own storage and arm the session over it — the same low-level
 * prefix+arm mechanism srvrun_start_app_resp uses for a normal 200, minus the
 * app handler: this is protocol-level WebTransport response building
 * (draft-ietf-webtrans-http3-15 SS3.2), not an application response. Used for
 * both the 2xx that establishes a session and the 403 that rejects one
 * (WT-B-005/007/008). */
static void srvrun_start_wt_status(srvrun_conn* c, int slot, u16 status) {
  u8*       st  = g_srvrun_respstore[slot];
  u8        pre[SRVRUN_RESP_HDR_ROOM];
  quic_obuf pob = quic_obuf_of(pre, sizeof pre);
  usz       off;
  if (!quic_h3resp_prefix(status, 0, 0, &pob)) return;
  off = SRVRUN_RESP_HDR_ROOM - pob.len;
  quic_put_bytes(
      quic_mspan_of(st, SRVRUN_RESP_HDR_ROOM), &off,
      quic_span_of(pre, pob.len));
  wired_sendsess_arm(
      &c->sess, st + SRVRUN_RESP_HDR_ROOM - pob.len, pob.len, SRVRUN_CHUNK);
}

/* Establish a WebTransport session for this Extended CONNECT (draft-ietf-
 * webtrans-http3-15 SS3.2/SS4): the session id is the CONNECT stream's own
 * id. Skips the normal app-handler response path entirely. */
static void srvrun_start_wt(srvrun_conn* c, int slot) {
  wired_wt_session_init(&c->wt, c->l.req_stream_id);
  wired_wt_session_establish(&c->wt);
  c->wt_active = 1;
  srvrun_start_wt_status(c, slot, 200);
}

/* Reject this Extended CONNECT with 403 (WT-B-005/007/008: a present but
 * malformed Origin) without establishing a session. */
static void srvrun_reject_wt(srvrun_conn* c, int slot) {
  srvrun_start_wt_status(c, slot, 403);
}

/* Body of srvrun_start_resp for a normal (non-WT) request: run the app
 * handler, then frame+arm the response exactly as before this task. Split
 * out so srvrun_start_resp itself stays at its gate/dispatch decision (CCN). */
static void srvrun_start_app_resp(
    const srvrun_step_ctx* ctx, srvrun_conn* c, int slot) {
  u8*         st   = g_srvrun_respstore[slot];
  quic_obuf   body = quic_obuf_of(
      st + SRVRUN_RESP_HDR_ROOM, WIRED_SRVRUN_RESP_MAX - SRVRUN_RESP_HDR_ROOM);
  u8          pre[SRVRUN_RESP_HDR_ROOM];
  quic_obuf   pob = quic_obuf_of(pre, sizeof pre);
  const char* ct  = 0;
  usz         off;
  srvrun_call_handler(ctx, c, &body, &ct);
  if (!quic_h3resp_prefix(200, ct, body.len, &pob)) return;
  off = SRVRUN_RESP_HDR_ROOM - pob.len;
  quic_put_bytes(
      quic_mspan_of(st, SRVRUN_RESP_HDR_ROOM), &off,
      quic_span_of(pre, pob.len));
  wired_sendsess_arm(
      &c->sess, st + SRVRUN_RESP_HDR_ROOM - pob.len, pob.len + body.len,
      SRVRUN_CHUNK);
}

/* Reject this Extended CONNECT with 429 (WT-C-010/011: a second Extended
 * CONNECT arriving while a WT session is already active on this connection)
 * without disturbing the existing session. One session per connection for
 * now (tasks/webtransport-plan.md scope) -- srvrun_start_wt would otherwise
 * unconditionally re-init c->wt, silently resetting an ESTABLISHED session
 * back to UNESTABLISHED and dropping its buffered state. */
static void srvrun_reject_wt_busy(srvrun_conn* c, int slot) {
  srvrun_start_wt_status(c, slot, 429);
}

/* A well-formed Extended CONNECT for WebTransport either establishes a
 * session (Origin absent, or present and well-formed, and no session already
 * active on this connection -- WT-C-010/011), or is rejected: 403 for a
 * malformed Origin (WT-B-005/007/008), 429 if a session is already active. */
static void srvrun_dispatch_wt(srvrun_conn* c, int slot) {
  if (!wt_origin_ok(&c->l.req)) {
    srvrun_reject_wt(c, slot);
    return;
  }
  if (c->wt_active) {
    srvrun_reject_wt_busy(c, slot);
    return;
  }
  srvrun_start_wt(c, slot);
}

/* Build the decoded request's response into the slot's own storage and arm
 * the session over the whole stream. A session already in flight keeps the
 * storage; the new request is dropped (one response at a time per
 * connection, matching the one-request stream model). An Extended CONNECT
 * for WebTransport (RFC 9220 3, draft-ietf-webtrans-http3-15 SS3) establishes
 * a WT session or is rejected with 403, and never reaches the app handler. */
static void srvrun_start_resp(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (c->sess.active) return;
  if (srvrun_is_wt_connect(&c->l.req)) {
    srvrun_dispatch_wt(c, slot);
    return;
  }
  srvrun_start_app_resp(ctx, c, slot);
}

/* Seal one slice as its own 1-RTT packet (a STREAM frame on the request
 * stream, RFC 9000 19.8) and send it. Returns 1 once logged in flight. */
static int srvrun_send_slice(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_sendq_slice* sl) {
  u8                pl[1400], out[1500];
  quic_obuf         plb = quic_obuf_of(pl, sizeof pl);
  quic_obuf         ob  = quic_obuf_of(out, sizeof out);
  quic_stream_frame f   = {
      0, sl->offset, sl->len, c->sess.q.p + sl->offset, sl->fin};
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
  return wired_sendsess_sent(&c->sess, sl, pn, ctx->now_ms);
}

static int  srvrun_pace_ok(const srvrun_step_ctx* ctx, const srvrun_conn* c);
static void srvrun_pace_next(const srvrun_step_ctx* ctx, srvrun_conn* c);

/* 1 when both the congestion window (RFC 9002 7) and the pacing schedule
 * (RFC 9002 7.7) allow another packet now. */
static int srvrun_can_send(const srvrun_step_ctx* ctx, const srvrun_conn* c) {
  return wired_sendsess_inflight_bytes(&c->sess) + SRVRUN_CHUNK <= c->cc.cwnd &&
         srvrun_pace_ok(ctx, c);
}

/* Ship one slice and schedule the next paced send. */
static int srvrun_slice_out(
    const srvrun_step_ctx* ctx, srvrun_conn* c, const wired_sendq_slice* sl) {
  if (!srvrun_send_slice(ctx, c, sl)) return 0;
  srvrun_pace_next(ctx, c);
  return 1;
}

/* Send one slice if the gates allow and one is ready. */
static int srvrun_pump_one(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  wired_sendq_slice sl;
  if (!srvrun_can_send(ctx, c)) return 0;
  if (!wired_sendsess_take(&c->sess, &sl)) return 0;
  return srvrun_slice_out(ctx, c, &sl);
}

/* Transmit while the window has room and slices are ready. */
static void srvrun_pump_sess(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!c->sess.active) return;
  while (srvrun_pump_one(ctx, c)) {
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
/* RFC 9002 5.3 (shape): seed on the first sample, then 7/8 old + 1/8 new. */
static void srvrun_rtt_note(srvrun_conn* c, u64 sample_ms) {
  c->srtt_ms = c->srtt_ms ? (7 * c->srtt_ms + sample_ms) / 8 : sample_ms;
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

/* Feed one acked packet's RTT sample (now - send time) to the slow-start
 * exit detector (RFC 9406); on the verdict, end slow start by dropping
 * ssthresh to the current window. Round boundary: the next pn to be sent. */
static void srvrun_hystart_ack(srvrun_conn* c, u64 pn, u64 sent_ms, u64 now) {
  srvrun_rtt_note(c, now - sent_ms);
  if (!srvrun_in_slow_start(c)) return;
  if (quic_hystart_sample(&c->hs, now - sent_ms, pn, c->l.tx_pn))
    c->cc.ssthresh = c->cc.cwnd;
}

/* Feed every in-flight packet an ACK range covers to the detector before
 * the range is consumed. */
static void srvrun_hystart_range(srvrun_conn* c, u64 lo, u64 hi, u64 now) {
  for (usz i = 0; i < WIRED_SENDSESS_LOG; i++) {
    const wired_sent_slice* e = &c->sess.log[i];
    if (wired_sendsess_covered(e, lo, hi))
      srvrun_hystart_ack(c, e->pn, e->sent_ms, now);
  }
}

/* Credit one ACK range to the congestion controller before consuming it
 * (RFC 9002 7.3.2: growth per acked bytes; the newest send time among the
 * hits drives recovery exit). */
static void srvrun_cc_range(srvrun_conn* c, u64 lo, u64 hi, u64 now_ms) {
  u64 newest = 0;
  usz bytes  = wired_sendsess_peek_ack(&c->sess, lo, hi, &newest);
  srvrun_hystart_range(c, lo, hi, now_ms);
  if (bytes) quic_cc_on_ack(&c->cc, bytes, newest, now_ms);
  wired_sendsess_ack(&c->sess, lo, hi);
}

/* Threshold pass: requeue losses, shrink the window once per loss event,
 * log each lost packet.
 * ponytail: on_loss is fed now for both times (a fresh recovery per loss
 * event — more conservative than per-period; refine with per-packet sent
 * times when RTT sampling lands). */
static void srvrun_reap_losses(
    const srvrun_step_ctx* ctx, const srvrun_cfg* cfg, srvrun_conn* c) {
  u64 lost[WIRED_SENDSESS_LOG];
  usz n = wired_sendsess_detect_lost(
      &c->sess, c->sess.largest_acked, lost, WIRED_SENDSESS_LOG);
  if (n) quic_cc_on_loss(&c->cc, ctx->now_ms, ctx->now_ms);
  srvrun_qlog_lost(cfg, lost, n);
}

static void srvrun_feed_acks(
    const srvrun_step_ctx* ctx, const srvrun_cfg* cfg, srvrun_conn* c) {
  for (usz i = 0; i < c->l.ack_n; i++)
    srvrun_cc_range(c, c->l.ack_lo[i], c->l.ack_hi[i], ctx->now_ms);
  if (c->sess.has_acked) srvrun_reap_losses(ctx, cfg, c);
}

/* Send c's pending DATAGRAM (if any) using a scratch quic_obuf on the stack,
 * the same shape srvrun_send_pending_datagram expects. */
static void srvrun_pump_datagram(const srvrun_step_ctx* ctx, srvrun_conn* c) {
  u8        out[1500];
  quic_obuf ob = quic_obuf_of(out, sizeof out);
  if (!c->dg_pending) return;
  srvrun_send_pending_datagram(ctx->cfg, c, &ob);
}

static void srvrun_sess_on_step(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  srvrun_feed_acks(ctx, ctx->cfg, c);
  quic_cc_bbr_tick(
      &c->cc, wired_sendsess_inflight_bytes(&c->sess), ctx->now_ms);
  wired_sendsess_done(&c->sess);
  if (c->l.got_request) srvrun_start_resp(ctx, slot);
  srvrun_pump_sess(ctx, slot);
  srvrun_pump_datagram(ctx, c);
}

/* 1 while this slot still owes response bytes (in flight, paced, or window
 * blocked) — the loop must keep ticking for it. */
static int srvrun_sess_waiting(const srvrun_conn* c) {
  return c->up && c->sess.active;
}

/* Probe or tear down one slot on a PTO tick (RFC 9002 6.2): a spent probe
 * budget frees the slot (the peer stopped acknowledging), otherwise the
 * requeued probe goes straight back out. */
static void srvrun_pto_slot(const srvrun_step_ctx* ctx, int slot) {
  srvrun_conn* c = &ctx->st->conns[slot];
  if (!srvrun_sess_waiting(c)) return;
  if (!wired_sendsess_pto_fire(&c->sess, SRVRUN_PTO_MAX)) {
    srvrun_free_slot(ctx->st, slot);
    return;
  }
  srvrun_pump_sess(ctx, slot);
}

/* A poll timeout with responses in flight: fire the probe pass over every
 * waiting slot. */
static void srvrun_fire_ptos(const srvrun_cfg* cfg, srvrun_state* st) {
  srvrun_step_ctx ctx = {cfg, 0, st, quic_clock_mono_ms()};
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++) srvrun_pto_slot(&ctx, (int)i);
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

static void srvrun_serve_slot(
    const srvrun_step_ctx* ctx, int slot, quic_mspan dg) {
  srvrun_conn* c = &ctx->st->conns[slot];
  c->last_ms     = ctx->now_ms; /* RFC 9000 10.1: activity resets idle age */
  if (srvrun_is_new(c, dg)) {
    srvrun_cold_start(ctx, slot, dg);
    return;
  }
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
  wired_udp_send(ctx->cfg->fd, ctx->peer, quic_span_of(vn, n));
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

/* Bind a UDP socket on port. Returns the fd, or <0 on failure. */
static i64 srvrun_listen(u16 port, int so_busy_poll_us) {
  quic_sockaddr_in sa;
  i64              fd = wired_udp_socket();
  if (fd < 0) return fd;
  /* Best-effort: lets multiple srvworkers children share one port (tasks/
   * core-pinning-plan.md PIN-004). A single-worker run does not need it, so a
   * failure here is not fatal -- fall through to bind unconditionally. */
  wired_udp_reuseport_enable(fd);
  srvrun_maybe_busy_poll(fd, so_busy_poll_us);
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

/* Receive batch: srvrun drains up to this many datagrams per recvmmsg call.
 * ponytail: 16 x 2048B static buffers (32KB, BSS like g_srvrun_state); raise
 * if a profile ever shows the loop syscall-bound at higher fan-in. */
#define SRVRUN_RX_BATCH 16
static u8 g_srvrun_rxstorage[SRVRUN_RX_BATCH][2048];

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
    if (srvrun_sess_waiting(&st->conns[i])) return 1;
  return 0;
}

/* busy_poll=1: the blocking poll(2) itself is replaced by a non-blocking
 * return (tasks/polling-driver-plan.md — the srvrun_any_waiting branch above
 * is kept as-is; only this leaf call changes). The actual non-blocking
 * receive happens at the recvmmsg step (srvrun_recv), so there is nothing
 * left to wait for here. */
static int srvrun_wait_input(const srvrun_cfg* cfg, srvrun_state* st) {
  if (!srvrun_any_waiting(st)) return 1; /* nothing in flight: just block */
  if (cfg->busy_poll) return 1;
  return quic_poll_wait_readable(cfg->fd, SRVRUN_PTO_MS) > 0;
}

/* The batch receive call itself: MSG_DONTWAIT spin-step in busy_poll mode,
 * the existing blocking recvmmsg otherwise (byte-identical default path). */
static i64 srvrun_recv(const srvrun_cfg* cfg, quic_mmsg_buf* bufs, usz nbufs) {
  if (cfg->busy_poll) return wired_srvpoll_spin_step(cfg->fd, bufs, nbufs);
  return wired_udp_recvmmsg(cfg->fd, bufs, nbufs);
}

static void srvrun_step(
    const srvrun_cfg* cfg, srvrun_state* st, quic_mmsg_buf* bufs, usz nbufs) {
  i64 r;
  srvrun_reload_if_requested(cfg);
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

/* Point each batch slot at its static storage. */
static void srvrun_rx_init(quic_mmsg_buf* bufs) {
  for (usz i = 0; i < SRVRUN_RX_BATCH; i++)
    bufs[i].buf =
        quic_mspan_of(g_srvrun_rxstorage[i], sizeof g_srvrun_rxstorage[i]);
}

/* Receive datagrams until told to stop: normal service while no shutdown has
 * been requested; once requested, send GOAWAY to every live connection once
 * and drain for a bounded grace period (RFC 9114 5.2) before returning. */
static void srvrun_loop(const srvrun_cfg* cfg) {
  srvrun_state  st = {g_srvrun_table, g_srvrun_state.conns};
  quic_mmsg_buf bufs[SRVRUN_RX_BATCH];
  int           tick = 0;
  quic_conntable_init(st.table, QUIC_CONNTABLE_CAP);
  srvrun_rx_init(bufs);
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
 * SIGHUP conditionally (srvrun_install_sighup). */
static void srvrun_install_signals(const srvrun_cfg* cfg) {
  if (!wired_sigterm_install(srvrun_sigterm_handler))
    WIRED_LOG("SIGTERM install failed, no graceful shutdown\n");
  srvrun_install_sighup(cfg);
}

int wired_server_run_opt(
    u16                     port,
    wired_srvboot_id*       id,
    wired_srvrun_handler    h,
    wired_srvrun_obs        obs,
    const wired_srvrun_opt* opt) {
  srvrun_cfg cfg = {
      srvrun_listen(port, opt->so_busy_poll_us),
      id,
      h.cb,
      h.ctx,
      obs.qlog_path,
      obs.keylog_path,
      obs.cert_path,
      obs.key_path,
      obs.cc_algo,
      opt->busy_poll};
  if (cfg.fd < 0) return 0;
  srvrun_install_signals(&cfg);
  WIRED_LOG("listening\n");
  srvrun_loop(&cfg);
  return 1;
}

int wired_server_run(
    u16                  port,
    wired_srvboot_id*    id,
    wired_srvrun_handler h,
    wired_srvrun_obs     obs) {
  static const wired_srvrun_opt default_opt = {0, 0};
  return wired_server_run_opt(port, id, h, obs, &default_opt);
}
