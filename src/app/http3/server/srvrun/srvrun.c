#include "app/http3/server/srvrun/srvrun.h"

#include "app/http3/core/h3/frame.h"
#include "app/http3/core/h3conn/establish.h"
#include "app/http3/server/sigterm/sigterm.h"
#include "app/http3/server/srvloop/send.h"
#include "common/platform/debug/debug.h"
#include "common/platform/rng/cidgen.h"
#include "transport/conn/lifecycle/conntable/conntable.h"
#include "transport/io/socket/io/udp.h"
#include "transport/io/socket/poll/wait.h"
#include "transport/packet/header/dcidresolve/dcidresolve.h"
#include "transport/packet/header/packet/header.h"
#include "transport/stream/data/appdata/stream_send.h"

/* The server's fixed run context: the bound socket and the application's
 * identity + request handler. Set once at startup, never mutated — passed by
 * const pointer so no per-datagram copy (a Parameter Object folds what were 4
 * separate args threaded through every step). */
typedef struct {
  i64                     fd;
  const wired_srvboot_id *id;
  wired_srvloop_handler   handler;
  void                   *ctx;
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
typedef struct {
  wired_server     s;
  wired_srvloop    l;
  int              up;
  quic_sockaddr_in peer;
  u8               scid[WIRED_MAX_CID_LEN];
  int              goaway_sent; /**< 1 once graceful-shutdown GOAWAY sent */
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
  quic_conntable *table;
  srvrun_conn    *conns;
} srvrun_state;

/* Everything one datagram-serving step needs besides the datagram itself and
 * the resolved slot: the fixed run config, the peer address the datagram
 * arrived from, and the mutable server state. Folded into one parameter so
 * srvrun_send/on_initial/on_step/serve stay <=3 args. */
typedef struct {
  const srvrun_cfg       *cfg;
  const quic_sockaddr_in *peer;
  srvrun_state           *st;
} srvrun_step_ctx;

/* Send a sealed buffer to c's recorded peer, with a trace line (skip an empty
 * buffer). Always targets the slot's own peer (RFC 9000 5.1), not whichever
 * datagram was received most recently. */
static void srvrun_send(
    const srvrun_cfg  *cfg,
    const srvrun_conn *c,
    quic_span          pkt,
    const char        *what) {
  (void)what; /* WIRED_LOG compiles out without -DQUIC_DEBUG */
  if (pkt.n) {
    wired_udp_send(cfg->fd, &c->peer, pkt);
    WIRED_LOG(what);
  }
}

/* Send each sealed Handshake flight datagram in order (a flight split per
 * RFC 9000 19.6 arrives as dgram_count slices of the flight buffer). */
static void srvrun_send_flight(
    const srvrun_cfg        *cfg,
    const srvrun_conn       *c,
    const u8                *hs,
    const wired_srvboot_out *out) {
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
    const wired_srvboot_id *base, const srvrun_conn *c) {
  wired_srvboot_id id = *base;
  id.scid             = c->scid;
  return id;
}

/* First datagram on this slot: cold-start the connection, register the
 * handler, send the server Initial and each Handshake flight datagram (the
 * Initial alone is padded to 1200 bytes, RFC 9000 14.1, so coalescing them
 * would exceed a 1500-byte MTU datagram). Returns 1 once the connection is
 * up. */
static int srvrun_on_initial(
    const srvrun_step_ctx *ctx, srvrun_conn *c, quic_mspan dg) {
  u8                 ini[1500], hs[4096];
  quic_obuf          iob  = quic_obuf_of(ini, sizeof ini);
  quic_obuf          hob  = quic_obuf_of(hs, sizeof hs);
  wired_srvboot_conn conn = {&c->s, &c->l};
  wired_srvboot_id   sid  = srvrun_slot_id(ctx->cfg->id, c);
  wired_srvboot_in   in   = {&sid, dg};
  wired_srvboot_out  out  = {&iob, &hob, {0}, 0};
  if (!wired_srvboot_accept(&conn, &in, &out))
    return WIRED_LOG("srvboot accept failed\n"), 0;
  wired_srvloop_set_handler(&c->l, ctx->cfg->handler, ctx->cfg->ctx);
  srvrun_send(ctx->cfg, c, quic_span_of(ini, iob.len), "server Initial sent\n");
  srvrun_send_flight(ctx->cfg, c, hs, &out);
  return 1;
}

/* A later datagram on a live slot: one real-wire step, send any sealed
 * reply. */
static void srvrun_on_step(
    const srvrun_step_ctx *ctx, srvrun_conn *c, quic_mspan dg) {
  u8                 out[1500];
  quic_obuf          ob   = quic_obuf_of(out, sizeof out);
  wired_srvloop_conn conn = {&c->l, &c->s};
  if (wired_srvloop_step(&conn, dg, &ob))
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
static int srvrun_goaway_payload(quic_obuf *plb) {
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
    const srvrun_cfg *cfg, srvrun_conn *c, quic_obuf *out) {
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
static int srvrun_owes_goaway(const srvrun_conn *c) {
  return c->up && c->l.hs_done_sent && !c->goaway_sent;
}

/* Send GOAWAY to every live connection that still owes one (RFC 9114 5.2), the
 * first step of graceful shutdown. Connections not yet confirmed simply have
 * no 1-RTT key to receive it and are left to time out normally. */
static void srvrun_goaway_all(const srvrun_cfg *cfg, srvrun_state *st) {
  u8        out[256];
  quic_obuf ob = quic_obuf_of(out, sizeof out);
  for (usz i = 0; i < QUIC_CONNTABLE_CAP; i++)
    if (srvrun_owes_goaway(&st->conns[i]))
      srvrun_send_goaway(cfg, &st->conns[i], &ob);
}

/* 1 once every slot has drained (gone down) or never came up — the condition
 * that lets the shutdown grace period end early instead of waiting out the
 * whole budget. */
static int srvrun_all_drained(const srvrun_state *st) {
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

/* RFC 9000 7: a long-header Initial on a slot already up only (re)cold-starts
 * it once that connection is confirmed (its DCID legitimately changes after
 * ServerHello, so gate on confirmation, not the DCID). */
static int srvrun_reinit_ok(const srvrun_conn *c) {
  if (!c->up) return 1;
  return wired_server_is_confirmed(&c->s);
}

/* Whether dg may (re)open c: a long-header Initial, not during graceful
 * shutdown (no new Initial is accepted, fresh slot or existing one alike),
 * and only on a slot eligible to (re)cold-start. */
static int srvrun_is_new(const srvrun_conn *c, quic_mspan dg) {
  if (!wired_srvboot_is_initial(dg.p, dg.n)) return 0;
  if (srvrun_shutdown_requested()) return 0;
  return srvrun_reinit_ok(c);
}

/* Drive one received datagram against its resolved slot: a new Initial
 * (re)opens the connection, any other datagram steps the live loop. */
static void srvrun_serve_slot(
    const srvrun_step_ctx *ctx, srvrun_conn *c, quic_mspan dg) {
  if (srvrun_is_new(c, dg))
    c->up = srvrun_on_initial(ctx, c, dg);
  else if (c->up)
    srvrun_on_step(ctx, c, dg);
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
static int srvrun_find_slot(const srvrun_step_ctx *ctx, quic_span dcid) {
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
    const srvrun_step_ctx *ctx, quic_span dcid, int is_initial) {
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
    const srvrun_step_ctx *ctx, quic_span dcid, int is_initial) {
  int slot = srvrun_claim_slot(ctx, dcid, is_initial);
  if (slot < 0) return -1;
  ctx->st->conns[slot] = (srvrun_conn){{0}, {0}, 0, *ctx->peer, {0}, 0};
  if (quic_cid_generate(ctx->st->conns[slot].scid, ctx->cfg->id->scid_len))
    return slot;
  quic_conntable_remove(ctx->st->table, QUIC_CONNTABLE_CAP, slot);
  return -1;
}

/* Drive one received datagram: resolve it to a connection slot by DCID (a
 * fresh slot only for an unrecognized DCID on a new Initial, RFC 9000 5.1/7)
 * and serve it there. Silently drops a datagram that matches no slot and
 * cannot claim or initialize a new one. */
static void srvrun_serve(const srvrun_step_ctx *ctx, quic_mspan dg) {
  quic_span dcid = srvrun_dcid(dg, ctx->cfg->id->scid_len);
  int       slot = srvrun_find_slot(ctx, dcid);
  if (slot < 0) {
    slot = srvrun_open_slot(ctx, dcid, wired_srvboot_is_initial(dg.p, dg.n));
    if (slot < 0) return;
  }
  srvrun_serve_slot(ctx, &ctx->st->conns[slot], dg);
}

/* Bind a UDP socket on port. Returns the fd, or <0 on failure. */
static i64 srvrun_listen(u16 port) {
  quic_sockaddr_in sa;
  i64              fd = wired_udp_socket();
  if (fd < 0) return fd;
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

/* One receive+serve step when a datagram is waiting. */
static void srvrun_step(
    const srvrun_cfg *cfg, srvrun_state *st, u8 *buf, usz cap) {
  quic_sockaddr_in peer;
  i64 r = wired_udp_recvfrom(cfg->fd, quic_mspan_of(buf, cap), &peer);
  if (r > 0) {
    srvrun_step_ctx ctx = {cfg, &peer, st};
    srvrun_serve(&ctx, quic_mspan_of(buf, (usz)r));
  }
}

/* Drain phase (RFC 9114 5.2): GOAWAY already sent to every live connection:
 * poll with a timeout instead of blocking forever, so the loop keeps making
 * progress toward the tick budget even if the peer sends nothing more.
 * Returns 1 once every connection has drained or the tick budget is spent
 * (the caller should stop), 0 to keep draining. */
static int srvrun_drain_tick(
    const srvrun_cfg *cfg, srvrun_state *st, u8 *buf, usz cap, int tick) {
  if (quic_poll_wait_readable(cfg->fd, SRVRUN_DRAIN_TICK_MS) > 0)
    srvrun_step(cfg, st, buf, cap);
  return srvrun_all_drained(st) || tick >= SRVRUN_DRAIN_TICKS;
}

/* Receive datagrams until told to stop: normal service while no shutdown has
 * been requested; once requested, send GOAWAY to every live connection once
 * and drain for a bounded grace period (RFC 9114 5.2) before returning. */
static void srvrun_loop(const srvrun_cfg *cfg) {
  srvrun_state st = {g_srvrun_table, g_srvrun_state.conns};
  u8           buf[2048];
  int          tick = 0;
  quic_conntable_init(st.table, QUIC_CONNTABLE_CAP);
  while (!srvrun_shutdown_requested()) srvrun_step(cfg, &st, buf, sizeof buf);
  srvrun_goaway_all(cfg, &st);
  while (!srvrun_drain_tick(cfg, &st, buf, sizeof buf, tick)) tick++;
}

int wired_server_run(
    u16 port, const wired_srvboot_id *id, wired_srvrun_handler h) {
  srvrun_cfg cfg = {srvrun_listen(port), id, h.cb, h.ctx};
  if (cfg.fd < 0) return 0;
  if (!wired_sigterm_install(srvrun_sigterm_handler))
    WIRED_LOG("SIGTERM install failed, no graceful shutdown\n");
  WIRED_LOG("listening\n");
  srvrun_loop(&cfg);
  return 1;
}
