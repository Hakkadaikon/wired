#include "app/http3/server/srvrun/srvrun.h"

#include "app/http3/server/srvloop/send.h"
#include "common/platform/debug/debug.h"
#include "transport/io/socket/io/udp.h"

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

/* The running server's mutable state: the orchestrator, the HTTP/3 loop, and
 * whether a connection is currently up. */
typedef struct {
  wired_server  s;
  wired_srvloop l;
  int           up;
} srvrun_state;

/* Everything one datagram-serving step needs besides the datagram itself: the
 * fixed run config, the peer address to reply to, and the mutable server
 * state. Folded into one parameter so srvrun_send/on_initial/on_step/serve
 * stay <=3 args. */
typedef struct {
  const srvrun_cfg       *cfg;
  const quic_sockaddr_in *peer;
  srvrun_state           *st;
} srvrun_step_ctx;

/* Send a sealed buffer with a trace line (skip an empty one). */
static void srvrun_send(
    const srvrun_step_ctx *ctx, quic_span pkt, const char *what) {
  (void)what; /* WIRED_LOG compiles out without -DQUIC_DEBUG */
  if (pkt.n) {
    wired_udp_send(ctx->cfg->fd, ctx->peer, pkt);
    WIRED_LOG(what);
  }
}

/* First datagram: cold-start the connection, register the handler, send the
 * server Initial and the Handshake flight as two datagrams (the Initial alone
 * is padded to 1200 bytes, RFC 9000 14.1, so coalescing both would exceed a
 * 1500-byte MTU datagram). Returns 1 once the server is up. */
static int srvrun_on_initial(const srvrun_step_ctx *ctx, quic_mspan dg) {
  u8                 ini[1500], hs[1500];
  quic_obuf          iob  = quic_obuf_of(ini, sizeof ini);
  quic_obuf          hob  = quic_obuf_of(hs, sizeof hs);
  wired_srvboot_conn conn = {&ctx->st->s, &ctx->st->l};
  wired_srvboot_in   in   = {ctx->cfg->id, dg};
  wired_srvboot_out  out  = {&iob, &hob};
  if (!wired_srvboot_accept(&conn, &in, &out))
    return WIRED_LOG("srvboot accept failed\n"), 0;
  wired_srvloop_set_handler(&ctx->st->l, ctx->cfg->handler, ctx->cfg->ctx);
  srvrun_send(ctx, quic_span_of(ini, iob.len), "server Initial sent\n");
  srvrun_send(ctx, quic_span_of(hs, hob.len), "server Handshake flight sent\n");
  return 1;
}

/* A later datagram: one real-wire step, send any sealed reply. */
static void srvrun_on_step(const srvrun_step_ctx *ctx, quic_mspan dg) {
  u8                 out[1500];
  quic_obuf          ob   = quic_obuf_of(out, sizeof out);
  wired_srvloop_conn conn = {&ctx->st->l, &ctx->st->s};
  if (wired_srvloop_step(&conn, dg, &ob))
    srvrun_send(
        ctx, quic_span_of(out, ob.len), "1-RTT reply sealed and sent\n");
}

/* RFC 9000 7: a long-header Initial only starts a NEW connection once the live
 * one is confirmed (its DCID legitimately changes after ServerHello, so gate
 * on confirmation, not the DCID). */
static int srvrun_is_new(srvrun_state *st, quic_mspan dg) {
  if (!wired_srvboot_is_initial(dg.p, dg.n)) return 0;
  if (!st->up) return 1;
  return wired_server_is_confirmed(&st->s);
}

/* Drive one received datagram: a new Initial (re)opens the connection, any
 * other datagram steps the live loop. */
static void srvrun_serve(const srvrun_step_ctx *ctx, quic_mspan dg) {
  if (srvrun_is_new(ctx->st, dg))
    ctx->st->up = srvrun_on_initial(ctx, dg);
  else if (ctx->st->up)
    srvrun_on_step(ctx, dg);
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

/* Receive datagrams forever, serving each. */
static void srvrun_loop(const srvrun_cfg *cfg) {
  srvrun_state     st = {{0}, {0}, 0};
  quic_sockaddr_in peer;
  u8               buf[2048];
  for (;;) {
    i64 r = wired_udp_recvfrom(cfg->fd, quic_mspan_of(buf, sizeof buf), &peer);
    if (r > 0) {
      srvrun_step_ctx ctx = {cfg, &peer, &st};
      srvrun_serve(&ctx, quic_mspan_of(buf, (usz)r));
    }
  }
}

int wired_server_run(
    u16 port, const wired_srvboot_id *id, wired_srvrun_handler h) {
  srvrun_cfg cfg = {srvrun_listen(port), id, h.cb, h.ctx};
  if (cfg.fd < 0) return 0;
  WIRED_LOG("listening\n");
  srvrun_loop(&cfg);
  return 1;
}
