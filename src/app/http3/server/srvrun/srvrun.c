#include "app/http3/server/srvrun/srvrun.h"

#include "app/http3/server/srvloop/send.h"
#include "common/platform/debug/debug.h"
#include "transport/io/socket/io/udp.h"

/* The running server's mutable state: the orchestrator, the HTTP/3 loop, and
 * whether a connection is currently up. */
typedef struct {
  quic_server  s;
  quic_srvloop l;
  int          up;
} srvrun_state;

/* Send a sealed buffer with a trace line (skip an empty one). */
static void srvrun_send(
    i64                     fd,
    const quic_sockaddr_in *peer,
    const u8               *pkt,
    usz                     n,
    const char             *what) {
  (void)what; /* WIRED_LOG compiles out without -DQUIC_DEBUG */
  if (n) {
    quic_udp_send(fd, peer, pkt, n);
    WIRED_LOG(what);
  }
}

/* First datagram: cold-start the connection, register the handler, send the
 * sealed flight. Returns 1 once the server is up. */
static int srvrun_on_initial(
    i64                     fd,
    const quic_sockaddr_in *peer,
    srvrun_state           *st,
    const wired_srvboot_id *id,
    quic_srvloop_handler    h,
    void                   *ctx,
    u8                     *dg,
    usz                     len) {
  u8  out[1500];
  usz n = 0;
  if (!wired_srvboot_accept(&st->s, &st->l, id, dg, len, out, sizeof out, &n))
    return WIRED_LOG("srvboot accept failed\n"), 0;
  quic_srvloop_set_handler(&st->l, h, ctx);
  srvrun_send(fd, peer, out, n, "server flight sent\n");
  return 1;
}

/* A later datagram: one real-wire step, send any sealed reply. */
static void srvrun_on_step(
    i64 fd, const quic_sockaddr_in *peer, srvrun_state *st, u8 *dg, usz len) {
  u8  out[1500];
  usz n = 0;
  if (quic_srvloop_step(&st->l, &st->s, dg, len, out, sizeof out, &n))
    srvrun_send(fd, peer, out, n, "1-RTT reply sealed and sent\n");
}

/* RFC 9000 7: a long-header Initial only starts a NEW connection once the live
 * one is confirmed (its DCID legitimately changes after ServerHello, so gate
 * on confirmation, not the DCID). */
static int srvrun_is_new(srvrun_state *st, u8 *dg, usz len) {
  if (!wired_srvboot_is_initial(dg, len)) return 0;
  if (!st->up) return 1;
  return quic_server_is_confirmed(&st->s);
}

/* Drive one received datagram: a new Initial (re)opens the connection, any
 * other datagram steps the live loop. */
static void srvrun_serve(
    i64                     fd,
    const quic_sockaddr_in *peer,
    srvrun_state           *st,
    const wired_srvboot_id *id,
    quic_srvloop_handler    h,
    void                   *ctx,
    u8                     *dg,
    usz                     len) {
  if (srvrun_is_new(st, dg, len))
    st->up = srvrun_on_initial(fd, peer, st, id, h, ctx, dg, len);
  else if (st->up)
    srvrun_on_step(fd, peer, st, dg, len);
}

/* Bind a UDP socket on port. Returns the fd, or <0 on failure. */
static i64 srvrun_listen(u16 port) {
  quic_sockaddr_in sa;
  i64              fd = quic_udp_socket();
  if (fd < 0) return fd;
  quic_udp_addr(&sa, port, 0, 0, 0, 0);
  if (quic_udp_bind(fd, &sa) < 0) return -1;
  return fd;
}

/* Receive datagrams forever, serving each. */
static void srvrun_loop(
    i64 fd, const wired_srvboot_id *id, quic_srvloop_handler h, void *ctx) {
  srvrun_state     st = {{0}, {0}, 0};
  quic_sockaddr_in peer;
  u8               buf[2048];
  for (;;) {
    i64 r = quic_udp_recvfrom(fd, buf, sizeof buf, &peer);
    if (r > 0) srvrun_serve(fd, &peer, &st, id, h, ctx, buf, (usz)r);
  }
}

int wired_server_run(
    u16 port, const wired_srvboot_id *id, quic_srvloop_handler h, void *ctx) {
  i64 fd = srvrun_listen(port);
  if (fd < 0) return 0;
  WIRED_LOG("listening\n");
  srvrun_loop(fd, id, h, ctx);
  return 1;
}
