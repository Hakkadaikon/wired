#include "app/http3/server/srvloop/srvloop.h"

#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvloop/respond.h"
#include "transport/conn/loop/connrunner/level.h"
#include "transport/io/udp/udploop/rxloop.h"
#include "transport/packet/header/lhdr/lhdr_parse.h"
#include "transport/packet/header/packet/pnum.h"

#define WIRED_SRVLOOP_MAXPKTS \
  8 /* coalesced packets per datagram (RFC 9000 12.2) */

int wired_srvloop_init(wired_srvloop* l, const u8* cli_scid, u8 cli_scid_len) {
  if (cli_scid_len > 20) return 0;
  l->h3.settings_sent = 0;
  l->h3.peer_control  = 0;
  l->h3.peer_settings = 0;
  l->h3.request_seen  = 0;
  l->cli_scid_len     = cli_scid_len;
  for (usz i = 0; i < cli_scid_len; i++) l->cli_scid[i] = cli_scid[i];
  l->tx_pn        = 0;
  l->hs_tx_pn     = 0;
  l->app_rx_pn    = 0;
  l->app_rx_seen  = 0;
  l->hs_rx_pn     = 0;
  l->hs_rx_seen   = 0;
  l->hs_done_sent = 0;
  l->ticket_sent  = 0;
  l->on_request   = 0;
  l->req_ctx      = 0;
  l->got_request  = 0;
  l->req_len      = 0;
  l->req_fin      = 0;
  l->req_done     = 0;
  return 1;
}

void wired_srvloop_set_handler(
    wired_srvloop* l, wired_srvloop_handler cb, void* ctx) {
  l->on_request = cb;
  l->req_ctx    = ctx;
}

/* The largest 1-RTT packet number received so far (0 before any), the baseline
 * for recovering a truncated PN (RFC 9000 A.3). */
static u64 app_largest_pn(const wired_srvloop* l) {
  return l->app_rx_seen ? l->app_rx_pn : 0;
}

/* The opened packet's level and its (still-mutable) bytes, as note_app_rx /
 * note_hs_rx need both together. */
typedef struct {
  int        level;
  quic_mspan pkt;
} srvloop_opened;

/* RFC 9000 13.2.1 / A.3: once a 1-RTT packet is opened, the truncated (1..4
 * byte) packet number is cleartext in the header (header protection removed in
 * place) and byte0's low bits give its length. Recover the full PN against the
 * largest seen so far and record it as the number to ACK / the new baseline. */
static void note_app_rx(
    wired_srvloop* l, wired_server* s, const srvloop_opened* o) {
  const u8* pn;
  usz       pn_len;
  if (o->level != QUIC_LEVEL_ONERTT) return;
  pn             = o->pkt.p + 1u + s->sdrv.iscid_len;
  pn_len         = (o->pkt.p[0] & 0x03u) + 1u;
  l->app_rx_pn   = quic_pnum_decode(pn, pn_len, app_largest_pn(l));
  l->app_rx_seen = 1;
}

/* The largest Handshake packet number received so far (0 before any), the
 * baseline for recovering a truncated PN (RFC 9000 A.3). */
static u64 hs_largest_pn(const wired_srvloop* l) {
  return l->hs_rx_seen ? l->hs_rx_pn : 0;
}

/* RFC 9000 13.2.1: after a Handshake packet is opened (header protection
 * removed in place), re-parse its long header for the packet-number offset and
 * record the recovered PN. The client Finished does not always arrive at PN 0
 * (curl leads with an ACK-only Handshake packet), so a fixed ACK of 0 leaves
 * the Finished unacknowledged and the client PTO-retransmits it for seconds. */
static void note_hs_rx(wired_srvloop* l, const srvloop_opened* o) {
  quic_lhdr h;
  if (o->level != QUIC_LEVEL_HANDSHAKE) return;
  if (!quic_lhdr_parse(quic_span_of(o->pkt.p, o->pkt.n), 0, &h)) return;
  l->hs_rx_pn = quic_pnum_decode(
      o->pkt.p + h.pn_off, quic_lhdr_pn_len(o->pkt.p[0]), hs_largest_pn(l));
  l->hs_rx_seen = 1;
}

/* RFC 9000 2.2: view the loop's cross-datagram request-stream accumulator. */
static wired_srvloop_reqacc step_reqacc(wired_srvloop* l) {
  wired_srvloop_reqacc acc;
  acc.buf  = l->req_buf;
  acc.cap  = sizeof l->req_buf;
  acc.len  = &l->req_len;
  acc.fin  = &l->req_fin;
  acc.done = &l->req_done;
  return acc;
}

/* RFC 9001 5 / 5.1: open one coalesced packet slice and walk its frames. A
 * STREAM frame sets *got_request; CRYPTO is fed to the handshake. A slice that
 * fails to open (wrong level/key) is silently skipped, as the next slice in the
 * datagram may still be ours (RFC 9000 12.2). */
static void step_one(
    const wired_srvloop_conn* conn, quic_mspan pkt, int* got_request) {
  wired_srvloop*            l = conn->l;
  wired_server*             s = conn->s;
  wired_srvloop_recv_out    ro;
  wired_srvloop_reqacc      acc    = step_reqacc(l);
  wired_srvloop_recv_in     ri     = {pkt, app_largest_pn(l)};
  int                       opened = wired_srvloop_recv(s, &ri, &ro);
  srvloop_opened            o;
  wired_srvloop_dispatch_in in;
  if (!opened) return;
  o.level = ro.level;
  o.pkt   = pkt;
  note_app_rx(l, s, &o);
  note_hs_rx(l, &o);
  in = (wired_srvloop_dispatch_in){
      ro.payload, quic_mspan_of(l->req_scratch, sizeof l->req_scratch),
      quic_mspan_of(l->req_wrap, sizeof l->req_wrap), got_request, &l->req};
  {
    wired_srvloop_dispatch_ctx ctx = {s, &l->h3, &acc};
    wired_srvloop_dispatch(&ctx, &in);
  }
}

/* RFC 9000 2.2: re-arm the request-stream accumulator after a completed request
 * has been answered, so the next request (curl reuses stream 0 across requests)
 * reassembles from a clean buffer rather than re-triggering the finished one.
 */
static void rearm_reqacc(wired_srvloop* l, int got_request) {
  if (!got_request) return;
  l->req_len  = 0;
  l->req_fin  = 0;
  l->req_done = 0;
}

/* RFC 9000 12.2: a received datagram may coalesce several QUIC packets (e.g. an
 * Initial/ACK ahead of the Handshake carrying the client Finished). Split it
 * and process every slice before building one reply for the whole datagram. */
int wired_srvloop_step(
    const wired_srvloop_conn* conn, quic_mspan dgram, quic_obuf* out) {
  const u8*    pkts[WIRED_SRVLOOP_MAXPKTS];
  usz          offs[WIRED_SRVLOOP_MAXPKTS], lens[WIRED_SRVLOOP_MAXPKTS], n, i;
  int          got_request = 0;
  int          r;
  quic_pktlist plist = {pkts, offs, lens, WIRED_SRVLOOP_MAXPKTS};
  n = quic_udploop_split(quic_span_of(dgram.p, dgram.n), &plist);
  for (i = 0; i < n; i++)
    step_one(conn, quic_mspan_of(dgram.p + offs[i], lens[i]), &got_request);
  r = wired_srvloop_produce(conn, got_request, out);
  rearm_reqacc(conn->l, got_request);
  return r;
}
