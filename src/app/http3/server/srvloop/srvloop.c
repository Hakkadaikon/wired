#include "app/http3/server/srvloop/srvloop.h"
#include "connrunner/level.h"
#include "transport/packet/header/packet/pnum.h"
#include "app/http3/server/srvloop/dispatch.h"
#include "app/http3/server/srvloop/recv.h"
#include "app/http3/server/srvloop/respond.h"
#include "transport/io/udp/udploop/rxloop.h"

#define QUIC_SRVLOOP_MAXPKTS 8     /* coalesced packets per datagram (RFC 9000 12.2) */

int quic_srvloop_init(quic_srvloop *l, const u8 *cli_scid, u8 cli_scid_len)
{
    if (cli_scid_len > 20)
        return 0;
    l->h3.settings_sent = 0;
    l->h3.peer_control = 0;
    l->h3.peer_settings = 0;
    l->h3.request_seen = 0;
    l->cli_scid_len = cli_scid_len;
    for (usz i = 0; i < cli_scid_len; i++)
        l->cli_scid[i] = cli_scid[i];
    l->tx_pn = 0;
    l->hs_tx_pn = 0;
    l->app_rx_pn = 0;
    l->app_rx_seen = 0;
    l->hs_done_sent = 0;
    l->on_request = 0;
    l->req_ctx = 0;
    l->got_request = 0;
    l->req_len = 0;
    l->req_fin = 0;
    l->req_done = 0;
    return 1;
}

void quic_srvloop_set_handler(quic_srvloop *l, quic_srvloop_handler cb, void *ctx)
{
    l->on_request = cb;
    l->req_ctx = ctx;
}

/* The largest 1-RTT packet number received so far (0 before any), the baseline
 * for recovering a truncated PN (RFC 9000 A.3). */
static u64 app_largest_pn(const quic_srvloop *l)
{
    return l->app_rx_seen ? l->app_rx_pn : 0;
}

/* RFC 9000 13.2.1 / A.3: once a 1-RTT packet is opened, the truncated (1..4
 * byte) packet number is cleartext in the header (header protection removed in
 * place) and byte0's low bits give its length. Recover the full PN against the
 * largest seen so far and record it as the number to ACK / the new baseline. */
static void note_app_rx(quic_srvloop *l, quic_server *s, int level, const u8 *pkt)
{
    const u8 *pn;
    usz pn_len;
    if (level != QUIC_LEVEL_ONERTT)
        return;
    pn = pkt + 1u + s->sdrv.iscid_len;
    pn_len = (pkt[0] & 0x03u) + 1u;
    l->app_rx_pn = quic_pnum_decode(pn, pn_len, app_largest_pn(l));
    l->app_rx_seen = 1;
}

/* RFC 9000 2.2: view the loop's cross-datagram request-stream accumulator. */
static quic_srvloop_reqacc step_reqacc(quic_srvloop *l)
{
    quic_srvloop_reqacc acc;
    acc.buf = l->req_buf;
    acc.cap = sizeof l->req_buf;
    acc.len = &l->req_len;
    acc.fin = &l->req_fin;
    acc.done = &l->req_done;
    return acc;
}

/* RFC 9001 5 / 5.1: open one coalesced packet slice and walk its frames. A
 * STREAM frame sets *got_request; CRYPTO is fed to the handshake. A slice that
 * fails to open (wrong level/key) is silently skipped, as the next slice in the
 * datagram may still be ours (RFC 9000 12.2). */
static void step_one(quic_srvloop *l, quic_server *s, u8 *pkt, usz len,
                     int *got_request)
{
    const u8 *payload;
    usz plen;
    int level;
    quic_srvloop_reqacc acc = step_reqacc(l);
    int opened = quic_srvloop_recv(s, pkt, len, app_largest_pn(l),
                                   &level, &payload, &plen);
    if (!opened)
        return;
    note_app_rx(l, s, level, pkt);
    quic_srvloop_dispatch(s, &l->h3, payload, plen, &acc, l->req_scratch,
                          sizeof l->req_scratch, got_request, &l->req);
}

/* RFC 9000 2.2: re-arm the request-stream accumulator after a completed request
 * has been answered, so the next request (curl reuses stream 0 across requests)
 * reassembles from a clean buffer rather than re-triggering the finished one. */
static void rearm_reqacc(quic_srvloop *l, int got_request)
{
    if (!got_request)
        return;
    l->req_len = 0;
    l->req_fin = 0;
    l->req_done = 0;
}

/* RFC 9000 12.2: a received datagram may coalesce several QUIC packets (e.g. an
 * Initial/ACK ahead of the Handshake carrying the client Finished). Split it and
 * process every slice before building one reply for the whole datagram. */
int quic_srvloop_step(quic_srvloop *l, quic_server *s, u8 *dgram, usz len,
                      u8 *out, usz cap, usz *out_len)
{
    const u8 *pkts[QUIC_SRVLOOP_MAXPKTS];
    usz offs[QUIC_SRVLOOP_MAXPKTS], lens[QUIC_SRVLOOP_MAXPKTS], n, i;
    int got_request = 0;
    int r;
    n = quic_udploop_split(dgram, len, pkts, offs, lens, QUIC_SRVLOOP_MAXPKTS);
    for (i = 0; i < n; i++)
        step_one(l, s, dgram + offs[i], lens[i], &got_request);
    r = quic_srvloop_produce(l, s, got_request, out, cap, out_len);
    rearm_reqacc(l, got_request);
    return r;
}
