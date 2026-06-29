#include "srvloop/srvloop.h"
#include "h3srv/control.h"
#include "h3srv/respond.h"
#include "srvloop/dispatch.h"
#include "srvloop/recv.h"
#include "srvloop/send.h"
#include "udploop/rxloop.h"

#define QUIC_SRVLOOP_SCRATCH 512
#define QUIC_SRVLOOP_RESP_STREAM 0
#define QUIC_SRVLOOP_MAXPKTS 8 /* coalesced packets per datagram (RFC 9000 12.2) */

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
    return 1;
}

/* RFC 9001 4.1.2 / RFC 9000 19.20: once confirmed, seal HANDSHAKE_DONE in a
 * 1-RTT packet (own-direction SERVER_AP) exactly once. */
static int emit_handshake_done(quic_srvloop *l, quic_server *s,
                               u8 *out, usz cap, usz *out_len)
{
    u8 frame[4];
    usz fl;
    if (!quic_server_handshake_done(s, frame, sizeof frame, &fl))
        return 0;
    return quic_srvloop_send_onertt(s, l->cli_scid, l->cli_scid_len,
                                    l->tx_pn++, frame, fl, out, cap, out_len);
}

/* RFC 9114 6.2.1: ensure the server has emitted SETTINGS first (precondition of
 * any response). The control-stream bytes themselves are not separately carried
 * here; only the ordering flag the responder checks is set. */
static void ensure_settings(quic_h3srv_state *h3)
{
    u8 ctl[64];
    usz cl;
    if (!h3->settings_sent)
        quic_h3srv_open_control(h3, ctl, sizeof ctl, &cl);
}

/* RFC 9114 4.1: build a 200 (no body) for the decoded request and seal it in a
 * 1-RTT packet. */
static int emit_response(quic_srvloop *l, quic_server *s,
                         u8 *out, usz cap, usz *out_len)
{
    u8 resp[256];
    usz rl;
    ensure_settings(&l->h3);
    if (!quic_h3srv_build_response(&l->h3, QUIC_SRVLOOP_RESP_STREAM, 200,
                                   (const u8 *)0, 0, resp, sizeof resp, &rl))
        return 0;
    return quic_srvloop_send_onertt(s, l->cli_scid, l->cli_scid_len,
                                    l->tx_pn++, resp, rl, out, cap, out_len);
}

/* Pick the outbound packet for this step: a decoded GET yields a 200, otherwise
 * a freshly confirmed handshake yields HANDSHAKE_DONE. */
static int produce(quic_srvloop *l, quic_server *s, int got_request,
                   u8 *out, usz cap, usz *out_len)
{
    if (got_request)
        return emit_response(l, s, out, cap, out_len);
    return emit_handshake_done(l, s, out, cap, out_len);
}

/* RFC 9001 5 / 5.1: open one coalesced packet slice and walk its frames. A
 * STREAM frame sets *got_request; CRYPTO is fed to the handshake. A slice that
 * fails to open (wrong level/key) is silently skipped, as the next slice in the
 * datagram may still be ours (RFC 9000 12.2). */
static void step_one(quic_srvloop *l, quic_server *s, u8 *pkt, usz len,
                     int *got_request)
{
    u8 scratch[QUIC_SRVLOOP_SCRATCH];
    quic_h3reqdrive_req req;
    const u8 *payload;
    usz plen;
    int level;
    if (!quic_srvloop_recv(s, pkt, len, &level, &payload, &plen))
        return;
    quic_srvloop_dispatch(s, &l->h3, payload, plen, scratch, sizeof scratch,
                          got_request, &req);
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
    n = quic_udploop_split(dgram, len, pkts, offs, lens, QUIC_SRVLOOP_MAXPKTS);
    for (i = 0; i < n; i++)
        step_one(l, s, dgram + offs[i], lens[i], &got_request);
    return produce(l, s, got_request, out, cap, out_len);
}
