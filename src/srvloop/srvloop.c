#include "srvloop/srvloop.h"
#include "connrunner/level.h"
#include "frame/ack.h"
#include "h3srv/control.h"
#include "h3srv/respond.h"
#include "hspkt/hspkt_build.h"
#include "keys/keyset.h"
#include "packet/pnum.h"
#include "appdata/stream_send.h"
#include "srvloop/dispatch.h"
#include "srvloop/keys.h"
#include "srvloop/recv.h"
#include "srvloop/send.h"
#include "udploop/rxloop.h"

#define QUIC_SRVLOOP_SCRATCH 512
#define QUIC_SRVLOOP_RESP_STREAM 0
#define QUIC_SRVLOOP_CTRL_STREAM 3 /* RFC 9114 6.2.1: first server uni stream */
#define QUIC_SRVLOOP_MAXPKTS 8     /* coalesced packets per datagram (RFC 9000 12.2) */
#define QUIC_SRVLOOP_CLIENT_FIN_PN 0 /* RFC 9000 13.1: client Finished arrives at Handshake PN 0 */

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
    l->last_1rtt_open_ok = 0;
    return 1;
}

/* RFC 9000 13.2.1 / 19.3: encode an ACK frame for the single packet number pn. */
static usz encode_ack_one(u8 *frames, usz cap, u64 pn)
{
    quic_ack_frame f = {0};
    f.n_ranges = 1;
    f.ranges[0].hi = pn;
    f.ranges[0].lo = pn;
    return quic_ack_encode(frames, cap, &f);
}

/* RFC 9000 13.2.1: seal a Handshake packet that carries only an ACK of the
 * client Finished's packet number (no CRYPTO), so curl stops retransmitting it.
 * ponytail: acks the fixed Handshake PN 0 (curl's first Handshake packet);
 * track the received PN if a peer ever delays its Finished to a later one. */
static int emit_handshake_ack(quic_srvloop *l, quic_server *s,
                              u8 *out, usz cap, usz *out_len)
{
    const quic_initial_keys *k;
    quic_aes128 hp;
    u8 frames[16];
    usz fl;
    if (!quic_srvloop_seal_keys(s, QUIC_LEVEL_HANDSHAKE, &k, &hp))
        return 0;
    fl = encode_ack_one(frames, sizeof frames, QUIC_SRVLOOP_CLIENT_FIN_PN);
    if (fl == 0)
        return 0;
    return quic_hspkt_build(k, &hp, l->cli_scid, l->cli_scid_len, s->sdrv.iscid,
                            s->sdrv.iscid_len, l->hs_tx_pn++, frames, fl,
                            out, cap, out_len);
}

/* RFC 9114 6.2.1: wrap the control-stream type + SETTINGS in a STREAM frame on
 * the first server unidirectional stream (id 3, no FIN: the stream stays open). */
static int build_settings_frame(quic_srvloop *l, u8 *out, usz cap, usz *len)
{
    u8 ctl[64];
    usz cl;
    if (!quic_h3srv_open_control(&l->h3, ctl, sizeof ctl, &cl))
        return 0;
    return quic_appdata_stream_frame(QUIC_SRVLOOP_CTRL_STREAM, 0, ctl, cl, 0,
                                     out, cap, len);
}

/* The 1-RTT payload sent at confirmation: the SETTINGS STREAM frame (RFC 9114
 * 6.2.1) followed by HANDSHAKE_DONE (RFC 9000 19.20), in one packet. */
static int confirm_payload(quic_srvloop *l, quic_server *s,
                           u8 *buf, usz cap, usz *len)
{
    usz a, b;
    if (!build_settings_frame(l, buf, cap, &a))
        return 0;
    if (!quic_server_handshake_done(s, buf + a, cap - a, &b))
        return 0;
    *len = a + b;
    return 1;
}

/* Seal the confirmation 1-RTT packet (SETTINGS + HANDSHAKE_DONE) into out. */
static int seal_confirm_onertt(quic_srvloop *l, quic_server *s,
                               u8 *out, usz cap, usz *out_len)
{
    u8 pl[128];
    usz pll;
    if (!confirm_payload(l, s, pl, sizeof pl, &pll))
        return 0;
    return quic_srvloop_send_onertt(s, l->cli_scid, l->cli_scid_len, l->tx_pn++,
                                    pl, pll, out, cap, out_len);
}

/* RFC 9000 12.2: at confirmation, coalesce a Handshake ACK and a 1-RTT packet
 * (SETTINGS + HANDSHAKE_DONE) into one datagram. */
static int emit_confirm(quic_srvloop *l, quic_server *s,
                        u8 *out, usz cap, usz *out_len)
{
    usz hl = 0, rl = 0;
    if (!emit_handshake_ack(l, s, out, cap, &hl))
        return 0;
    if (!seal_confirm_onertt(l, s, out + hl, cap - hl, &rl))
        return 0;
    *out_len = hl + rl;
    return 1;
}

/* RFC 9000 13.2.1: append an ACK of the last received 1-RTT packet number to a
 * 1-RTT payload, so the client stops retransmitting it. Returns the ACK length
 * (0 if no 1-RTT packet has been received yet). */
static usz app_ack_append(quic_srvloop *l, u8 *buf, usz cap)
{
    if (!l->app_rx_seen)
        return 0;
    return encode_ack_one(buf, cap, l->app_rx_pn);
}

/* RFC 9114 4.1 / RFC 9000 13.2.1: build a 200 (no body) for the decoded request,
 * then append a 1-RTT ACK of the received GET, sealed in one 1-RTT packet. The
 * response STREAM frame carries an explicit length, so a peer's response decoder
 * stops at it and ignores the trailing ACK. SETTINGS were already sent at
 * confirmation (build_response needs settings_sent). */
static int emit_response(quic_srvloop *l, quic_server *s,
                         u8 *out, usz cap, usz *out_len)
{
    u8 pl[288];
    usz rl;
    if (!quic_h3srv_build_response(&l->h3, QUIC_SRVLOOP_RESP_STREAM, 200,
                                   (const u8 *)0, 0, pl, sizeof pl, &rl))
        return 0;
    rl += app_ack_append(l, pl + rl, sizeof pl - rl);
    return quic_srvloop_send_onertt(s, l->cli_scid, l->cli_scid_len,
                                    l->tx_pn++, pl, rl, out, cap, out_len);
}

/* RFC 9000 13.2.1: a 1-RTT packet carrying only an ACK of the received packet,
 * sent post-confirmation when no request decoded — so the confirmation is not
 * re-emitted yet the client's 1-RTT packet is still acknowledged. */
static int emit_ack_only(quic_srvloop *l, quic_server *s,
                         u8 *out, usz cap, usz *out_len)
{
    u8 pl[16];
    usz a = app_ack_append(l, pl, sizeof pl);
    if (a == 0)
        return 0;
    return quic_srvloop_send_onertt(s, l->cli_scid, l->cli_scid_len,
                                    l->tx_pn++, pl, a, out, cap, out_len);
}

/* Post-confirmation outbound: a decoded GET yields a 200 (+ACK), else a bare
 * ACK of the received 1-RTT packet, else nothing. The confirmation is never
 * re-emitted here (RFC 9000 13.2.1). */
static int produce_confirmed(quic_srvloop *l, quic_server *s, int got_request,
                             u8 *out, usz cap, usz *out_len)
{
    if (got_request)
        return emit_response(l, s, out, cap, out_len);
    return emit_ack_only(l, s, out, cap, out_len);
}

/* The confirmation (ACK + SETTINGS + HANDSHAKE_DONE) is emitted exactly once,
 * the first time the handshake confirms. On success the hs_done_sent latch is
 * set so a later non-request 1-RTT datagram no longer re-emits it. */
static int emit_confirm_once(quic_srvloop *l, quic_server *s,
                             u8 *out, usz cap, usz *out_len)
{
    if (!emit_confirm(l, s, out, cap, out_len))
        return 0;
    l->hs_done_sent = 1;
    return 1;
}

/* 1 when this step should emit the one-time confirmation: it has not been sent
 * yet and the step decoded no request (a Finished, not a GET). */
static int confirm_pending(const quic_srvloop *l, int got_request)
{
    return !l->hs_done_sent && !got_request;
}

/* Pick the outbound datagram. Before the confirmation has been sent, a step with
 * no request confirms the handshake; otherwise it is a 200 or a bare 1-RTT ACK,
 * never a repeat of the confirmation (RFC 9000 13.2.1). */
static int produce(quic_srvloop *l, quic_server *s, int got_request,
                   u8 *out, usz cap, usz *out_len)
{
    if (confirm_pending(l, got_request))
        return emit_confirm_once(l, s, out, cap, out_len);
    return produce_confirmed(l, s, got_request, out, cap, out_len);
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

/* Diagnostics: a 1-RTT (ONERTT) slice's open outcome latches last_1rtt_open_ok
 * to 1 (any slice in the datagram decrypted) so a curl run can tell an AEAD-open
 * failure apart from a later QPACK/HTTP3 decode failure. Non-1-RTT slices and a
 * first byte that never reached ONERTT leave it untouched. */
static int is_onertt_byte(u8 byte0)
{
    int level;
    return quic_connrunner_packet_level(byte0, &level) &&
           level == QUIC_LEVEL_ONERTT;
}

static void note_1rtt_open(quic_srvloop *l, int opened, u8 byte0)
{
    if (opened && is_onertt_byte(byte0))
        l->last_1rtt_open_ok = 1;
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
    int opened = quic_srvloop_recv(s, pkt, len, app_largest_pn(l),
                                   &level, &payload, &plen);
    note_1rtt_open(l, opened, pkt[0]);
    if (!opened)
        return;
    note_app_rx(l, s, level, pkt);
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
    l->last_1rtt_open_ok = 0;
    n = quic_udploop_split(dgram, len, pkts, offs, lens, QUIC_SRVLOOP_MAXPKTS);
    for (i = 0; i < n; i++)
        step_one(l, s, dgram + offs[i], lens[i], &got_request);
    return produce(l, s, got_request, out, cap, out_len);
}
