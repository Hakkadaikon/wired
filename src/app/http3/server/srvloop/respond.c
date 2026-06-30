#include "app/http3/server/srvloop/respond.h"
#include "connrunner/level.h"
#include "frame/ack.h"
#include "app/http3/server/h3srv/control.h"
#include "app/http3/server/h3srv/respond.h"
#include "hspkt/hspkt_build.h"
#include "appdata/stream_send.h"
#include "app/http3/server/srvloop/keys.h"
#include "app/http3/server/srvloop/send.h"

#define QUIC_SRVLOOP_RESP_STREAM 0
#define QUIC_SRVLOOP_CTRL_STREAM 3 /* RFC 9114 6.2.1: first server uni stream */
#define QUIC_SRVLOOP_CLIENT_FIN_PN 0 /* RFC 9000 13.1: client Finished arrives at Handshake PN 0 */

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

/* RFC 9000 13.2.1: append an ACK of the last received 1-RTT packet number to a
 * 1-RTT payload, so the client stops retransmitting it. Returns the ACK length
 * (0 if no 1-RTT packet has been received yet). */
static usz app_ack_append(quic_srvloop *l, u8 *buf, usz cap)
{
    if (!l->app_rx_seen)
        return 0;
    return encode_ack_one(buf, cap, l->app_rx_pn);
}

#define QUIC_SRVLOOP_BODY_MAX 1024 /* ponytail: app response body cap; raise here if a handler needs more */

/* RFC 9110 9.3: ask the registered handler to build the response body for the
 * decoded request. No handler (or it declines) -> a body-less 200. The body is
 * written into the caller's buffer; *body_len is 0 when there is none. */
static const u8 *build_body(quic_srvloop *l, u8 *body, usz *body_len)
{
    *body_len = 0;
    if (l->on_request && l->on_request(l->req_ctx, &l->req, body,
                                       QUIC_SRVLOOP_BODY_MAX, body_len))
        return body;
    return (const u8 *)0;
}

/* RFC 9114 4.1 / 4.3.2: the 200 STREAM frame for the decoded request, carrying
 * the handler-built body; an empty section when no request was decoded. */
static int response_frame(quic_srvloop *l, int got_request,
                          u8 *buf, usz cap, usz *len)
{
    u8 body[QUIC_SRVLOOP_BODY_MAX];
    usz body_len;
    const u8 *b;
    if (!got_request) {
        *len = 0;
        return 1;
    }
    b = build_body(l, body, &body_len);
    return quic_h3srv_build_response(&l->h3, QUIC_SRVLOOP_RESP_STREAM, 200,
                                     b, body_len, buf, cap, len);
}

/* RFC 9000 12.2 / 19.4: a short-header (1-RTT) packet carries no length and must
 * be the datagram's last packet, so the confirmation and a coalesced 200 cannot
 * be two separate 1-RTT packets — they share ONE payload. SETTINGS +
 * HANDSHAKE_DONE come first (build_settings_frame must mark SETTINGS sent before
 * the 200 may be built), then the 200 STREAM when a GET was decoded; otherwise
 * the payload is the confirmation alone. Frame order within a packet does not
 * constrain HTTP/3 stream order, so a peer routes each STREAM by its id. */
static int confirm_then_maybe_200(quic_srvloop *l, quic_server *s, int got_request,
                                  u8 *buf, usz cap, usz *len)
{
    usz a, b;
    if (!confirm_payload(l, s, buf, cap, &a))
        return 0;
    if (!response_frame(l, got_request, buf + a, cap - a, &b))
        return 0;
    *len = a + b;
    return 1;
}

/* Seal the confirmation 1-RTT packet (SETTINGS + HANDSHAKE_DONE, and the 200 +
 * received-packet ACK when a GET was decoded) into out, in one 1-RTT packet. */
static int seal_confirm_onertt(quic_srvloop *l, quic_server *s, int got_request,
                               u8 *out, usz cap, usz *out_len)
{
    u8 pl[QUIC_SRVLOOP_BODY_MAX + 288];
    usz pll;
    if (!confirm_then_maybe_200(l, s, got_request, pl, sizeof pl, &pll))
        return 0;
    pll += app_ack_append(l, pl + pll, sizeof pl - pll);
    return quic_srvloop_send_onertt(s, l->cli_scid, l->cli_scid_len, l->tx_pn++,
                                    pl, pll, out, cap, out_len);
}

/* RFC 9000 12.2: at confirmation, coalesce a long-header Handshake ACK and the
 * single 1-RTT packet (SETTINGS + HANDSHAKE_DONE, plus the 200 when a GET came
 * in the same datagram) into one datagram. */
static int emit_confirm(quic_srvloop *l, quic_server *s, int got_request,
                        u8 *out, usz cap, usz *out_len)
{
    usz hl = 0, rl = 0;
    if (!emit_handshake_ack(l, s, out, cap, &hl))
        return 0;
    if (!seal_confirm_onertt(l, s, got_request, out + hl, cap - hl, &rl))
        return 0;
    *out_len = hl + rl;
    return 1;
}

/* RFC 9114 4.1 / RFC 9000 13.2.1: build a 200 (no body) for the decoded request,
 * then append a 1-RTT ACK of the received GET, sealed in one 1-RTT packet. The
 * response STREAM frame carries an explicit length, so a peer's response decoder
 * stops at it and ignores the trailing ACK. SETTINGS were already sent at
 * confirmation (build_response needs settings_sent). */
static int emit_response(quic_srvloop *l, quic_server *s,
                         u8 *out, usz cap, usz *out_len)
{
    u8 pl[QUIC_SRVLOOP_BODY_MAX + 288];
    usz rl;
    if (!response_frame(l, 1, pl, sizeof pl, &rl))
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

/* RFC 9000 12.2 / RFC 9114 6.2.1: emit the confirmation — a Handshake ACK plus
 * one 1-RTT packet that carries SETTINGS + HANDSHAKE_DONE and, when this datagram
 * also carried a GET, the 200 in the SAME 1-RTT payload (short-header packets
 * cannot coalesce). So curl receives SETTINGS to establish HTTP/3 and the 200
 * together, never the 200 alone with SETTINGS still missing. */
static int emit_confirm_then_maybe_200(quic_srvloop *l, quic_server *s,
                                       int got_request,
                                       u8 *out, usz cap, usz *out_len)
{
    if (!emit_confirm(l, s, got_request, out, cap, out_len))
        return 0;
    l->hs_done_sent = 1;
    return 1;
}

/* 1 while the one-time confirmation (SETTINGS + HANDSHAKE_DONE) has not been
 * emitted yet. It is sent exactly once — coalescing the 200 when the confirming
 * datagram also carried a GET — and not repeated thereafter (RFC 9000 13.2.1). */
static int confirm_pending(const quic_srvloop *l)
{
    return !l->hs_done_sent;
}

int quic_srvloop_produce(quic_srvloop *l, quic_server *s, int got_request,
                         u8 *out, usz cap, usz *out_len)
{
    if (confirm_pending(l))
        return emit_confirm_then_maybe_200(l, s, got_request, out, cap, out_len);
    return produce_confirmed(l, s, got_request, out, cap, out_len);
}
