#include "ed25519/ed25519.h"
#include "frame/ack.h"
#include "frame/frame.h"
#include "pipeline/framewalk.h"
#include "h3conn/response.h"
#include "h3reqdrive/request_drive.h"
#include "srvloop/dispatch.h"
#include "udploop/rxloop.h"
#include "hspkt/onertt.h"
#include "keys/keyset.h"
#include "schedule_drive/keyschedule.h"
#include "srvloop/keys.h"
#include "srvloop/recv.h"
#include "srvloop/send.h"
#include "srvloop/srvloop.h"
#include "srvwire/wire.h"
#include "test.h"
#include "tls/clienthello.h"
#include "tls/finished.h"
#include "tls/handshake.h"
#include "tls/schedule.h"
#include "tls/serverhello.h"
#include "tls/transcript.h"
#include "tls/x25519.h"

/* RFC 9001 4 / 5 / 5.1, RFC 9000 17.2: the server real-wire loop. The server
 * seals with its own direction (SERVER_*) and opens with the peer direction
 * (CLIENT_*). The client role is simulated symmetrically using the same keys
 * the server's schedule holds, so seal-then-open across the wire is identity.
 * A normal exchange climbs Initial -> Handshake -> 1-RTT; a forged Finished
 * promotes nothing; the wrong direction key fails to open. */

static const u8 g_cli_scid[6] = {'C', 'L', 'I', 'S', 'C', 'I'};

/* Minimal Ed25519 end-entity cert carrying pub in its SPKI (RFC 5280 4.1). */
static usz lp_ed_cert(u8 *out, const u8 pub[32])
{
    static const u8 head[] = {
        0x30,
        0x48,
        0x30,
        0x3c,
        0xa0,
        0x03,
        0x02,
        0x01,
        0x02,
        0x02,
        0x01,
        0x01,
        0x30,
        0x00,
        0x30,
        0x00,
        0x30,
        0x00,
        0x30,
        0x00,
        0x30,
        0x2a,
        0x30,
        0x05,
        0x06,
        0x03,
        0x2b,
        0x65,
        0x70,
        0x03,
        0x21,
        0x00,
    };
    static const u8 tail[] = {
        0x30,
        0x05,
        0x06,
        0x03,
        0x2b,
        0x65,
        0x70,
        0x03,
        0x01,
        0x00,
    };
    usz off = 0, i;
    for (i = 0; i < sizeof(head); i++)
        out[off++] = head[i];
    for (i = 0; i < 32; i++)
        out[off++] = pub[i];
    for (i = 0; i < sizeof(tail); i++)
        out[off++] = tail[i];
    return off;
}

struct lp_fix {
    quic_server s;
    quic_srvloop l;
    u8 ch[512];
    usz ch_len;
    u8 sh[256];
    usz sh_len;
    u8 flight[2048];
    usz flight_len;
    u8 srv_random[32];
    u8 cli_priv[32];
    u8 sh_pub[32];
    u8 cli_fin[64];
    usz cli_fin_len;
};

static void lp_make_client_hello(struct lp_fix *f)
{
    static const u8 tp[1] = {0};
    u8 cli_pub[32];
    for (usz i = 0; i < 32; i++) {
        f->cli_priv[i] = (u8)(i + 1);
        f->srv_random[i] = (u8)(0xa0 + i);
    }
    quic_x25519_base(cli_pub, f->cli_priv);
    f->ch_len = quic_tls_client_hello(f->ch, sizeof(f->ch), f->srv_random,
                                      cli_pub, 0, 0, tp, sizeof(tp));
}

/* Bring the server to FLIGHT_SENT (Handshake keys derived) and init the loop. */
static void lp_drive_to_flight(struct lp_fix *f)
{
    u8 srv_priv[32], srv_pub[32], cert_seed[32], cert_pub[32];
    static u8 cert[128];
    usz cert_len;
    for (usz i = 0; i < 32; i++) {
        srv_priv[i] = (u8)(0x40 + i);
        cert_seed[i] = (u8)(0x80 + i);
    }
    quic_x25519_base(srv_pub, srv_priv);
    CHECK(quic_ed25519_keypair(cert_seed, cert_pub));
    cert_len = lp_ed_cert(cert, cert_pub);

    quic_server_init(&f->s, srv_priv, srv_pub, cert_seed, cert, cert_len);
    CHECK(quic_server_set_cids(&f->s, g_cli_scid, 6, g_cli_scid, 6) == 1);
    CHECK(quic_srvloop_init(&f->l, g_cli_scid, 6) == 1);
    CHECK(quic_server_recv_initial(&f->s, f->ch, f->ch_len) == 1);
    CHECK(quic_server_build_flight(&f->s, f->srv_random,
                                   f->sh, sizeof(f->sh), &f->sh_len,
                                   f->flight, sizeof(f->flight),
                                   &f->flight_len) == 1);
    CHECK(f->s.phase == QUIC_SERVER_HS_FLIGHT_SENT);
}

/* Compute the genuine client Finished message (RFC 8446 4.4.4). */
static void lp_make_client_finished(struct lp_fix *f)
{
    u16 cipher, version;
    u8 hs[32], c_traffic[32], th[32];
    quic_transcript tr;
    usz off;
    CHECK(quic_tls_parse_server_hello(f->sh, f->sh_len, f->sh_pub,
                                      &cipher, &version));
    {
        u8 shared[32];
        quic_x25519(shared, f->cli_priv, f->sh_pub);
        quic_tls_handshake_secret(shared, hs);
    }
    quic_transcript_init(&tr);
    quic_transcript_add(&tr, f->ch, f->ch_len);
    quic_transcript_add(&tr, f->sh, f->sh_len);
    quic_transcript_hash(&tr, th);
    quic_hkdf_expand_label(hs, "c hs traffic", 12, th, 32, c_traffic, 32);
    quic_transcript_add(&tr, f->flight, f->flight_len);
    quic_transcript_hash(&tr, th);

    off = quic_hs_begin(f->cli_fin, sizeof(f->cli_fin), QUIC_HS_FINISHED);
    quic_tls_finished_verify_data(c_traffic, th, f->cli_fin + off);
    f->cli_fin_len = off + QUIC_TLS_VERIFY_DATA;
    quic_hs_finish(f->cli_fin, f->cli_fin_len);
}

/* Client role: seal a Handshake CRYPTO flight toward the server with the
 * peer-direction CLIENT_HS key (which the server opens with). */
static usz client_seal_handshake(struct lp_fix *f, const u8 *msg, usz mlen,
                                 u8 *pkt, usz cap)
{
    const quic_initial_keys *k;
    quic_aes128 hp;
    usz total = 0;
    CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_HS, &k) == 1);
    quic_aes128_init(&hp, k->hp);
    CHECK(quic_srvwire_seal_handshake(k, &hp, f->s.sdrv.iscid,
                                      f->s.sdrv.iscid_len, g_cli_scid, 6, 0, -1,
                                      msg, mlen, pkt, cap, &total));
    return total;
}

/* Client role: seal a 1-RTT STREAM payload toward the server with CLIENT_AP. */
static usz client_seal_onertt(struct lp_fix *f, const u8 *pl, usz pln,
                              u8 *pkt, usz cap)
{
    const quic_initial_keys *k;
    quic_aes128 hp;
    usz total = 0;
    CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_AP, &k) == 1);
    quic_aes128_init(&hp, k->hp);
    CHECK(quic_hspkt_onertt_build(k, &hp, f->s.sdrv.iscid, f->s.sdrv.iscid_len,
                                  0, pl, pln, pkt, cap, &total));
    return total;
}

/* DIRECTION: server seals Initial/Handshake and the matching open recovers the
 * bytes; the wrong-direction key fails. */
static void test_srvloop_send_initial_roundtrip(void)
{
    struct lp_fix f;
    u8 pkt[1300];
    usz total = 0;
    const u8 *tls = 0;
    usz tls_len = 0;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    CHECK(quic_srvloop_send_initial(&f.s, g_cli_scid, 6, 1, -1,
                                    f.sh, f.sh_len, pkt, sizeof pkt, &total));
    CHECK(quic_srvwire_open_initial(f.s.sdrv.odcid, f.s.sdrv.odcid_len,
                                    pkt, total, 1, &tls, &tls_len));
    CHECK(tls_len == f.sh_len);
}

/* DIRECTION SAFETY: a server-sealed Handshake packet (SERVER_HS) opens with the
 * server's own-direction key (the client's peer key) but NOT with CLIENT_HS,
 * the peer-direction key the server itself uses to open inbound packets. */
static void test_srvloop_wrong_direction_open_fails(void)
{
    struct lp_fix f;
    u8 pkt[2300];
    usz total = 0;
    const quic_initial_keys *own, *peer;
    quic_aes128 ownhp, peerhp;
    const u8 *tls = 0;
    usz tls_len = 0;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    CHECK(quic_srvloop_send_handshake(&f.s, g_cli_scid, 6, 0, -1,
                                      f.flight, f.flight_len,
                                      pkt, sizeof pkt, &total));
    /* SERVER_HS (own / client-peer) opens it; CLIENT_HS (server-open) must NOT. */
    CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_SERVER_HS, &own) == 1);
    quic_aes128_init(&ownhp, own->hp);
    CHECK(quic_srvwire_open_handshake(own, &ownhp, pkt, total, 6,
                                      &tls, &tls_len) == 1);
    CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_CLIENT_HS, &peer) == 1);
    quic_aes128_init(&peerhp, peer->hp);
    CHECK(quic_srvwire_open_handshake(peer, &peerhp, pkt, total, 6,
                                      &tls, &tls_len) == 0);
}

/* No 1-RTT key before confirmation: seal at 1-RTT is refused (RFC 9001 5). */
static void test_srvloop_no_onertt_seal_before_confirm(void)
{
    struct lp_fix f;
    u8 pkt[256], frame[1] = {0x1e};
    usz total = 0;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    CHECK(quic_server_is_confirmed(&f.s) == 0);
    CHECK(quic_srvloop_send_onertt(&f.s, g_cli_scid, 6, 0, frame, 1,
                                   pkt, sizeof pkt, &total) == 0);
}

/* CENTRAL SAFETY: a forged client Finished does not promote the server, so the
 * step produces no HANDSHAKE_DONE and 1-RTT stays unarmed. */
static void test_srvloop_forged_finished_no_promote(void)
{
    struct lp_fix f;
    u8 cpkt[512], out[512];
    usz clen, out_len = 0;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    lp_make_client_finished(&f);
    f.cli_fin[4] ^= 0x01;
    clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
    CHECK(quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out,
                            &out_len) == 0);
    CHECK(quic_server_is_confirmed(&f.s) == 0);
    {
        const quic_initial_keys *k;
        CHECK(quic_keyset_for_level(&f.s.keys, QUIC_LEVEL_ONERTT, &k) == 0);
    }
}

/* Client role: open a server-sealed 1-RTT packet with the peer SERVER_AP key
 * (the client's view) and view its raw frame payload. */
static int client_open_onertt(struct lp_fix *f, u8 *pkt, usz len,
                              const u8 **pl, usz *pll)
{
    const quic_initial_keys *k;
    quic_aes128 hp;
    CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_SERVER_AP, &k) == 1);
    quic_aes128_init(&hp, k->hp);
    return quic_hspkt_onertt_open(k, &hp, pkt, len, 6, 0, pl, pll);
}

/* The confirmation 1-RTT payload carries a STREAM frame on the server control
 * stream (id 3) whose data leads with the control type 0x00 + SETTINGS, and
 * then a HANDSHAKE_DONE (0x1e) frame (RFC 9114 6.2.1 / RFC 9000 19.20). */
static void check_settings_and_done(const u8 *pl, usz pll)
{
    quic_stream_frame sf;
    usz n = quic_frame_get_stream(pl, pll, &sf);
    CHECK(n > 0);
    CHECK(sf.stream_id == 3);     /* first server unidirectional stream */
    CHECK(sf.length > 0 && sf.data[0] == 0x00); /* control stream type */
    CHECK(pll > n && pl[pll - 1] == 0x1e);       /* trailing HANDSHAKE_DONE */
}

/* LIVENESS: a genuine client Finished drives the server to confirmed. The step
 * now seals a coalesced datagram: a Handshake ACK of the client Finished
 * (RFC 9000 13.2.1) ahead of a 1-RTT packet carrying SETTINGS + HANDSHAKE_DONE
 * (RFC 9114 6.2.1). A following GET yields a decodable 200 (RFC 9114 4.1). */
static void test_srvloop_full_roundtrip(void)
{
    struct lp_fix f;
    u8 cpkt[1024], out[1024], get[512];
    usz clen, out_len = 0, glen;
    const u8 *pkts[4];
    usz offs[4], lens[4], np;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    lp_make_client_finished(&f);
    clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
    CHECK(quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out,
                            &out_len) == 1);
    CHECK(quic_server_is_confirmed(&f.s) == 1);
    /* The reply coalesces a Handshake ACK (long header) and a 1-RTT packet. */
    np = quic_udploop_split(out, out_len, pkts, offs, lens, 4);
    CHECK(np == 2);
    CHECK((out[offs[0]] & 0x80) != 0); /* slice 0: long-header Handshake ACK */
    {
        const u8 *pl;
        usz pll;
        CHECK(client_open_onertt(&f, out + offs[1], lens[1], &pl, &pll) == 1);
        check_settings_and_done(pl, pll);
    }

    /* GET over 1-RTT -> a 200 response that the client can decode. */
    CHECK(quic_h3reqdrive_send_get(0, (const u8 *)"/", 1,
                                   (const u8 *)"h", 1, get, sizeof get, &glen));
    {
        u8 spkt[1024];
        usz slen = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
        const u8 *pl, *body;
        usz pll, body_len;
        u16 status = 0;
        out_len = 0;
        CHECK(quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out,
                                &out_len) == 1);
        CHECK(client_open_onertt(&f, out, out_len, &pl, &pll) == 1);
        CHECK(quic_h3conn_recv_response(pl, pll, &status, &body, &body_len) == 1);
        CHECK(status == 200);
    }
}

/* Client role: seal a 1-RTT STREAM payload at an explicit packet number. */
static usz client_seal_onertt_pn(struct lp_fix *f, u64 pn, const u8 *pl, usz pln,
                                 u8 *pkt, usz cap)
{
    const quic_initial_keys *k;
    quic_aes128 hp;
    usz total = 0;
    CHECK(quic_keysched_get(&f->s.sched, QUIC_KS_CLIENT_AP, &k) == 1);
    quic_aes128_init(&hp, k->hp);
    CHECK(quic_hspkt_onertt_build(k, &hp, f->s.sdrv.iscid, f->s.sdrv.iscid_len,
                                  pn, pl, pln, pkt, cap, &total));
    return total;
}

/* Walk a 1-RTT payload and assert it carries an ACK frame whose largest range
 * acknowledges pn (RFC 9000 19.3) — this is what stops the client retransmitting. */
static void check_acks_pn(const u8 *pl, usz pll, u64 pn)
{
    quic_framewalk it;
    u64 type;
    const u8 *frame;
    usz rem;
    int found = 0;
    quic_framewalk_init(&it, pl, pll);
    while (quic_framewalk_next(&it, &type, &frame, &rem))
        if (type == QUIC_FRAME_ACK) {
            quic_ack_frame a;
            CHECK(quic_ack_decode(frame, rem, &a) > 0);
            CHECK(a.ranges[0].hi == pn);
            found = 1;
        }
    CHECK(found);
}

/* Drive the loop to confirmed with a genuine client Finished. */
static void lp_confirm(struct lp_fix *f, u8 *out, usz cap, usz *out_len)
{
    u8 cpkt[1024];
    usz clen;
    lp_make_client_hello(f);
    lp_drive_to_flight(f);
    lp_make_client_finished(f);
    clen = client_seal_handshake(f, f->cli_fin, f->cli_fin_len, cpkt, sizeof cpkt);
    *out_len = 0;
    CHECK(quic_srvloop_step(&f->l, &f->s, cpkt, clen, out, cap, out_len) == 1);
    CHECK(quic_server_is_confirmed(&f->s) == 1);
}

/* (C) ACK A 1-RTT GET: a decoded GET yields a 200 whose 1-RTT packet also
 * carries an ACK of the received GET's packet number (RFC 9000 13.2.1), so the
 * client stops retransmitting the GET once the 200 is received. */
static void test_srvloop_onertt_get_is_acked(void)
{
    struct lp_fix f;
    u8 out[1024], get[512], spkt[1024];
    usz out_len = 0, glen, slen;
    const u8 *pl;
    usz pll;
    lp_confirm(&f, out, sizeof out, &out_len);
    CHECK(quic_h3reqdrive_send_get(0, (const u8 *)"/", 1,
                                   (const u8 *)"h", 1, get, sizeof get, &glen));
    slen = client_seal_onertt_pn(&f, 7, get, glen, spkt, sizeof spkt);
    out_len = 0;
    CHECK(quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out,
                            &out_len) == 1);
    CHECK(client_open_onertt(&f, out, out_len, &pl, &pll) == 1);
    check_acks_pn(pl, pll, 7);
}

/* (A) CONFIRM ONCE: after confirmation, a further 1-RTT datagram that does not
 * decode to a request must NOT re-emit the confirmation (SETTINGS +
 * HANDSHAKE_DONE). It either acks the received 1-RTT packet or sends nothing,
 * but never the confirmation again, so the client is not flooded with it. */
static void test_srvloop_confirm_emitted_once(void)
{
    struct lp_fix f;
    u8 out[1024], junk[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    u8 spkt[1024];
    usz out_len = 0, slen;
    lp_confirm(&f, out, sizeof out, &out_len);
    /* A 1-RTT packet that carries only PADDING: no request decoded. */
    slen = client_seal_onertt_pn(&f, 3, junk, sizeof junk, spkt, sizeof spkt);
    out_len = 0;
    quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out, &out_len);
    if (out_len > 0) {
        const u8 *pl;
        usz pll;
        CHECK(client_open_onertt(&f, out, out_len, &pl, &pll) == 1);
        /* must not be the confirmation: no HANDSHAKE_DONE trailer. */
        CHECK(!(pll > 0 && pl[pll - 1] == 0x1e));
    }
}

/* Prepend a PADDING (0x00) byte to src into dst; returns the new length. */
static usz lp_pad_prefix(u8 *dst, const u8 *src, usz n)
{
    dst[0] = 0x00; /* RFC 9000 19.1 PADDING */
    for (usz i = 0; i < n; i++)
        dst[1 + i] = src[i];
    return n + 1;
}

/* Build a dispatcher payload [PADDING][CRYPTO(msg)] (RFC 9000 12.4 / 19.6). */
static usz lp_padding_then_crypto(u8 *out, usz cap, const u8 *msg, usz mlen)
{
    quic_crypto_frame cf = {0, (u64)mlen, msg};
    out[0] = 0x00; /* leading PADDING, as curl/quiche emit */
    return 1 + quic_frame_put_crypto(out + 1, cap - 1, &cf);
}

/* NON-CRYPTO-FIRST handshake: a Handshake payload that leads with PADDING before
 * its CRYPTO frame (curl/quiche do this) must still confirm. The dispatcher is
 * exercised directly because the wire helper wraps everything in one CRYPTO
 * frame (RFC 9000 12.4). */
static void test_srvloop_dispatch_padding_before_crypto(void)
{
    struct lp_fix f;
    u8 payload[256];
    usz plen;
    quic_h3reqdrive_req req;
    u8 scratch[512];
    int got = 0;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    lp_make_client_finished(&f);
    plen = lp_padding_then_crypto(payload, sizeof payload,
                                  f.cli_fin, f.cli_fin_len);
    CHECK(quic_srvloop_dispatch(&f.s, &f.l.h3, payload, plen,
                                scratch, sizeof scratch, &got, &req) == 1);
    CHECK(quic_server_is_confirmed(&f.s) == 1);
}

/* NON-STREAM-FIRST 1-RTT: a 1-RTT packet that leads with PADDING before the
 * STREAM frame still yields a 200 (RFC 9000 12.4). The full seal/open path is
 * used here since onertt carries the raw frame payload. */
static void test_srvloop_padding_before_stream(void)
{
    struct lp_fix f;
    u8 cpkt[1024], out[1024], get[512], pget[576], spkt[1024];
    usz clen, out_len = 0, glen, plen, slen;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    lp_make_client_finished(&f);
    clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
    CHECK(quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out,
                            &out_len) == 1);
    CHECK(quic_h3reqdrive_send_get(0, (const u8 *)"/", 1,
                                   (const u8 *)"h", 1, get, sizeof get, &glen));
    plen = lp_pad_prefix(pget, get, glen);
    slen = client_seal_onertt(&f, pget, plen, spkt, sizeof spkt);
    out_len = 0;
    CHECK(quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out,
                            &out_len) == 1);
    CHECK(out_len > 0);
}

/* COALESCED RECEIVE (RFC 9000 12.2): curl/quiche coalesce the client Finished
 * Handshake packet behind a leading packet (an Initial ACK or a PADDING-only
 * Handshake) in one datagram. A leading Handshake carrying only PADDING does not
 * confirm; the step must walk past it to the second slice's genuine Finished and
 * reach confirmed — proving the loop no longer drops non-first slices. */
static void test_srvloop_coalesced_finished_behind_leading(void)
{
    struct lp_fix f;
    u8 lead[256], rest[512], dg[1024], out[1024];
    u8 padding[1] = {0x00}; /* RFC 9000 19.1 */
    usz lead_len, rest_len, i, off = 0, out_len = 0;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    lp_make_client_finished(&f);
    lead_len = client_seal_handshake(&f, padding, 1, lead, sizeof lead);
    rest_len = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len,
                                     rest, sizeof rest);
    for (i = 0; i < lead_len; i++) dg[off++] = lead[i];
    for (i = 0; i < rest_len; i++) dg[off++] = rest[i];
    CHECK(quic_srvloop_step(&f.l, &f.s, dg, off, out, sizeof out,
                            &out_len) == 1);
    CHECK(quic_server_is_confirmed(&f.s) == 1);
}

/* Build a STREAM frame on `stream_id` whose data is one type byte `lead`
 * (RFC 9114 6.2: control 0x00 / QPACK encoder 0x02 / decoder 0x03). */
static usz lp_uni_stream(u8 *out, usz cap, u64 stream_id, u8 lead)
{
    quic_stream_frame sf = {stream_id, 0, 1, &lead, 0};
    return quic_frame_put_stream(out, cap, &sf);
}

/* STREAM ID CLASSIFICATION (RFC 9000 2.1, RFC 9114 6.2): a 1-RTT payload that
 * carries only unidirectional STREAM frames (curl's control/encoder/decoder,
 * ids 2 and 6) must be accepted without being mistaken for a request — no
 * got_request, no error. */
static void test_srvloop_dispatch_uni_streams_not_request(void)
{
    struct lp_fix f;
    u8 payload[256];
    usz off = 0;
    quic_h3reqdrive_req req;
    u8 scratch[512];
    int got = 0;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    off += lp_uni_stream(payload + off, sizeof payload - off, 2, 0x00);
    off += lp_uni_stream(payload + off, sizeof payload - off, 6, 0x02);
    CHECK(quic_srvloop_dispatch(&f.s, &f.l.h3, payload, off,
                                scratch, sizeof scratch, &got, &req) == 1);
    CHECK(got == 0);
}

/* A client bidi request stream (id 0, HEADERS=GET) arriving AFTER leading
 * unidirectional streams is the one decoded: the dispatcher skips the uni
 * STREAMs and drives the request (RFC 9000 2.1, RFC 9114 6.1/6.2). */
static void test_srvloop_dispatch_get_after_uni_streams(void)
{
    struct lp_fix f;
    u8 payload[576], get[512];
    usz off = 0, glen;
    quic_h3reqdrive_req req;
    u8 scratch[512];
    int got = 0;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    off += lp_uni_stream(payload + off, sizeof payload - off, 2, 0x00);
    off += lp_uni_stream(payload + off, sizeof payload - off, 3, 0x03);
    CHECK(quic_h3reqdrive_send_get(0, (const u8 *)"/", 1, (const u8 *)"h", 1,
                                   get, sizeof get, &glen));
    for (usz i = 0; i < glen; i++) payload[off++] = get[i];
    CHECK(quic_srvloop_dispatch(&f.s, &f.l.h3, payload, off,
                                scratch, sizeof scratch, &got, &req) == 1);
    CHECK(got == 1);
}

/* DIAGNOSTICS: a genuine 1-RTT GET decrypts, so last_1rtt_open_ok latches to 1;
 * corrupting the same packet's ciphertext makes the AEAD open fail while it stays
 * a short-header (ONERTT) packet, so the diagnostic reports 0 (RFC 9001 5.1). */
static void test_srvloop_records_1rtt_open(void)
{
    struct lp_fix f;
    u8 out[1024], get[512], spkt[1024];
    usz out_len = 0, glen, slen;
    lp_confirm(&f, out, sizeof out, &out_len);
    CHECK(quic_h3reqdrive_send_get(0, (const u8 *)"/", 1,
                                   (const u8 *)"h", 1, get, sizeof get, &glen));
    slen = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
    out_len = 0;
    quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out, &out_len);
    CHECK(f.l.last_1rtt_open_ok == 1);
    spkt[slen - 1] ^= 0x80; /* flip a ciphertext byte: AEAD tag no longer matches */
    out_len = 0;
    quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out, &out_len);
    CHECK(f.l.last_1rtt_open_ok == 0);
}

void test_srvloop(void)
{
    test_srvloop_records_1rtt_open();
    test_srvloop_dispatch_uni_streams_not_request();
    test_srvloop_dispatch_get_after_uni_streams();
    test_srvloop_send_initial_roundtrip();
    test_srvloop_wrong_direction_open_fails();
    test_srvloop_no_onertt_seal_before_confirm();
    test_srvloop_forged_finished_no_promote();
    test_srvloop_full_roundtrip();
    test_srvloop_dispatch_padding_before_crypto();
    test_srvloop_padding_before_stream();
    test_srvloop_coalesced_finished_behind_leading();
    test_srvloop_onertt_get_is_acked();
    test_srvloop_confirm_emitted_once();
}
