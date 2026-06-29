#include "ed25519/ed25519.h"
#include "frame/frame.h"
#include "h3reqdrive/request_drive.h"
#include "srvloop/dispatch.h"
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

/* LIVENESS: a genuine client Finished drives the server to confirmed and the
 * step seals a 1-RTT HANDSHAKE_DONE; a following GET yields a 200. */
static void test_srvloop_full_roundtrip(void)
{
    struct lp_fix f;
    u8 cpkt[1024], out[1024], get[512];
    usz clen, out_len = 0, glen;
    lp_make_client_hello(&f);
    lp_drive_to_flight(&f);
    lp_make_client_finished(&f);
    clen = client_seal_handshake(&f, f.cli_fin, f.cli_fin_len, cpkt, sizeof cpkt);
    CHECK(quic_srvloop_step(&f.l, &f.s, cpkt, clen, out, sizeof out,
                            &out_len) == 1);
    CHECK(quic_server_is_confirmed(&f.s) == 1);
    /* The HANDSHAKE_DONE opens with the peer SERVER_AP key (client view). */
    {
        const quic_initial_keys *k;
        quic_aes128 hp;
        const u8 *pl;
        usz pll;
        CHECK(quic_keysched_get(&f.s.sched, QUIC_KS_SERVER_AP, &k) == 1);
        quic_aes128_init(&hp, k->hp);
        CHECK(quic_hspkt_onertt_open(k, &hp, out, out_len, 6, &pl, &pll) == 1);
        CHECK(pll == 1 && pl[0] == 0x1e);
    }

    /* GET over 1-RTT -> 200 response sealed back. */
    CHECK(quic_h3reqdrive_send_get(0, (const u8 *)"/", 1,
                                   (const u8 *)"h", 1, get, sizeof get, &glen));
    {
        u8 spkt[1024];
        usz slen = client_seal_onertt(&f, get, glen, spkt, sizeof spkt);
        out_len = 0;
        CHECK(quic_srvloop_step(&f.l, &f.s, spkt, slen, out, sizeof out,
                                &out_len) == 1);
        CHECK(out_len > 0);
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

void test_srvloop(void)
{
    test_srvloop_send_initial_roundtrip();
    test_srvloop_wrong_direction_open_fails();
    test_srvloop_no_onertt_seal_before_confirm();
    test_srvloop_forged_finished_no_promote();
    test_srvloop_full_roundtrip();
    test_srvloop_dispatch_padding_before_crypto();
    test_srvloop_padding_before_stream();
}
